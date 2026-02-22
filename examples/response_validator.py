"""
LLM response validation for structured agent outputs.

AI agents that take consequential actions (send messages, approve requests,
execute code) must not blindly trust LLM output. LLMs can return:
  - Malformed JSON
  - JSON wrapped in markdown fences (```json … ```)
  - Valid JSON with missing required fields
  - Out-of-range numeric values (confidence > 1.0)
  - Invalid enum values for constrained fields

This module validates LLM response strings against a schema before any
downstream code uses the values. Invalid responses return None (or a safe
default) rather than raising exceptions, so the agent pipeline can degrade
gracefully.

Three patterns are demonstrated:
1. validate_analysis_response() — parse, check enum, check bounds, check required
2. get_safe_default_analysis()  — fallback when validation fails
3. ResponseValidator.validate_with_retry() — call LLM again on failure

Adapting for your agent:
  - Change ActionType to match your agent's action space
  - Add or remove required fields in validate_analysis_response()
  - Adjust confidence bounds if your model uses a different scale (e.g., 0–100)

Usage:
    from response_validator import (
        validate_analysis_response,
        get_safe_default_analysis,
        ResponseValidator,
    )

    raw = llm_client.complete(prompt)
    result = validate_analysis_response(raw)
    if result is None:
        result = get_safe_default_analysis()

    # Or with retry:
    validator = ResponseValidator(max_retries=2)
    result = validator.validate_with_retry(
        response_getter=lambda: llm_client.complete(prompt),
        validator_func=validate_analysis_response,
    )
    if result is None:
        result = get_safe_default_analysis()
"""

from __future__ import annotations

import json
import logging
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Action type enum — exhaustive list of valid values.
# Using an Enum means the set of valid actions is defined in one place and
# can be used for both validation and type hints.
# ---------------------------------------------------------------------------

class ActionType(Enum):
    """All valid action types the agent may return."""
    REPLY_URGENT = "reply_urgent"
    REPLY_NORMAL = "reply_normal"
    ACTION_REQUIRED = "action_required"
    READ = "read"
    ARCHIVE = "archive"
    REVIEW = "review"


# Pre-compute the valid value set once for O(1) membership checks
_VALID_ACTION_TYPES: frozenset[str] = frozenset(a.value for a in ActionType)


# ---------------------------------------------------------------------------
# Validation functions
# ---------------------------------------------------------------------------

def _strip_markdown_fences(text: str) -> str:
    """
    Remove JSON markdown fences from LLM output.

    Many LLMs wrap JSON in ```json … ``` even when instructed not to.
    This handles both ```json … ``` and ``` … ``` variants.
    """
    content = text.strip()
    if "```json" in content:
        content = content.split("```json", 1)[1].split("```", 1)[0].strip()
    elif "```" in content:
        content = content.split("```", 1)[1].split("```", 1)[0].strip()
    return content


def validate_analysis_response(response: str) -> dict[str, Any] | None:
    """
    Validate a structured analysis response from an LLM.

    Expected JSON shape:
        {
            "action_type":  <ActionType value>,
            "confidence":   <float 0.0–1.0>,
            "summary":      <non-empty string>,
            "why_this_action":  <string, optional>,
            "recommendation":   <string or null, optional>,
            "action_items":     <list of strings, optional>
        }

    Args:
        response: Raw string from the LLM (may include markdown fences)

    Returns:
        Validated dict if the response is well-formed, None otherwise.
        Validation failures are logged at WARNING level with the reason.
    """
    try:
        content = _strip_markdown_fences(response)
        data = json.loads(content)
    except json.JSONDecodeError as exc:
        logger.warning("Invalid JSON in LLM response: %s", exc)
        return None
    except Exception as exc:
        logger.warning("Unexpected error parsing LLM response: %s", exc)
        return None

    if not isinstance(data, dict):
        logger.warning("LLM response is not a JSON object")
        return None

    # Required fields
    for field in ("action_type", "confidence", "summary"):
        if field not in data:
            logger.warning("Missing required field: '%s'", field)
            return None

    # Validate action_type against the enum
    if data["action_type"] not in _VALID_ACTION_TYPES:
        logger.warning(
            "Invalid action_type: '%s'. Valid values: %s",
            data["action_type"],
            sorted(_VALID_ACTION_TYPES),
        )
        return None

    # Validate confidence is a number in [0, 1]
    try:
        confidence = float(data["confidence"])
    except (ValueError, TypeError):
        logger.warning("Non-numeric confidence: %r", data.get("confidence"))
        return None

    if not 0.0 <= confidence <= 1.0:
        logger.warning("Confidence out of [0, 1] range: %f", confidence)
        return None

    data["confidence"] = confidence  # normalised to float

    # Validate summary is a non-empty string
    if not isinstance(data["summary"], str) or not data["summary"].strip():
        logger.warning("summary must be a non-empty string")
        return None

    # Coerce action_items to a list if present but wrong type
    if "action_items" in data and not isinstance(data["action_items"], list):
        logger.debug("action_items was not a list, coercing to []")
        data["action_items"] = []

    return data


def validate_draft_response(response: str) -> dict[str, str] | None:
    """
    Validate a draft generation response (subject + body pair).

    Expected JSON shape:
        {"subject": <non-empty string>, "body": <non-empty string>}

    Args:
        response: Raw LLM response string

    Returns:
        {"subject": ..., "body": ...} if valid, None otherwise.
    """
    try:
        content = _strip_markdown_fences(response)
        data = json.loads(content)
    except json.JSONDecodeError as exc:
        logger.warning("Invalid JSON in draft response: %s", exc)
        return None
    except Exception as exc:
        logger.warning("Unexpected error parsing draft response: %s", exc)
        return None

    if not isinstance(data, dict):
        logger.warning("Draft response is not a JSON object")
        return None

    for field in ("subject", "body"):
        if field not in data:
            logger.warning("Missing required draft field: '%s'", field)
            return None
        if not isinstance(data[field], str) or not data[field].strip():
            logger.warning("Draft field '%s' must be a non-empty string", field)
            return None

    return {"subject": data["subject"], "body": data["body"]}


def get_safe_default_analysis() -> dict[str, Any]:
    """
    Return a safe fallback analysis when validation fails.

    The "read" action is the lowest-risk action available — it records
    that the item was seen but takes no consequential steps. A confidence
    of 0.0 signals to any downstream display code that this is a fallback.
    """
    return {
        "action_type": ActionType.READ.value,
        "confidence": 0.0,
        "summary": "Automated analysis unavailable — please review manually.",
        "why_this_action": "Response validation failed; defaulting to safe no-op action.",
        "action_items": [],
    }


# ---------------------------------------------------------------------------
# Validator class with retry logic
# ---------------------------------------------------------------------------

class ResponseValidator:
    """
    Wraps validation functions with configurable retry logic.

    On validation failure, calls response_getter() again up to max_retries
    additional times. This handles transient LLM formatting errors without
    baking retry logic into every call site.
    """

    def __init__(self, max_retries: int = 2):
        """
        Args:
            max_retries: Number of additional attempts after the first failure.
                         Total attempts = max_retries + 1.
        """
        self.max_retries = max_retries
        self._failure_count = 0

    def validate_with_retry(
        self,
        response_getter,
        validator_func=None,
    ) -> dict[str, Any] | None:
        """
        Attempt validation, retrying by calling response_getter on failure.

        Args:
            response_getter: Zero-argument callable that returns a new LLM
                             response string. Called once per attempt.
            validator_func: Validation function to apply. Defaults to
                            validate_analysis_response.

        Returns:
            Validated response dict, or None if all attempts fail.
        """
        if validator_func is None:
            validator_func = validate_analysis_response

        total_attempts = self.max_retries + 1

        for attempt in range(total_attempts):
            response = response_getter()
            result = validator_func(response)

            if result is not None:
                if attempt > 0:
                    logger.info(
                        "Validation succeeded on attempt %d/%d",
                        attempt + 1, total_attempts,
                    )
                return result

            if attempt < self.max_retries:
                logger.info(
                    "Validation failed on attempt %d/%d, retrying…",
                    attempt + 1, total_attempts,
                )

        self._failure_count += 1
        logger.warning(
            "Validation failed after %d attempt(s). Total persistent failures: %d",
            total_attempts, self._failure_count,
        )
        return None

    @property
    def failure_count(self) -> int:
        """Total number of validate_with_retry calls that exhausted all retries."""
        return self._failure_count


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    print("=== Response validator demo ===\n")

    test_cases = [
        # Valid response
        (
            "Valid response",
            '{"action_type": "reply_normal", "confidence": 0.87, '
            '"summary": "Sender is requesting a meeting next week.", '
            '"action_items": ["Check calendar", "Reply by EOD"]}',
        ),
        # Wrapped in markdown fences (common LLM output)
        (
            "Markdown-wrapped JSON",
            '```json\n{"action_type": "archive", "confidence": 0.95, '
            '"summary": "Automated newsletter — no action required."}\n```',
        ),
        # Invalid action_type
        (
            "Invalid action_type",
            '{"action_type": "wire_transfer", "confidence": 0.99, "summary": "Do it."}',
        ),
        # Confidence out of range
        (
            "Confidence > 1",
            '{"action_type": "read", "confidence": 1.5, "summary": "Fine."}',
        ),
        # Missing required field
        (
            "Missing summary",
            '{"action_type": "read", "confidence": 0.5}',
        ),
        # Totally broken JSON
        (
            "Malformed JSON",
            'Sure! Here is my analysis: action=read confidence=high',
        ),
    ]

    for label, raw in test_cases:
        result = validate_analysis_response(raw)
        if result:
            print(f"  [VALID]   {label}: action={result['action_type']} "
                  f"conf={result['confidence']:.2f}")
        else:
            safe = get_safe_default_analysis()
            print(f"  [INVALID] {label}: using safe default → action={safe['action_type']}")

    print()
    print("=== validate_with_retry demo ===\n")

    call_count = 0
    responses = [
        "not json",                           # fail
        "also not json",                      # fail
        '{"action_type": "review", "confidence": 0.60, "summary": "Needs review."}',  # pass
    ]

    def mock_llm():
        global call_count
        r = responses[min(call_count, len(responses) - 1)]
        call_count += 1
        return r

    validator = ResponseValidator(max_retries=2)
    result = validator.validate_with_retry(mock_llm)
    if result:
        print(f"  Succeeded after {call_count} call(s): {result['action_type']}")
    else:
        print(f"  Failed after {call_count} call(s)")
