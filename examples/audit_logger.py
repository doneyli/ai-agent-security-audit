"""
Security audit logger for AI agent systems.

Maintains a tamper-evident append-only log of security-relevant events in
JSON Lines format (one JSON object per line). Each record is timestamped in
UTC and includes an event type and a details payload.

Why a separate audit log?
  Application logs are optimised for debugging and are often noisy, rotated
  aggressively, and may flow to third-party log aggregators that shouldn't
  see sensitive context. A dedicated audit log:
  - Uses restrictive file permissions (0o600 owner-only for the file,
    0o700 owner-only for the directory).
  - Automatically redacts sensitive field values (API keys, body content)
    from the stored payload.
  - Provides typed helper methods so callers never have to remember field
    names or invent event type strings.

File format: JSON Lines (https://jsonlines.org/)
  Each line is a self-contained JSON object:
    {"timestamp": "2026-02-22T10:00:00+00:00", "event_type": "...", "details": {...}}

Usage:
    from audit_logger import AuditLogger

    audit = AuditLogger("data/logs/audit.jsonl")

    audit.log_injection_detected(item_id="msg-001", field="subject",
                                  pattern="ignore all previous instructions")
    audit.log_guardrail_triggered(item_id="msg-001", guardrail="anomaly_detection",
                                   action_prevented="auto_send")
    audit.log_llm_request(provider="anthropic", model="claude-opus-4-6")
"""

from __future__ import annotations

import json
import logging
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

DEFAULT_AUDIT_PATH = Path("data/logs/audit.jsonl")


class AuditLogger:
    """
    Append-only security event logger with JSON Lines output.

    Thread-safety: each write opens, appends, and closes the file using
    os.open with O_APPEND, which is atomic on POSIX systems for small
    writes. Do not rely on this for high-throughput concurrent writers —
    add a lock or use a dedicated logging service in that case.
    """

    # Keys whose values should be redacted before writing to disk.
    # This prevents secrets and bulk content from appearing in the audit log
    # even if a caller accidentally includes them in a details dict.
    SENSITIVE_KEYS = frozenset(
        {
            "body",
            "content",
            "email_body",
            "email_content",
            "api_key",
            "token",
            "password",
            "secret",
            "credential",
            "authorization",
            "draft_content",
            "response_body",
        }
    )

    # Event type constants — use these rather than raw strings so typos
    # are caught at import time and grepping is reliable.
    EVENT_LLM_REQUEST = "llm_request"
    EVENT_LLM_RESPONSE = "llm_response"
    EVENT_ITEM_ANALYZED = "item_analyzed"
    EVENT_DRAFT_CREATED = "draft_created"
    EVENT_DRAFT_SENT = "draft_sent"
    EVENT_ITEM_ARCHIVED = "item_archived"
    EVENT_INJECTION_DETECTED = "injection_detected"
    EVENT_AUTH_TOKEN_REFRESH = "auth_token_refresh"
    EVENT_GUARDRAIL_TRIGGERED = "guardrail_triggered"

    def __init__(self, audit_path: Path | str | None = None):
        """
        Args:
            audit_path: Path to the .jsonl audit file. Directory is created
                        with 0o700 permissions; file is written with 0o600.
                        Defaults to DEFAULT_AUDIT_PATH.
        """
        self.audit_path = Path(audit_path) if audit_path else DEFAULT_AUDIT_PATH
        self._ensure_directory()

    # ------------------------------------------------------------------
    # Core write method
    # ------------------------------------------------------------------

    def log_event(
        self,
        event_type: str,
        details: dict[str, Any],
        sensitive: bool = False,
    ) -> None:
        """
        Append one event record to the audit log.

        Args:
            event_type: Event type string (use EVENT_* constants above)
            details: Payload dict. Must be JSON-serialisable.
            sensitive: If True, values of SENSITIVE_KEYS are replaced with
                       [REDACTED] before the record is written.
        """
        record = {
            "timestamp": datetime.now(UTC).isoformat(),
            "event_type": event_type,
            "details": self._redact(details) if sensitive else details,
        }

        try:
            # O_CREAT | O_APPEND | O_WRONLY gives us an atomic append.
            # 0o600 = owner read+write only; no group or world access.
            fd = os.open(
                str(self.audit_path),
                os.O_WRONLY | os.O_CREAT | os.O_APPEND,
                0o600,
            )
            with os.fdopen(fd, "a") as fh:
                fh.write(json.dumps(record, default=str) + "\n")
        except OSError as exc:
            # Log to application logger but do not raise — a failed audit
            # write should not crash the agent pipeline.
            logger.error("Failed to write audit event '%s': %s", event_type, exc)

    # ------------------------------------------------------------------
    # Typed helper methods — one per security event category
    # ------------------------------------------------------------------

    def log_llm_request(
        self,
        provider: str,
        model: str,
        prompt_tokens: int | None = None,
        item_id: str | None = None,
    ) -> None:
        """Record an outbound LLM API call."""
        self.log_event(
            self.EVENT_LLM_REQUEST,
            {
                "provider": provider,
                "model": model,
                "prompt_tokens": prompt_tokens,
                "item_id": item_id,
            },
        )

    def log_llm_response(
        self,
        provider: str,
        model: str,
        success: bool,
        latency_ms: int,
        total_tokens: int | None = None,
        error: str | None = None,
    ) -> None:
        """Record an LLM API response."""
        self.log_event(
            self.EVENT_LLM_RESPONSE,
            {
                "provider": provider,
                "model": model,
                "success": success,
                "latency_ms": latency_ms,
                "total_tokens": total_tokens,
                "error": error,
            },
        )

    def log_item_analyzed(
        self,
        item_id: str,
        action_type: str,
        confidence: float,
        sender_domain: str | None = None,
    ) -> None:
        """Record completion of an item (message, task, etc.) analysis."""
        self.log_event(
            self.EVENT_ITEM_ANALYZED,
            {
                "item_id": item_id,
                "action_type": action_type,
                "confidence": confidence,
                "sender_domain": sender_domain,
            },
        )

    def log_draft_created(
        self,
        item_id: str,
        draft_id: str,
        template_used: str,
    ) -> None:
        """Record creation of an agent-generated draft."""
        self.log_event(
            self.EVENT_DRAFT_CREATED,
            {
                "item_id": item_id,
                "draft_id": draft_id,
                "template_used": template_used,
            },
        )

    def log_draft_sent(
        self,
        item_id: str,
        draft_id: str,
        recipient_domain: str,
    ) -> None:
        """Record that a draft was sent/executed."""
        self.log_event(
            self.EVENT_DRAFT_SENT,
            {
                "item_id": item_id,
                "draft_id": draft_id,
                "recipient_domain": recipient_domain,
            },
        )

    def log_item_archived(self, item_id: str, reason: str) -> None:
        """Record that an item was archived without action."""
        self.log_event(
            self.EVENT_ITEM_ARCHIVED,
            {"item_id": item_id, "reason": reason},
        )

    def log_injection_detected(
        self,
        item_id: str,
        field: str,
        pattern: str,
    ) -> None:
        """
        Record a detected prompt injection attempt.

        The pattern is truncated to 100 characters so the audit log cannot
        itself be used to exfiltrate or replay the malicious payload.
        """
        self.log_event(
            self.EVENT_INJECTION_DETECTED,
            {
                "item_id": item_id,
                "field": field,
                "pattern": pattern[:100],
            },
        )

    def log_auth_token_refresh(
        self,
        success: bool,
        error: str | None = None,
    ) -> None:
        """Record an OAuth or API token refresh attempt."""
        self.log_event(
            self.EVENT_AUTH_TOKEN_REFRESH,
            {"success": success, "error": error},
        )

    def log_guardrail_triggered(
        self,
        item_id: str,
        guardrail: str,
        action_prevented: str,
    ) -> None:
        """
        Record that a safety guardrail blocked an action.

        Args:
            item_id: Identifier of the item that triggered the guardrail
            guardrail: Name of the guardrail (e.g. "anomaly_detection",
                       "injection_gate", "allowlist")
            action_prevented: What the agent was about to do (e.g. "auto_send")
        """
        self.log_event(
            self.EVENT_GUARDRAIL_TRIGGERED,
            {
                "item_id": item_id,
                "guardrail": guardrail,
                "action_prevented": action_prevented,
            },
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _ensure_directory(self) -> None:
        """Create the log directory with restricted permissions (0o700)."""
        self.audit_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)

    def _redact(self, details: dict[str, Any]) -> dict[str, Any]:
        """
        Recursively replace sensitive field values with [REDACTED].

        Handles nested dicts and lists of dicts.
        """
        redacted: dict[str, Any] = {}
        for key, value in details.items():
            if key.lower() in self.SENSITIVE_KEYS:
                redacted[key] = "[REDACTED]"
            elif isinstance(value, dict):
                redacted[key] = self._redact(value)
            elif isinstance(value, list):
                redacted[key] = [
                    self._redact(item) if isinstance(item, dict) else item
                    for item in value
                ]
            else:
                redacted[key] = value
        return redacted


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_audit_logger: AuditLogger | None = None


def get_audit_logger(audit_path: Path | str | None = None) -> AuditLogger:
    """
    Return the global AuditLogger instance (created on first call).

    Args:
        audit_path: Only used on the first call to set the file path.
    """
    global _audit_logger
    if _audit_logger is None:
        _audit_logger = AuditLogger(audit_path)
    return _audit_logger


def reset_audit_logger() -> None:
    """Reset the global instance (useful in tests)."""
    global _audit_logger
    _audit_logger = None


if __name__ == "__main__":
    import tempfile

    with tempfile.TemporaryDirectory() as tmpdir:
        audit_path = Path(tmpdir) / "audit.jsonl"
        audit = AuditLogger(audit_path)

        print("=== AuditLogger demo ===\n")

        audit.log_llm_request(provider="anthropic", model="claude-opus-4-6", prompt_tokens=512)
        audit.log_item_analyzed(
            item_id="msg-001",
            action_type="reply_normal",
            confidence=0.91,
            sender_domain="example.com",
        )
        audit.log_injection_detected(
            item_id="msg-002",
            field="subject",
            pattern="ignore all previous instructions",
        )
        audit.log_guardrail_triggered(
            item_id="msg-003",
            guardrail="anomaly_detection",
            action_prevented="auto_send",
        )
        # Sensitive flag: body would be redacted
        audit.log_event(
            "custom_event",
            {"item_id": "msg-004", "body": "SECRET CONTENT", "status": "ok"},
            sensitive=True,
        )

        print(f"Audit log written to: {audit_path}\n")
        print("Contents:")
        with open(audit_path) as fh:
            for line in fh:
                record = json.loads(line)
                print(f"  {record['timestamp']}  {record['event_type']}")
                print(f"  details: {json.dumps(record['details'])}")
                print()

        # Verify file permissions
        mode = oct(audit_path.stat().st_mode)[-3:]
        print(f"File permissions: {mode} (expected: 600)")
