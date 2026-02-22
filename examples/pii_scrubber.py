"""
Standalone PII scrubbing for agent logs and stored content.

Replaces common personally-identifiable information patterns with clearly
labelled placeholder tokens. Use this before:
- Writing user-provided content to log files
- Storing external data in a database that retains plaintext
- Including raw text in tracing/observability payloads
- Sending content to third-party APIs for processing

Patterns covered:
- Phone numbers (US/international common formats)
- US Social Security Numbers (NNN-NN-NNNN)
- Credit/debit card numbers (13–19 digits with optional separators)
- IPv4 addresses

Limitations:
- These are heuristic regex patterns, not ML-based NER. They will produce
  false positives (e.g., some product codes match the CC pattern) and false
  negatives (phone numbers in unusual formats won't match).
- Names, addresses, and dates are NOT covered here — add NER if required.
- The CC pattern intentionally casts wide; prefer false positives over
  leaking real card numbers in logs.

Usage:
    from pii_scrubber import scrub_pii, scrub_fields

    # Scrub a single string
    safe_text = scrub_pii("Call me at 514-555-0198 or charge card 4111 1111 1111 1111")

    # Scrub a dict of fields (returns a new dict, does not mutate)
    safe_record = scrub_fields({"body": raw_body, "subject": subject})
"""

from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# Compiled PII patterns
# Ordered from most specific to least specific to avoid partial-match
# collisions (e.g., SSN should match before the phone pattern grabs it).
# ---------------------------------------------------------------------------

# US Social Security Numbers: NNN-NN-NNNN
SSN_PATTERN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")

# Credit/debit card numbers: 13–19 digits with optional spaces or dashes.
# This is intentionally broad — false positives are acceptable in logs.
CC_PATTERN = re.compile(r"\b(?:\d{4}[-\s]?){3,4}\d{1,4}\b")

# Phone numbers: US and international common formats.
# Matches: +1 (514) 555-0198, 514.555.0198, 5145550198, +44 20 7946 0958, etc.
PHONE_PATTERN = re.compile(r"\+?1?[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}")

# IPv4 addresses: N.N.N.N (1–3 digits per octet, no range validation)
IP_PATTERN = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")

# Ordered list of (pattern, replacement_token) pairs.
# Replacements are uppercase bracketed tokens so they are easy to grep for
# in log analysis pipelines.
PII_PATTERNS: list[tuple[re.Pattern, str]] = [
    (SSN_PATTERN, "[SSN]"),
    (CC_PATTERN, "[CC_NUMBER]"),
    (PHONE_PATTERN, "[PHONE]"),
    (IP_PATTERN, "[IP_ADDR]"),
]


def scrub_pii(text: str) -> str:
    """
    Replace PII patterns in text with safe placeholder tokens.

    Args:
        text: Input string that may contain PII

    Returns:
        String with PII replaced. Returns the original value unchanged if
        it is empty or not a string.
    """
    if not text or not isinstance(text, str):
        return text

    result = text
    for pattern, replacement in PII_PATTERNS:
        result = pattern.sub(replacement, result)
    return result


def scrub_fields(record: dict, fields: list[str] | None = None) -> dict:
    """
    Scrub PII from selected fields in a dictionary.

    Returns a new dict; the original is not mutated.

    Args:
        record: Dictionary of field_name → value
        fields: List of field names to scrub. If None, all string-valued
                fields are scrubbed.

    Returns:
        New dict with PII replaced in the specified fields
    """
    scrubbed = dict(record)
    for key, value in scrubbed.items():
        if fields is not None and key not in fields:
            continue
        if isinstance(value, str):
            scrubbed[key] = scrub_pii(value)
    return scrubbed


if __name__ == "__main__":
    samples = [
        # Phone numbers in various formats
        ("Phone (dashes)",     "Reach me at 514-555-0198."),
        ("Phone (dots)",       "Office: 514.555.0199."),
        ("Phone (intl)",       "Call +1 (800) 555-0100 for support."),
        # SSN
        ("SSN",                "SSN on file: 123-45-6789."),
        # Credit card
        ("CC (spaces)",        "Charge card 4111 1111 1111 1111 for $99."),
        ("CC (dashes)",        "Backup card: 5500-0000-0000-0004."),
        # IP address
        ("IP",                 "Request came from 203.0.113.42."),
        # Mixed PII in one string
        ("Mixed",              "User 123-45-6789 at 192.168.0.5 called 800-555-0100."),
        # Clean content — should not be modified
        ("Clean",              "Please review the attached proposal by Friday."),
    ]

    print("=== PII scrubber demo ===\n")
    for label, text in samples:
        result = scrub_pii(text)
        changed = " (modified)" if result != text else ""
        print(f"{label:<18} {text}")
        print(f"{'':18} -> {result}{changed}")
        print()

    print("=== scrub_fields demo ===\n")
    record = {
        "id": "rec-001",
        "subject": "Invoice for John - card 4111 1111 1111 1111",
        "body": "Hi, my SSN is 987-65-4321 and IP is 10.0.0.1",
        "action_type": "read",
    }
    scrubbed = scrub_fields(record, fields=["subject", "body"])
    for k, v in scrubbed.items():
        print(f"  {k}: {v}")
