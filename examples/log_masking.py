"""
Log masking for AI agent applications — prevent secrets and PII from
appearing in application logs.

Problem: agent logs often contain:
- API keys accidentally included in error messages or debug output
- Email addresses in "Processing message from alice@example.com" lines
- OAuth tokens in HTTP request/response logs
- JWT tokens in authentication debug lines

Once these appear in logs they flow to stdout, log files, log shippers,
and aggregation services — any of which may be less secured than the
application itself.

Solution: a custom logging Formatter and Filter that scan every log message
for known secret patterns and email addresses, replacing them before the
message is written anywhere.

Patterns covered (7 secret types):
  - Anthropic API keys      (sk-ant-…)
  - OpenAI-style keys       (sk-…)
  - GitHub OAuth tokens     (gho_…)
  - GitHub personal tokens  (ghp_…)
  - Google OAuth access     (ya29.…)
  - Google refresh tokens   (1//…)
  - JWT tokens              (eyJ….eyJ…)

Plus email address masking: user@domain.com → ***@domain.com
(Domain is preserved for routing/debugging; local part is masked.)

Usage:
    import logging
    from log_masking import setup_masked_logging, MaskingFormatter, MaskingFilter

    # Option A: one-call setup (recommended)
    setup_masked_logging(level="INFO", log_file=Path("app.log"))

    # Option B: attach to an existing logger manually
    handler = logging.StreamHandler()
    handler.setFormatter(MaskingFormatter("%(asctime)s %(levelname)s %(message)s"))
    logging.getLogger("myapp").addHandler(handler)

    # Option C: filter on the logger (masks args too, useful for % formatting)
    logging.getLogger("myapp").addFilter(MaskingFilter())
"""

from __future__ import annotations

import logging
import re
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path

# ---------------------------------------------------------------------------
# Compiled patterns
# ---------------------------------------------------------------------------

# Email: mask local part, keep domain for routing context
EMAIL_PATTERN = re.compile(r"[a-zA-Z0-9._%+-]+@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})")

# Secret patterns — ordered from most specific to least specific
SECRET_PATTERNS = [
    re.compile(r"sk-ant-[a-zA-Z0-9_-]{20,}"),       # Anthropic API keys
    re.compile(r"sk-[a-zA-Z0-9]{20,}"),              # OpenAI-style keys
    re.compile(r"gho_[a-zA-Z0-9]{36}"),              # GitHub OAuth tokens
    re.compile(r"ghp_[a-zA-Z0-9]{36}"),              # GitHub personal access tokens
    re.compile(r"ya29\.[a-zA-Z0-9_-]{50,}"),         # Google OAuth access tokens
    re.compile(r"1//[a-zA-Z0-9_-]{40,}"),            # Google refresh tokens
    re.compile(r"eyJ[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,}"),  # JWT tokens
]

# Replacement token — distinctive enough to spot in logs,
# short enough not to bloat the line.
SECRET_REPLACEMENT = "***SECRET***"
EMAIL_REPLACEMENT = r"***@\1"  # keeps the domain


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def mask_text(text: str) -> str:
    """
    Apply all masking rules to a single string.

    Args:
        text: Log message string

    Returns:
        String with emails and secrets replaced
    """
    if not text:
        return text

    # Email masking: preserve domain, redact local part
    text = EMAIL_PATTERN.sub(EMAIL_REPLACEMENT, text)

    # Secret masking
    for pattern in SECRET_PATTERNS:
        text = pattern.sub(SECRET_REPLACEMENT, text)

    return text


def mask_email(email: str) -> str:
    """
    Mask a single email address, showing only the domain.

    Args:
        email: Full email address

    Returns:
        "***@domain.com" or "***" if the format is unexpected
    """
    if not email:
        return "***"
    if "@" in email:
        _, domain = email.split("@", 1)
        return f"***@{domain}"
    return "***"


# ---------------------------------------------------------------------------
# Logging Formatter
# ---------------------------------------------------------------------------

class MaskingFormatter(logging.Formatter):
    """
    Logging formatter that masks secrets and email addresses.

    Apply this to any handler (StreamHandler, FileHandler, etc.) to ensure
    every formatted log message is scrubbed before it is written.

    The formatter runs after the base class formats the full record
    (including asctime, level, module, message), so the masking covers
    the complete output string.
    """

    def format(self, record: logging.LogRecord) -> str:
        formatted = super().format(record)
        return mask_text(formatted)


# ---------------------------------------------------------------------------
# Logging Filter
# ---------------------------------------------------------------------------

class MaskingFilter(logging.Filter):
    """
    Logging filter that masks secrets and email addresses in record fields.

    Unlike MaskingFormatter (which operates on the final formatted string),
    this filter operates on the raw LogRecord before formatting. This is
    useful when you use structured logging or when multiple formatters
    may consume the same record.

    The filter mutates record.msg and record.args in place, which is safe
    because filters run before the record is passed to any handler.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        # Mask the format string
        if isinstance(record.msg, str):
            record.msg = mask_text(record.msg)

        # Mask % formatting args
        if record.args:
            if isinstance(record.args, dict):
                record.args = {
                    k: mask_text(v) if isinstance(v, str) else v
                    for k, v in record.args.items()
                }
            elif isinstance(record.args, tuple):
                record.args = tuple(
                    mask_text(arg) if isinstance(arg, str) else arg
                    for arg in record.args
                )

        return True  # Always allow the record through — we're masking, not filtering


# ---------------------------------------------------------------------------
# Setup helper
# ---------------------------------------------------------------------------

def setup_masked_logging(
    level: str = "INFO",
    log_file: Path | None = None,
    format_string: str | None = None,
    max_bytes: int = 1_000_000,
    backup_count: int = 5,
) -> logging.Logger:
    """
    Configure the root logger with masking enabled on all handlers.

    Args:
        level: Logging level ("DEBUG", "INFO", "WARNING", "ERROR")
        log_file: Optional file path for rotating file output
        format_string: Custom format string (default: timestamp + level + message)
        max_bytes: Max file size before rotation (default 1 MB)
        backup_count: Number of rotated files to keep

    Returns:
        Configured root logger
    """
    if format_string is None:
        format_string = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

    root = logging.getLogger()
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    root.handlers.clear()

    # Console handler
    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(MaskingFormatter(format_string))
    root.addHandler(console)

    # File handler (optional)
    if log_file:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        fh = RotatingFileHandler(
            log_file,
            maxBytes=max_bytes,
            backupCount=backup_count,
        )
        fh.setFormatter(MaskingFormatter(format_string))
        root.addHandler(fh)

    return root


if __name__ == "__main__":
    # Set up masked logging for the demo
    setup_masked_logging(level="DEBUG")

    demo_logger = logging.getLogger("demo")

    print("=== Log masking demo ===\n")

    # These messages contain secrets and PII that should be masked
    test_messages = [
        # Email addresses
        ("Email in message",
         "Processing message from alice@example.com to bob@corp.io"),
        # Anthropic key
        ("Anthropic key",
         "Initialising client with key sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"),
        # OpenAI-style key
        ("OpenAI key",
         "Fallback provider key: sk-ABCDEF1234567890ABCDEF1234567890"),
        # GitHub token
        ("GitHub OAuth token",
         "GitHub token: ghp_" + "A" * 36),
        # Google token
        ("Google token",
         "Access token: ya29." + "x" * 55),
        # JWT
        ("JWT token",
         "Bearer eyJhbGciOiJSUzI1NiJ9." + "x" * 25 + "." + "y" * 25),
        # Clean message — should not be modified
        ("Clean message",
         "Successfully processed 42 items in 1.3 seconds"),
    ]

    for label, message in test_messages:
        print(f"  [{label}]")
        demo_logger.info(message)
        print()

    print("=== mask_text() direct call ===\n")
    raw = "User alice@company.com used key sk-ant-abc123ABCDEF456789GHIJKL to call API"
    masked = mask_text(raw)
    print(f"  Before: {raw}")
    print(f"  After:  {masked}")
