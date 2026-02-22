"""
Domain allowlist and HTTPS enforcement for browser-based agents.

Browser-capable agents (computer-use, web research, RPA) can be tricked
into visiting attacker-controlled sites through prompt injection or
malicious redirects. This module provides three layers of defence:

1. Domain allowlist — only pre-approved domains may be fetched.
2. HTTPS enforcement — plain HTTP is rejected regardless of domain.
3. Redirect validation — after every redirect hop, the final URL is
   re-validated against the allowlist before content is returned.

Design choices:
- Allowlists are defined as frozensets of lowercase bare domains.
  Subdomains are handled by an explicit include_subdomains flag so the
  scope is always visible in the config, not hidden in a wildcard rule.
- The module raises AllowlistViolation (a ValueError subclass) so callers
  can catch domain violations distinctly from network errors.
- No external dependencies — works with Python's urllib.parse.

Usage:
    from browser_allowlist import BrowserAllowlist, AllowlistViolation

    # Define the allowlist for your agent
    allowlist = BrowserAllowlist(
        domains={"example.com", "docs.example.com"},
        include_subdomains={"example.com"},  # allow *.example.com
    )

    # Validate before fetching
    try:
        allowlist.validate("https://docs.example.com/guide")
    except AllowlistViolation as exc:
        print(f"Blocked: {exc}")

    # Validate a redirect chain
    redirect_chain = [
        "https://example.com/start",
        "https://docs.example.com/final",
    ]
    allowlist.validate_redirect_chain(redirect_chain)
"""

from __future__ import annotations

from urllib.parse import urlparse


class AllowlistViolation(ValueError):
    """Raised when a URL does not pass the allowlist check."""


class BrowserAllowlist:
    """
    Validates URLs against an explicit domain allowlist.

    Attributes:
        domains: Set of allowed bare domains (e.g. "example.com").
                 Exact match only unless the domain also appears in
                 include_subdomains.
        include_subdomains: Set of domains for which any subdomain is also
                            allowed (e.g. "example.com" covers
                            "api.example.com", "docs.example.com", etc.).
        require_https: If True (default), reject any non-HTTPS URL.
    """

    def __init__(
        self,
        domains: set[str],
        include_subdomains: set[str] | None = None,
        require_https: bool = True,
    ):
        """
        Args:
            domains: Allowed bare domains, case-insensitive.
            include_subdomains: Subset of domains whose subdomains are also
                                permitted. Must be a subset of domains.
            require_https: Reject plain-HTTP URLs (default True).
        """
        # Store everything lowercase for case-insensitive comparison
        self._domains = frozenset(d.lower() for d in domains)
        self._subdomain_roots = frozenset(
            d.lower() for d in (include_subdomains or set())
        )
        self.require_https = require_https

        # Sanity check: subdomain roots must be listed in domains too
        unknown = self._subdomain_roots - self._domains
        if unknown:
            raise ValueError(
                f"include_subdomains contains domains not in the allowlist: {unknown}"
            )

    def is_allowed(self, url: str) -> tuple[bool, str]:
        """
        Check a single URL against the allowlist.

        Args:
            url: Absolute URL to validate

        Returns:
            (allowed: bool, reason: str) — reason explains the outcome
            whether allowed or blocked.
        """
        try:
            parsed = urlparse(url)
        except Exception as exc:
            return False, f"URL parse error: {exc}"

        scheme = (parsed.scheme or "").lower()
        host = (parsed.hostname or "").lower()

        # 1. Scheme check
        if self.require_https and scheme != "https":
            return False, f"Non-HTTPS scheme rejected: '{scheme}'"

        if not scheme:
            return False, "URL has no scheme"

        if not host:
            return False, "URL has no host"

        # 2. Exact domain match
        if host in self._domains:
            return True, f"Exact match: {host}"

        # 3. Subdomain match — check if host ends with .<root>
        for root in self._subdomain_roots:
            if host.endswith(f".{root}"):
                return True, f"Subdomain of allowed root: {root}"

        return False, f"Domain not in allowlist: {host}"

    def validate(self, url: str) -> None:
        """
        Validate a URL, raising AllowlistViolation if not allowed.

        Args:
            url: Absolute URL to validate

        Raises:
            AllowlistViolation: With a descriptive message
        """
        allowed, reason = self.is_allowed(url)
        if not allowed:
            raise AllowlistViolation(f"URL blocked — {reason}: {url}")

    def validate_redirect_chain(self, urls: list[str]) -> None:
        """
        Validate every URL in a redirect chain.

        A redirect to an allowlisted domain that then redirects to an
        off-allowlist domain would bypass a single-URL check. Validating
        the full chain closes this gap.

        Args:
            urls: Ordered list of URLs from initial request to final
                  destination, as returned by a redirect-following HTTP client.

        Raises:
            AllowlistViolation: On the first URL that fails, with its
                                position in the chain included in the message.
        """
        for i, url in enumerate(urls):
            allowed, reason = self.is_allowed(url)
            if not allowed:
                raise AllowlistViolation(
                    f"Redirect chain blocked at hop {i + 1}/{len(urls)} — "
                    f"{reason}: {url}"
                )

    def allowed_domains(self) -> list[str]:
        """Return a sorted list of the allowed domains (for display/audit)."""
        return sorted(self._domains)


# ---------------------------------------------------------------------------
# Example pre-built allowlists for common agent use cases
# ---------------------------------------------------------------------------

# Research agent: public documentation and reference sites only
RESEARCH_ALLOWLIST = BrowserAllowlist(
    domains={
        "arxiv.org",
        "wikipedia.org",
        "github.com",
        "docs.python.org",
        "pypi.org",
    },
    include_subdomains={"arxiv.org", "wikipedia.org", "github.com"},
    require_https=True,
)

# Internal tools agent: your own infrastructure only
INTERNAL_ALLOWLIST = BrowserAllowlist(
    domains={
        "internal.example.com",
        "api.example.com",
        "docs.example.com",
    },
    include_subdomains={"example.com"},
    require_https=True,
)


if __name__ == "__main__":
    print("=== BrowserAllowlist demo ===\n")

    allowlist = BrowserAllowlist(
        domains={"example.com", "docs.example.com", "api.example.com"},
        include_subdomains={"example.com"},
        require_https=True,
    )

    test_cases = [
        # Should pass
        ("PASS", "https://example.com/page"),
        ("PASS", "https://docs.example.com/guide"),
        ("PASS", "https://api.example.com/v1/data"),
        ("PASS", "https://sub.example.com/anything"),   # subdomain of example.com
        # Should block
        ("FAIL", "http://example.com/page"),             # non-HTTPS
        ("FAIL", "https://attacker.com/payload"),        # not in allowlist
        ("FAIL", "https://evil-example.com/trick"),      # not a real subdomain
        ("FAIL", "https://example.com.evil.net/path"),   # lookalike domain
        ("FAIL", "ftp://example.com/file"),              # wrong scheme
    ]

    for expected, url in test_cases:
        allowed, reason = allowlist.is_allowed(url)
        status = "PASS" if allowed else "FAIL"
        marker = "OK" if status == expected else "UNEXPECTED"
        print(f"  [{marker}] {status:4} {url}")
        print(f"           {reason}")
        print()

    print("=== Redirect chain validation ===\n")

    good_chain = [
        "https://example.com/start",
        "https://docs.example.com/final",
    ]
    try:
        allowlist.validate_redirect_chain(good_chain)
        print("Good chain: allowed")
    except AllowlistViolation as exc:
        print(f"Good chain: UNEXPECTED block — {exc}")

    print()

    bad_chain = [
        "https://example.com/start",
        "https://attacker.com/harvest",   # redirect escapes allowlist
    ]
    try:
        allowlist.validate_redirect_chain(bad_chain)
        print("Bad chain: UNEXPECTED allow")
    except AllowlistViolation as exc:
        print(f"Bad chain: blocked correctly — {exc}")
