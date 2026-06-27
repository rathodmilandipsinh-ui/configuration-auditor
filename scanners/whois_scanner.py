"""
scanners/whois_scanner.py
Configuration Auditor — WHOIS Scanner Module

Performs WHOIS lookups on a given domain and returns a
JSON-compatible dictionary of key registration metadata.
"""

import re
import whois
from datetime import datetime, date


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# RFC-compliant domain pattern (labels up to 63 chars, TLD 2-24 chars)
_DOMAIN_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9]"
    r"(?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,24}$"
)

_MAX_DOMAIN_LENGTH = 253


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _validate_domain(domain: str) -> tuple[bool, str]:
    """
    Validate that *domain* is a well-formed hostname.

    Returns:
        (True, "")            — domain is valid.
        (False, reason_str)   — domain is invalid, with a human-readable reason.
    """
    if not domain or not isinstance(domain, str):
        return False, "Domain must be a non-empty string."

    domain = domain.strip().lower()

    if len(domain) > _MAX_DOMAIN_LENGTH:
        return False, f"Domain exceeds maximum length of {_MAX_DOMAIN_LENGTH} characters."

    if not _DOMAIN_REGEX.match(domain):
        return False, f"'{domain}' is not a valid domain name."

    return True, ""


def _normalise_date(value) -> str | None:
    """
    Coerce a WHOIS date field to an ISO-8601 string (YYYY-MM-DD).

    python-whois may return:
      - a single datetime / date object
      - a list of datetime / date objects (takes the first)
      - None
    """
    if value is None:
        return None

    if isinstance(value, list):
        value = value[0] if value else None

    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%d")

    if isinstance(value, date):
        return value.isoformat()

    # Already a string — return as-is after stripping whitespace
    if isinstance(value, str):
        return value.strip() or None

    return None


def _normalise_nameservers(value) -> list[str]:
    """
    Return a deduplicated, sorted list of lowercase nameserver strings.

    python-whois may return a list, a single string, or None.
    """
    if not value:
        return []

    if isinstance(value, str):
        value = [value]

    cleaned = sorted(
        {ns.lower().rstrip(".") for ns in value if isinstance(ns, str) and ns.strip()}
    )
    return cleaned


def _normalise_registrar(value) -> str | None:
    """Return a clean registrar string or None."""
    if isinstance(value, list):
        value = value[0] if value else None

    if isinstance(value, str):
        return value.strip() or None

    return None


# ---------------------------------------------------------------------------
# Public Interface
# ---------------------------------------------------------------------------

def scan(domain: str) -> dict:
    """
    Perform a WHOIS lookup on *domain* and return a JSON-compatible dict.

    Successful response shape:
    {
        "success":         True,
        "domain":          "example.com",
        "registrar":       "ICANN",
        "creation_date":   "1995-08-14",
        "expiration_date": "2026-08-13",
        "updated_date":    "2024-07-31",
        "nameservers":     ["a.iana-servers.net", "b.iana-servers.net"]
    }

    Error response shape:
    {
        "success": False,
        "domain":  "bad-input",
        "error":   "Human-readable error message."
    }
    """
    # ---- Sanitise input ----------------------------------------------------
    if isinstance(domain, str):
        domain = domain.strip().lower()

    # ---- Validate ----------------------------------------------------------
    valid, reason = _validate_domain(domain)
    if not valid:
        return {"success": False, "domain": domain, "error": reason}

    # ---- WHOIS lookup ------------------------------------------------------
    try:
        w = whois.whois(domain)
    except whois.parser.PywhoisError as exc:
        return {
            "success": False,
            "domain": domain,
            "error": f"WHOIS lookup failed: {exc}",
        }
    except ConnectionError as exc:
        return {
            "success": False,
            "domain": domain,
            "error": f"Network error during WHOIS lookup: {exc}",
        }
    except Exception as exc:  # noqa: BLE001 — surface unexpected errors safely
        return {
            "success": False,
            "domain": domain,
            "error": f"Unexpected error: {type(exc).__name__}: {exc}",
        }

    # ---- Guard: no data returned -------------------------------------------
    if w is None or not w.domain_name:
        return {
            "success": False,
            "domain": domain,
            "error": "No WHOIS record found for this domain.",
        }

    # ---- Build result ------------------------------------------------------
    return {
        "success": True,
        "domain": domain,
        "registrar": _normalise_registrar(w.registrar),
        "creation_date": _normalise_date(w.creation_date),
        "expiration_date": _normalise_date(w.expiration_date),
        "updated_date": _normalise_date(w.updated_date),
        "nameservers": _normalise_nameservers(w.name_servers),
    }