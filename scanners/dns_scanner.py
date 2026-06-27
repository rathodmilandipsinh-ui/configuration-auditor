"""
scanners/dns_scanner.py
Configuration Auditor — DNS Scanner Module

Resolves A, AAAA, MX, TXT, and NS records for a given domain and
returns a JSON-compatible dictionary of the results.
"""

import re
import dns.resolver
import dns.exception


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_DOMAIN_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9]"
    r"(?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,24}$"
)

_MAX_DOMAIN_LENGTH = 253
_QUERY_TIMEOUT     = 10    # seconds per record type query
_QUERY_LIFETIME    = 15    # total resolver lifetime per query

# Record types to collect and their extraction logic (defined below)
_RECORD_TYPES = ("A", "AAAA", "MX", "TXT", "NS")


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def _validate_domain(domain: str) -> tuple[bool, str]:
    """
    Validate *domain* is a well-formed hostname.

    Returns:
        (True, "")           — valid.
        (False, reason_str)  — invalid, with a human-readable reason.
    """
    if not domain or not isinstance(domain, str):
        return False, "Domain must be a non-empty string."

    domain = domain.strip().lower()

    if len(domain) > _MAX_DOMAIN_LENGTH:
        return False, f"Domain exceeds maximum length of {_MAX_DOMAIN_LENGTH} characters."

    if not _DOMAIN_REGEX.match(domain):
        return False, f"'{domain}' is not a valid domain name."

    return True, ""


# ---------------------------------------------------------------------------
# Per-record extractors
# ---------------------------------------------------------------------------

def _extract_a(rdata) -> str:
    """Return the IPv4 address string."""
    return rdata.address


def _extract_aaaa(rdata) -> str:
    """Return the IPv6 address string."""
    return rdata.address


def _extract_mx(rdata) -> dict:
    """Return exchange host and priority for an MX record."""
    return {
        "priority": rdata.preference,
        "exchange": str(rdata.exchange).rstrip("."),
    }


def _extract_txt(rdata) -> str:
    """
    Return the full TXT record value as a single decoded string.
    TXT records can span multiple strings; join them with no separator.
    """
    return b"".join(rdata.strings).decode("utf-8", errors="replace")


def _extract_ns(rdata) -> str:
    """Return the nameserver hostname, stripped of trailing dot."""
    return str(rdata.target).rstrip(".")


_EXTRACTORS = {
    "A":    _extract_a,
    "AAAA": _extract_aaaa,
    "MX":   _extract_mx,
    "TXT":  _extract_txt,
    "NS":   _extract_ns,
}


# ---------------------------------------------------------------------------
# Core resolver
# ---------------------------------------------------------------------------

def _query(resolver: dns.resolver.Resolver, domain: str, record_type: str) -> dict:
    """
    Query *domain* for *record_type* using *resolver*.

    Returns:
        {
            "records": [...],   # on success
            "error":   "...",   # on failure (NXDOMAIN, timeout, etc.)
        }
    """
    extractor = _EXTRACTORS[record_type]

    try:
        answers = resolver.resolve(domain, record_type)
        records = [extractor(rdata) for rdata in answers]
        return {"records": records}

    except dns.resolver.NXDOMAIN:
        return {"records": [], "error": "Domain does not exist (NXDOMAIN)."}

    except dns.resolver.NoAnswer:
        # Domain exists but has no records of this type — not an error
        return {"records": []}

    except dns.resolver.NoNameservers:
        return {"records": [], "error": "No nameservers available for this domain."}

    except dns.exception.Timeout:
        return {"records": [], "error": f"Query timed out after {_QUERY_TIMEOUT}s."}

    except dns.resolver.LifetimeTimeout:
        return {"records": [], "error": f"Resolver lifetime exceeded ({_QUERY_LIFETIME}s)."}

    except dns.exception.DNSException as exc:
        return {"records": [], "error": f"DNS error: {type(exc).__name__}: {exc}"}

    except Exception as exc:  # noqa: BLE001
        return {"records": [], "error": f"Unexpected error: {type(exc).__name__}: {exc}"}


# ---------------------------------------------------------------------------
# Public Interface
# ---------------------------------------------------------------------------

def scan(domain: str) -> dict:
    """
    Resolve DNS records for *domain* and return a JSON-compatible dict.

    Successful response shape:
    {
        "success": true,
        "domain":  "example.com",
        "records": {
            "A":    { "records": ["93.184.216.34"] },
            "AAAA": { "records": ["2606:2800:21f:cb07:6820:80da:af6b:8b2c"] },
            "MX":   { "records": [{ "priority": 0, "exchange": "." }] },
            "TXT":  { "records": ["v=spf1 -all"] },
            "NS":   { "records": ["a.iana-servers.net", "b.iana-servers.net"] }
        }
    }

    Individual record types that fail carry an "error" key alongside
    an empty "records" list so partial results are always returned:
    {
        "A": { "records": [], "error": "Query timed out after 10s." }
    }

    Hard error response (invalid domain / unexpected failure):
    {
        "success": false,
        "domain":  "bad-input",
        "error":   "Human-readable error message."
    }
    """
    # ---- Sanitise ----------------------------------------------------------
    if isinstance(domain, str):
        domain = domain.strip().lower()

    # ---- Validate ----------------------------------------------------------
    valid, reason = _validate_domain(domain)
    if not valid:
        return {"success": False, "domain": domain, "error": reason}

    # ---- Configure resolver ------------------------------------------------
    resolver = dns.resolver.Resolver()
    resolver.timeout  = _QUERY_TIMEOUT
    resolver.lifetime = _QUERY_LIFETIME

    # ---- Resolve each record type ------------------------------------------
    records = {}
    for rtype in _RECORD_TYPES:
        records[rtype] = _query(resolver, domain, rtype)

    # ---- Build result ------------------------------------------------------
    return {
        "success": True,
        "domain":  domain,
        "records": records,
    }