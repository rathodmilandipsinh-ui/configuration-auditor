"""
scanners/header_scanner.py
Configuration Auditor — HTTP Security Header Scanner Module

Fetches the HTTP response headers for a given URL and audits the
presence and basic validity of key security headers, returning a
JSON-compatible dictionary with findings and an overall risk level.
"""

import re
import requests
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_REQUEST_TIMEOUT = 10  # seconds

# Headers to audit and their metadata
# weight: contribution toward risk score if missing (higher = more critical)
_SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "weight":      30,
        "description": "Enforces HTTPS connections and prevents protocol downgrade attacks.",
    },
    "Content-Security-Policy": {
        "weight":      25,
        "description": "Controls resources the browser is allowed to load, mitigating XSS.",
    },
    "X-Frame-Options": {
        "weight":      15,
        "description": "Prevents the page from being embedded in iframes (clickjacking defence).",
    },
    "X-Content-Type-Options": {
        "weight":      10,
        "description": "Stops browsers from MIME-sniffing responses away from the declared type.",
    },
    "Referrer-Policy": {
        "weight":      10,
        "description": "Controls how much referrer information is included with requests.",
    },
    "Permissions-Policy": {
        "weight":      10,
        "description": "Restricts access to browser features (camera, microphone, geolocation…).",
    },
}

# Risk thresholds (based on cumulative missing-header weight)
_RISK_THRESHOLDS = (
    (0,  "NONE"),
    (10, "LOW"),
    (30, "MEDIUM"),
    (55, "HIGH"),
    (101, "CRITICAL"),   # sentinel — anything >= 55 that isn't caught earlier
)

# Acceptable values / patterns for lightweight header validation
_VALID_VALUES = {
    "X-Frame-Options":       re.compile(r"^(DENY|SAMEORIGIN)$", re.IGNORECASE),
    "X-Content-Type-Options": re.compile(r"^nosniff$", re.IGNORECASE),
}


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def _validate_url(url: str) -> tuple[bool, str]:
    """
    Validate that *url* is an absolute HTTP/HTTPS URL.

    Returns:
        (True, normalised_url)  — valid.
        (False, reason_str)     — invalid.
    """
    if not url or not isinstance(url, str):
        return False, "URL must be a non-empty string."

    url = url.strip()

    # Prepend scheme if missing so users can pass bare domains
    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = "https://" + url

    try:
        parsed = urlparse(url)
    except ValueError as exc:
        return False, f"URL parsing failed: {exc}"

    if parsed.scheme not in ("http", "https"):
        return False, "URL scheme must be http or https."

    if not parsed.netloc:
        return False, "URL is missing a host / domain."

    # Reject bare IP octets that look like internal ranges (basic SSRF guard)
    host = parsed.hostname or ""
    if _is_private_host(host):
        return False, f"Scanning private/internal addresses is not permitted: {host}"

    return True, url


def _is_private_host(host: str) -> bool:
    """
    Return True when *host* resolves to a private/loopback address range.
    Checked purely by string pattern to avoid DNS round-trips here.
    """
    private_patterns = (
        re.compile(r"^localhost$", re.IGNORECASE),
        re.compile(r"^127\."),
        re.compile(r"^10\."),
        re.compile(r"^192\.168\."),
        re.compile(r"^172\.(1[6-9]|2\d|3[01])\."),
        re.compile(r"^::1$"),
        re.compile(r"^0\.0\.0\.0$"),
    )
    return any(p.match(host) for p in private_patterns)


# ---------------------------------------------------------------------------
# Risk scoring
# ---------------------------------------------------------------------------

def _compute_risk(missing_headers: list[str]) -> str:
    """
    Compute overall risk level from the list of missing security headers.

    Risk is calculated as the cumulative weight of all absent headers,
    then mapped to a label via _RISK_THRESHOLDS.
    """
    score = sum(
        _SECURITY_HEADERS[h]["weight"]
        for h in missing_headers
        if h in _SECURITY_HEADERS
    )

    label = "NONE"
    for threshold, level in _RISK_THRESHOLDS:
        if score >= threshold:
            label = level

    return label


# ---------------------------------------------------------------------------
# Header analysis
# ---------------------------------------------------------------------------

def _audit_header(name: str, value: str) -> dict:
    """
    Return an audit entry for a *present* header.

    Performs a lightweight value check for headers that have a small set
    of known-good values (e.g. X-Frame-Options, X-Content-Type-Options).
    """
    entry = {
        "present": True,
        "value":   value,
        "note":    None,
    }

    validator = _VALID_VALUES.get(name)
    if validator and not validator.match(value.strip()):
        entry["note"] = (
            f"Unexpected value '{value}'. "
            f"Review whether this is intentional."
        )

    return entry


# ---------------------------------------------------------------------------
# Public Interface
# ---------------------------------------------------------------------------

def scan(url: str) -> dict:
    """
    Fetch *url* and audit its HTTP security headers.

    Args:
        url: Absolute or scheme-less URL (e.g. "https://example.com" or
             "example.com"). HTTPS is assumed when no scheme is supplied.

    Successful response shape:
    {
        "success": true,
        "url": "https://example.com",
        "headers": {
            "Strict-Transport-Security": {
                "present": true,
                "value":   "max-age=31536000; includeSubDomains",
                "note":    null
            },
            "Content-Security-Policy": {
                "present": false,
                "value":   null,
                "note":    null
            },
            ...
        },
        "missing_headers": ["Content-Security-Policy", "Permissions-Policy"],
        "risk_level": "MEDIUM"
    }

    Error response shape:
    {
        "success": false,
        "url":     "bad-input",
        "error":   "Human-readable error message."
    }
    """
    # ---- Sanitise ----------------------------------------------------------
    raw_url = url.strip() if isinstance(url, str) else ""

    # ---- Validate ----------------------------------------------------------
    valid, result = _validate_url(raw_url)
    if not valid:
        return {"success": False, "url": raw_url, "error": result}

    normalised_url = result  # _validate_url returns the normalised URL on success

    # ---- HTTP request ------------------------------------------------------
    try:
        response = requests.get(
            normalised_url,
            timeout=_REQUEST_TIMEOUT,
            allow_redirects=True,           # follow redirects to the final page
            headers={"User-Agent": "ConfigurationAuditor/1.0 SecurityScanner"},
            verify=True,                    # enforce SSL certificate verification
        )
    except requests.exceptions.SSLError as exc:
        return {
            "success": False,
            "url": normalised_url,
            "error": f"SSL certificate verification failed: {exc}",
        }
    except requests.exceptions.ConnectionError as exc:
        return {
            "success": False,
            "url": normalised_url,
            "error": f"Failed to connect to host: {exc}",
        }
    except requests.exceptions.Timeout:
        return {
            "success": False,
            "url": normalised_url,
            "error": f"Request timed out after {_REQUEST_TIMEOUT}s.",
        }
    except requests.exceptions.TooManyRedirects:
        return {
            "success": False,
            "url": normalised_url,
            "error": "Too many redirects; the URL may be in a redirect loop.",
        }
    except requests.exceptions.RequestException as exc:
        return {
            "success": False,
            "url": normalised_url,
            "error": f"HTTP request error: {type(exc).__name__}: {exc}",
        }
    except Exception as exc:  # noqa: BLE001
        return {
            "success": False,
            "url": normalised_url,
            "error": f"Unexpected error: {type(exc).__name__}: {exc}",
        }

    # ---- Audit headers -----------------------------------------------------
    response_headers = response.headers   # CaseInsensitiveDict
    audited          = {}
    missing          = []

    for header_name, meta in _SECURITY_HEADERS.items():
        value = response_headers.get(header_name)

        if value:
            audited[header_name] = _audit_header(header_name, value)
        else:
            missing.append(header_name)
            audited[header_name] = {
                "present":     False,
                "value":       None,
                "note":        meta["description"],
            }

    risk_level = _compute_risk(missing)

    # ---- Build result ------------------------------------------------------
    return {
        "success":        True,
        "url":            normalised_url,
        "status_code":    response.status_code,
        "headers":        audited,
        "missing_headers": missing,
        "risk_level":     risk_level,
    }