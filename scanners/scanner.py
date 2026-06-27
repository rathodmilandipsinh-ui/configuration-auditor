"""
scanners/ssl_scanner.py
Configuration Auditor — SSL/TLS Certificate Scanner Module

Connects to a host on port 443, retrieves the X.509 certificate,
and returns a JSON-compatible dictionary of key certificate metadata.
"""

import re
import ssl
import socket
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Reuse the same RFC-compliant domain regex as whois_scanner
_DOMAIN_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9]"
    r"(?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,24}$"
)

_MAX_DOMAIN_LENGTH = 253
_DEFAULT_PORT       = 443
_CONNECT_TIMEOUT    = 10   # seconds


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
# Helpers
# ---------------------------------------------------------------------------

def _parse_cert_field(rdns: tuple) -> dict[str, str]:
    """
    Convert an SSL cert RDN sequence into a flat dictionary.

    ssl.getpeercert() returns tuples of ((key, value),) pairs, e.g.:
        ((('commonName', 'example.com'),),)
    """
    result = {}
    for rdn in rdns:
        for key, value in rdn:
            result[key] = value
    return result


def _parse_ssl_date(date_str: str) -> datetime:
    """
    Parse the date string returned by ssl.getpeercert() into a UTC datetime.

    ssl uses the format: 'MMM DD HH:MM:SS YYYY GMT'
    e.g. 'Jan  1 00:00:00 2025 GMT'
    """
    return datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z").replace(
        tzinfo=timezone.utc
    )


def _certificate_status(expiry: datetime, now: datetime) -> str:
    """
    Return a human-readable certificate status string.

    Statuses (in priority order):
        EXPIRED      — expiry is in the past.
        CRITICAL     — expires within 14 days.
        WARNING      — expires within 30 days.
        VALID        — all other valid certificates.
    """
    days_remaining = (expiry - now).days

    if days_remaining < 0:
        return "EXPIRED"
    if days_remaining <= 14:
        return "CRITICAL"
    if days_remaining <= 30:
        return "WARNING"
    return "VALID"


# ---------------------------------------------------------------------------
# Public Interface
# ---------------------------------------------------------------------------

def scan(domain: str, port: int = _DEFAULT_PORT) -> dict:
    """
    Retrieve and inspect the SSL/TLS certificate for *domain*.

    Args:
        domain: Hostname to inspect (e.g. "example.com").
        port:   TCP port to connect on (default: 443).

    Successful response shape:
    {
        "success":         True,
        "domain":          "example.com",
        "issuer": {
            "commonName":         "R11",
            "organizationName":   "Let's Encrypt",
            "countryName":        "US"
        },
        "subject": {
            "commonName": "example.com"
        },
        "valid_from":      "2025-01-01",
        "expiration_date": "2025-04-01",
        "days_remaining":  87,
        "status":          "VALID"
    }

    Error response shape:
    {
        "success": False,
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

    # ---- Open TLS connection and fetch certificate -------------------------
    try:
        ctx = ssl.create_default_context()

        with socket.create_connection((domain, port), timeout=_CONNECT_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as tls_sock:
                cert = tls_sock.getpeercert()

    except ssl.CertificateError as exc:
        # Hostname mismatch or certificate verification failure
        return {
            "success": False,
            "domain": domain,
            "error": f"Certificate verification failed: {exc}",
        }
    except ssl.SSLError as exc:
        return {
            "success": False,
            "domain": domain,
            "error": f"SSL/TLS error: {exc.reason if exc.reason else str(exc)}",
        }
    except socket.timeout:
        return {
            "success": False,
            "domain": domain,
            "error": f"Connection timed out after {_CONNECT_TIMEOUT}s.",
        }
    except socket.gaierror as exc:
        # DNS resolution failure
        return {
            "success": False,
            "domain": domain,
            "error": f"DNS resolution failed: {exc.strerror}",
        }
    except ConnectionRefusedError:
        return {
            "success": False,
            "domain": domain,
            "error": f"Connection refused on port {port}.",
        }
    except OSError as exc:
        return {
            "success": False,
            "domain": domain,
            "error": f"Network error: {exc.strerror or str(exc)}",
        }
    except Exception as exc:  # noqa: BLE001
        return {
            "success": False,
            "domain": domain,
            "error": f"Unexpected error: {type(exc).__name__}: {exc}",
        }

    # ---- Guard: empty certificate ------------------------------------------
    if not cert:
        return {
            "success": False,
            "domain": domain,
            "error": "Server did not return a certificate.",
        }

    # ---- Parse dates -------------------------------------------------------
    try:
        valid_from  = _parse_ssl_date(cert["notBefore"])
        expiry      = _parse_ssl_date(cert["notAfter"])
    except (KeyError, ValueError) as exc:
        return {
            "success": False,
            "domain": domain,
            "error": f"Failed to parse certificate dates: {exc}",
        }

    now            = datetime.now(tz=timezone.utc)
    days_remaining = (expiry - now).days
    status         = _certificate_status(expiry, now)

    # ---- Parse issuer / subject --------------------------------------------
    issuer  = _parse_cert_field(cert.get("issuer",  ()))
    subject = _parse_cert_field(cert.get("subject", ()))

    # ---- Build result ------------------------------------------------------
    return {
        "success":         True,
        "domain":          domain,
        "issuer":          issuer,
        "subject":         subject,
        "valid_from":      valid_from.strftime("%Y-%m-%d"),
        "expiration_date": expiry.strftime("%Y-%m-%d"),
        "days_remaining":  days_remaining,
        "status":          status,
    }