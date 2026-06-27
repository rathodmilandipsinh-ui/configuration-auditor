"""
scanners/security_score.py
Configuration Auditor — Security Score Calculator

Aggregates findings from all five scanners into a single 0–100 security
score and a corresponding risk level.

Scoring philosophy
──────────────────
Each scanner contributes a maximum number of points ("budget"). Points are
DEDUCTED for findings that represent real security risk. The final score is
clamped to [0, 100].

Scanner budgets (total = 100 pts):
  ┌─────────────────────┬────────┐
  │ Scanner             │ Budget │
  ├─────────────────────┼────────┤
  │ SSL / TLS           │  30    │
  │ Security Headers    │  25    │
  │ WHOIS / Domain      │  20    │
  │ DNS                 │  15    │
  │ Technology Stack    │  10    │
  └─────────────────────┴────────┘

Risk levels:
  90 – 100  →  SECURE
  75 –  89  →  LOW
  50 –  74  →  MEDIUM
  25 –  49  →  HIGH
   0 –  24  →  CRITICAL
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing   import Any


# ---------------------------------------------------------------------------
# Risk level mapping
# ---------------------------------------------------------------------------

_RISK_LEVELS: list[tuple[int, str]] = [
    (90, "SECURE"),
    (75, "LOW"),
    (50, "MEDIUM"),
    (25, "HIGH"),
    (0,  "CRITICAL"),
]


def _risk_label(score: int) -> str:
    """Map a numeric score to its risk-level label."""
    for threshold, label in _RISK_LEVELS:
        if score >= threshold:
            return label
    return "CRITICAL"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_date(value: str | None) -> datetime | None:
    """
    Parse an ISO-8601 date string (YYYY-MM-DD) into a UTC datetime.
    Returns None on failure so callers can treat missing dates safely.
    """
    if not value or not isinstance(value, str):
        return None
    for fmt in ("%Y-%m-%d", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(value.strip()[:19], fmt).replace(
                tzinfo=timezone.utc
            )
        except ValueError:
            continue
    return None


def _days_until(date_str: str | None) -> int | None:
    """Return days between now and *date_str*. Negative = already passed."""
    dt = _parse_date(date_str)
    if dt is None:
        return None
    return (dt - datetime.now(tz=timezone.utc)).days


def _clamp(value: int, lo: int = 0, hi: int = 100) -> int:
    return max(lo, min(hi, value))


# ---------------------------------------------------------------------------
# Per-scanner scoring functions
# ---------------------------------------------------------------------------

# ── SSL / TLS (budget: 30 pts) ────────────────────────────────────────────

def _score_ssl(ssl: dict[str, Any]) -> tuple[int, list[dict]]:
    """
    Evaluate SSL/TLS certificate health.

    Rules (deductions from 30-pt budget):
      -30  Scanner could not connect or returned no certificate.
            A site with no reachable SSL is maximally risky in this category.
      -30  Certificate is EXPIRED.
            An expired cert means HTTPS is actively broken or bypassed.
      -20  Certificate expires within 14 days (CRITICAL window).
            Imminent expiry; any outage leaves users exposed.
      -10  Certificate expires within 30 days (WARNING window).
            Needs urgent renewal attention.
      -5   days_remaining field is missing.
            We cannot verify validity; treat as partial risk.
    """
    budget     = 30
    deductions = 0
    findings: list[dict] = []

    if not ssl.get("success"):
        deductions += 30
        findings.append({
            "rule":      "ssl_unreachable",
            "severity":  "CRITICAL",
            "detail":    "SSL scan failed — certificate could not be retrieved.",
            "deduction": 30,
        })
        return _clamp(budget - deductions), findings

    status = (ssl.get("status") or "").upper()

    if status == "EXPIRED":
        deductions += 30
        findings.append({
            "rule":      "ssl_expired",
            "severity":  "CRITICAL",
            "detail":    "SSL certificate has expired.",
            "deduction": 30,
        })
    elif status == "CRITICAL":
        deductions += 20
        findings.append({
            "rule":      "ssl_expiry_critical",
            "severity":  "HIGH",
            "detail":    f"Certificate expires in {ssl.get('days_remaining')} day(s) — critical window.",
            "deduction": 20,
        })
    elif status == "WARNING":
        deductions += 10
        findings.append({
            "rule":      "ssl_expiry_warning",
            "severity":  "MEDIUM",
            "detail":    f"Certificate expires in {ssl.get('days_remaining')} day(s) — renewal recommended.",
            "deduction": 10,
        })
    elif ssl.get("days_remaining") is None:
        deductions += 5
        findings.append({
            "rule":      "ssl_expiry_unknown",
            "severity":  "LOW",
            "detail":    "Certificate expiry date could not be determined.",
            "deduction": 5,
        })

    return _clamp(budget - deductions), findings


# ── Security Headers (budget: 25 pts) ─────────────────────────────────────

# Individual header weights within the 25-pt budget.
# Chosen to reflect the severity of each header's absence:
#   HSTS absence allows protocol downgrade (most dangerous) → 8 pts
#   CSP absence enables XSS / injection → 7 pts
#   X-Frame-Options absence enables clickjacking → 4 pts
#   X-Content-Type-Options absence allows MIME sniffing → 3 pts
#   Referrer-Policy absence leaks sensitive URLs → 2 pts
#   Permissions-Policy absence exposes browser APIs → 1 pt
_HEADER_WEIGHTS: dict[str, int] = {
    "Strict-Transport-Security": 8,
    "Content-Security-Policy":   7,
    "X-Frame-Options":           4,
    "X-Content-Type-Options":    3,
    "Referrer-Policy":           2,
    "Permissions-Policy":        1,
}


def _score_headers(headers: dict[str, Any]) -> tuple[int, list[dict]]:
    """
    Evaluate HTTP security headers.

    Rules (deductions from 25-pt budget):
      -25  Scanner failed — no header data available.
      Per missing header (see _HEADER_WEIGHTS above):
        -8   Strict-Transport-Security missing
        -7   Content-Security-Policy missing
        -4   X-Frame-Options missing
        -3   X-Content-Type-Options missing
        -2   Referrer-Policy missing
        -1   Permissions-Policy missing
    """
    budget     = 25
    deductions = 0
    findings: list[dict] = []

    if not headers.get("success"):
        deductions += 25
        findings.append({
            "rule":      "headers_unreachable",
            "severity":  "HIGH",
            "detail":    "Header scan failed — no header data could be retrieved.",
            "deduction": 25,
        })
        return _clamp(budget - deductions), findings

    missing: list[str] = headers.get("missing_headers", [])

    for header_name in missing:
        weight = _HEADER_WEIGHTS.get(header_name, 1)
        severity = (
            "HIGH"   if weight >= 7 else
            "MEDIUM" if weight >= 3 else
            "LOW"
        )
        deductions += weight
        findings.append({
            "rule":      f"header_missing_{header_name.lower().replace('-', '_')}",
            "severity":  severity,
            "detail":    f"Missing security header: {header_name}.",
            "deduction": weight,
        })

    return _clamp(budget - deductions), findings


# ── WHOIS / Domain (budget: 20 pts) ───────────────────────────────────────

def _score_whois(whois: dict[str, Any]) -> tuple[int, list[dict]]:
    """
    Evaluate domain registration health.

    Rules (deductions from 20-pt budget):
      -20  WHOIS scan failed — no domain data available.
      -15  Domain expires within 30 days.
            An expiring domain can be sniped by attackers causing full
            takeover of all associated services.
      -10  Domain expires within 90 days.
            Urgent renewal required.
      -5   Domain expires within 180 days.
            Renewal should be scheduled soon.
      -5   No registrar information found.
            May indicate a privacy proxy, incomplete record, or data issue.
      -5   No nameservers recorded in WHOIS.
            Missing nameservers may indicate DNS misconfiguration.
      -3   Domain creation date unavailable.
            Very new or private registrations may indicate throwaway domains.
    """
    budget     = 20
    deductions = 0
    findings: list[dict] = []

    if not whois.get("success"):
        deductions += 20
        findings.append({
            "rule":      "whois_unavailable",
            "severity":  "HIGH",
            "detail":    "WHOIS scan failed — domain registration data unavailable.",
            "deduction": 20,
        })
        return _clamp(budget - deductions), findings

    # Domain expiry
    days = _days_until(whois.get("expiration_date"))
    if days is None:
        pass  # no deduction — absence of expiry date is not itself risky
    elif days <= 30:
        deductions += 15
        findings.append({
            "rule":      "domain_expiry_critical",
            "severity":  "CRITICAL",
            "detail":    f"Domain expires in {days} day(s) — immediate renewal required.",
            "deduction": 15,
        })
    elif days <= 90:
        deductions += 10
        findings.append({
            "rule":      "domain_expiry_warning",
            "severity":  "HIGH",
            "detail":    f"Domain expires in {days} day(s) — renewal urgently needed.",
            "deduction": 10,
        })
    elif days <= 180:
        deductions += 5
        findings.append({
            "rule":      "domain_expiry_soon",
            "severity":  "MEDIUM",
            "detail":    f"Domain expires in {days} day(s) — schedule renewal.",
            "deduction": 5,
        })

    # Registrar presence
    if not whois.get("registrar"):
        deductions += 5
        findings.append({
            "rule":      "whois_no_registrar",
            "severity":  "LOW",
            "detail":    "No registrar information found in WHOIS record.",
            "deduction": 5,
        })

    # Nameserver presence
    if not whois.get("nameservers"):
        deductions += 5
        findings.append({
            "rule":      "whois_no_nameservers",
            "severity":  "LOW",
            "detail":    "No nameservers found in WHOIS record.",
            "deduction": 5,
        })

    # Creation date presence
    if not whois.get("creation_date"):
        deductions += 3
        findings.append({
            "rule":      "whois_no_creation_date",
            "severity":  "INFO",
            "detail":    "Domain creation date unavailable — may be privacy-protected or very new.",
            "deduction": 3,
        })

    return _clamp(budget - deductions), findings


# ── DNS (budget: 15 pts) ──────────────────────────────────────────────────

def _score_dns(dns: dict[str, Any]) -> tuple[int, list[dict]]:
    """
    Evaluate DNS configuration health.

    Rules (deductions from 15-pt budget):
      -15  DNS scan failed entirely.
      -10  No A records found.
            The domain cannot be resolved to IPv4 — effectively offline.
      -5   No NS records found.
            Missing nameserver records indicate serious DNS misconfiguration.
      -4   No MX records found.
            Domain cannot receive email, which may be intentional but is noted.
      -3   No TXT records found.
            Missing TXT records means no SPF, DMARC, or domain verification.
      -2   Individual record-type query error (per type, max once each).
            A query failure for a specific type indicates partial DNS issues.
    """
    budget     = 15
    deductions = 0
    findings: list[dict] = []

    if not dns.get("success"):
        deductions += 15
        findings.append({
            "rule":      "dns_scan_failed",
            "severity":  "HIGH",
            "detail":    "DNS scan failed — no record data available.",
            "deduction": 15,
        })
        return _clamp(budget - deductions), findings

    records: dict[str, dict] = dns.get("records", {})

    def _has_records(rtype: str) -> bool:
        return bool(records.get(rtype, {}).get("records"))

    def _has_error(rtype: str) -> bool:
        return bool(records.get(rtype, {}).get("error"))

    # A records — critical for resolution
    if not _has_records("A"):
        deductions += 10
        findings.append({
            "rule":      "dns_no_a_records",
            "severity":  "HIGH",
            "detail":    "No A (IPv4) records found — domain may not resolve.",
            "deduction": 10,
        })

    # NS records — DNS delegation
    if not _has_records("NS"):
        deductions += 5
        findings.append({
            "rule":      "dns_no_ns_records",
            "severity":  "HIGH",
            "detail":    "No NS records found — nameserver delegation is missing.",
            "deduction": 5,
        })

    # MX records — email capability
    if not _has_records("MX"):
        deductions += 4
        findings.append({
            "rule":      "dns_no_mx_records",
            "severity":  "MEDIUM",
            "detail":    "No MX records found — domain cannot receive email.",
            "deduction": 4,
        })

    # TXT records — SPF / DMARC / verification
    if not _has_records("TXT"):
        deductions += 3
        findings.append({
            "rule":      "dns_no_txt_records",
            "severity":  "MEDIUM",
            "detail":    "No TXT records found — SPF/DMARC/domain verification may be absent.",
            "deduction": 3,
        })

    # Per-type query errors
    for rtype in ("A", "AAAA", "MX", "TXT", "NS"):
        if _has_error(rtype):
            deductions += 2
            findings.append({
                "rule":      f"dns_query_error_{rtype.lower()}",
                "severity":  "LOW",
                "detail":    f"DNS query error for {rtype} records: {records[rtype]['error']}",
                "deduction": 2,
            })

    return _clamp(budget - deductions), findings


# ── Technology Stack (budget: 10 pts) ─────────────────────────────────────

# Technologies that indicate higher risk when exposed
_RISKY_TECH: dict[str, dict] = {
    # Outdated / commonly exploited server software
    "IIS": {
        "severity":  "MEDIUM",
        "detail":    "Microsoft IIS detected — ensure it is fully patched.",
        "deduction": 3,
    },
    # Exposing the exact server software aids targeted attacks
    "Apache": {
        "severity":  "LOW",
        "detail":    "Apache server banner exposed — consider suppressing version info.",
        "deduction": 2,
    },
    "Nginx": {
        "severity":  "LOW",
        "detail":    "Nginx server banner exposed — consider suppressing version info.",
        "deduction": 1,
    },
    # CMS platforms with large attack surfaces
    "WordPress": {
        "severity":  "MEDIUM",
        "detail":    "WordPress detected — ensure core, themes, and plugins are up to date.",
        "deduction": 3,
    },
    "Joomla": {
        "severity":  "MEDIUM",
        "detail":    "Joomla detected — frequently targeted; keep fully patched.",
        "deduction": 3,
    },
    "Drupal": {
        "severity":  "MEDIUM",
        "detail":    "Drupal detected — keep core and modules patched (Drupalgeddon history).",
        "deduction": 3,
    },
    # PHP version exposure
    "PHP": {
        "severity":  "LOW",
        "detail":    "PHP runtime exposed in headers — consider suppressing X-Powered-By.",
        "deduction": 2,
    },
    # ASP.NET version disclosure
    "ASP.NET": {
        "severity":  "LOW",
        "detail":    "ASP.NET version exposed in headers — suppress X-Powered-By and X-AspNet-Version.",
        "deduction": 2,
    },
}


def _score_technology(tech: dict[str, Any]) -> tuple[int, list[dict]]:
    """
    Evaluate technology stack risk exposure.

    Rules (deductions from 10-pt budget):
      -10  Technology scan failed.
      Per detected technology (see _RISKY_TECH above):
        -3  High-risk CMS (WordPress, Joomla, Drupal) or IIS
        -2  Server/language banners exposed (Apache, PHP, ASP.NET)
        -1  Low-risk but noted software (Nginx)
      Deductions in this category are capped at the 10-pt budget.
    """
    budget     = 10
    deductions = 0
    findings: list[dict] = []

    if not tech.get("success"):
        deductions += 10
        findings.append({
            "rule":      "tech_scan_failed",
            "severity":  "MEDIUM",
            "detail":    "Technology scan failed — stack fingerprint unavailable.",
            "deduction": 10,
        })
        return _clamp(budget - deductions), findings

    detected_names = {
        t.get("name", "") for t in tech.get("technologies", [])
    }

    for tech_name, meta in _RISKY_TECH.items():
        if tech_name in detected_names:
            deductions += meta["deduction"]
            findings.append({
                "rule":      f"tech_risky_{tech_name.lower().replace('.', '_').replace(' ', '_')}",
                "severity":  meta["severity"],
                "detail":    meta["detail"],
                "deduction": meta["deduction"],
            })

    return _clamp(budget - deductions), findings


# ---------------------------------------------------------------------------
# Public Interface
# ---------------------------------------------------------------------------

def calculate(
    whois:      dict[str, Any],
    ssl:        dict[str, Any],
    dns:        dict[str, Any],
    headers:    dict[str, Any],
    technology: dict[str, Any],
) -> dict[str, Any]:
    """
    Aggregate scanner results into a single security score.

    Args:
        whois:      Output of scanners.whois_scanner.scan()
        ssl:        Output of scanners.ssl_scanner.scan()
        dns:        Output of scanners.dns_scanner.scan()
        headers:    Output of scanners.header_scanner.scan()
        technology: Output of scanners.tech_scanner.scan()

    Returns a JSON-compatible dict:
    {
        "score":      87,
        "risk_level": "LOW",
        "breakdown": {
            "ssl":        28,
            "headers":    20,
            "whois":      18,
            "dns":        12,
            "technology":  9
        },
        "findings": [
            {
                "rule":      "header_missing_content_security_policy",
                "severity":  "HIGH",
                "detail":    "Missing security header: Content-Security-Policy.",
                "deduction": 7
            },
            ...
        ],
        "max_scores": {
            "ssl":        30,
            "headers":    25,
            "whois":      20,
            "dns":        15,
            "technology": 10
        }
    }
    """
    # Ensure inputs are dicts even if caller passes None
    whois      = whois      or {}
    ssl        = ssl        or {}
    dns        = dns        or {}
    headers    = headers    or {}
    technology = technology or {}

    # ---- Run per-scanner scoring -------------------------------------------
    ssl_score,    ssl_findings    = _score_ssl(ssl)
    header_score, header_findings = _score_headers(headers)
    whois_score,  whois_findings  = _score_whois(whois)
    dns_score,    dns_findings    = _score_dns(dns)
    tech_score,   tech_findings   = _score_technology(technology)

    # ---- Aggregate ---------------------------------------------------------
    total_score = _clamp(
        ssl_score + header_score + whois_score + dns_score + tech_score
    )

    all_findings = (
        ssl_findings
        + header_findings
        + whois_findings
        + dns_findings
        + tech_findings
    )

    # Sort findings by deduction descending so the most impactful appear first
    all_findings.sort(key=lambda f: f.get("deduction", 0), reverse=True)

    return {
        "score":      total_score,
        "risk_level": _risk_label(total_score),
        "breakdown":  {
            "ssl":        ssl_score,
            "headers":    header_score,
            "whois":      whois_score,
            "dns":        dns_score,
            "technology": tech_score,
        },
        "max_scores": {
            "ssl":        30,
            "headers":    25,
            "whois":      20,
            "dns":        15,
            "technology": 10,
        },
        "findings": all_findings,
    }