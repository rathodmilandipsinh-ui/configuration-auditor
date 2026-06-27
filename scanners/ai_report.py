"""
scanners/ai_report.py
Configuration Auditor — AI-Powered Security Report Generator

Accepts the complete scan payload (WHOIS, SSL, DNS, Headers, Technology,
Security Score) and calls the OpenAI Chat Completions API to produce a
structured, human-readable security report in JSON format.

Environment variable required:
    OPENAI_API_KEY  — your OpenAI secret key

Output shape:
{
    "success": true,
    "report": {
        "executive_summary":        "...",
        "security_findings":        [ { "title": "...", "severity": "...", "detail": "..." } ],
        "vulnerabilities":          [ { "title": "...", "severity": "...", "cve": "...", "detail": "..." } ],
        "recommendations":          [ { "priority": "...", "action": "...", "detail": "..." } ],
        "score_explanation":        "..."
    },
    "model":   "gpt-4o",
    "tokens":  { "prompt": 512, "completion": 384, "total": 896 }
}
"""

from __future__ import annotations

import json
import os
import re
from typing import Any

import openai


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_MODEL           = "gpt-4o"
_MAX_TOKENS      = 2500
_TEMPERATURE     = 0.3        # low temperature → consistent, factual output
_REQUEST_TIMEOUT = 60         # seconds

# System prompt establishes the persona and output contract
_SYSTEM_PROMPT = """You are a senior cybersecurity analyst producing professional \
security audit reports. You write clearly for both technical and non-technical \
audiences. You always respond with ONLY a valid JSON object — no markdown fences, \
no prose outside the JSON, no extra keys. Every string value must be plain text \
(no markdown inside values). Arrays must contain at least one item."""

# Output schema sent to the model so it understands the exact shape required
_OUTPUT_SCHEMA = {
    "executive_summary": "<2–3 sentence plain-English summary of the target's overall security posture>",
    "security_findings": [
        {
            "title":    "<short finding name>",
            "severity": "<CRITICAL | HIGH | MEDIUM | LOW | INFO>",
            "detail":   "<one-paragraph explanation of the finding and its impact>"
        }
    ],
    "vulnerabilities": [
        {
            "title":    "<vulnerability name>",
            "severity": "<CRITICAL | HIGH | MEDIUM | LOW>",
            "cve":      "<CVE-YYYY-NNNNN or N/A>",
            "detail":   "<description of the vulnerability and exploitation risk>"
        }
    ],
    "recommendations": [
        {
            "priority": "<IMMEDIATE | SHORT_TERM | LONG_TERM>",
            "action":   "<concise action title>",
            "detail":   "<step-by-step guidance on how to implement this recommendation>"
        }
    ],
    "score_explanation": "<2–3 sentences explaining the numeric security score and how it was derived from the scan findings>"
}


# ---------------------------------------------------------------------------
# Input sanitisation
# ---------------------------------------------------------------------------

def _build_scan_summary(scan_results: dict[str, Any]) -> str:
    """
    Serialise scan_results to a compact JSON string, truncating fields
    that carry large amounts of data (e.g. raw HTML, long TXT records)
    to keep prompt tokens under control.
    """
    def _truncate(obj: Any, depth: int = 0) -> Any:
        """Recursively truncate long strings and large lists."""
        if isinstance(obj, str):
            return obj[:500] + "…(truncated)" if len(obj) > 500 else obj
        if isinstance(obj, list):
            # Keep first 20 items to avoid blowing the context window
            trimmed = [_truncate(i, depth + 1) for i in obj[:20]]
            if len(obj) > 20:
                trimmed.append(f"…and {len(obj) - 20} more items")
            return trimmed
        if isinstance(obj, dict):
            return {k: _truncate(v, depth + 1) for k, v in obj.items()}
        return obj

    safe = _truncate(scan_results)
    return json.dumps(safe, indent=2, default=str)


def _build_user_prompt(target: str, scan_summary: str) -> str:
    """Compose the user-turn message sent to the model."""
    return f"""Analyse the following security scan results for target: {target}

SCAN DATA:
{scan_summary}

Produce a structured security report matching EXACTLY this JSON schema:
{json.dumps(_OUTPUT_SCHEMA, indent=2)}

Rules:
1. base all findings strictly on the scan data provided
2. do not invent CVEs — only include them when a detected technology has a well-known, publicly documented CVE
3. severity values must be one of: CRITICAL, HIGH, MEDIUM, LOW, INFO
4. priority values must be one of: IMMEDIATE, SHORT_TERM, LONG_TERM
5. every array must contain at least one item
6. return ONLY the JSON object — no markdown, no commentary"""


# ---------------------------------------------------------------------------
# Response parsing
# ---------------------------------------------------------------------------

def _extract_json(raw: str) -> dict:
    """
    Parse the model's response into a Python dict.

    Handles edge cases where the model wraps output in ```json fences
    despite the system prompt instructing it not to.
    """
    text = raw.strip()

    # Strip markdown fences if present
    text = re.sub(r"^```(?:json)?\s*", "", text, flags=re.IGNORECASE)
    text = re.sub(r"\s*```$",          "", text)
    text = text.strip()

    return json.loads(text)


def _validate_report(report: dict) -> tuple[bool, str]:
    """
    Ensure the parsed report contains all required top-level keys
    and that array fields are actually lists.
    """
    required_keys = {
        "executive_summary",
        "security_findings",
        "vulnerabilities",
        "recommendations",
        "score_explanation",
    }
    array_keys = {"security_findings", "vulnerabilities", "recommendations"}

    missing = required_keys - report.keys()
    if missing:
        return False, f"Report is missing required keys: {', '.join(sorted(missing))}"

    for key in array_keys:
        if not isinstance(report[key], list):
            return False, f"'{key}' must be a list, got {type(report[key]).__name__}"

    return True, ""


# ---------------------------------------------------------------------------
# Public Interface
# ---------------------------------------------------------------------------

def generate(
    scan_results: dict[str, Any],
    target:       str = "unknown",
    model:        str = _MODEL,
) -> dict[str, Any]:
    """
    Generate an AI-powered security report from *scan_results*.

    Args:
        scan_results: Combined output from all scanners plus security score.
                      Expected keys: whois, ssl, dns, headers, technology,
                      security_score (all optional — missing keys are handled
                      gracefully).
        target:       Hostname / URL that was scanned (used for context).
        model:        OpenAI model to use (default: gpt-4o).

    Returns a JSON-compatible dict (see module docstring for shape).
    """
    # ---- Resolve API key ---------------------------------------------------
    api_key = os.environ.get("OPENAI_API_KEY", "").strip()
    if not api_key:
        return {
            "success": False,
            "error":   "OPENAI_API_KEY environment variable is not set.",
        }

    # ---- Validate inputs ---------------------------------------------------
    if not isinstance(scan_results, dict) or not scan_results:
        return {
            "success": False,
            "error":   "scan_results must be a non-empty dictionary.",
        }

    target = (target or "unknown").strip()

    # ---- Build prompts -----------------------------------------------------
    scan_summary = _build_scan_summary(scan_results)
    user_prompt  = _build_user_prompt(target, scan_summary)

    # ---- Call OpenAI -------------------------------------------------------
    try:
        client = openai.OpenAI(
            api_key=api_key,
            timeout=_REQUEST_TIMEOUT,
        )

        response = client.chat.completions.create(
            model=model,
            temperature=_TEMPERATURE,
            max_tokens=_MAX_TOKENS,
            messages=[
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user",   "content": user_prompt},
            ],
        )

    except openai.AuthenticationError:
        return {
            "success": False,
            "error":   "OpenAI authentication failed — check your OPENAI_API_KEY.",
        }
    except openai.RateLimitError:
        return {
            "success": False,
            "error":   "OpenAI rate limit exceeded — please retry after a short delay.",
        }
    except openai.APIConnectionError as exc:
        return {
            "success": False,
            "error":   f"Could not connect to OpenAI API: {exc}",
        }
    except openai.APITimeoutError:
        return {
            "success": False,
            "error":   f"OpenAI request timed out after {_REQUEST_TIMEOUT}s.",
        }
    except openai.APIStatusError as exc:
        return {
            "success": False,
            "error":   f"OpenAI API error {exc.status_code}: {exc.message}",
        }
    except Exception as exc:  # noqa: BLE001
        return {
            "success": False,
            "error":   f"Unexpected error calling OpenAI: {type(exc).__name__}: {exc}",
        }

    # ---- Extract content ---------------------------------------------------
    try:
        raw_content = response.choices[0].message.content or ""
    except (IndexError, AttributeError) as exc:
        return {
            "success": False,
            "error":   f"Unexpected OpenAI response shape: {exc}",
        }

    if not raw_content.strip():
        return {
            "success": False,
            "error":   "OpenAI returned an empty response.",
        }

    # ---- Parse JSON --------------------------------------------------------
    try:
        report = _extract_json(raw_content)
    except json.JSONDecodeError as exc:
        return {
            "success":      False,
            "error":        f"Model returned non-JSON content: {exc}",
            "raw_response": raw_content[:1000],   # include snippet for debugging
        }

    # ---- Validate structure ------------------------------------------------
    valid, reason = _validate_report(report)
    if not valid:
        return {
            "success":      False,
            "error":        f"Report validation failed: {reason}",
            "raw_response": raw_content[:1000],
        }

    # ---- Token usage -------------------------------------------------------
    usage = response.usage
    tokens = {
        "prompt":     usage.prompt_tokens     if usage else None,
        "completion": usage.completion_tokens if usage else None,
        "total":      usage.total_tokens      if usage else None,
    }

    # ---- Success -----------------------------------------------------------
    return {
        "success": True,
        "report":  report,
        "model":   response.model,
        "tokens":  tokens,
    }