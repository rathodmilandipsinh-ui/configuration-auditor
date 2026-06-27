"""
Configuration Auditor - Flask Application Entry Point
A cybersecurity tool for auditing system and network configurations.
"""

import concurrent.futures

from flask import Flask, render_template, request, jsonify
from werkzeug.exceptions import HTTPException

from scanners.whois_scanner  import scan as whois_scan
from scanners.scanner    import scan as ssl_scan
from scanners.dns_scanner    import scan as dns_scan
from scanners.header_scanner import scan as header_scan
from scanners.tech_scanner   import scan as tech_scan
from scanners.security_score import calculate   

# ---------------------------------------------------------------------------
# App Initialisation
# ---------------------------------------------------------------------------

app = Flask(__name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _safe_run(fn, *args) -> dict:
    """
    Execute *fn* with *args* and always return a dict.

    If the scanner raises an unhandled exception the error is caught here
    so one failing scanner can never abort the entire /api/scan pipeline.
    """
    try:
        return fn(*args)
    except Exception as exc:  # noqa: BLE001
        return {
            "success": False,
            "error": f"Scanner crashed unexpectedly: {type(exc).__name__}: {exc}",
        }


# ---------------------------------------------------------------------------
# Page Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    """Serve the landing page."""
    return render_template("index.html")


@app.route("/auditor")
def auditor():
    """Serve the configuration auditor interface."""
    return render_template("auditor.html")


@app.route("/about")
def about():
    """Serve the about / documentation page."""
    return render_template("about.html")


# ---------------------------------------------------------------------------
# Individual API Routes
# ---------------------------------------------------------------------------

@app.route("/api/whois", methods=["POST"])
def api_whois():
    """
    POST /api/whois
    Perform a WHOIS lookup for the submitted domain.

    Request body (JSON):
        { "domain": "google.com" }

    Success response (200):
        {
            "success": true,
            "domain": "google.com",
            "registrar": "MarkMonitor Inc.",
            "creation_date": "1997-09-15",
            "expiration_date": "2028-09-14",
            "updated_date": "2019-09-09",
            "nameservers": ["ns1.google.com", "ns2.google.com"]
        }

    Error responses:
        400 — missing / invalid JSON body or missing domain field.
        422 — domain failed validation or WHOIS returned no record.
        500 — unexpected server-side error.
    """
    if not request.is_json:
        return jsonify({"success": False,
                        "error": "Content-Type must be application/json."}), 400

    body = request.get_json(silent=True)
    if not body:
        return jsonify({"success": False,
                        "error": "Request body is missing or not valid JSON."}), 400

    domain = body.get("domain", "").strip()
    if not domain:
        return jsonify({"success": False,
                        "error": "The 'domain' field is required and must not be empty."}), 400

    result = _safe_run(whois_scan, domain)
    status = 200 if result.get("success") else 422
    return jsonify(result), status


@app.route("/api/ssl", methods=["POST"])
def api_ssl():
    """
    POST /api/ssl
    Retrieve and inspect the SSL/TLS certificate for a domain.

    Request body (JSON):
        { "domain": "google.com" }
    """
    if not request.is_json:
        return jsonify({"success": False,
                        "error": "Content-Type must be application/json."}), 400

    body = request.get_json(silent=True)
    if not body:
        return jsonify({"success": False,
                        "error": "Request body is missing or not valid JSON."}), 400

    domain = body.get("domain", "").strip()
    if not domain:
        return jsonify({"success": False,
                        "error": "The 'domain' field is required and must not be empty."}), 400

    result = _safe_run(ssl_scan, domain)
    status = 200 if result.get("success") else 422
    return jsonify(result), status


@app.route("/api/dns", methods=["POST"])
def api_dns():
    """
    POST /api/dns
    Resolve DNS records (A, AAAA, MX, TXT, NS) for a domain.

    Request body (JSON):
        { "domain": "google.com" }
    """
    if not request.is_json:
        return jsonify({"success": False,
                        "error": "Content-Type must be application/json."}), 400

    body = request.get_json(silent=True)
    if not body:
        return jsonify({"success": False,
                        "error": "Request body is missing or not valid JSON."}), 400

    domain = body.get("domain", "").strip()
    if not domain:
        return jsonify({"success": False,
                        "error": "The 'domain' field is required and must not be empty."}), 400

    result = _safe_run(dns_scan, domain)
    status = 200 if result.get("success") else 422
    return jsonify(result), status


@app.route("/api/headers", methods=["POST"])
def api_headers():
    """
    POST /api/headers
    Audit HTTP security headers for a URL.

    Request body (JSON):
        { "url": "https://google.com" }
    """
    if not request.is_json:
        return jsonify({"success": False,
                        "error": "Content-Type must be application/json."}), 400

    body = request.get_json(silent=True)
    if not body:
        return jsonify({"success": False,
                        "error": "Request body is missing or not valid JSON."}), 400

    url = body.get("url", "").strip()
    if not url:
        return jsonify({"success": False,
                        "error": "The 'url' field is required and must not be empty."}), 400

    result = _safe_run(header_scan, url)
    status = 200 if result.get("success") else 422
    return jsonify(result), status


@app.route("/api/tech", methods=["POST"])
def api_tech():
    """
    POST /api/tech
    Fingerprint the technology stack of a URL.

    Request body (JSON):
        { "url": "https://google.com" }
    """
    if not request.is_json:
        return jsonify({"success": False,
                        "error": "Content-Type must be application/json."}), 400

    body = request.get_json(silent=True)
    if not body:
        return jsonify({"success": False,
                        "error": "Request body is missing or not valid JSON."}), 400

    url = body.get("url", "").strip()
    if not url:
        return jsonify({"success": False,
                        "error": "The 'url' field is required and must not be empty."}), 400

    result = _safe_run(tech_scan, url)
    status = 200 if result.get("success") else 422
    return jsonify(result), status


# ---------------------------------------------------------------------------
# Unified Full-Scan Route
# ---------------------------------------------------------------------------

@app.route("/api/scan", methods=["POST"])
def api_scan():
    """
    POST /api/scan
    Run all five scanners concurrently against a single target and return
    their combined results in one response.

    Request body (JSON):
        { "target": "google.com" }

    The 'target' value is used as:
        - domain  → WHOIS, SSL, DNS scanners
        - url     → Header and Technology scanners
          (https:// is prepended automatically when the scheme is absent)

    Success response (200):
    {
        "success": true,
        "target":  "google.com",
        "whois": { ... },
        "ssl":   { ... },
        "dns":   { ... },
        "headers":    { ... },
        "technology": { ... }
    }

    The top-level "success" is true as long as the request itself is valid.
    Each scanner sub-object carries its own "success" field so callers can
    distinguish which (if any) individual scans failed.

    Error responses:
        400 — missing / invalid JSON body, or missing 'target' field.
    """
    # ---- Enforce Content-Type ----------------------------------------------
    if not request.is_json:
        return jsonify({"success": False,
                        "error": "Content-Type must be application/json."}), 400

    # ---- Parse body --------------------------------------------------------
    body = request.get_json(silent=True)
    if not body:
        return jsonify({"success": False,
                        "error": "Request body is missing or not valid JSON."}), 400

    # ---- Validate 'target' -------------------------------------------------
    target = body.get("target", "").strip()
    if not target:
        return jsonify({"success": False,
                        "error": "The 'target' field is required and must not be empty."}), 400

    # ---- Derive URL from target (prepend scheme when absent) ---------------
    url = target if target.startswith(("http://", "https://")) else f"https://{target}"

    # ---- Run all scanners concurrently -------------------------------------
    # ThreadPoolExecutor is used so that I/O-bound network calls (WHOIS,
    # SSL handshake, DNS queries, HTTP fetches) run in parallel rather than
    # sequentially, cutting total wall-clock time significantly.
    tasks = {
        "whois":      (whois_scan,  target),
        "ssl":        (ssl_scan,    target),
        "dns":        (dns_scan,    target),
        "headers":    (header_scan, url),
        "technology": (tech_scan,   url),
    }

    results: dict[str, dict] = {}

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        # Submit all tasks
        future_to_key = {
            executor.submit(_safe_run, fn, arg): key
            for key, (fn, arg) in tasks.items()
        }

        # Collect results as they complete
        for future in concurrent.futures.as_completed(future_to_key):
            key = future_to_key[future]
            try:
                results[key] = future.result()
            except Exception as exc:  # noqa: BLE001
                # _safe_run already catches exceptions; this is a belt-and-
                # suspenders guard for any Future-level failure.
                results[key] = {
                    "success": False,
                    "error": f"Future error: {type(exc).__name__}: {exc}",
                }
    security_score = calculate(
    whois=results.get("whois", {}),
    ssl=results.get("ssl", {}),
    dns=results.get("dns", {}),
    headers=results.get("headers", {}),
    technology=results.get("technology", {}),
)
    # ---- Build unified response --------------------------------------------
    return jsonify({
        "success":    True,
        "target":     target,
        "whois":      results.get("whois",      {"success": False, "error": "Scanner did not run."}),
        "ssl":        results.get("ssl",        {"success": False, "error": "Scanner did not run."}),
        "dns":        results.get("dns",        {"success": False, "error": "Scanner did not run."}),
        "headers":    results.get("headers",    {"success": False, "error": "Scanner did not run."}),
        "technology": results.get("technology", {"success": False, "error": "Scanner did not run."}),
        "security_score": security_score,
    }), 200


# ---------------------------------------------------------------------------
# Error Handlers
# ---------------------------------------------------------------------------

@app.errorhandler(404)
def not_found(error):
    """Return a clean 404 page when a route is not found."""
    return render_template("404.html"), 404


@app.errorhandler(403)
def forbidden(error):
    """Return a 403 page when access is denied."""
    return render_template("403.html"), 403


@app.errorhandler(500)
def internal_server_error(error):
    """Return a 500 page for unexpected server-side errors."""
    return render_template("500.html"), 500


@app.errorhandler(HTTPException)
def handle_http_exception(error):
    """
    Catch-all handler for any other HTTP exceptions not covered above.
    Returns the Werkzeug default description alongside the correct status code.
    """
    return render_template(
        "error.html",
        error_code=error.code,
        error_name=error.name,
        error_description=error.description,
    ), error.code


# ---------------------------------------------------------------------------
# Entry Point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # debug=False and host="0.0.0.0" are production-safe defaults.
    # In real deployments, run via a WSGI server such as Gunicorn:
    #   gunicorn -w 4 -b 0.0.0.0:5000 app:app
    app.run(host="0.0.0.0", port=5000, debug=False)
