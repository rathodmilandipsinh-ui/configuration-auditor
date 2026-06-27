"""
scanners/tech_scanner.py
Configuration Auditor — Technology Fingerprinting Scanner Module

Fetches a URL and fingerprints the technology stack by inspecting:
  - HTTP response headers
  - HTML meta tags and script/link elements
  - Cookie names
  - Inline script content

Returns a structured, JSON-compatible dictionary.
"""

import re
import requests
from urllib.parse import urlparse
from bs4 import BeautifulSoup

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_REQUEST_TIMEOUT = 12   # seconds
_MAX_BODY_BYTES  = 1_500_000   # 1.5 MB — cap response body to limit memory use


# ---------------------------------------------------------------------------
# Fingerprint Signatures
# ---------------------------------------------------------------------------
# Each entry is a dict with ONE or more of:
#   header   : { header_name: regex_pattern }
#   meta     : { meta_name_or_property: regex_pattern }
#   html     : regex matched against raw HTML
#   script   : regex matched against src attributes of <script> tags
#   cookie   : regex matched against cookie names
#   implies  : list of tech names this detection implies (e.g. WP → PHP)
# ---------------------------------------------------------------------------

_SIGNATURES: list[dict] = [

    # ── Servers ─────────────────────────────────────────────────────────────
    {"name": "Apache",      "category": "Server",
     "header": {"Server": r"Apache"}},

    {"name": "Nginx",       "category": "Server",
     "header": {"Server": r"nginx"}},

    {"name": "IIS",         "category": "Server",
     "header": {"Server": r"Microsoft-IIS(?:/(?P<version>[\d.]+))?"}},

    {"name": "LiteSpeed",   "category": "Server",
     "header": {"Server": r"LiteSpeed"}},

    {"name": "Caddy",       "category": "Server",
     "header": {"Server": r"Caddy"}},

    {"name": "OpenResty",   "category": "Server",
     "header": {"Server": r"openresty"}},

    {"name": "Cloudflare",  "category": "CDN",
     "header": {"Server": r"cloudflare"}},

    {"name": "Cloudfront",  "category": "CDN",
     "header": {"Via": r"CloudFront"}},

    {"name": "Fastly",      "category": "CDN",
     "header": {"X-Served-By": r"cache-"}},

    # ── Languages & runtimes ────────────────────────────────────────────────
    {"name": "PHP",         "category": "Language",
     "header": {"X-Powered-By": r"PHP(?:/(?P<version>[\d.]+))?"}},

    {"name": "ASP.NET",     "category": "Language",
     "header": {"X-Powered-By": r"ASP\.NET",
                "X-AspNet-Version": r".+"}},

    {"name": "Ruby on Rails","category": "Framework",
     "header": {"X-Powered-By": r"Phusion Passenger",
                "Server":       r"Passenger"}},

    {"name": "Node.js",     "category": "Runtime",
     "header": {"X-Powered-By": r"Express|Node\.js"}},

    # ── CMS ─────────────────────────────────────────────────────────────────
    {"name": "WordPress",   "category": "CMS",
     "html":   r"/wp-content/|/wp-includes/",
     "meta":   {"generator": r"WordPress(?:\s(?P<version>[\d.]+))?"},
     "cookie": r"^wordpress_|^wp-settings-",
     "implies": ["PHP"]},

    {"name": "Joomla",      "category": "CMS",
     "html":   r"/media/jui/|Joomla!",
     "meta":   {"generator": r"Joomla"},
     "implies": ["PHP"]},

    {"name": "Drupal",      "category": "CMS",
     "html":   r"Drupal\.settings|/sites/default/files/",
     "header": {"X-Generator": r"Drupal(?:\s(?P<version>[\d.]+))?",
                "X-Drupal-Cache": r".+"},
     "implies": ["PHP"]},

    {"name": "Magento",     "category": "CMS",
     "html":   r"Mage\.|/skin/frontend/",
     "cookie": r"^frontend$",
     "implies": ["PHP"]},

    {"name": "Shopify",     "category": "CMS",
     "html":   r"cdn\.shopify\.com",
     "header": {"X-ShopId": r".+",
                "X-ShardId": r".+"}},

    {"name": "Wix",         "category": "CMS",
     "html":   r"static\.wixstatic\.com|wix\.com/"},

    {"name": "Squarespace", "category": "CMS",
     "html":   r"squarespace\.com"},

    {"name": "Ghost",       "category": "CMS",
     "meta":   {"generator": r"Ghost(?:\s(?P<version>[\d.]+))?"},
     "html":   r"ghost\.org"},

    {"name": "TYPO3",       "category": "CMS",
     "meta":   {"generator": r"TYPO3"},
     "html":   r"typo3conf/"},

    {"name": "Webflow",     "category": "CMS",
     "html":   r"webflow\.com"},

    # ── Frameworks ──────────────────────────────────────────────────────────
    {"name": "Laravel",     "category": "Framework",
     "cookie": r"^laravel_session$",
     "header": {"X-Powered-By": r"PHP"},
     "implies": ["PHP"]},

    {"name": "Django",      "category": "Framework",
     "cookie": r"^csrftoken$",
     "header": {"X-Frame-Options": r"SAMEORIGIN"}},

    {"name": "Next.js",     "category": "Framework",
     "header": {"X-Powered-By": r"Next\.js"},
     "html":   r"__NEXT_DATA__",
     "implies": ["React", "Node.js"]},

    {"name": "Nuxt.js",     "category": "Framework",
     "html":   r"__NUXT__|nuxt",
     "implies": ["Vue.js", "Node.js"]},

    {"name": "Gatsby",      "category": "Framework",
     "html":   r"___gatsby|gatsby-",
     "implies": ["React"]},

    {"name": "Ruby on Rails","category": "Framework",
     "cookie": r"^_session_id$"},

    {"name": "Spring Boot", "category": "Framework",
     "header": {"X-Application-Context": r".+"}},

    {"name": "ASP.NET MVC", "category": "Framework",
     "header": {"X-AspNetMvc-Version": r"(?P<version>[\d.]+)"},
     "cookie": r"^\.ASPXAUTH$|^ASP\.NET_SessionId$"},

    # ── JavaScript libraries ─────────────────────────────────────────────────
    {"name": "jQuery",      "category": "JavaScript Library",
     "script": r"jquery(?:[-.](?P<version>[\d.]+))?(?:\.min)?\.js",
     "html":   r"jquery(?:[-.][\d.]+)?(?:\.min)?\.js"},

    {"name": "React",       "category": "JavaScript Library",
     "script": r"react(?:[-.]dom)?(?:\.production|\.development)?(?:\.min)?\.js",
     "html":   r"react(?:\.production\.min|\.development)?\.js|__reactFiber|data-reactroot"},

    {"name": "Vue.js",      "category": "JavaScript Library",
     "script": r"vue(?:\.(?P<version>\d))?(?:\.min)?\.js",
     "html":   r"vue(?:\.min)?\.js|__vue__"},

    {"name": "Angular",     "category": "JavaScript Library",
     "html":   r"ng-version=|angular(?:\.min)?\.js",
     "script": r"angular(?:\.min)?\.js"},

    {"name": "Bootstrap",   "category": "CSS Framework",
     "script": r"bootstrap(?:\.bundle)?(?:\.min)?\.js",
     "html":   r"bootstrap(?:\.min)?\.css"},

    {"name": "Tailwind CSS","category": "CSS Framework",
     "html":   r"tailwindcss|tailwind\.config"},

    {"name": "Lodash",      "category": "JavaScript Library",
     "script": r"lodash(?:\.min)?\.js"},

    {"name": "Moment.js",   "category": "JavaScript Library",
     "script": r"moment(?:\.min)?\.js"},

    {"name": "Alpine.js",   "category": "JavaScript Library",
     "script": r"alpinejs|alpine\.js",
     "html":   r"x-data="},

    {"name": "HTMX",        "category": "JavaScript Library",
     "script": r"htmx(?:\.min)?\.js",
     "html":   r"hx-get=|hx-post="},

    # ── Analytics & tag managers ─────────────────────────────────────────────
    {"name": "Google Analytics","category": "Analytics",
     "html":   r"google-analytics\.com/analytics\.js|gtag\(|UA-\d+-\d+|G-[A-Z0-9]+"},

    {"name": "Google Tag Manager","category": "Analytics",
     "html":   r"googletagmanager\.com/gtm\.js"},

    {"name": "Matomo",      "category": "Analytics",
     "html":   r"matomo\.js|piwik\.js"},

    {"name": "Hotjar",      "category": "Analytics",
     "html":   r"hotjar\.com"},

    {"name": "Segment",     "category": "Analytics",
     "html":   r"cdn\.segment\.com"},

    # ── Hosting / Cloud ───────────────────────────────────────────────────────
    {"name": "Vercel",      "category": "Hosting",
     "header": {"X-Vercel-Id": r".+",
                "Server":      r"Vercel"}},

    {"name": "Netlify",     "category": "Hosting",
     "header": {"X-Nf-Request-Id": r".+",
                "Server":          r"Netlify"}},

    {"name": "GitHub Pages","category": "Hosting",
     "header": {"Server": r"GitHub\.com"}},

    {"name": "Heroku",      "category": "Hosting",
     "header": {"X-Request-Id":    r"[0-9a-f-]{36}",
                "Via":             r"1\.1 vegur"}},

    # ── Security ──────────────────────────────────────────────────────────────
    {"name": "reCAPTCHA",   "category": "Security",
     "html":   r"google\.com/recaptcha|grecaptcha"},

    {"name": "hCaptcha",    "category": "Security",
     "html":   r"hcaptcha\.com"},

    {"name": "Cloudflare Turnstile", "category": "Security",
     "html":   r"challenges\.cloudflare\.com/turnstile"},
]


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

_DOMAIN_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24}$"
)

_PRIVATE_PATTERNS = [
    re.compile(r"^localhost$", re.IGNORECASE),
    re.compile(r"^127\."),
    re.compile(r"^10\."),
    re.compile(r"^192\.168\."),
    re.compile(r"^172\.(1[6-9]|2\d|3[01])\."),
    re.compile(r"^::1$"),
    re.compile(r"^0\.0\.0\.0$"),
]


def _validate_url(url: str) -> tuple[bool, str]:
    """
    Validate and normalise *url*.

    Returns (True, normalised_url) or (False, error_message).
    """
    if not url or not isinstance(url, str):
        return False, "URL must be a non-empty string."

    url = url.strip()

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

    host = parsed.hostname or ""
    if any(p.match(host) for p in _PRIVATE_PATTERNS):
        return False, f"Scanning private/internal addresses is not permitted: {host}"

    return True, url


# ---------------------------------------------------------------------------
# Detection helpers
# ---------------------------------------------------------------------------

def _match(pattern: str, text: str) -> str | None:
    """
    Case-insensitive regex match. Returns captured 'version' group if
    present, otherwise returns the matched string, or None on no match.
    """
    m = re.search(pattern, text, re.IGNORECASE)
    if not m:
        return None
    try:
        return m.group("version") or "detected"
    except IndexError:
        return "detected"


def _check_signature(
    sig: dict,
    response_headers: dict,
    html: str,
    script_srcs: list[str],
    meta_tags: dict[str, str],
    cookie_names: list[str],
) -> str | None:
    """
    Test a single signature against the collected page artefacts.

    Returns a version string / "detected" on a match, or None.
    """
    # Header checks — ANY matching header is sufficient
    for header_name, pattern in sig.get("header", {}).items():
        value = response_headers.get(header_name.lower(), "")
        result = _match(pattern, value)
        if result:
            return result

    # HTML body check
    if "html" in sig:
        result = _match(sig["html"], html)
        if result:
            return result

    # <script src="..."> checks
    for src in script_srcs:
        if "script" in sig:
            result = _match(sig["script"], src)
            if result:
                return result

    # <meta name/property="..."> checks
    for meta_key, pattern in sig.get("meta", {}).items():
        value = meta_tags.get(meta_key.lower(), "")
        result = _match(pattern, value)
        if result:
            return result

    # Cookie name checks
    if "cookie" in sig:
        for cname in cookie_names:
            result = _match(sig["cookie"], cname)
            if result:
                return result

    return None


# ---------------------------------------------------------------------------
# Public Interface
# ---------------------------------------------------------------------------

def scan(url: str) -> dict:
    """
    Fetch *url* and fingerprint its technology stack.

    Args:
        url: Target URL (scheme optional; HTTPS assumed when omitted).

    Successful response shape:
    {
        "success": true,
        "url": "https://example.com",
        "status_code": 200,
        "technologies": [
            {
                "name":     "WordPress",
                "category": "CMS",
                "version":  "6.5.2"
            },
            ...
        ],
        "summary": {
            "Server":              ["Nginx"],
            "CMS":                 ["WordPress"],
            "Language":            ["PHP"],
            "Framework":           [],
            "JavaScript Library":  ["jQuery", "React"],
            "CSS Framework":       ["Bootstrap"],
            "CDN":                 ["Cloudflare"],
            "Analytics":           ["Google Analytics"],
            "Hosting":             [],
            "Security":            [],
            "Runtime":             []
        }
    }

    Error response shape:
    {
        "success": false,
        "url":   "bad-input",
        "error": "Human-readable error message."
    }
    """
    # ---- Sanitise & validate -----------------------------------------------
    raw_url = url.strip() if isinstance(url, str) else ""
    valid, result = _validate_url(raw_url)
    if not valid:
        return {"success": False, "url": raw_url, "error": result}

    normalised_url = result

    # ---- HTTP request -------------------------------------------------------
    try:
        response = requests.get(
            normalised_url,
            timeout=_REQUEST_TIMEOUT,
            allow_redirects=True,
            stream=True,
            headers={"User-Agent": "ConfigurationAuditor/1.0 TechScanner"},
            verify=True,
        )

        # Read up to _MAX_BODY_BYTES to avoid memory issues on huge pages
        raw_bytes = b""
        for chunk in response.iter_content(chunk_size=8192):
            raw_bytes += chunk
            if len(raw_bytes) >= _MAX_BODY_BYTES:
                break

        html = raw_bytes.decode("utf-8", errors="replace")

    except requests.exceptions.SSLError as exc:
        return {"success": False, "url": normalised_url,
                "error": f"SSL certificate error: {exc}"}
    except requests.exceptions.ConnectionError as exc:
        return {"success": False, "url": normalised_url,
                "error": f"Connection failed: {exc}"}
    except requests.exceptions.Timeout:
        return {"success": False, "url": normalised_url,
                "error": f"Request timed out after {_REQUEST_TIMEOUT}s."}
    except requests.exceptions.TooManyRedirects:
        return {"success": False, "url": normalised_url,
                "error": "Too many redirects."}
    except requests.exceptions.RequestException as exc:
        return {"success": False, "url": normalised_url,
                "error": f"HTTP error: {type(exc).__name__}: {exc}"}
    except Exception as exc:  # noqa: BLE001
        return {"success": False, "url": normalised_url,
                "error": f"Unexpected error: {type(exc).__name__}: {exc}"}

    # ---- Parse HTML ---------------------------------------------------------
    try:
        soup = BeautifulSoup(html, "html.parser")
    except Exception:  # noqa: BLE001
        soup = BeautifulSoup("", "html.parser")

    # Normalise response headers to lowercase keys for case-insensitive lookup
    response_headers_lower = {k.lower(): v for k, v in response.headers.items()}

    # Collect <script src="..."> values
    script_srcs = [
        tag.get("src", "")
        for tag in soup.find_all("script", src=True)
    ]

    # Collect <meta name/property="..." content="...">
    meta_tags: dict[str, str] = {}
    for tag in soup.find_all("meta"):
        key   = (tag.get("name") or tag.get("property") or "").lower().strip()
        value = tag.get("content", "").strip()
        if key:
            meta_tags[key] = value

    # Collect cookie names from Set-Cookie headers
    cookie_names: list[str] = []
    set_cookie_raw = response.headers.get("Set-Cookie", "")
    for raw in response.raw.headers.getlist("Set-Cookie"):
        name = raw.split("=")[0].strip()
        if name:
            cookie_names.append(name)

    # ---- Run signatures -----------------------------------------------------
    detected: dict[str, dict] = {}   # name -> {category, version}
    implied:  set[str]        = set()

    for sig in _SIGNATURES:
        name = sig["name"]
        version = _check_signature(
            sig,
            response_headers_lower,
            html,
            script_srcs,
            meta_tags,
            cookie_names,
        )
        if version and name not in detected:
            detected[name] = {
                "name":     name,
                "category": sig["category"],
                "version":  version if version != "detected" else None,
            }
            # Collect implied technologies
            for implied_name in sig.get("implies", []):
                implied.add(implied_name)

    # Add implied technologies not already detected
    for sig in _SIGNATURES:
        name = sig["name"]
        if name in implied and name not in detected:
            detected[name] = {
                "name":     name,
                "category": sig["category"],
                "version":  None,
            }

    # ---- Build summary grouped by category ----------------------------------
    categories = [
        "Server", "CMS", "Language", "Framework",
        "JavaScript Library", "CSS Framework",
        "CDN", "Analytics", "Hosting", "Security", "Runtime",
    ]
    summary: dict[str, list[str]] = {cat: [] for cat in categories}

    for tech in detected.values():
        cat = tech["category"]
        if cat in summary:
            summary[cat].append(tech["name"])

    technologies = sorted(detected.values(), key=lambda t: (t["category"], t["name"]))

    # ---- Return result -------------------------------------------------------
    return {
        "success":      True,
        "url":          normalised_url,
        "status_code":  response.status_code,
        "technologies": technologies,
        "summary":      summary,
    }