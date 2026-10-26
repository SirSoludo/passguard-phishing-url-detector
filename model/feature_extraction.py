"""
feature_extraction.py
=====================
Final Year Project: Intelligent URL Phishing Detection System

PURPOSE:
    This module extracts LEXICAL features from a URL string.
    "Lexical" means we only look at the text of the URL itself —
    we do NOT visit the webpage, check DNS records, or use WHOIS.

    This makes the system:
      - Very fast (no network requests needed)
      - Privacy-friendly
      - Usable offline

FEATURES EXTRACTED (16 total):
    1.  url_length          — Total character count of the URL
    2.  domain_length       — Length of the domain name only
    3.  num_dots            — Count of '.' characters
    4.  num_subdomains      — Number of subdomain levels (dots in hostname - 1)
    5.  num_hyphens         — Count of '-' characters
    6.  num_underscores     — Count of '_' characters
    7.  num_digits          — Count of numeric digits (0–9)
    8.  has_at_symbol       — 1 if '@' present, else 0
    9.  has_double_slash    — 1 if '//' appears after the scheme, else 0
    10. has_equals          — 1 if '=' present in query string, else 0
    11. has_question_mark   — 1 if '?' present, else 0
    12. has_percent         — 1 if '%' present (URL encoding), else 0
    13. has_ip_address      — 1 if domain looks like an IP address (e.g. 192.168.1.1)
    14. num_special_chars   — Count of chars in set: {~!@#$%^&*()+=[]|{}<>?}
    15. uses_https          — 1 if scheme is HTTPS, else 0
    16. suspicious_keywords — Count of phishing-related keywords found in URL
"""

import re
from urllib.parse import urlparse


# ──────────────────────────────────────────────────────────────────────────────
# CONSTANTS
# ──────────────────────────────────────────────────────────────────────────────

# Words frequently found in phishing URLs
SUSPICIOUS_KEYWORDS = [
    "login", "verify", "update", "secure", "account", "bank",
    "confirm", "signin", "password", "recover", "suspended",
    "unlock", "validate", "credential", "ebayisapi", "webscr",
    "billing", "checkout", "free", "offer", "prize", "winner"
]

# Regular expression that matches an IPv4 address
IP_PATTERN = re.compile(
    r"^(\d{1,3}\.){3}\d{1,3}$"
)

# Characters considered "special" in the context of URL phishing analysis
SPECIAL_CHARS = set("~!@#$%^&*()+=[]|{}<>?")


# ──────────────────────────────────────────────────────────────────────────────
# HELPER: PARSE URL SAFELY
# ──────────────────────────────────────────────────────────────────────────────

def safe_parse(url: str) -> urlparse:
    """
    Parse a URL string using Python's urlparse.
    If the URL has no scheme, prepend 'http://' so parsing works correctly.

    urlparse returns a named tuple with fields:
        scheme, netloc, path, params, query, fragment
    """
    url = url.strip()
    if not url.startswith(("http://", "https://", "ftp://")):
        url = "http://" + url
    return urlparse(url), url


# ──────────────────────────────────────────────────────────────────────────────
# MAIN FEATURE EXTRACTOR
# ──────────────────────────────────────────────────────────────────────────────

def extract_features(url: str) -> dict:
    """
    Given a raw URL string, return a dictionary of 16 numerical features.

    Parameters
    ----------
    url : str
        The URL to analyze (e.g. "https://example.com/login?id=123")

    Returns
    -------
    dict
        Keys are feature names; values are integers (or 0/1 for binary flags).

    Example
    -------
    >>> features = extract_features("http://paypal-secure.xyz/login?id=abc")
    >>> features["uses_https"]        # → 0  (HTTP, not HTTPS)
    >>> features["suspicious_keywords"] # → 2  ("paypal"..."login")
    """

    parsed, cleaned_url = safe_parse(url)

    # ── Scheme ───────────────────────────────────────────────────────────────
    scheme = parsed.scheme.lower()                   # "http" or "https"

    # ── Hostname (domain + subdomains) ───────────────────────────────────────
    # netloc may include port number (e.g. "example.com:8080")
    # We strip the port with split(":")[0]
    hostname = (parsed.netloc or "").split(":")[0].lower()

    # Remove the "www." prefix for cleaner domain analysis
    hostname_clean = re.sub(r"^www\.", "", hostname)

    # ── Full URL string (lowercase for keyword search) ────────────────────────
    url_lower = cleaned_url.lower()

    # ─────────────────────────────────────────────────────────────────────────
    # FEATURE 1: Total URL length
    # Phishing URLs tend to be longer to hide the real domain
    # ─────────────────────────────────────────────────────────────────────────
    url_length = len(cleaned_url)

    # ─────────────────────────────────────────────────────────────────────────
    # FEATURE 2: Domain length
    # Attackers often use long domain names to confuse users
    # ─────────────────────────────────────────────────────────────────────────
    domain_length = len(hostname_clean)

    # ─────────────────────────────────────────────────────────────────────────
    # FEATURE 3: Number of dots in the full URL
    # Multiple dots may indicate deep subdomain nesting (e.g. paypal.evil.com.net)
    # ─────────────────────────────────────────────────────────────────────────
    num_dots = cleaned_url.count(".")

    # ─────────────────────────────────────────────────────────────────────────
    # FEATURE 4: Number of subdomains
    # Counted as: (number of dots in hostname) - 1
    # e.g. "a.b.evil.com" → 3 dots in hostname → 2 subdomains
    # ─────────────────────────────────────────────────────────────────────────
    hostname_parts = hostname_clean.split(".")
    num_subdomains = max(0, len(hostname_parts) - 2)

    # ─────────────────────────────────────────────────────────────────────────
    # FEATURE 5: Number of hyphens
    # Phishing domains often use hyphens to mimic brands: "pay-pal-login.com"
    # ─────────────────────────────────────────────────────────────────────────
    num_hyphens = cleaned_url.count("-")

    # ─────────────────────────────────────────────────────────────────────────
    # FEATURE 6: Number of underscores
    # Underscores are unusual in legitimate domains
    # ─────────────────────────────────────────────────────────────────────────
    num_underscores = cleaned_url.count("_")

    # ─────────────────────────────────────────────────────────────────────────
    # FEATURE 7: Number of digits
    # High digit counts can indicate random/generated domain names
    # ─────────────────────────────────────────────────────────────────────────
    num_digits = sum(1 for c in cleaned_url if c.isdigit())

    # ─────────────────────────────────────────────────────────────────────────
    # FEATURE 8: Presence of '@' symbol
    # Browser ignores everything before '@' in a URL:
    # http://paypal.com@evil.com  →  actually visits evil.com
    # ─────────────────────────────────────────────────────────────────────────
    has_at_symbol = 1 if "@" in cleaned_url else 0

    # ─────────────────────────────────────────────────────────────────────────
    # FEATURE 9: Double slash (//) after scheme
    # "http://legit.com//login" is suspicious — the extra slash is abnormal
    # ─────────────────────────────────────────────────────────────────────────
    # We check after the scheme ("http://") — position index 7 for http, 8 for https
    path_part = parsed.path + parsed.query
    has_double_slash = 1 if "//" in path_part else 0

    # ─────────────────────────────────────────────────────────────────────────
    # FEATURE 10: Presence of '='
    # Often appears in redirects: ?redirect=http://evil.com
    # ─────────────────────────────────────────────────────────────────────────
    has_equals = 1 if "=" in cleaned_url else 0

    # ─────────────────────────────────────────────────────────────────────────
    # FEATURE 11: Presence of '?'
    # Phishing pages often require query strings for credential harvesting
    # ─────────────────────────────────────────────────────────────────────────
    has_question_mark = 1 if "?" in cleaned_url else 0

    # ─────────────────────────────────────────────────────────────────────────
    # FEATURE 12: Presence of '%' (URL encoding)
    # Encoded characters like %20 %3D are used to obfuscate malicious content
    # ─────────────────────────────────────────────────────────────────────────
    has_percent = 1 if "%" in cleaned_url else 0

    # ─────────────────────────────────────────────────────────────────────────
    # FEATURE 13: IP address as hostname
    # Legitimate websites use domain names; attackers often use raw IP addresses
    # e.g. http://192.168.1.100/paypal/login
    # ─────────────────────────────────────────────────────────────────────────
    has_ip_address = 1 if IP_PATTERN.match(hostname) else 0

    # ─────────────────────────────────────────────────────────────────────────
    # FEATURE 14: Number of special characters
    # Counts characters in: ~!@#$%^&*()+=[]|{}<>?
    # ─────────────────────────────────────────────────────────────────────────
    num_special_chars = sum(1 for c in cleaned_url if c in SPECIAL_CHARS)

    # ─────────────────────────────────────────────────────────────────────────
    # FEATURE 15: HTTPS usage
    # HTTPS doesn't guarantee safety, but HTTP is a red flag
    # ─────────────────────────────────────────────────────────────────────────
    uses_https = 1 if scheme == "https" else 0

    # ─────────────────────────────────────────────────────────────────────────
    # FEATURE 16: Suspicious keyword count
    # Count how many phishing-related words appear anywhere in the URL
    # ─────────────────────────────────────────────────────────────────────────
    suspicious_keywords = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in url_lower)

    # ─────────────────────────────────────────────────────────────────────────
    # ASSEMBLE AND RETURN
    # ─────────────────────────────────────────────────────────────────────────
    return {
        "url_length":          url_length,
        "domain_length":       domain_length,
        "num_dots":            num_dots,
        "num_subdomains":      num_subdomains,
        "num_hyphens":         num_hyphens,
        "num_underscores":     num_underscores,
        "num_digits":          num_digits,
        "has_at_symbol":       has_at_symbol,
        "has_double_slash":    has_double_slash,
        "has_equals":          has_equals,
        "has_question_mark":   has_question_mark,
        "has_percent":         has_percent,
        "has_ip_address":      has_ip_address,
        "num_special_chars":   num_special_chars,
        "uses_https":          uses_https,
        "suspicious_keywords": suspicious_keywords,
    }


def get_feature_names() -> list:
    """Return the ordered list of feature names (matches the extract_features dict)."""
    return list(extract_features("http://example.com").keys())


# ──────────────────────────────────────────────────────────────────────────────
# QUICK DEMO (run this file directly to test)
# ──────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    test_urls = [
        "https://www.google.com/search?q=python",
        "http://paypal-secure-login.xyz/verify?account=123&token=abc",
        "http://192.168.1.100/bank/login.php",
        "https://amazon.com/order/history",
        "http://apple.com@evil-phishing.net/update",
    ]

    print(f"{'URL':<55} {'HTTPS':>5} {'LEN':>4} {'KWORDS':>6} {'IP':>2} {'@':>2}")
    print("-" * 80)
    for url in test_urls:
        f = extract_features(url)
        display = (url[:52] + "...") if len(url) > 55 else url
        print(f"{display:<55} {f['uses_https']:>5} {f['url_length']:>4} "
              f"{f['suspicious_keywords']:>6} {f['has_ip_address']:>2} {f['has_at_symbol']:>2}")
