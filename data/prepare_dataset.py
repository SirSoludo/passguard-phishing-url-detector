"""
prepare_dataset.py
==================
Final Year Project: Intelligent URL Phishing Detection System
Author: [Your Name]

PURPOSE:
    This script generates a labelled dataset of phishing and legitimate URLs
    for training our machine learning model.

    In a real-world project you would use publicly available datasets such as:
      - PhishTank (phishtank.org)
      - UCI Phishing Websites Dataset
      - OpenPhish

    Because we cannot download external files here, this script programmatically
    constructs a representative dataset that mirrors the statistical properties
    of real phishing / legitimate URL datasets.

    The generated CSV is saved to:  data/phishing_dataset.csv

LABELS:
    0 = Legitimate
    1 = Phishing
"""

import csv
import random
import re
import os

random.seed(42)   # Fix seed so the dataset is reproducible

# ──────────────────────────────────────────────────────────────────────────────
# SECTION A — URL BUILDING BLOCKS
# ──────────────────────────────────────────────────────────────────────────────

# Legitimate domains used in safe URLs
LEGIT_DOMAINS = [
    "google.com", "youtube.com", "facebook.com", "twitter.com",
    "wikipedia.org", "amazon.com", "linkedin.com", "github.com",
    "stackoverflow.com", "reddit.com", "microsoft.com", "apple.com",
    "bbc.co.uk", "cnn.com", "nytimes.com", "theguardian.com",
    "ubuntu.com", "python.org", "django-project.com", "flask.palletsprojects.com",
    "cloudflare.com", "stripe.com", "paypal.com", "shopify.com",
    "airbnb.com", "booking.com", "tripadvisor.com", "imdb.com",
    "netflix.com", "spotify.com"
]

LEGIT_PATHS = [
    "/", "/about", "/contact", "/products", "/services", "/blog",
    "/help", "/faq", "/support", "/pricing", "/features",
    "/news/latest", "/category/tech", "/user/profile", "/docs/guide"
]

# Keywords common in phishing URLs
PHISHING_KEYWORDS = [
    "login", "verify", "update", "secure", "account", "bank",
    "confirm", "signin", "password", "recover", "suspended",
    "unlock", "validate", "credential"
]

PHISHING_FAKE_DOMAINS = [
    "paypal-secure", "amazon-login", "apple-verify", "google-account",
    "facebook-update", "microsoft-secure", "bank-verify", "ebay-login",
    "netflix-account", "instagram-secure", "whatsapp-verify", "coinbase-login"
]

PHISHING_TLDS = [".com", ".net", ".org", ".info", ".biz", ".xyz", ".tk", ".ml", ".ga", ".cf"]

RANDOM_CHARS = "abcdefghijklmnopqrstuvwxyz0123456789"


# ──────────────────────────────────────────────────────────────────────────────
# SECTION B — URL GENERATORS
# ──────────────────────────────────────────────────────────────────────────────

def gen_legitimate_url():
    """
    Build a realistic-looking legitimate URL.
    These mimic real website structures: short domains, HTTPS, clean paths.
    """
    scheme = "https://"
    domain = random.choice(LEGIT_DOMAINS)
    path   = random.choice(LEGIT_PATHS)

    # Occasionally add a query parameter
    query = ""
    if random.random() < 0.25:
        param = random.choice(["id", "page", "q", "ref", "lang"])
        value = random.randint(1, 999)
        query = f"?{param}={value}"

    return scheme + domain + path + query


def gen_phishing_url():
    """
    Build a phishing-style URL with one or more red flags:
      - Suspicious keywords in path or domain
      - Long, obfuscated domain names
      - IP address instead of domain
      - HTTP (not HTTPS)
      - Excessive subdomains
      - @ symbol, //, %
    """
    strategy = random.randint(1, 6)

    if strategy == 1:
        # Brand impersonation: paypal-secure-login.xyz/verify?account=123
        brand = random.choice(PHISHING_FAKE_DOMAINS)
        tld   = random.choice(PHISHING_TLDS)
        kw    = random.choice(PHISHING_KEYWORDS)
        rand  = ''.join(random.choices(RANDOM_CHARS, k=random.randint(4, 8)))
        return f"http://{brand}{tld}/{kw}?id={rand}&token={''.join(random.choices(RANDOM_CHARS,k=16))}"

    elif strategy == 2:
        # IP address instead of domain name
        ip = f"{random.randint(1,254)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
        kw = random.choice(PHISHING_KEYWORDS)
        return f"http://{ip}/{kw}/{''.join(random.choices(RANDOM_CHARS,k=12))}.php"

    elif strategy == 3:
        # Legitimate brand as subdomain of attacker domain
        brand  = random.choice(["paypal","amazon","google","apple","facebook"])
        attack = ''.join(random.choices("abcdefghijklmnopqrstuvwxyz", k=random.randint(8,14)))
        tld    = random.choice(PHISHING_TLDS)
        kw     = random.choice(PHISHING_KEYWORDS)
        return f"http://{brand}.{attack}{tld}/{kw}"

    elif strategy == 4:
        # @ symbol trick: user@evil.com  (browser ignores everything before @)
        brand = random.choice(["paypal.com","amazon.com","google.com"])
        evil  = ''.join(random.choices("abcdefghijklmnopqrstuvwxyz", k=10))
        tld   = random.choice(PHISHING_TLDS)
        return f"http://{brand}@{evil}{tld}/login"

    elif strategy == 5:
        # Obfuscated URL with double slash and suspicious path
        evil = ''.join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789-", k=random.randint(12,20)))
        tld  = random.choice(PHISHING_TLDS)
        kw   = random.choice(PHISHING_KEYWORDS)
        return f"http://{evil}{tld}//{kw}/{''.join(random.choices(RANDOM_CHARS,k=8))}.html?redirect=http://evil.com"

    else:
        # Very long URL with encoded characters and multiple parameters
        evil = ''.join(random.choices("abcdefghijklmnopqrstuvwxyz-", k=random.randint(15,25)))
        tld  = random.choice(PHISHING_TLDS)
        kw   = random.choice(PHISHING_KEYWORDS)
        params = "&".join([f"{random.choice(['user','pass','token','id','ref','key'])}={''.join(random.choices(RANDOM_CHARS,k=8))}" for _ in range(random.randint(3,6))])
        encoded = "%20%3D%26" * random.randint(1, 3)
        return f"https://{evil}{tld}/{kw}/{encoded}?{params}"


# ──────────────────────────────────────────────────────────────────────────────
# SECTION C — GENERATE AND SAVE DATASET
# ──────────────────────────────────────────────────────────────────────────────

def build_dataset(n_legit=600, n_phishing=600):
    """
    Create a balanced dataset with n_legit + n_phishing rows.
    Each row: url, label  (0 = legitimate, 1 = phishing)
    """
    rows = []

    for _ in range(n_legit):
        rows.append({"url": gen_legitimate_url(), "label": 0})

    for _ in range(n_phishing):
        rows.append({"url": gen_phishing_url(), "label": 1})

    # Shuffle so legitimate and phishing are interleaved
    random.shuffle(rows)
    return rows


if __name__ == "__main__":
    out_dir = os.path.dirname(os.path.abspath(__file__))
    out_path = os.path.join(out_dir, "phishing_dataset.csv")

    dataset = build_dataset(n_legit=600, n_phishing=600)

    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["url", "label"])
        writer.writeheader()
        writer.writerows(dataset)

    total = len(dataset)
    legit = sum(1 for r in dataset if r["label"] == 0)
    phish = sum(1 for r in dataset if r["label"] == 1)

    print(f"Dataset saved → {out_path}")
    print(f"Total URLs : {total}")
    print(f"Legitimate : {legit}")
    print(f"Phishing   : {phish}")
