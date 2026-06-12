"""
URL Feature Extractor — sec-toolkit
Extracts measurable characteristics from any URL string.
These features are then fed into the ML model for phishing detection.
"""

import re
import math
from urllib.parse import urlparse
import tldextract


# Suspicious words commonly found in phishing URLs
SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "secure", "account", "update",
    "confirm", "banking", "paypal", "ebay", "amazon", "apple",
    "microsoft", "google", "facebook", "password", "credential",
    "wallet", "bitcoin", "support", "alert", "suspended",
]

# URL shortener domains
URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly",
    "is.gd", "buff.ly", "adf.ly", "shorturl.at", "rebrand.ly",
]


def shannon_entropy(s: str) -> float:
    """
    Calculates Shannon entropy of a string.
    Random-looking strings (like phishing domains) have HIGH entropy.
    Real domain names have LOW entropy.
    """
    if not s:
        return 0.0
    prob = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in prob)


def has_ip_address(host: str) -> int:
    """Returns 1 if the host is an IP address instead of a domain name."""
    ip_pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
    return 1 if re.match(ip_pattern, host) else 0


def count_suspicious_words(url: str) -> int:
    """Counts how many suspicious phishing keywords appear in the URL."""
    url_lower = url.lower()
    return sum(1 for word in SUSPICIOUS_KEYWORDS if word in url_lower)


def is_shortened(host: str) -> int:
    """Returns 1 if the URL uses a known URL shortener."""
    return 1 if any(short in host for short in URL_SHORTENERS) else 0


def has_at_symbol(url: str) -> int:
    """The '@' symbol in URLs is a classic phishing trick."""
    return 1 if "@" in url else 0


def has_hyphen_in_domain(host: str) -> int:
    """Hyphens in domain names are more common in phishing (paypal-login.com)."""
    return 1 if "-" in host else 0


def extract_features(url: str) -> dict:
    """
    Extracts all features from a URL and returns them as a dictionary.
    These are the same features the ML model was trained on.
    """
    # Make sure URL has a scheme so urlparse works
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)
    host = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""

    # Extract domain parts cleanly using tldextract
    extracted = tldextract.extract(url)
    domain = extracted.domain
    subdomain = extracted.subdomain

    features = {
        # ── Length-based features ───────────────────────────────
        "url_length":       len(url),
        "host_length":      len(host),
        "path_length":      len(path),
        "query_length":     len(query),

        # ── Counting features ────────────────────────────────────
        "num_dots":         url.count("."),
        "num_hyphens":      url.count("-"),
        "num_slashes":      url.count("/"),
        "num_digits":       sum(c.isdigit() for c in url),
        "num_special":      sum(not c.isalnum() and c not in "./:?-=&" for c in url),
        "num_subdomains":   len(subdomain.split(".")) if subdomain else 0,
        "suspicious_words": count_suspicious_words(url),

        # ── Binary flags (0 or 1) ────────────────────────────────
        "has_ip":           has_ip_address(host),
        "has_at_symbol":    has_at_symbol(url),
        "has_https":        1 if parsed.scheme == "https" else 0,
        "has_hyphen_domain": has_hyphen_in_domain(host),
        "is_shortened":     is_shortened(host),

        # ── Statistical features ─────────────────────────────────
        "domain_entropy":   round(shannon_entropy(domain), 3),
        "url_entropy":      round(shannon_entropy(url), 3),
    }

    return features


# Quick test if you run this file directly
if __name__ == "__main__":
    test_urls = [
        "https://www.google.com",
        "http://paypa1-secure-login.com/verify-account",
        "http://192.168.1.5/login.php",
    ]
    for url in test_urls:
        print(f"\n{url}")
        for k, v in extract_features(url).items():
            print(f"  {k:20s} = {v}")