"""
URL Phishing Detector — sec-toolkit

Loads the trained ML model and predicts whether any URL is phishing.
Uses both ML prediction AND a rule-based safety check on known good domains
to reduce false positives.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

import argparse
import joblib
import pandas as pd
from pathlib import Path
from urllib.parse import urlparse
import tldextract

from utils import output as out
from tools.urldetect.features import (
    has_ip_address, is_shortened, count_suspicious_words,
)


HERE          = Path(__file__).parent
MODEL_FILE    = HERE / "models" / "phishing_model.joblib"
FEATURES_FILE = HERE / "models" / "feature_names.joblib"


# Well-known legitimate domains — used to override false positives.
# This is a small allow-list of brands a phishing detector should NEVER
# flag, since their real domains have known characteristics.
KNOWN_SAFE_DOMAINS = {
    "google.com", "youtube.com", "github.com", "microsoft.com",
    "apple.com", "amazon.com", "facebook.com", "twitter.com", "x.com",
    "linkedin.com", "wikipedia.org", "stackoverflow.com", "reddit.com",
    "instagram.com", "netflix.com", "spotify.com", "cloudflare.com",
    "mozilla.org", "ubuntu.com", "debian.org", "python.org",
    "openai.com", "anthropic.com", "claude.ai",
}


def extract_dataset_features(url: str) -> dict:
    """
    Extract the SAME features the model was trained on.
    Maps a raw URL string to the column names the dataset uses.
    """
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)
    host = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""

    extracted = tldextract.extract(url)
    domain = extracted.domain

    vowels = set("aeiouAEIOU")

    return {
        "qty_dot_url":          url.count("."),
        "qty_hyphen_url":       url.count("-"),
        "qty_slash_url":        url.count("/"),
        "qty_questionmark_url": url.count("?"),
        "qty_equal_url":        url.count("="),
        "qty_at_url":           url.count("@"),
        "qty_and_url":          url.count("&"),
        "qty_percent_url":      url.count("%"),
        "qty_tld_url":          1 if extracted.suffix else 0,
        "length_url":           len(url),
        "qty_dot_domain":       host.count("."),
        "qty_hyphen_domain":    host.count("-"),
        "qty_vowels_domain":    sum(1 for c in domain if c in vowels),
        "domain_length":        len(host),
        "domain_in_ip":         has_ip_address(host),
        "qty_dot_directory":    path.count("."),
        "directory_length":     len(path),
        "qty_params":           len(query.split("&")) if query else 0,
        "url_shortened":        is_shortened(host),
    }


def get_reasons(url: str, features: dict) -> list[str]:
    """Builds human-readable reasons explaining why a URL looks suspicious."""
    reasons = []

    if features["length_url"] > 75:
        reasons.append(f"URL is very long ({features['length_url']} chars)")
    if features["domain_in_ip"]:
        reasons.append("Uses an IP address instead of a domain name")
    if features["qty_at_url"] > 0:
        reasons.append("Contains '@' symbol (phishing trick)")
    if features["qty_hyphen_domain"] > 0:
        reasons.append("Contains hyphens in domain (paypal-login style)")
    if features["url_shortened"]:
        reasons.append("Uses a URL shortener (hides real destination)")
    if not url.startswith("https"):
        reasons.append("No HTTPS — connection is not encrypted")

    suspicious = count_suspicious_words(url)
    if suspicious > 0:
        reasons.append(f"Contains {suspicious} suspicious keyword(s) (login, verify, secure, etc.)")

    if features["qty_dot_domain"] > 3:
        reasons.append(f"Too many dots in domain ({features['qty_dot_domain']})")

    return reasons


def is_known_safe(url: str) -> bool:
    """Check if the URL's registered domain is on our allow-list."""
    extracted = tldextract.extract(url)
    registered_domain = f"{extracted.domain}.{extracted.suffix}".lower()
    return registered_domain in KNOWN_SAFE_DOMAINS


def predict(url: str):
    # ── Load model ──────────────────────────────────────────────────
    if not MODEL_FILE.exists():
        out.error("Model not found. Train it first with:")
        out.info("  python3 tools/urldetect/train.py")
        sys.exit(1)

    model = joblib.load(MODEL_FILE)
    feature_names = joblib.load(FEATURES_FILE)

    # ── Extract features ────────────────────────────────────────────
    features = extract_dataset_features(url)

    # Use a pandas DataFrame so sklearn keeps feature names (removes warning)
    feature_df = pd.DataFrame([features])[feature_names]

    # ── Predict ─────────────────────────────────────────────────────
    probability = model.predict_proba(feature_df)[0]
    phishing_prob = probability[1]
    score_pct = phishing_prob * 100

    # ── Get reasons & known-safe check ──────────────────────────────
    reasons = get_reasons(url, features)
    safe_domain = is_known_safe(url)

    # ── Combined verdict ────────────────────────────────────────────
    # Override ML if domain is a known brand. The ML model was trained on
    # ratios of phishing characteristics — short legit URLs can confuse it.
    if safe_domain:
        verdict = "SAFE"
        verdict_color = "success"
        score_msg = f"Known trusted domain ({(100-score_pct):.1f}% safe by model)"
    elif phishing_prob >= 0.85 and len(reasons) >= 2:
        verdict = "PHISHING"
        verdict_color = "danger"
        score_msg = f"{score_pct:.1f}% confidence"
    elif phishing_prob >= 0.60 or len(reasons) >= 3:
        verdict = "SUSPICIOUS"
        verdict_color = "warning"
        score_msg = f"{score_pct:.1f}% phishing probability"
    else:
        verdict = "SAFE"
        verdict_color = "success"
        score_msg = f"{(100-score_pct):.1f}% safe"

    # ── Display result ──────────────────────────────────────────────
    out.console.print()
    out.console.rule("[bold magenta]URL Analysis[/bold magenta]")
    out.console.print(f"\n  URL : [bold]{url}[/bold]\n")

    if verdict == "PHISHING":
        out.error(f"VERDICT: {verdict}  ({score_msg})")
    elif verdict == "SUSPICIOUS":
        out.warning(f"VERDICT: {verdict}  ({score_msg})")
    else:
        out.success(f"VERDICT: {verdict}  ({score_msg})")

    out.console.print()

    if reasons:
        out.info("Reasons:")
        for r in reasons:
            out.console.print(f"   • {r}")
    elif verdict == "SAFE":
        out.info("No red flags detected.")

    out.console.print()


def main():
    parser = argparse.ArgumentParser(
        prog="urldetect",
        description="sec-toolkit phishing URL detector using ML",
        epilog="Example: python3 urldetect.py --url https://paypa1-login.com"
    )
    parser.add_argument("--url", required=True, help="The URL to analyse")
    args = parser.parse_args()

    out.banner("Phishing URL Detector")
    predict(args.url)


if __name__ == "__main__":
    main()