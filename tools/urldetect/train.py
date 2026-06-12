"""
URL Phishing Model Trainer — sec-toolkit

Reads a labeled dataset of URLs, extracts features, trains a Random Forest
classifier, then saves the trained model to disk.

Run this ONCE before using urldetect.py. The model file will persist.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

import pandas as pd
import numpy as np
import joblib
from pathlib import Path
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

from utils import output as out


# ── File paths ─────────────────────────────────────────────────────────
HERE         = Path(__file__).parent
DATA_FILE    = HERE / "data" / "urls.csv"
MODEL_FILE   = HERE / "models" / "phishing_model.joblib"
FEATURES_FILE = HERE / "models" / "feature_names.joblib"


# Features we will use from the pre-featured dataset.
# These match what features.py can extract from any URL in real-time.
# We pick the URL-only features that don't require network calls
# (no WHOIS, no DNS, no TLS — those would be too slow at prediction time).
DATASET_FEATURES = [
    "qty_dot_url",          # number of dots
    "qty_hyphen_url",       # number of hyphens
    "qty_slash_url",        # number of slashes
    "qty_questionmark_url", # number of '?'
    "qty_equal_url",        # number of '='
    "qty_at_url",           # @ symbol count
    "qty_and_url",          # & count
    "qty_percent_url",      # URL-encoded chars
    "qty_tld_url",          # number of TLDs in URL
    "length_url",           # total URL length
    "qty_dot_domain",       # dots in domain
    "qty_hyphen_domain",    # hyphens in domain
    "qty_vowels_domain",    # vowel count in domain
    "domain_length",        # length of domain
    "domain_in_ip",         # is the domain an IP?
    "qty_dot_directory",    # dots in path
    "directory_length",     # path length
    "qty_params",           # number of query params
    "url_shortened",        # URL shortener?
]


def main():
    out.banner("URL Phishing — Model Trainer")

    # ── Step 1: Load the dataset ────────────────────────────────────
    if not DATA_FILE.exists():
        out.error(f"Dataset not found: {DATA_FILE}")
        out.info("Download with: wget https://raw.githubusercontent.com/GregaVrbancic/Phishing-Dataset/master/dataset_small.csv -O data/urls.csv")
        return

    out.info(f"Loading dataset from {DATA_FILE.name}...")
    df = pd.read_csv(DATA_FILE)
    out.success(f"Loaded {len(df):,} rows with {df.shape[1]} columns")

    # ── Step 2: Pick features + label ───────────────────────────────
    # 'phishing' column is the label: 1 = phishing, 0 = safe
    if "phishing" not in df.columns:
        out.error("Dataset missing 'phishing' label column")
        return

    X = df[DATASET_FEATURES]        # features
    y = df["phishing"]              # label

    safe_count     = (y == 0).sum()
    phishing_count = (y == 1).sum()
    out.info(f"Class distribution: {safe_count:,} safe, {phishing_count:,} phishing\n")

    # ── Step 3: Split into training and test sets ──────────────────
    # 80% to train, 20% to test the model on data it has never seen
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    out.info(f"Training set: {len(X_train):,} samples")
    out.info(f"Test set    : {len(X_test):,} samples\n")

    # ── Step 4: Train the Random Forest ─────────────────────────────
    out.info("Training Random Forest classifier...")
    model = RandomForestClassifier(
        n_estimators=100,    # 100 decision trees vote on each prediction
        max_depth=20,        # each tree can ask up to 20 questions
        random_state=42,
        n_jobs=-1,           # use all CPU cores
    )
    model.fit(X_train, y_train)
    out.success("Training complete!\n")

    # ── Step 5: Evaluate ────────────────────────────────────────────
    predictions = model.predict(X_test)
    accuracy    = accuracy_score(y_test, predictions)

    out.console.rule("[bold magenta]Model Evaluation[/bold magenta]")
    out.success(f"Accuracy: [bold]{accuracy*100:.2f}%[/bold]\n")

    out.info("Classification report:")
    print(classification_report(y_test, predictions, target_names=["Safe", "Phishing"]))

    out.info("Confusion matrix:")
    cm = confusion_matrix(y_test, predictions)
    print(f"                  Predicted Safe  Predicted Phishing")
    print(f"  Actual Safe      {cm[0][0]:>6}             {cm[0][1]:>6}")
    print(f"  Actual Phishing  {cm[1][0]:>6}             {cm[1][1]:>6}\n")

    # ── Step 6: Show which features matter most ─────────────────────
    importances = sorted(
        zip(DATASET_FEATURES, model.feature_importances_),
        key=lambda x: x[1], reverse=True,
    )
    out.info("Top 10 most important features:")
    for name, score in importances[:10]:
        bar = "█" * int(score * 200)
        out.console.print(f"   {name:25s} {bar} {score:.3f}")

    # ── Step 7: Save the model ──────────────────────────────────────
    MODEL_FILE.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, MODEL_FILE)
    joblib.dump(DATASET_FEATURES, FEATURES_FILE)
    out.console.print()
    out.success(f"Model saved → {MODEL_FILE}")
    out.success(f"Features saved → {FEATURES_FILE}")


if __name__ == "__main__":
    main()