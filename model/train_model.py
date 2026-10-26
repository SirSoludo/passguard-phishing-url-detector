"""
train_model.py
==============
Final Year Project: Intelligent URL Phishing Detection System

PURPOSE:
    This script:
      1. Loads the labelled dataset (CSV)
      2. Extracts features from each URL
      3. Trains three machine learning models
      4. Compares their performance
      5. Saves the best model to disk for use by the Flask server

MODELS COMPARED:
    - Logistic Regression   (linear, simple, interpretable)
    - Decision Tree         (rule-based, easy to visualize)
    - Random Forest         (ensemble of decision trees, usually highest accuracy)

OUTPUT FILES:
    model/best_model.pkl        — The trained ML model (serialized)
    model/feature_names.pkl     — Feature name list (for consistent ordering)
    model/label_encoder.pkl     — Label encoder (not needed here but good practice)

HOW TO RUN:
    python train_model.py
"""

import os
import csv
import joblib
import numpy as np
import sys

# Add parent so we can import feature_extraction
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from feature_extraction import extract_features, get_feature_names

from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, confusion_matrix, classification_report
)


# ──────────────────────────────────────────────────────────────────────────────
# STEP 1: LOAD DATASET
# ──────────────────────────────────────────────────────────────────────────────

def load_dataset(csv_path: str):
    """
    Read the CSV file and return (urls, labels) as parallel lists.

    CSV format expected:
        url,label
        https://google.com,0
        http://evil-login.xyz,1
    """
    urls   = []
    labels = []

    with open(csv_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            urls.append(row["url"])
            labels.append(int(row["label"]))

    print(f"Loaded {len(urls)} URLs  →  Legitimate: {labels.count(0)}  |  Phishing: {labels.count(1)}")
    return urls, labels


# ──────────────────────────────────────────────────────────────────────────────
# STEP 2: BUILD FEATURE MATRIX
# ──────────────────────────────────────────────────────────────────────────────

def build_feature_matrix(urls: list) -> np.ndarray:
    """
    Apply extract_features() to every URL and stack results into a 2D array.

    Each row = one URL
    Each column = one feature value

    Shape: (n_urls, 16)
    """
    feature_names = get_feature_names()
    rows = []

    for url in urls:
        features = extract_features(url)
        # Ensure consistent column order using feature_names
        row = [features[name] for name in feature_names]
        rows.append(row)

    return np.array(rows, dtype=float)


# ──────────────────────────────────────────────────────────────────────────────
# STEP 3: TRAIN AND EVALUATE MODELS
# ──────────────────────────────────────────────────────────────────────────────

def evaluate_model(model, X_test, y_test, model_name: str) -> dict:
    """
    Compute performance metrics for a trained model on the test set.

    Metrics:
      - Accuracy  = (TP + TN) / total
      - Precision = TP / (TP + FP)  → "when it says phishing, how often is it right?"
      - Recall    = TP / (TP + FN)  → "how many real phishing URLs did it catch?"
      - F1        = harmonic mean of Precision and Recall
    """
    y_pred = model.predict(X_test)

    acc  = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec  = recall_score(y_test, y_pred, zero_division=0)
    f1   = f1_score(y_test, y_pred, zero_division=0)
    cm   = confusion_matrix(y_test, y_pred)

    print(f"\n{'='*50}")
    print(f"  Model: {model_name}")
    print(f"{'='*50}")
    print(f"  Accuracy  : {acc:.4f}  ({acc*100:.2f}%)")
    print(f"  Precision : {prec:.4f}")
    print(f"  Recall    : {rec:.4f}")
    print(f"  F1 Score  : {f1:.4f}")
    print(f"\n  Confusion Matrix:")
    print(f"  {'':15} Predicted Legit  Predicted Phishing")
    print(f"  {'Actual Legit':15}      {cm[0][0]:<12}   {cm[0][1]}")
    print(f"  {'Actual Phish':15}      {cm[1][0]:<12}   {cm[1][1]}")
    print(f"\n  False Positive Rate: {cm[0][1]/(cm[0][0]+cm[0][1]):.4f}  (legit classified as phishing)")
    print(f"  False Negative Rate: {cm[1][0]/(cm[1][0]+cm[1][1]):.4f}  (phishing missed)")

    return {
        "name":      model_name,
        "model":     model,
        "accuracy":  acc,
        "precision": prec,
        "recall":    rec,
        "f1":        f1,
        "confusion": cm.tolist(),
    }


# ──────────────────────────────────────────────────────────────────────────────
# STEP 4: MAIN TRAINING PIPELINE
# ──────────────────────────────────────────────────────────────────────────────

def train(csv_path: str, out_dir: str):

    print("\n" + "="*60)
    print("  PHISHING DETECTION — MODEL TRAINING")
    print("="*60)

    # ── Load data ─────────────────────────────────────────────────
    urls, labels = load_dataset(csv_path)
    X = build_feature_matrix(urls)
    y = np.array(labels)
    print(f"\nFeature matrix shape: {X.shape}  (rows=URLs, cols=features)")

    # ── Train/Test Split ──────────────────────────────────────────
    # 80% training data, 20% held out for testing
    # stratify=y ensures both splits have the same phishing/legit ratio
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )
    print(f"Training set: {len(X_train)} URLs  |  Test set: {len(X_test)} URLs")

    # ── Define Models ─────────────────────────────────────────────
    # Each model is wrapped in a Pipeline with StandardScaler.
    # StandardScaler normalizes features to zero mean, unit variance.
    # This is required for Logistic Regression (but doesn't hurt tree models).

    models = {
        "Logistic Regression": Pipeline([
            ("scaler", StandardScaler()),
            ("clf",    LogisticRegression(max_iter=1000, random_state=42))
        ]),
        "Decision Tree": Pipeline([
            ("scaler", StandardScaler()),
            ("clf",    DecisionTreeClassifier(max_depth=10, random_state=42))
        ]),
        "Random Forest": Pipeline([
            ("scaler", StandardScaler()),
            ("clf",    RandomForestClassifier(
                n_estimators=100,    # 100 individual decision trees
                max_depth=12,
                random_state=42,
                n_jobs=-1            # use all CPU cores
            ))
        ]),
    }

    # ── Train and Evaluate Each Model ─────────────────────────────
    results = []
    for name, model in models.items():
        print(f"\nTraining: {name} ...")
        model.fit(X_train, y_train)

        # 5-fold cross-validation on the training set
        cv_scores = cross_val_score(model, X_train, y_train, cv=5, scoring="accuracy")
        print(f"  Cross-Val Accuracy: {cv_scores.mean():.4f} ± {cv_scores.std():.4f}")

        result = evaluate_model(model, X_test, y_test, name)
        results.append(result)

    # ── Select Best Model ─────────────────────────────────────────
    # We rank by F1 score (balances precision and recall)
    best = max(results, key=lambda r: r["f1"])

    print(f"\n\n{'='*60}")
    print(f"  BEST MODEL: {best['name']}")
    print(f"  Accuracy : {best['accuracy']*100:.2f}%")
    print(f"  F1 Score : {best['f1']:.4f}")
    print(f"{'='*60}")

    # ── Feature Importance (Random Forest only) ───────────────────
    if best["name"] == "Random Forest":
        clf = best["model"].named_steps["clf"]
        feature_names = get_feature_names()
        importances = clf.feature_importances_
        sorted_idx  = np.argsort(importances)[::-1]

        print("\n  Feature Importances (top 16):")
        for rank, idx in enumerate(sorted_idx, 1):
            print(f"  {rank:>2}. {feature_names[idx]:<25} {importances[idx]:.4f}")

    # ── Save Artefacts ────────────────────────────────────────────
    os.makedirs(out_dir, exist_ok=True)

    model_path   = os.path.join(out_dir, "best_model.pkl")
    names_path   = os.path.join(out_dir, "feature_names.pkl")
    metrics_path = os.path.join(out_dir, "metrics.pkl")

    joblib.dump(best["model"],   model_path)
    joblib.dump(get_feature_names(), names_path)
    joblib.dump({
        "best_name": best["name"],
        "accuracy":  best["accuracy"],
        "precision": best["precision"],
        "recall":    best["recall"],
        "f1":        best["f1"],
        "confusion": best["confusion"],
        "all_results": [
            {k: v for k, v in r.items() if k != "model"}
            for r in results
        ]
    }, metrics_path)

    print(f"\nSaved model    → {model_path}")
    print(f"Saved features → {names_path}")
    print(f"Saved metrics  → {metrics_path}")
    print("\nTraining complete!")

    return best


# ──────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ──────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    base_dir    = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    csv_path    = os.path.join(base_dir, "data", "phishing_dataset.csv")
    out_dir     = os.path.dirname(os.path.abspath(__file__))

    if not os.path.exists(csv_path):
        print(f"Dataset not found at {csv_path}")
        print("Run:  python data/prepare_dataset.py  first.")
    else:
        train(csv_path, out_dir)
