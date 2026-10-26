"""
evaluate_model.py
=================
Final Year Project: Intelligent URL Phishing Detection System

PURPOSE:
    This script loads the saved trained model and generates a detailed
    evaluation report, including:
      - Accuracy, Precision, Recall, F1
      - Confusion Matrix
      - Per-class classification report
      - Model comparison table
      - Sample predictions on new URLs

    Run this AFTER train_model.py has been executed.

HOW TO RUN:
    python evaluate_model.py
"""

import os
import sys
import joblib
import numpy as np
import csv

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from feature_extraction import extract_features, get_feature_names

from sklearn.metrics import classification_report


# ──────────────────────────────────────────────────────────────────────────────
# HELPER: PRINT A FRAMED SECTION HEADER
# ──────────────────────────────────────────────────────────────────────────────

def header(title: str):
    width = 60
    print("\n" + "═" * width)
    print(f"  {title}")
    print("═" * width)


# ──────────────────────────────────────────────────────────────────────────────
# HELPER: DRAW CONFUSION MATRIX IN TEXT
# ──────────────────────────────────────────────────────────────────────────────

def print_confusion_matrix(cm: list):
    """
    Pretty-prints the 2×2 confusion matrix.

    Layout:
                        PREDICTED
                      Legit   Phishing
    ACTUAL  Legit   [  TN  ] [  FP  ]
            Phish   [  FN  ] [  TP  ]

    TN = True Negatives  (correctly identified legitimate)
    FP = False Positives (legitimate wrongly flagged as phishing)
    FN = False Negatives (phishing that slipped through as legitimate)
    TP = True Positives  (correctly identified phishing)
    """
    tn, fp, fn, tp = cm[0][0], cm[0][1], cm[1][0], cm[1][1]

    print()
    print("                   ┌─────────────────────────────────┐")
    print("                   │         PREDICTED LABEL         │")
    print("                   ├────────────────┬────────────────┤")
    print("                   │   Legitimate   │    Phishing    │")
    print("  ┌────────────────┼────────────────┼────────────────┤")
    print(f"  │  Legitimate   │  TN = {tn:>5}    │  FP = {fp:>5}    │  ← False Positives (bad)")
    print("  ├────────────────┼────────────────┼────────────────┤")
    print(f"  │  Phishing     │  FN = {fn:>5}    │  TP = {tp:>5}    │  ← False Negatives (dangerous!)")
    print("  └────────────────┴────────────────┴────────────────┘")
    print()
    total = tn + fp + fn + tp
    print(f"  Correct predictions : {tn+tp} / {total}  ({(tn+tp)/total*100:.1f}%)")
    print(f"  False Positive Rate : {fp/(tn+fp)*100:.1f}%  (legitimate URLs flagged)")
    print(f"  False Negative Rate : {fn/(fn+tp)*100:.1f}%  (phishing URLs missed)")


# ──────────────────────────────────────────────────────────────────────────────
# SAMPLE PREDICTION DEMO
# ──────────────────────────────────────────────────────────────────────────────

DEMO_URLS = [
    # Legitimate
    ("https://www.google.com/search?q=weather",             0),
    ("https://github.com/user/repository",                  0),
    ("https://stackoverflow.com/questions/12345",           0),
    ("https://www.amazon.com/dp/B08N5WRWNW",                0),
    ("https://en.wikipedia.org/wiki/Machine_learning",      0),
    # Phishing
    ("http://paypal-secure-verify.xyz/login?id=abc123",     1),
    ("http://192.168.1.100/bank/account/update.php",        1),
    ("http://amazon.com@evil-phishing.net/update",          1),
    ("http://google-account-verify.info/signin?token=xyz",  1),
    ("http://apple-id-suspended.com//verify%20account",     1),
]


def demo_predictions(model, feature_names: list):
    header("SAMPLE PREDICTIONS ON NEW URLS")
    print(f"  {'URL':<55} {'ACTUAL':>10} {'PRED':>10} {'CONFIDENCE':>12}")
    print("  " + "-"*90)

    correct = 0
    for url, true_label in DEMO_URLS:
        features_dict = extract_features(url)
        X_row = np.array([[features_dict[f] for f in feature_names]])

        pred_label = model.predict(X_row)[0]
        # predict_proba gives [prob_legit, prob_phishing]
        proba = model.predict_proba(X_row)[0]
        confidence = proba[pred_label] * 100

        actual_str = "Phishing" if true_label == 1 else "Legitimate"
        pred_str   = "Phishing" if pred_label == 1 else "Legitimate"
        match      = "✓" if pred_label == true_label else "✗"

        display_url = (url[:52] + "...") if len(url) > 55 else url
        print(f"  {match} {display_url:<55} {actual_str:>10} {pred_str:>10} {confidence:>10.1f}%")
        if pred_label == true_label:
            correct += 1

    print(f"\n  Demo accuracy: {correct}/{len(DEMO_URLS)} = {correct/len(DEMO_URLS)*100:.0f}%")


# ──────────────────────────────────────────────────────────────────────────────
# MAIN EVALUATION
# ──────────────────────────────────────────────────────────────────────────────

def run_evaluation():
    model_dir  = os.path.dirname(os.path.abspath(__file__))
    model_path   = os.path.join(model_dir, "best_model.pkl")
    metrics_path = os.path.join(model_dir, "metrics.pkl")
    names_path   = os.path.join(model_dir, "feature_names.pkl")

    # ── Load artefacts ─────────────────────────────────────────────
    if not all(os.path.exists(p) for p in [model_path, metrics_path, names_path]):
        print("ERROR: Trained model files not found.")
        print("Run:  python model/train_model.py  first.")
        return

    model         = joblib.load(model_path)
    metrics       = joblib.load(metrics_path)
    feature_names = joblib.load(names_path)

    # ── Project Header ─────────────────────────────────────────────
    print("\n" + "█"*60)
    print("█  PHISHING DETECTION SYSTEM — EVALUATION REPORT         █")
    print("█  Final Year Project  |  Department of Computer Science  █")
    print("█"*60)

    # ── Best Model Summary ─────────────────────────────────────────
    header(f"BEST MODEL: {metrics['best_name']}")
    print(f"  Accuracy  : {metrics['accuracy']*100:.2f}%")
    print(f"  Precision : {metrics['precision']:.4f}")
    print(f"  Recall    : {metrics['recall']:.4f}")
    print(f"  F1 Score  : {metrics['f1']:.4f}")

    # ── Model Comparison Table ─────────────────────────────────────
    header("MODEL COMPARISON TABLE")
    print(f"  {'Model':<22} {'Accuracy':>10} {'Precision':>10} {'Recall':>8} {'F1':>8}")
    print("  " + "-"*62)
    for r in metrics["all_results"]:
        marker = " ◄ BEST" if r["name"] == metrics["best_name"] else ""
        print(f"  {r['name']:<22} {r['accuracy']*100:>9.2f}% {r['precision']:>10.4f} "
              f"{r['recall']:>8.4f} {r['f1']:>8.4f}{marker}")

    # ── Confusion Matrix ───────────────────────────────────────────
    header("CONFUSION MATRIX")
    print_confusion_matrix(metrics["confusion"])

    # ── Feature List ───────────────────────────────────────────────
    header("EXTRACTED FEATURES (16 LEXICAL FEATURES)")
    for i, name in enumerate(feature_names, 1):
        print(f"  {i:>2}. {name}")

    # ── Demo Predictions ───────────────────────────────────────────
    demo_predictions(model, feature_names)

    print("\n\n  Evaluation complete.\n")


if __name__ == "__main__":
    run_evaluation()
