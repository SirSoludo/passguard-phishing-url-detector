"""
app.py
======
Final Year Project: Intelligent URL Phishing Detection System

PURPOSE:
    This is the Flask web server — it acts as the bridge between the
    HTML/JS frontend and the trained machine learning model.

    It exposes three API endpoints:
      GET  /            → Serve the main HTML page
      POST /analyze     → Accept a URL, extract features, return prediction
      GET  /stats       → Return detection statistics (admin dashboard)
      GET  /metrics     → Return model evaluation metrics

HOW TO RUN:
    python app.py

    Then open your browser and go to:  http://127.0.0.1:5000
"""

import os
import sys
import json
import joblib
import numpy as np
from datetime import datetime
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS

# Allow importing from the model/ subdirectory
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "model"))
from feature_extraction import extract_features, get_feature_names

# ──────────────────────────────────────────────────────────────────────────────
# APP SETUP
# ──────────────────────────────────────────────────────────────────────────────

app = Flask(__name__)
CORS(app)   # Allow cross-origin requests (useful during development)

# ──────────────────────────────────────────────────────────────────────────────
# LOAD MODEL ARTEFACTS
# ──────────────────────────────────────────────────────────────────────────────

MODEL_DIR   = os.path.join(os.path.dirname(__file__), "model")
model       = joblib.load(os.path.join(MODEL_DIR, "best_model.pkl"))
feat_names  = joblib.load(os.path.join(MODEL_DIR, "feature_names.pkl"))
saved_metrics = joblib.load(os.path.join(MODEL_DIR, "metrics.pkl"))

print(f"[PassGuard] Model loaded: {saved_metrics['best_name']}")
print(f"[PassGuard] Accuracy: {saved_metrics['accuracy']*100:.2f}%")

# ──────────────────────────────────────────────────────────────────────────────
# IN-MEMORY STATISTICS TRACKER
# ──────────────────────────────────────────────────────────────────────────────
# In a real system, this would be stored in a database (e.g. SQLite, MySQL)

stats = {
    "total":      0,
    "legitimate": 0,
    "suspicious": 0,
    "phishing":   0,
    "history":    []      # List of last 20 analyzed URLs
}


# ──────────────────────────────────────────────────────────────────────────────
# HELPER: CLASSIFY CONFIDENCE INTO RISK LEVEL
# ──────────────────────────────────────────────────────────────────────────────

def get_risk_label(pred_class: int, confidence: float) -> dict:
    """
    Convert model output into a three-tier risk label:
      - Legitimate  (class 0, high confidence)
      - Suspicious  (class 1, low-medium confidence)
      - Phishing    (class 1, high confidence)

    This gives users a more nuanced result than a binary safe/unsafe.

    Parameters
    ----------
    pred_class  : int    — 0=legitimate, 1=phishing (from model.predict)
    confidence  : float  — probability of the predicted class (0.0 – 1.0)

    Returns
    -------
    dict with keys: level, label, color, icon, recommendation
    """
    if pred_class == 0:
        # Model says legitimate
        if confidence >= 0.80:
            return {
                "level":          "safe",
                "label":          "Legitimate",
                "color":          "#39d353",
                "icon":           "shield-check",
                "recommendation": "This URL appears safe. The domain is clean and follows legitimate URL patterns."
            }
        else:
            # Low confidence legitimate → treat as suspicious
            return {
                "level":          "suspicious",
                "label":          "Suspicious",
                "color":          "#f0d000",
                "icon":           "alert-triangle",
                "recommendation": "The model is uncertain about this URL. Proceed with caution and verify the source."
            }
    else:
        # Model says phishing
        if confidence >= 0.75:
            return {
                "level":          "phishing",
                "label":          "Phishing",
                "color":          "#ff3b3b",
                "icon":           "x-octagon",
                "recommendation": "HIGH RISK — Do NOT visit this URL. It exhibits multiple phishing indicators. Report it to your IT team or phishtank.org."
            }
        else:
            return {
                "level":          "suspicious",
                "label":          "Suspicious",
                "color":          "#f0d000",
                "icon":           "alert-triangle",
                "recommendation": "This URL has some suspicious characteristics. Avoid entering credentials and verify through official channels."
            }


# ──────────────────────────────────────────────────────────────────────────────
# ROUTE 1 — SERVE MAIN PAGE
# ──────────────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    """Serve the main HTML interface."""
    return render_template("index.html")


# ──────────────────────────────────────────────────────────────────────────────
# ROUTE 2 — ANALYZE A URL
# ──────────────────────────────────────────────────────────────────────────────

@app.route("/analyze", methods=["POST"])
def analyze():
    """
    Accept a URL via POST request, extract features, run ML prediction.

    Request body (JSON):
        { "url": "https://example.com/login" }

    Response (JSON):
        {
            "url":        "...",
            "risk":       { "level": "phishing", "label": "Phishing", ... },
            "confidence": 98.5,
            "features":   { "url_length": 45, ... },
            "timestamp":  "2024-01-15 14:30:22"
        }
    """
    # ── Parse request ─────────────────────────────────────────────
    data = request.get_json()
    if not data or "url" not in data:
        return jsonify({"error": "No URL provided"}), 400

    url = data["url"].strip()
    if not url:
        return jsonify({"error": "URL is empty"}), 400

    # ── Feature extraction ────────────────────────────────────────
    features_dict = extract_features(url)

    # Build feature vector in the correct column order
    X = np.array([[features_dict[f] for f in feat_names]])

    # ── Model prediction ──────────────────────────────────────────
    pred_class = int(model.predict(X)[0])              # 0 or 1
    proba      = model.predict_proba(X)[0]             # [p_legit, p_phishing]
    confidence = float(proba[pred_class]) * 100        # as percentage

    # ── Risk classification ───────────────────────────────────────
    risk = get_risk_label(pred_class, float(proba[pred_class]))

    # ── Update stats ──────────────────────────────────────────────
    stats["total"] += 1
    if risk["level"] == "safe":
        stats["legitimate"] += 1
    elif risk["level"] == "suspicious":
        stats["suspicious"] += 1
    else:
        stats["phishing"] += 1

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Keep rolling history of last 20 URLs
    stats["history"].insert(0, {
        "url":       url[:80] + ("..." if len(url) > 80 else ""),
        "result":    risk["label"],
        "level":     risk["level"],
        "timestamp": timestamp
    })
    stats["history"] = stats["history"][:20]

    # ── Build response ────────────────────────────────────────────
    return jsonify({
        "url":        url,
        "risk":       risk,
        "confidence": round(confidence, 2),
        "pred_class": pred_class,
        "proba": {
            "legitimate": round(float(proba[0]) * 100, 2),
            "phishing":   round(float(proba[1]) * 100, 2),
        },
        "features":  features_dict,
        "timestamp": timestamp
    })


# ──────────────────────────────────────────────────────────────────────────────
# ROUTE 3 — ADMIN STATISTICS
# ──────────────────────────────────────────────────────────────────────────────

@app.route("/stats")
def get_stats():
    """
    Return detection statistics for the admin dashboard.

    Response (JSON):
        {
            "total": 45,
            "legitimate": 30,
            "suspicious": 5,
            "phishing": 10,
            "history": [...]
        }
    """
    total = stats["total"]
    return jsonify({
        "total":        total,
        "legitimate":   stats["legitimate"],
        "suspicious":   stats["suspicious"],
        "phishing":     stats["phishing"],
        "legit_pct":    round(stats["legitimate"] / total * 100, 1) if total > 0 else 0,
        "phishing_pct": round(stats["phishing"]   / total * 100, 1) if total > 0 else 0,
        "history":      stats["history"]
    })


# ──────────────────────────────────────────────────────────────────────────────
# ROUTE 4 — MODEL METRICS
# ──────────────────────────────────────────────────────────────────────────────

@app.route("/metrics")
def get_metrics():
    """
    Return the saved model evaluation metrics.
    Used to populate the Model Performance section of the dashboard.
    """
    return jsonify({
        "best_model": saved_metrics["best_name"],
        "accuracy":   round(saved_metrics["accuracy"] * 100, 2),
        "precision":  round(saved_metrics["precision"] * 100, 2),
        "recall":     round(saved_metrics["recall"] * 100, 2),
        "f1_score":   round(saved_metrics["f1"] * 100, 2),
        "confusion":  saved_metrics["confusion"],
        "all_models": [
            {
                "name":      r["name"],
                "accuracy":  round(r["accuracy"] * 100, 2),
                "precision": round(r["precision"] * 100, 2),
                "recall":    round(r["recall"] * 100, 2),
                "f1":        round(r["f1"] * 100, 2),
            }
            for r in saved_metrics["all_results"]
        ]
    })


# ──────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ──────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("\n" + "="*50)
    print("  PassGuard — Phishing Detection System")
    print("  Final Year Project")
    print("="*50)
    print("  Open your browser:  http://127.0.0.1:5000")
    print("="*50 + "\n")
    app.run(debug=True, host="0.0.0.0", port=5000)
