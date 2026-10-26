#!/bin/bash
echo ""
echo " =========================================="
echo "  PassGuard — Phishing Detection System"
echo "  Final Year Project"
echo " =========================================="
echo ""
echo " [1/3] Installing required packages..."
pip install flask flask-cors scikit-learn numpy joblib --quiet

echo " [2/3] Training the machine learning model..."
python3 data/prepare_dataset.py
python3 model/train_model.py

echo " [3/3] Starting web server..."
echo ""
echo " =========================================="
echo "  System is running!"
echo "  Open your browser and go to:"
echo "  http://127.0.0.1:5000"
echo " =========================================="
echo ""
python3 app.py
