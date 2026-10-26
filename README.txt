============================================================
  PassGuard — Intelligent URL Phishing Detection System
  Final Year Project | Computer Science
  AMAECHI KING DAVID | 2022/CSC/016
============================================================

HOW TO RUN (read this first):
─────────────────────────────

STEP 1: Install Python
  Download from: https://www.python.org/downloads/
  During install → CHECK THE BOX that says "Add Python to PATH"

STEP 2: Run the startup file
  On Windows:  Double-click  RUN_WINDOWS.bat
  On Mac/Linux: Open terminal, type:  bash RUN_MAC_LINUX.sh

STEP 3: Open your browser
  Go to:  http://127.0.0.1:5000
  The system will open and be ready to use.

STEP 4: Stop the server
  Press CTRL + C in the terminal/command window.

─────────────────────────────
WHAT THE STARTUP FILE DOES:
  1. Installs Flask, Scikit-learn, NumPy automatically
  2. Generates the 1,200-URL training dataset
  3. Trains the machine learning model (Random Forest)
  4. Starts the web server
  (This takes about 30 seconds on first run)

─────────────────────────────
FOLDER STRUCTURE:
  PassGuard/
  ├── app.py                    ← Flask backend (web server)
  ├── RUN_WINDOWS.bat           ← Double-click to start (Windows)
  ├── RUN_MAC_LINUX.sh          ← Run in terminal (Mac/Linux)
  ├── templates/
  │   └── index.html            ← The web interface
  ├── static/
  │   ├── css/style.css         ← Styling
  │   └── js/script.js          ← Frontend interactions
  ├── model/
  │   ├── feature_extraction.py ← Extracts 16 URL features
  │   ├── train_model.py        ← Trains the ML models
  │   └── evaluate_model.py     ← Generates evaluation report
  └── data/
      ├── prepare_dataset.py    ← Builds the training dataset
      └── phishing_dataset.csv  ← 1,200 labelled URLs (generated)

─────────────────────────────
IF SOMETHING GOES WRONG:
  Error: "python not found"
    → Reinstall Python and check "Add to PATH"

  Error: "No module named flask"
    → Open terminal in this folder, run:
      pip install flask flask-cors scikit-learn numpy joblib

  Error: "best_model.pkl not found"
    → Run: python data/prepare_dataset.py
    → Then: python model/train_model.py

  Browser shows "This site can't be reached"
    → Make sure the terminal is still open (don't close it)
    → Try: http://localhost:5000  instead

============================================================
