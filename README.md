# PassGuard: Phishing URL Detection System

A web app that checks whether a URL is likely to be a phishing link. It extracts 16 features from the URL (length, special characters, suspicious keywords, domain structure and more) and classifies it with a trained machine-learning model (Random Forest, scikit-learn). Built with Python and Flask.

## Quick start

**Windows:** double-click `RUN_WINDOWS.bat`
**Mac/Linux:** `bash RUN_MAC_LINUX.sh`

Then open http://127.0.0.1:5000. The startup script installs the packages, builds the dataset, trains the model and starts the server (about 30 seconds on first run).

Manual setup:

```bash
pip install flask flask-cors scikit-learn numpy joblib
python data/prepare_dataset.py
python model/train_model.py
python app.py
```

## Project files

| Path | What it does |
|---|---|
| `app.py` | Flask server. Routes: `/` (UI), `/analyze` (classify a URL), `/stats`, `/metrics` |
| `templates/index.html` | The web interface |
| `static/css/style.css`, `static/js/script.js` | Styling and frontend logic |
| `model/feature_extraction.py` | Turns a URL into the 16 numeric features the model uses |
| `model/train_model.py` | Trains and compares models, saves the best one |
| `model/evaluate_model.py` | Prints an evaluation report (accuracy, precision, recall, test URLs) |
| `model/best_model.pkl`, `feature_names.pkl`, `metrics.pkl` | Saved trained model, feature list and metrics |
| `data/prepare_dataset.py` | Generates the labelled training dataset |
| `data/phishing_dataset.csv` | 1,200 labelled URLs (legitimate / phishing) |
| `RUN_WINDOWS.bat`, `RUN_MAC_LINUX.sh` | One-click setup and launch scripts |
| `README.txt` | Original step-by-step guide with troubleshooting |
