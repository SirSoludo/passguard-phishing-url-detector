@echo off
title PassGuard — Phishing Detection System
color 0A
echo.
echo  ==========================================
echo   PassGuard — Phishing Detection System
echo   Final Year Project
echo  ==========================================
echo.

:: Check Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo  ERROR: Python is not installed or not in PATH.
    echo  Please install Python from https://www.python.org/downloads/
    echo  Make sure to check "Add Python to PATH" during installation.
    pause
    exit /b
)

echo  [1/3] Installing required packages...
pip install flask flask-cors scikit-learn numpy joblib --quiet

echo  [2/3] Training the machine learning model...
python data\prepare_dataset.py
python model\train_model.py

echo  [3/3] Starting web server...
echo.
echo  ==========================================
echo   System is running!
echo   Open your browser and go to:
echo   http://127.0.0.1:5000
echo  ==========================================
echo.
echo  Press CTRL+C to stop the server.
echo.
python app.py
pause
