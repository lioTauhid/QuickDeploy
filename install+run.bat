@echo off
REM Cross-platform installation and run script for QuickDeploy on Windows

setlocal enabledelayedexpansion

echo ================================
echo QuickDeploy - Installation Script (Windows)
echo ================================

REM Create a virtual environment if it doesn't exist
if not exist ".venv" (
    echo Creating virtual environment...
    python -m venv .venv
)

REM Activate the virtual environment
echo Activating virtual environment...
call .venv\Scripts\activate.bat

REM Install dependencies from requirements.txt if available
if exist "requirements.txt" (
    echo Installing dependencies from requirements.txt...
    pip install -r requirements.txt
) else (
    echo No requirements.txt found. Skipping dependency installation.
)

REM Run app
if exist "app.py" (
    echo Starting QuickDeploy application...
    python app.py
) else (
    echo app.py not found. Exiting.
    exit /b 1
)

endlocal
