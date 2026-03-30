#!/bin/bash

# Detect OS
if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "win32" ]]; then
    OS="windows"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macos"
else
    OS="linux"
fi

echo "Detected OS: $OS"
cd ..

# Create a virtual environment if it doesn't exist
if [ ! -d ".venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv .venv/
fi

# Activate the virtual environment
echo "Activating virtual environment..."
if [[ "$OS" == "windows" ]]; then
    source .venv/Scripts/activate
else
    source .venv/bin/activate
fi

# Install dependencies from requirements.txt if available
if [ -f "requirements.txt" ]; then
    echo "Installing dependencies from requirements.txt..."
    pip install -r requirements.txt
else
    echo "No requirements.txt found. Skipping dependency installation."
fi

# Build app binary
pip install pyinstaller
if [ -f "app.py" ]; then
    echo "Starting QuickDeploy application binary..."
    pyinstaller scripts/quickdeploy.spec --clean
else
    echo "app.py not found. Exiting."
    exit 1
fi
