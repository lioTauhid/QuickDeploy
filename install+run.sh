#!/bin/bash

# Create a virtual environment if it doesn't exist
if [ ! -d ".venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv .venv/
fi

# Activate the virtual environment
echo "Activating virtual environment..."
source .venv/bin/activate

# Install dependencies from requirements.txt if available
if [ -f "requirements.txt" ]; then
    echo "Installing dependencies from requirements.txt..."
    pip install -r requirements.txt
else
    echo "No requirements.txt found. Skipping dependency installation."
fi

# Run app in the background
if [ -f "deployment_app.py" ]; then
    echo "Running deployment_app.py in the background..."
    python deployment_app.py # Run the Python app in the background
else
    echo "deployment_app.py not found. Exiting."
    exit 1
fi