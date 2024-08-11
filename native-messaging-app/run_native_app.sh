#!/bin/bash

PYTHON_PATH=$(which python3)
SCRIPT_PATH="$(dirname "$0")/main.py"

# Run the Python script in the background, suppressing all output
nohup "$PYTHON_PATH" "$SCRIPT_PATH" > /dev/null 2>&1 &