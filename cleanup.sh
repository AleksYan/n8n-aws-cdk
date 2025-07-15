#!/bin/bash

# Exit on error
set -e

echo "Cleaning up n8n AWS POC resources..."

# Activate virtual environment
cd cdk
source .venv/bin/activate

# Destroy the stack
cdk destroy --force

echo "Cleanup complete!"
