#!/bin/bash

# DemoAnalyzer Launcher Script
set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

print_success() { echo -e "${GREEN}✅ $1${NC}"; }
print_warning() { echo -e "${YELLOW}⚠  $1${NC}"; }
print_error() { echo -e "${RED}❌ $1${NC}"; }

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    print_error "Virtual environment not found. Please run install.sh first."
    exit 1
fi

# Activate virtual environment
print_success "Activating virtual environment..."
source venv/bin/activate

# Check if main.py exists
if [ ! -f "main.py" ]; then
    print_error "main.py not found. Please check your installation."
    exit 1
fi

# Run the application
print_success "Starting ForensicsMainHand..."
python main.py 