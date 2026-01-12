#!/bin/bash
# Single startup script for WiFi IDPS

set -e

echo "=========================================="
echo "WiFi IDPS - Starting System"
echo "=========================================="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "⚠️  This script requires root privileges for WiFi operations"
    echo "   Running with sudo..."
    exec sudo "$0" "$@"
fi

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 not found. Please install Python 3."
    exit 1
fi

echo "✓ Python found: $(python3 --version)"
echo ""

# Setup virtual environment if needed
if [ ! -d "venv" ] || [ ! -f "venv/bin/activate" ]; then
    echo "📦 Creating virtual environment..."
    # Remove incomplete venv if it exists
    [ -d "venv" ] && rm -rf venv
    
    # Use --copies to avoid symlink issues in shared folders (VirtualBox)
    if ! python3 -m venv --copies venv; then
        echo "❌ Failed to create virtual environment"
        echo "   Try: sudo apt install python3-venv"
        exit 1
    fi
    
    # Verify venv was created
    if [ ! -f "venv/bin/activate" ]; then
        echo "❌ Virtual environment creation incomplete"
        echo "   venv/bin/activate not found"
        exit 1
    fi
    
    echo "✓ Virtual environment created"
fi

# Activate virtual environment
echo "🔌 Activating virtual environment..."
source venv/bin/activate

if [ -z "$VIRTUAL_ENV" ]; then
    echo "❌ Failed to activate virtual environment"
    exit 1
fi

# Upgrade pip
echo "⬆️  Upgrading pip..."
pip install --upgrade pip --quiet

# Install dependencies if needed
if [ ! -f "venv/.deps_installed" ]; then
    echo "📥 Installing dependencies..."
    pip install -r requirements.txt --quiet
    touch venv/.deps_installed
    echo "✓ Dependencies installed"
else
    echo "✓ Dependencies already installed"
fi

# Create necessary directories
mkdir -p logs templates static

echo ""
echo "=========================================="
echo "🚀 Starting WiFi IDPS..."
echo "=========================================="
echo ""
echo "📡 Dashboard will be available at:"
echo "   http://localhost:5000"
echo ""
echo "💡 You can select adapters in the web UI"
echo "   No need to specify interface on startup"
echo ""
echo "Press Ctrl+C to stop"
echo "=========================================="
echo ""

# Start the application (no interface needed - select in UI)
exec venv/bin/python app.py
