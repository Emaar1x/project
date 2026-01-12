#!/bin/bash
# Setup script for WiFi IDPS

echo "WiFi IDPS Setup Script"
echo "======================"
echo ""

# Check Python version
echo "Checking Python version..."
python3 --version

# Check if venv module is available
if ! python3 -m venv --help > /dev/null 2>&1; then
    echo "Error: python3-venv is not installed"
    echo "Installing python3-venv..."
    sudo apt update
    sudo apt install -y python3-venv
fi

# Create virtual environment
echo ""
echo "Creating virtual environment..."
# Use --copies to avoid symlink issues in shared folders (VirtualBox)
python3 -m venv --copies venv

# Activate virtual environment
echo ""
echo "Activating virtual environment..."
source venv/bin/activate

# Upgrade pip
echo ""
echo "Upgrading pip..."
pip install --upgrade pip

# Install Python dependencies
echo ""
echo "Installing Python dependencies..."
pip install -r requirements.txt

# Create necessary directories
echo ""
echo "Creating directories..."
mkdir -p logs
mkdir -p templates
mkdir -p static

# Check for monitor mode interface
echo ""
echo "Checking for WiFi interfaces..."
iwconfig 2>/dev/null | grep -i "wlan\|wifi" || echo "No WiFi interfaces found (this is OK if not set up yet)"

echo ""
echo "Setup complete!"
echo ""
echo "To start the system, simply run:"
echo "  sudo ./start.sh"
echo ""
echo "The web dashboard will be available at:"
echo "  http://localhost:5000"
echo ""
echo "You can select adapters and start monitoring from the web UI."

