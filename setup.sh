#!/bin/bash
# Liffy Ultimate Unified - Setup Script
# Complete LFI Exploitation & Vulnerability Testing Tool

set -e

echo "🚀 Liffy Ultimate Unified - Setup Script"
echo "========================================"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo -e "${BLUE}$1${NC}"
}

# Check if running as root
if [[ $EUID -eq 0 ]]; then
    print_warning "This script should not be run as root for security reasons"
    read -p "Continue anyway? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Check Python version
print_header "Checking Python version..."
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
    print_status "Python $PYTHON_VERSION found"
    
    # Check if version is 3.8 or higher
    if python3 -c 'import sys; exit(0 if sys.version_info >= (3, 8) else 1)'; then
        print_status "Python version is compatible"
    else
        print_error "Python 3.8 or higher is required"
        exit 1
    fi
else
    print_error "Python 3 is not installed"
    exit 1
fi

# Check Go installation
print_header "Checking Go installation..."
if command -v go &> /dev/null; then
    GO_VERSION=$(go version | cut -d' ' -f3)
    print_status "Go $GO_VERSION found"
else
    print_error "Go is not installed. Please install Go first:"
    echo "  - Visit: https://golang.org/dl/"
    echo "  - Or use package manager: apt install golang-go"
    exit 1
fi

# Check if GOPATH is set
if [ -z "$GOPATH" ]; then
    print_warning "GOPATH is not set. Setting default GOPATH..."
    export GOPATH="$HOME/go"
    echo 'export GOPATH="$HOME/go"' >> ~/.bashrc
    echo 'export PATH="$GOPATH/bin:$PATH"' >> ~/.bashrc
    print_status "GOPATH set to $GOPATH"
fi

# Add GOPATH/bin to PATH if not already there
if [[ ":$PATH:" != *":$GOPATH/bin:"* ]]; then
    export PATH="$GOPATH/bin:$PATH"
    echo 'export PATH="$GOPATH/bin:$PATH"' >> ~/.bashrc
    print_status "Added $GOPATH/bin to PATH"
fi

# Install Python dependencies
print_header "Installing Python dependencies..."
if [ -f "requirements.txt" ]; then
    pip3 install -r requirements.txt
    print_status "Python dependencies installed"
else
    print_warning "requirements.txt not found, installing basic dependencies..."
    pip3 install requests urllib3 blessings colorama tqdm rich
fi

# Install Go tools
print_header "Installing Go tools..."
print_status "Installing sqry (Shodan search)..."
go install github.com/Anon-Exploiter/sqry@latest

print_status "Installing gauplus (Historical URL gathering)..."
go install github.com/bp0lr/gauplus@latest

print_status "Installing airixss (XSS testing)..."
go install github.com/ferreiraklet/airixss@latest

print_status "Installing jeeves (SQL injection testing)..."
go install github.com/ferreiraklet/jeeves@latest

print_status "Installing qsreplace (Query string replacement)..."
go install github.com/tomnomnom/qsreplace@latest

print_status "Installing gf (Pattern matching)..."
go install github.com/tomnomnom/gf@latest

# Install GF patterns
print_status "Installing GF patterns..."
go install github.com/1ndianl33t/Gf-Patterns@latest

# Setup GF patterns directory
GF_DIR="$HOME/.gf"
mkdir -p "$GF_DIR"

# Copy GF patterns if available
if [ -d "$GOPATH/src/github.com/1ndianl33t/Gf-Patterns" ]; then
    cp -r "$GOPATH/src/github.com/1ndianl33t/Gf-Patterns"/* "$GF_DIR/"
    print_status "GF patterns installed"
else
    print_warning "GF patterns not found, will be installed on first use"
fi

# Create scope directory
print_header "Setting up scope directory..."
SCOPE_DIR="$HOME/targets/scope"
mkdir -p "$SCOPE_DIR"

# Create example scope files
cat > "$SCOPE_DIR/example.txt" << EOF
# Example scope file
# Add your target domains/URLs here
example.com
target.com
*.example.com
https://api.example.com
EOF

print_status "Scope directory created at $SCOPE_DIR"
print_status "Example scope file created"

# Make scripts executable
print_header "Setting up permissions..."
chmod +x liffy_ultimate_unified.py
chmod +x random
chmod +x setup.sh

print_status "Scripts made executable"

# Check Metasploit installation
print_header "Checking Metasploit Framework..."
if command -v msfvenom &> /dev/null; then
    print_status "Metasploit Framework found"
else
    print_warning "Metasploit Framework not found"
    print_warning "Install Metasploit for payload generation:"
    echo "  - Visit: https://www.metasploit.com/"
    echo "  - Or use: curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb | bash"
fi

# Create symlinks for easy access
print_header "Creating symlinks..."
if [ ! -L "/usr/local/bin/liffy" ]; then
    sudo ln -sf "$(pwd)/liffy_ultimate_unified.py" /usr/local/bin/liffy
    print_status "Created symlink: liffy"
fi

if [ ! -L "/usr/local/bin/random" ]; then
    sudo ln -sf "$(pwd)/random" /usr/local/bin/random
    print_status "Created symlink: random"
fi

# Test installation
print_header "Testing installation..."
python3 liffy_ultimate_unified.py --help > /dev/null
if [ $? -eq 0 ]; then
    print_status "Installation test passed"
else
    print_error "Installation test failed"
    exit 1
fi

# Final instructions
print_header "Setup Complete! 🎉"
echo ""
echo "Liffy Ultimate Unified is ready to use!"
echo ""
echo "Quick Start:"
echo "  liffy --random --test-mode all --auto-ip --auto-port"
echo ""
echo "Single Target:"
echo "  liffy --url 'http://target/file.php?page=' --data --lhost 192.168.1.100 --lport 4444"
echo ""
echo "Domain Testing:"
echo "  liffy --domain example.com --test-mode lfi --auto-ip --auto-port"
echo ""
echo "Scope Directory:"
echo "  Add your targets to: $SCOPE_DIR"
echo ""
echo "For more options:"
echo "  liffy --help"
echo ""
echo "Happy hunting! 🎯"