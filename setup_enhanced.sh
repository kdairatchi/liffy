#!/bin/bash
# Enhanced Liffy Setup Script
# Installs all dependencies and creates enhanced versions

set -e

echo "🚀 Setting up Liffy Enhanced - All-in-One Vulnerability Testing Tool"
echo "=================================================================="

# Colors
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

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   print_error "This script should not be run as root"
   exit 1
fi

# Update system packages
print_status "Updating system packages..."
sudo apt update

# Install Python dependencies
print_status "Installing Python dependencies..."
pip3 install --user blessings requests urllib3

# Install Go tools
print_status "Installing Go tools..."

# Check if Go is installed
if ! command -v go &> /dev/null; then
    print_status "Installing Go..."
    wget https://go.dev/dl/go1.21.0.linux-amd64.tar.gz
    sudo tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz
    echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
    export PATH=$PATH:/usr/local/go/bin
    rm go1.21.0.linux-amd64.tar.gz
fi

# Install sqry
print_status "Installing sqry..."
go install github.com/ferreiraklet/sqry@latest

# Install gauplus
print_status "Installing gauplus..."
go install github.com/lc/gau/v2/cmd/gauplus@latest

# Install jeeves
print_status "Installing jeeves..."
go install github.com/ferreiraklet/jeeves@latest

# Install airixss
print_status "Installing airixss..."
go install github.com/ferreiraklet/airixss@latest

# Install qsreplace
print_status "Installing qsreplace..."
go install github.com/tomnomnom/qsreplace@latest

# Install httpx
print_status "Installing httpx..."
go install github.com/projectdiscovery/httpx/cmd/httpx@latest

# Add Go bin to PATH
echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.bashrc
export PATH=$PATH:$(go env GOPATH)/bin

# Create scope directory if it doesn't exist
print_status "Creating scope directory..."
mkdir -p ~/targets/scope

# Create sample scope files
print_status "Creating sample scope files..."
cat > ~/targets/scope/sample.txt << EOF
# Sample scope file
# Add your target domains/URLs here
example.com
testphp.vulnweb.com
httpbin.org
EOF

# Make scripts executable
print_status "Making scripts executable..."
chmod +x liffy_ultimate_enhanced.py
chmod +x liffy_integrated.py
chmod +x random

# Create enhanced random script
print_status "Creating enhanced random script..."
cat > random_enhanced << 'EOF'
#!/bin/bash
# Enhanced Random Target Selector for Liffy Ultimate
# Usage: random_enhanced [count] [test_mode] [technique]

# Default values
COUNT=${1:-5}
TEST_MODE=${2:-all}
TECHNIQUE=${3:-auto}
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Check if scope directory exists
SCOPE_DIR="$HOME/targets/scope"
if [ ! -d "$SCOPE_DIR" ]; then
    echo "Error: Scope directory not found at $SCOPE_DIR"
    echo "Please create the directory and add your scope files"
    exit 1
fi

# Check if scope directory has files
if [ -z "$(find "$SCOPE_DIR" -type f -name "*.txt" -o -name "*.md" -o -name "*.json" -o -name "*.csv" 2>/dev/null)" ]; then
    echo "Error: No scope files found in $SCOPE_DIR"
    echo "Please add scope files (.txt, .md, .json, .csv) to the directory"
    exit 1
fi

echo "🎯 Liffy Ultimate Enhanced - Random Target Mode"
echo "=============================================="
echo "Scope directory: $SCOPE_DIR"
echo "Target count: $COUNT"
echo "Test mode: $TEST_MODE"
echo "Technique: $TECHNIQUE"
echo ""

# Run Liffy Integrated with random targets
cd "$SCRIPT_DIR"
python3 liffy_integrated.py --random --random-count "$COUNT" --test-mode "$TEST_MODE" --verbose
EOF

chmod +x random_enhanced

# Create comprehensive test script
print_status "Creating comprehensive test script..."
cat > test_all.sh << 'EOF'
#!/bin/bash
# Comprehensive test script for Liffy Enhanced

echo "🧪 Running comprehensive tests for Liffy Enhanced"
echo "================================================"

# Test 1: Random targets with all tests
echo "Test 1: Random targets with comprehensive testing"
python3 liffy_integrated.py --random --random-count 3 --test-mode all --output test_results.json

# Test 2: Domain crawling with XSS
echo "Test 2: Domain crawling with XSS testing"
python3 liffy_integrated.py --domain httpbin.org --test-mode xss --output test_xss.json

# Test 3: Shodan discovery with LFI
echo "Test 3: Shodan discovery with LFI testing"
python3 liffy_integrated.py --shodan-query "apache" --test-mode lfi --limit 5 --output test_lfi.json

echo "✅ All tests completed!"
EOF

chmod +x test_all.sh

# Create usage examples
print_status "Creating usage examples..."
cat > USAGE_EXAMPLES.md << 'EOF'
# Liffy Enhanced - Usage Examples

## Basic Usage

### Random Targets (Default)
```bash
# Use random targets from scope with all tests
python3 liffy_integrated.py

# Use random targets with specific test mode
python3 liffy_integrated.py --random --test-mode xss --random-count 10
```

### Domain Crawling
```bash
# Crawl domain with subdomains and test for XSS
python3 liffy_integrated.py --domain example.com --test-mode xss --subs

# Crawl domain with comprehensive testing
python3 liffy_integrated.py --domain example.com --test-mode all --subs
```

### Shodan Discovery
```bash
# Discover targets from Shodan and test for SQLi
python3 liffy_integrated.py --shodan-query "apache" --test-mode sqli --limit 50

# Shodan with country filter and LFI testing
python3 liffy_integrated.py --shodan-query "nginx" --test-mode lfi --country US --limit 100
```

## Advanced Usage

### Custom Scope Directory
```bash
python3 liffy_integrated.py --random --scope-dir ~/my-scope --random-count 20
```

### Output to File
```bash
python3 liffy_integrated.py --domain example.com --test-mode all --output results.json
```

### Verbose Output
```bash
python3 liffy_integrated.py --random --test-mode all --verbose
```

## Tool Integration Examples

### Using sqry directly
```bash
sqry -q "apache" --limit 10 --json
```

### Using gauplus for URL gathering
```bash
echo "example.com" | gauplus -subs
```

### Using jeeves for SQLi testing
```bash
echo "http://testphp.vulnweb.com/artists.php?artist=" | qsreplace "(select(0)from(select(sleep(5)))v)" | jeeves -t 5
```

### Using airixss for XSS testing
```bash
echo "http://testphp.vulnweb.com/artists.php?artist=test" | airixss -c 10
```

## Configuration

### Scope Directory Structure
```
~/targets/scope/
├── domains.txt
├── urls.json
├── targets.csv
└── scope.md
```

### Sample Scope Files
- **domains.txt**: One domain per line
- **urls.json**: JSON array of URLs
- **targets.csv**: CSV with URL, domain, type columns
- **scope.md**: Markdown with URLs in code blocks
EOF

# Create enhanced README
print_status "Creating enhanced README..."
cat > README_ENHANCED.md << 'EOF'
# Liffy Enhanced - Ultimate All-in-One Vulnerability Testing Tool

A comprehensive vulnerability testing tool that integrates multiple security tools for efficient bug bounty hunting and penetration testing.

## 🚀 Features

- **Multi-Source Target Discovery**: Shodan, domain crawling, scope-based random selection
- **Comprehensive Vulnerability Testing**: LFI, XSS, SQL injection
- **Tool Integration**: sqry, gauplus, jeeves, airixss, qsreplace, httpx
- **No API Keys Required**: Uses free tools and techniques
- **Multi-threaded**: Fast parallel processing
- **Flexible Output**: JSON, console, file export
- **Easy Setup**: Automated installation and configuration

## 🛠️ Integrated Tools

- **sqry**: Shodan-based target discovery (no API key required)
- **gauplus**: URL gathering and crawling
- **jeeves**: SQL injection testing
- **airixss**: XSS vulnerability testing
- **qsreplace**: Parameter manipulation
- **httpx**: HTTP probing and validation

## 📦 Installation

```bash
# Clone the repository
git clone <repository-url>
cd liffy

# Run setup script
chmod +x setup_enhanced.sh
./setup_enhanced.sh
```

## 🎯 Quick Start

### Random Targets (Recommended)
```bash
# Use random targets from scope with all tests
python3 liffy_integrated.py

# Use enhanced random script
./random_enhanced 10 all auto
```

### Domain Crawling
```bash
# Crawl domain with comprehensive testing
python3 liffy_integrated.py --domain example.com --test-mode all --subs
```

### Shodan Discovery
```bash
# Discover and test targets from Shodan
python3 liffy_integrated.py --shodan-query "apache" --test-mode all --limit 50
```

## 📋 Usage Examples

See [USAGE_EXAMPLES.md](USAGE_EXAMPLES.md) for detailed usage examples.

## 🔧 Configuration

### Scope Directory
Create `~/targets/scope/` and add your target files:
- `domains.txt`: One domain per line
- `urls.json`: JSON array of URLs
- `targets.csv`: CSV with URL, domain, type columns

### Tool Configuration
All tools are automatically configured during setup. No additional configuration required.

## 📊 Output

Results are displayed in the console and can be saved to JSON files for further analysis.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

## 📄 License

This project is licensed under the MIT License.

## ⚠️ Disclaimer

This tool is for educational and authorized testing purposes only. Use responsibly and only on systems you own or have explicit permission to test.
EOF

print_status "Setup completed successfully!"
print_status "Enhanced Liffy is ready to use!"
print_status ""
print_status "Quick start commands:"
print_status "  python3 liffy_integrated.py --random --test-mode all"
print_status "  python3 liffy_integrated.py --domain example.com --test-mode xss"
print_status "  python3 liffy_integrated.py --shodan-query 'apache' --test-mode sqli"
print_status ""
print_status "Enhanced random script:"
print_status "  ./random_enhanced 10 all auto"
print_status ""
print_status "Run comprehensive tests:"
print_status "  ./test_all.sh"
print_status ""
print_status "Scope directory created at: ~/targets/scope"
print_status "Add your target domains/URLs to the scope files"
print_status ""
print_status "For detailed usage, see: README_ENHANCED.md and USAGE_EXAMPLES.md"