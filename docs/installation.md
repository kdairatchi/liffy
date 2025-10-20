# 📦 Installation Guide

This guide will help you install Liffy Enhanced on your system.

## 📋 Prerequisites

### System Requirements
- **Operating System**: Linux, macOS, or Windows (with WSL)
- **Python**: Version 3.7 or higher
- **Memory**: Minimum 512MB RAM
- **Storage**: At least 100MB free space

### Required Software
- **Python 3.7+**: Core runtime environment
- **pip**: Python package manager
- **Metasploit Framework**: For payload generation (optional but recommended)
- **Git**: For cloning the repository

## 🚀 Quick Installation

### Method 1: Automated Installation (Recommended)

```bash
# Clone the repository
git clone https://github.com/your-repo/liffy-enhanced.git
cd liffy-enhanced

# Run the installation script
chmod +x install.sh
./install.sh
```

The installation script will:
- ✅ Check Python version compatibility
- ✅ Install Python dependencies
- ✅ Install Metasploit Framework (if not present)
- ✅ Set up file permissions
- ✅ Create global symlink (if possible)
- ✅ Test the installation

### Method 2: Manual Installation

```bash
# Clone the repository
git clone https://github.com/your-repo/liffy-enhanced.git
cd liffy-enhanced

# Install Python dependencies
pip3 install -r requirements.txt

# Make files executable
chmod +x liffy_enhanced.py
chmod +x http_server.py

# Test installation
python3 liffy_enhanced.py --help
```

## 🐧 Linux Installation

### Ubuntu/Debian/Kali Linux

```bash
# Update package list
sudo apt update

# Install Python 3 and pip
sudo apt install python3 python3-pip python3-venv

# Install Metasploit Framework
sudo apt install metasploit-framework

# Clone and install Liffy Enhanced
git clone https://github.com/your-repo/liffy-enhanced.git
cd liffy-enhanced
pip3 install -r requirements.txt
chmod +x liffy_enhanced.py
```

### Arch Linux

```bash
# Install Python and pip
sudo pacman -S python python-pip

# Install Metasploit Framework
sudo pacman -S metasploit

# Clone and install Liffy Enhanced
git clone https://github.com/your-repo/liffy-enhanced.git
cd liffy-enhanced
pip3 install -r requirements.txt
chmod +x liffy_enhanced.py
```

### CentOS/RHEL/Fedora

```bash
# Install Python 3 and pip
sudo yum install python3 python3-pip

# Install Metasploit Framework
sudo yum install metasploit-framework

# Clone and install Liffy Enhanced
git clone https://github.com/your-repo/liffy-enhanced.git
cd liffy-enhanced
pip3 install -r requirements.txt
chmod +x liffy_enhanced.py
```

## 🍎 macOS Installation

### Using Homebrew (Recommended)

```bash
# Install Homebrew (if not already installed)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install Python 3
brew install python3

# Install Metasploit Framework
brew install metasploit

# Clone and install Liffy Enhanced
git clone https://github.com/your-repo/liffy-enhanced.git
cd liffy-enhanced
pip3 install -r requirements.txt
chmod +x liffy_enhanced.py
```

### Using MacPorts

```bash
# Install Python 3
sudo port install python39

# Install Metasploit Framework
sudo port install metasploit

# Clone and install Liffy Enhanced
git clone https://github.com/your-repo/liffy-enhanced.git
cd liffy-enhanced
pip3 install -r requirements.txt
chmod +x liffy_enhanced.py
```

## 🪟 Windows Installation

### Using WSL (Windows Subsystem for Linux) - Recommended

```bash
# Install WSL2 (if not already installed)
wsl --install

# Open WSL terminal and follow Linux installation steps
# Ubuntu/Debian installation steps above
```

### Using Python directly

```cmd
# Install Python 3.7+ from python.org
# Make sure to check "Add Python to PATH" during installation

# Open Command Prompt or PowerShell
git clone https://github.com/your-repo/liffy-enhanced.git
cd liffy-enhanced
pip install -r requirements.txt
python liffy_enhanced.py --help
```

## 🐳 Docker Installation

### Using Docker

```bash
# Build the Docker image
docker build -t liffy-enhanced .

# Run Liffy Enhanced
docker run -it --rm liffy-enhanced --help

# Run with volume mount for persistent data
docker run -it --rm -v $(pwd)/data:/app/data liffy-enhanced
```

### Using Docker Compose

```bash
# Start the service
docker-compose up -d

# Run commands
docker-compose exec liffy-enhanced python3 liffy_enhanced.py --help
```

## 🔧 Virtual Environment (Recommended)

### Creating a Virtual Environment

```bash
# Create virtual environment
python3 -m venv liffy-env

# Activate virtual environment
# On Linux/macOS:
source liffy-env/bin/activate

# On Windows:
liffy-env\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Deactivate when done
deactivate
```

## 📦 Dependencies

### Python Dependencies

| Package | Version | Description |
|---------|---------|-------------|
| `requests` | >=2.25.0 | HTTP library for making requests |
| `blessings` | >=1.7 | Terminal colors and formatting |
| `urllib3` | >=1.26.0 | HTTP client library |

### System Dependencies

| Package | Description |
|---------|-------------|
| `metasploit-framework` | For payload generation |
| `python3` | Core runtime environment |
| `git` | Version control system |

## ✅ Verification

### Test Installation

```bash
# Check Python version
python3 --version

# Check Liffy Enhanced installation
python3 liffy_enhanced.py --help

# Test with a simple command
python3 liffy_enhanced.py --url http://example.com --filter --file /etc/passwd
```

### Expected Output

```
Liffy Enhanced - Ultimate Local File Inclusion Exploitation Tool
Version: 2.0.0
Author: rotlogix, unicornFurnace

Usage: liffy_enhanced.py [OPTIONS]

Options:
  --url TEXT                    Target URL with LFI parameter [required]
  --data                       Use data:// technique
  --input                      Use php://input technique
  --expect                     Use expect:// technique
  --environ                    Use /proc/self/environ technique
  --access                     Use Apache access log poisoning
  --ssh                        Use SSH auth log poisoning
  --filter                     Use php://filter technique
  --zip                        Use zip:// technique
  --phar                       Use phar:// technique
  --compress                   Use compress.zlib:// technique
  --auto                       Use automatic technique detection
  --lhost TEXT                 Callback host for reverse shells
  --lport INTEGER              Callback port for reverse shells
  --cookies TEXT               Session cookies
  --user-agent TEXT            Custom User-Agent string
  --proxy TEXT                 HTTP proxy (http://proxy:port)
  --timeout INTEGER            Request timeout in seconds
  --verbose                    Verbose output
  --output TEXT                Output file for logs
  --help                       Show this message and exit
```

## 🚨 Troubleshooting

### Common Issues

#### Python Version Error
```bash
# Error: Python 3.7+ required
# Solution: Install Python 3.7 or higher
python3 --version
```

#### Permission Denied
```bash
# Error: Permission denied
# Solution: Make files executable
chmod +x liffy_enhanced.py
chmod +x http_server.py
```

#### Module Not Found
```bash
# Error: No module named 'requests'
# Solution: Install dependencies
pip3 install -r requirements.txt
```

#### Metasploit Not Found
```bash
# Error: msfvenom not found
# Solution: Install Metasploit Framework
sudo apt install metasploit-framework  # Ubuntu/Debian
sudo pacman -S metasploit              # Arch Linux
brew install metasploit                # macOS
```

### Getting Help

If you encounter issues:

1. **Check the logs**: Look for error messages in the output
2. **Verify installation**: Run `python3 liffy_enhanced.py --help`
3. **Check dependencies**: Ensure all required packages are installed
4. **Report issues**: Create an issue on GitHub with details

## 🔄 Updating

### Update Liffy Enhanced

```bash
# Navigate to installation directory
cd liffy-enhanced

# Pull latest changes
git pull origin main

# Update dependencies
pip3 install -r requirements.txt --upgrade

# Test installation
python3 liffy_enhanced.py --help
```

### Update Dependencies

```bash
# Update all dependencies
pip3 install -r requirements.txt --upgrade

# Update specific package
pip3 install --upgrade requests
```

## 🗑️ Uninstallation

### Remove Liffy Enhanced

```bash
# Remove the directory
rm -rf liffy-enhanced

# Remove global symlink (if created)
sudo rm -f /usr/local/bin/liffy-enhanced

# Remove configuration directory
rm -rf ~/.liffy
```

### Remove Dependencies

```bash
# Remove Python packages
pip3 uninstall requests blessings urllib3

# Remove Metasploit Framework (optional)
sudo apt remove metasploit-framework  # Ubuntu/Debian
sudo pacman -R metasploit             # Arch Linux
brew uninstall metasploit             # macOS
```

---

**Next**: [Quick Start Guide](quick-start.md) to get started with Liffy Enhanced!
