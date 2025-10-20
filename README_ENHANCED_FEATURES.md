# 🚀 Liffy Enhanced Ultimate - Advanced Features

## ✨ New Features Added

### 1. 🔍 Subdomain Enumeration with Gauplus and Wayback
- **Enhanced Gauplus Integration**: Discover subdomains using historical data from Wayback Machine, Common Crawl, and OTX
- **Wayback-Specific Discovery**: Target Wayback Machine specifically for historical URL discovery
- **Subdomain Filtering**: Automatically filter and validate discovered subdomains
- **Comprehensive Coverage**: Combine multiple data sources for maximum subdomain discovery

```bash
# Subdomain enumeration
python3 url_gatherer.py --domain example.com --subdomains --limit 1000

# Wayback-specific discovery
python3 url_gatherer.py --domain example.com --wayback --limit 500
```

### 2. 🎯 GF Pattern Discovery for Parameter Injection
- **GF Integration**: Use GF (Grep for URLs) with custom patterns for parameter discovery
- **Pattern Matching**: Discover LFI, XSS, SQLi, SSTI, and RCE parameters automatically
- **Custom Patterns**: Support for custom GF patterns and pattern libraries
- **Parameter Analysis**: Intelligent analysis of discovered parameters for vulnerability potential

```bash
# GF pattern discovery
python3 url_gatherer.py --domain example.com --gf-patterns lfi xss sqli --limit 500

# List available patterns
python3 url_gatherer.py --list-gf-patterns
```

### 3. 🔄 QSReplace with Comprehensive Payload Lists
- **QSReplace Integration**: Automated query string replacement with payload testing
- **Comprehensive Payloads**: Pre-built payload lists for LFI, XSS, SQLi, SSTI, and RCE
- **Automated Testing**: Test multiple vulnerability types with single command
- **Custom Payloads**: Support for custom payload lists and testing strategies

```bash
# QSReplace testing
python3 url_gatherer.py --domain example.com --qsreplace --test-mode all

# Specific vulnerability testing
python3 url_gatherer.py --domain example.com --qsreplace --test-mode lfi
```

### 4. 🤖 Enhanced Automation Features
- **Comprehensive Discovery**: Combine all discovery methods for maximum coverage
- **Intelligent Analysis**: Automatic vulnerability potential assessment
- **Multi-threaded Processing**: Concurrent URL analysis and testing
- **Smart Filtering**: Remove duplicates and prioritize high-value targets
- **Progress Tracking**: Real-time progress updates and status reporting

```bash
# Comprehensive discovery
python3 url_gatherer.py --domain example.com --comprehensive --limit 1000

# Random target discovery
python3 url_gatherer.py --random --comprehensive --test-mode all
```

## 🛠️ Installation

### Quick Setup
```bash
# Run the setup script
chmod +x setup_enhanced_features.sh
./setup_enhanced_features.sh
```

### Manual Installation
```bash
# Install Go tools
go install github.com/bp0lr/gauplus@latest
go install github.com/tomnomnom/gf@latest
go install github.com/1ndianl33t/Gf-Patterns@latest
go install github.com/tomnomnom/qsreplace@latest
go install github.com/ferreiraklet/airixss@latest
go install github.com/ferreiraklet/jeeves@latest
go install github.com/ferreiraklet/sqry@latest

# Setup GF patterns
mkdir -p ~/.gf
cp -r $GOPATH/src/github.com/1ndianl33t/Gf-Patterns/* ~/.gf/

# Create scope directory
mkdir -p ~/targets/scope
```

## 📋 Usage Examples

### 1. Subdomain Enumeration
```bash
# Basic subdomain discovery
python3 url_gatherer.py --domain example.com --subdomains

# With specific providers
python3 url_gatherer.py --domain example.com --subdomains --providers wayback,otx

# Limit results
python3 url_gatherer.py --domain example.com --subdomains --limit 500
```

### 2. GF Pattern Discovery
```bash
# LFI pattern discovery
python3 url_gatherer.py --domain example.com --gf-patterns lfi

# Multiple patterns
python3 url_gatherer.py --domain example.com --gf-patterns lfi xss sqli

# All patterns
python3 url_gatherer.py --domain example.com --gf-patterns lfi xss sqli ssti rce
```

### 3. QSReplace Testing
```bash
# Test all vulnerability types
python3 url_gatherer.py --domain example.com --qsreplace

# Test specific types
python3 url_gatherer.py --domain example.com --qsreplace --test-mode lfi

# With custom payloads
python3 url_gatherer.py --domain example.com --qsreplace --payload-file custom_payloads.txt
```

### 4. Comprehensive Discovery
```bash
# Full comprehensive discovery
python3 url_gatherer.py --domain example.com --comprehensive --test-mode all

# With specific limits
python3 url_gatherer.py --domain example.com --comprehensive --limit 1000 --max-workers 20

# Random targets
python3 url_gatherer.py --random --comprehensive --random-count 10
```

## 🔧 Configuration

### Environment Variables
```bash
export GAUPLUS_PATH="/home/kali/go/bin/gauplus"
export GF_PATH="/home/kali/go/bin/gf"
export QSREPLACE_PATH="/home/kali/go/bin/qsreplace"
export SCOPE_DIR="~/targets/scope"
```

### Scope Files
Place your target scope files in `~/targets/scope/`:
- `inscope.txt` - General in-scope targets
- `priority_inscope.txt` - Priority targets (used first)
- `*.txt`, `*.md`, `*.json`, `*.csv` - Additional scope files

### GF Patterns
Custom GF patterns can be added to `~/.gf/`:
- `lfi.json` - LFI patterns
- `xss.json` - XSS patterns
- `sqli.json` - SQLi patterns
- `ssti.json` - SSTI patterns
- `rce.json` - RCE patterns

## 📊 Output Formats

### JSON Output
```bash
python3 url_gatherer.py --domain example.com --comprehensive --output results.json
```

### Console Output
```bash
python3 url_gatherer.py --domain example.com --comprehensive --verbose
```

### Log Files
```bash
python3 url_gatherer.py --domain example.com --comprehensive --log-file discovery.log
```

## 🎯 Advanced Features

### 1. Custom Payload Lists
Create custom payload files for QSReplace:
```bash
# LFI payloads
echo "../../../etc/passwd" > lfi_payloads.txt
echo "php://filter/convert.base64-encode/resource=index.php" >> lfi_payloads.txt

# Use custom payloads
python3 url_gatherer.py --domain example.com --qsreplace --payload-file lfi_payloads.txt
```

### 2. Pattern Customization
Add custom GF patterns:
```json
{
  "patterns": [
    {
      "name": "custom_lfi",
      "pattern": "file=.*\\.php",
      "description": "Custom LFI pattern"
    }
  ]
}
```

### 3. Multi-threaded Processing
```bash
# Increase worker threads
python3 url_gatherer.py --domain example.com --comprehensive --max-workers 50

# Adjust timeouts
python3 url_gatherer.py --domain example.com --comprehensive --timeout 60
```

## 🔍 Troubleshooting

### Common Issues

1. **GF not found**
   ```bash
   go install github.com/tomnomnom/gf@latest
   export PATH=$PATH:$(go env GOPATH)/bin
   ```

2. **Gauplus not found**
   ```bash
   go install github.com/bp0lr/gauplus@latest
   export PATH=$PATH:$(go env GOPATH)/bin
   ```

3. **QSReplace not found**
   ```bash
   go install github.com/tomnomnom/qsreplace@latest
   export PATH=$PATH:$(go env GOPATH)/bin
   ```

4. **Permission denied**
   ```bash
   chmod +x url_gatherer.py
   chmod +x liffy_enhanced_ultimate.py
   ```

### Debug Mode
```bash
# Enable verbose output
python3 url_gatherer.py --domain example.com --comprehensive --verbose

# Debug specific components
python3 url_gatherer.py --domain example.com --gf-patterns lfi --verbose
```

## 📈 Performance Tips

1. **Use appropriate limits**: Start with smaller limits and increase as needed
2. **Adjust worker threads**: More workers = faster processing, but more resource usage
3. **Filter results**: Use specific patterns instead of comprehensive when possible
4. **Cache results**: Save results to files for later analysis
5. **Monitor resources**: Watch CPU and memory usage during large scans

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Add your enhancements
4. Test thoroughly
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- **Gauplus**: For historical URL discovery
- **GF**: For pattern matching capabilities
- **QSReplace**: For query string replacement testing
- **Airixss**: For XSS testing
- **Jeeves**: For SQL injection testing
- **Sqry**: For Shodan integration

---

**Happy Hunting! 🎯**
