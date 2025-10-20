# Pagodo Integration with Proxychains3 Support

This document describes the integration of pagodo (Google Dorking tool) with proxychains3 support into the Liffy Enhanced target discovery system.

## Features

### 🔍 Pagodo Integration
- **Automatic Setup**: Automatically clones and sets up pagodo from GitHub
- **Dork Management**: Updates Google dorks using ghdb_scraper.py
- **Category Support**: 14 different dork categories for targeted searches
- **Result Parsing**: Converts pagodo results to TargetInfo objects
- **Error Handling**: Comprehensive error handling and fallback mechanisms

### 🔗 Proxychains3 Support
- **Auto-Detection**: Automatically detects proxychains3, proxychains4, or proxychains
- **Configuration Management**: Creates temporary proxychains configuration files
- **Proxy Support**: Supports HTTP, SOCKS4, and SOCKS5 proxies
- **Testing**: Built-in proxy configuration testing
- **Fallback**: Falls back to pagodo's built-in proxy support if proxychains3 unavailable

## Installation

### Prerequisites
```bash
# Install proxychains3 (optional but recommended)
sudo apt install proxychains3

# Or install proxychains4
sudo apt install proxychains4

# Install git (required for pagodo setup)
sudo apt install git

# Install Python dependencies
pip install -r requirements.txt
```

### Automatic Setup
The pagodo integration will automatically:
1. Clone the pagodo repository
2. Set up a Python virtual environment
3. Install required dependencies
4. Update Google dorks

## Usage

### Basic Usage

```python
from target_discovery import TargetDiscoveryEngine, DiscoveryMethod

# Initialize engine
engine = TargetDiscoveryEngine()

# Basic pagodo search
targets = engine.discover_targets(
    method=DiscoveryMethod.PAGODO,
    domain="example.com",
    max_results=50
)
```

### Advanced Usage with Categories

```python
# Search specific dork categories
targets = engine.discover_targets(
    method=DiscoveryMethod.PAGODO,
    domain="example.com",
    pagodo_category=5,  # Vulnerable Files
    max_results=100
)

# Available categories:
# 1: Footholds
# 2: File Containing Usernames
# 3: Sensitives Directories
# 4: Web Server Detection
# 5: Vulnerable Files
# 6: Vulnerable Servers
# 7: Error Messages
# 8: File Containing Juicy Info
# 9: File Containing Passwords
# 10: Sensitive Online Shopping Info
# 11: Network or Vulnerability Data
# 12: Pages Containing Login Portals
# 13: Various Online devices
# 14: Advisories and Vulnerabilities
```

### Using Built-in Proxy Support

```python
# Use pagodo's built-in proxy support
proxies = [
    "http://proxy1.example.com:8080",
    "socks5://127.0.0.1:9050",
    "socks5h://127.0.0.1:9051"
]

targets = engine.discover_targets(
    method=DiscoveryMethod.PAGODO,
    domain="example.com",
    pagodo_proxies=proxies,
    max_results=50
)
```

### Using Proxychains3

```python
# Use proxychains3 for advanced proxy management
targets = engine.discover_targets(
    method=DiscoveryMethod.PAGODO,
    domain="example.com",
    pagodo_proxies=proxies,
    use_proxychains=True,
    max_results=50
)
```

## Configuration

### Proxychains3 Configuration

The integration automatically creates a temporary proxychains configuration file with the following features:

- **Dynamic chaining**: Each connection uses a different proxy
- **DNS proxy**: Prevents DNS leaks
- **Timeout settings**: Optimized for web scraping
- **Multiple proxy types**: Supports HTTP, SOCKS4, and SOCKS5

### Custom Configuration

You can create custom proxychains configurations:

```python
# Create custom proxychains config
config_path = engine.pagodo.create_proxychains_config(
    proxies=["127.0.0.1:9050", "127.0.0.1:9051"],
    config_path="/tmp/custom_proxychains.conf"
)
```

## Testing

### Test Pagodo Integration

```bash
python test_pagodo.py
```

### Test Comprehensive Example

```bash
python pagodo_example.py
```

### Test Proxychains3

```python
# Test proxychains3 configuration
if engine.pagodo.test_proxychains():
    print("✅ Proxychains3 working")
else:
    print("❌ Proxychains3 not working")
```

## API Reference

### PagodoIntegration Class

#### Methods

- `is_available()`: Check if pagodo is available
- `update_dorks(force_update=False)`: Update Google dorks
- `get_dorks_by_category(category=None)`: Get dorks by category
- `search_targets(...)`: Search for targets using pagodo
- `is_proxychains_available()`: Check if proxychains3 is available
- `create_proxychains_config(proxies, config_path=None)`: Create proxychains config
- `test_proxychains(test_url="http://httpbin.org/ip")`: Test proxychains3
- `cleanup()`: Clean up temporary files

#### Parameters

- `domain`: Target domain for searching
- `dorks`: List of custom dorks to use
- `max_results`: Maximum number of results to return
- `min_delay`: Minimum delay between requests (seconds)
- `max_delay`: Maximum delay between requests (seconds)
- `proxies`: List of proxy servers
- `use_proxychains`: Use proxychains3 instead of built-in proxy support

## Error Handling

The integration includes comprehensive error handling:

- **Setup failures**: Falls back to basic dorking if pagodo setup fails
- **Network errors**: Retries and graceful degradation
- **Proxy failures**: Falls back to direct connections
- **Timeout handling**: Configurable timeouts for all operations
- **Resource cleanup**: Automatic cleanup of temporary files

## Performance Considerations

- **Rate limiting**: Built-in delays between requests to avoid blocking
- **Proxy rotation**: Automatic proxy rotation for better performance
- **Caching**: Dorks are cached and updated only when needed
- **Resource management**: Automatic cleanup of temporary files and directories

## Security Considerations

- **Proxy security**: Use trusted proxy servers
- **Rate limiting**: Respect target website rate limits
- **Legal compliance**: Ensure compliance with target website terms of service
- **Data privacy**: Be mindful of data collection and storage

## Troubleshooting

### Common Issues

1. **Pagodo setup fails**
   - Ensure git is installed
   - Check internet connectivity
   - Verify Python virtual environment support

2. **Proxychains3 not found**
   - Install proxychains3: `sudo apt install proxychains3`
   - Check PATH environment variable
   - Verify binary permissions

3. **Proxy connection fails**
   - Verify proxy server availability
   - Check proxy authentication
   - Test proxy configuration

4. **No results returned**
   - Check dork file existence
   - Verify target domain accessibility
   - Review proxy configuration

### Debug Mode

Enable debug output by setting environment variable:

```bash
export PAGODO_DEBUG=1
python your_script.py
```

## Examples

See the following files for complete examples:

- `test_pagodo.py`: Basic testing script
- `pagodo_example.py`: Comprehensive example with all features
- `target_discovery.py`: Main integration code

## Contributing

When contributing to the pagodo integration:

1. Follow the existing code style
2. Add comprehensive error handling
3. Include tests for new features
4. Update documentation
5. Test with both proxychains3 and built-in proxy support

## License

This integration follows the same license as the main Liffy Enhanced project.