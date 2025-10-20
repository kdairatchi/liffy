#!/usr/bin/env python3
"""
URL Processing Module for Liffy
Handles URL parsing, domain extraction, and subdomain enumeration
"""

import re
import subprocess
import requests
from urllib.parse import urlparse, urljoin
from blessings import Terminal
import datetime
import os
import json
import time

t = Terminal()

class URLProcessor:
    def __init__(self):
        self.domains = set()
        self.subdomains = set()
        self.urls = set()
        self.parameters = set()
        
    def extract_domain(self, url):
        """Extract domain from URL"""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc
            if domain:
                return domain
        except Exception as e:
            print(t.red(f"[{datetime.datetime.now()}] Error extracting domain: {str(e)}"))
        return None
    
    def strip_to_subdomain(self, url):
        """Strip URL to subdomain level"""
        try:
            parsed = urlparse(url)
            if parsed.netloc:
                # Extract subdomain (everything before the main domain)
                parts = parsed.netloc.split('.')
                if len(parts) >= 2:
                    # Keep the last two parts as main domain
                    subdomain = '.'.join(parts[:-2]) if len(parts) > 2 else ''
                    main_domain = '.'.join(parts[-2:])
                    return f"{parsed.scheme}://{parsed.netloc}", main_domain, subdomain
        except Exception as e:
            print(t.red(f"[{datetime.datetime.now()}] Error processing URL: {str(e)}"))
        return None, None, None
    
    def discover_subdomains_gauplus(self, domain, threads=50):
        """Discover subdomains using gauplus"""
        print(t.cyan(f"[{datetime.datetime.now()}] Starting subdomain discovery with gauplus for {domain}"))
        
        try:
            # Check if gauplus is available
            result = subprocess.run(['which', 'gauplus'], capture_output=True, text=True)
            if result.returncode != 0:
                print(t.yellow(f"[{datetime.datetime.now()}] gauplus not found, installing..."))
                self.install_gauplus()
            
            # Run gauplus
            cmd = ['gauplus', '-t', str(threads), '-subs', domain]
            print(t.cyan(f"[{datetime.datetime.now()}] Running: {' '.join(cmd)}"))
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                urls = result.stdout.strip().split('\n')
                for url in urls:
                    if url.strip():
                        self.urls.add(url.strip())
                        parsed = urlparse(url.strip())
                        if parsed.netloc:
                            self.subdomains.add(parsed.netloc)
                            self.domains.add('.'.join(parsed.netloc.split('.')[-2:]))
                
                print(t.green(f"[{datetime.datetime.now()}] Found {len(self.urls)} URLs and {len(self.subdomains)} subdomains"))
                return self.urls, self.subdomains
            else:
                print(t.red(f"[{datetime.datetime.now()}] gauplus failed: {result.stderr}"))
                return set(), set()
                
        except subprocess.TimeoutExpired:
            print(t.red(f"[{datetime.datetime.now()}] gauplus timed out"))
            return set(), set()
        except Exception as e:
            print(t.red(f"[{datetime.datetime.now()}] Error running gauplus: {str(e)}"))
            return set(), set()
    
    def discover_subdomains_wayback(self, domain):
        """Discover subdomains using wayback machine"""
        print(t.cyan(f"[{datetime.datetime.now()}] Starting subdomain discovery with wayback for {domain}"))
        
        try:
            # Check if waybackurls is available
            result = subprocess.run(['which', 'waybackurls'], capture_output=True, text=True)
            if result.returncode != 0:
                print(t.yellow(f"[{datetime.datetime.now()}] waybackurls not found, installing..."))
                self.install_waybackurls()
            
            # Run waybackurls
            cmd = ['waybackurls', domain]
            print(t.cyan(f"[{datetime.datetime.now()}] Running: {' '.join(cmd)}"))
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                urls = result.stdout.strip().split('\n')
                for url in urls:
                    if url.strip():
                        self.urls.add(url.strip())
                        parsed = urlparse(url.strip())
                        if parsed.netloc:
                            self.subdomains.add(parsed.netloc)
                            self.domains.add('.'.join(parsed.netloc.split('.')[-2:]))
                
                print(t.green(f"[{datetime.datetime.now()}] Found {len(self.urls)} URLs and {len(self.subdomains)} subdomains from wayback"))
                return self.urls, self.subdomains
            else:
                print(t.red(f"[{datetime.datetime.now()}] waybackurls failed: {result.stderr}"))
                return set(), set()
                
        except subprocess.TimeoutExpired:
            print(t.red(f"[{datetime.datetime.now()}] waybackurls timed out"))
            return set(), set()
        except Exception as e:
            print(t.red(f"[{datetime.datetime.now()}] Error running waybackurls: {str(e)}"))
            return set(), set()
    
    def extract_parameters(self, urls):
        """Extract parameters from URLs"""
        print(t.cyan(f"[{datetime.datetime.now()}] Extracting parameters from {len(urls)} URLs"))
        
        for url in urls:
            try:
                parsed = urlparse(url)
                if parsed.query:
                    params = parsed.query.split('&')
                    for param in params:
                        if '=' in param:
                            param_name = param.split('=')[0]
                            self.parameters.add(param_name)
            except Exception as e:
                continue
        
        print(t.green(f"[{datetime.datetime.now()}] Found {len(self.parameters)} unique parameters"))
        return self.parameters
    
    def discover_patterns_gf(self, urls):
        """Discover patterns using gf"""
        print(t.cyan(f"[{datetime.datetime.now()}] Discovering patterns with gf"))
        
        try:
            # Check if gf is available
            result = subprocess.run(['which', 'gf'], capture_output=True, text=True)
            if result.returncode != 0:
                print(t.yellow(f"[{datetime.datetime.now()}] gf not found, installing..."))
                self.install_gf()
            
            # Save URLs to temporary file
            temp_file = '/tmp/liffy_urls.txt'
            with open(temp_file, 'w') as f:
                for url in urls:
                    f.write(url + '\n')
            
            # Run gf with various patterns
            patterns = [
                'lfi', 'rce', 'ssti', 'ssrf', 'redirect', 'xss', 'sqli', 
                'nosql', 'xxe', 'openredirect', 'file', 'path', 'include'
            ]
            
            all_patterns = set()
            
            for pattern in patterns:
                try:
                    cmd = ['gf', pattern, temp_file]
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                    
                    if result.returncode == 0 and result.stdout.strip():
                        pattern_urls = result.stdout.strip().split('\n')
                        for url in pattern_urls:
                            if url.strip():
                                all_patterns.add(url.strip())
                                print(t.green(f"[{datetime.datetime.now()}] Found {pattern} pattern: {url.strip()}"))
                except subprocess.TimeoutExpired:
                    print(t.yellow(f"[{datetime.datetime.now()}] gf {pattern} timed out"))
                    continue
                except Exception as e:
                    print(t.red(f"[{datetime.datetime.now()}] Error running gf {pattern}: {str(e)}"))
                    continue
            
            # Clean up temp file
            os.remove(temp_file)
            
            print(t.green(f"[{datetime.datetime.now()}] Found {len(all_patterns)} URLs with interesting patterns"))
            return all_patterns
            
        except Exception as e:
            print(t.red(f"[{datetime.datetime.now()}] Error in pattern discovery: {str(e)}"))
            return set()
    
    def install_gauplus(self):
        """Install gauplus"""
        try:
            print(t.cyan(f"[{datetime.datetime.now()}] Installing gauplus..."))
            subprocess.run(['go', 'install', 'github.com/lc/gauplus@latest'], check=True)
            print(t.green(f"[{datetime.datetime.now()}] gauplus installed successfully"))
        except Exception as e:
            print(t.red(f"[{datetime.datetime.now()}] Failed to install gauplus: {str(e)}"))
    
    def install_waybackurls(self):
        """Install waybackurls"""
        try:
            print(t.cyan(f"[{datetime.datetime.now()}] Installing waybackurls..."))
            subprocess.run(['go', 'install', 'github.com/tomnomnom/waybackurls@latest'], check=True)
            print(t.green(f"[{datetime.datetime.now()}] waybackurls installed successfully"))
        except Exception as e:
            print(t.red(f"[{datetime.datetime.now()}] Failed to install waybackurls: {str(e)}"))
    
    def install_gf(self):
        """Install gf"""
        try:
            print(t.cyan(f"[{datetime.datetime.now()}] Installing gf..."))
            subprocess.run(['go', 'install', 'github.com/tomnomnom/gf@latest'], check=True)
            print(t.green(f"[{datetime.datetime.now()}] gf installed successfully"))
        except Exception as e:
            print(t.red(f"[{datetime.datetime.now()}] Failed to install gf: {str(e)}"))
    
    def process_urls(self, input_urls, use_gauplus=True, use_wayback=True, use_gf=True):
        """Main method to process URLs and discover targets"""
        print(t.cyan(f"[{datetime.datetime.now()}] Starting URL processing..."))
        
        # Process input URLs
        for url in input_urls:
            domain = self.extract_domain(url)
            if domain:
                self.domains.add(domain)
                self.subdomains.add(domain)
        
        # Discover more subdomains and URLs
        for domain in self.domains:
            if use_gauplus:
                urls, subdomains = self.discover_subdomains_gauplus(domain)
                self.urls.update(urls)
                self.subdomains.update(subdomains)
            
            if use_wayback:
                urls, subdomains = self.discover_subdomains_wayback(domain)
                self.urls.update(urls)
                self.subdomains.update(subdomains)
        
        # Extract parameters
        self.extract_parameters(self.urls)
        
        # Discover patterns
        if use_gf and self.urls:
            pattern_urls = self.discover_patterns_gf(self.urls)
            self.urls.update(pattern_urls)
        
        return {
            'domains': list(self.domains),
            'subdomains': list(self.subdomains),
            'urls': list(self.urls),
            'parameters': list(self.parameters)
        }