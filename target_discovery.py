#!/usr/bin/env python3
"""
Target Discovery Module for Liffy Enhanced
Handles automatic target discovery using dorking, GAU+, GF patterns, and bug bounty data
"""

import os
import json
import random
import subprocess
import requests
from typing import List, Dict, Any, Optional, Tuple
from pathlib import Path
import re
import time
from dataclasses import dataclass
from enum import Enum
import shutil
import tempfile

class DiscoveryMethod(Enum):
    DORKING = "dorking"
    GAUPLUS = "gauplus"
    GF_PATTERNS = "gf_patterns"
    BUG_BOUNTY = "bug_bounty"
    PAGODO = "pagodo"
    RANDOM = "random"

@dataclass
class TargetInfo:
    """Target information structure"""
    url: str
    method: DiscoveryMethod
    confidence: float
    source: str
    category: str
    parameters: List[str]
    technology: str
    notes: str

class DorkingEngine:
    """Advanced dorking engine for target discovery"""
    
    DORKING_QUERIES = {
        'lfi_basic': [
            'inurl:"file=" "index.php"',
            'inurl:"page=" "include"',
            'inurl:"path=" "file"',
            'inurl:"doc=" "include"',
            'inurl:"folder=" "file"',
            'inurl:"inc=" "include"',
            'inurl:"locate=" "file"',
            'inurl:"menu=" "include"',
            'inurl:"file=" "php"',
            'inurl:"page=" "php"'
        ],
        'lfi_advanced': [
            'inurl:"file=" "index.php" "include"',
            'inurl:"page=" "include" "file"',
            'inurl:"path=" "file" "include"',
            'inurl:"doc=" "include" "file"',
            'inurl:"folder=" "file" "include"',
            'inurl:"inc=" "include" "file"',
            'inurl:"locate=" "file" "include"',
            'inurl:"menu=" "include" "file"',
            'inurl:"file=" "php" "include"',
            'inurl:"page=" "php" "include"'
        ],
        'lfi_specific': [
            'inurl:"file=" "index.php" "include" "file"',
            'inurl:"page=" "include" "file" "php"',
            'inurl:"path=" "file" "include" "php"',
            'inurl:"doc=" "include" "file" "php"',
            'inurl:"folder=" "file" "include" "php"',
            'inurl:"inc=" "include" "file" "php"',
            'inurl:"locate=" "file" "include" "php"',
            'inurl:"menu=" "include" "file" "php"'
        ],
        'lfi_parameters': [
            'inurl:"file=" "index.php" "include" "file" "path"',
            'inurl:"page=" "include" "file" "path" "php"',
            'inurl:"path=" "file" "include" "path" "php"',
            'inurl:"doc=" "include" "file" "path" "php"',
            'inurl:"folder=" "file" "include" "path" "php"',
            'inurl:"inc=" "include" "file" "path" "php"',
            'inurl:"locate=" "file" "include" "path" "php"',
            'inurl:"menu=" "include" "file" "path" "php"'
        ]
    }
    
    SEARCH_ENGINES = {
        'google': 'https://www.google.com/search?q={query}&num=100',
        'bing': 'https://www.bing.com/search?q={query}&count=100',
        'duckduckgo': 'https://duckduckgo.com/?q={query}&t=h_&ia=web',
        'yandex': 'https://yandex.com/search/?text={query}&lr=84'
    }
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
    
    def search_dorks(self, query_type: str = 'lfi_basic', max_results: int = 50) -> List[str]:
        """Search for targets using dorking queries"""
        targets = []
        queries = self.DORKING_QUERIES.get(query_type, self.DORKING_QUERIES['lfi_basic'])
        
        for query in queries[:5]:  # Limit to first 5 queries
            try:
                # Use Google search
                search_url = self.SEARCH_ENGINES['google'].format(query=query)
                response = self.session.get(search_url, timeout=10)
                
                if response.status_code == 200:
                    # Extract URLs from search results
                    urls = self._extract_urls_from_html(response.text)
                    targets.extend(urls[:max_results//len(queries)])
                    
                time.sleep(2)  # Rate limiting
                
            except Exception as e:
                print(f"Error searching dorks: {e}")
                continue
        
        return list(set(targets))  # Remove duplicates
    
    def _extract_urls_from_html(self, html: str) -> List[str]:
        """Extract URLs from HTML search results"""
        urls = []
        
        # Simple regex to extract URLs from search results
        url_pattern = r'https?://[^\s<>"]+'
        matches = re.findall(url_pattern, html)
        
        for match in matches:
            # Clean up URL
            url = match.split('&')[0].split('?')[0]
            if self._is_valid_target_url(url):
                urls.append(url)
        
        return urls
    
    def _is_valid_target_url(self, url: str) -> bool:
        """Check if URL is a valid target for LFI testing"""
        try:
            # Check if URL contains common LFI parameters
            lfi_params = ['file', 'page', 'path', 'doc', 'folder', 'inc', 'locate', 'menu']
            return any(param in url.lower() for param in lfi_params)
        except:
            return False

class GAUPlusIntegration:
    """Integration with GAU+ for URL discovery"""
    
    def __init__(self):
        self.gauplus_path = self._find_gauplus()
    
    def _find_gauplus(self) -> Optional[str]:
        """Find GAU+ binary in system PATH"""
        try:
            result = subprocess.run(['which', 'gauplus'], capture_output=True, text=True)
            if result.returncode == 0:
                return result.stdout.strip()
        except:
            pass
        return None
    
    def discover_urls(self, domain: str, max_results: int = 100) -> List[str]:
        """Discover URLs using GAU+"""
        if not self.gauplus_path:
            return []
        
        try:
            cmd = [self.gauplus_path, '-subs', domain, '-o', '/tmp/gauplus_results.txt']
            subprocess.run(cmd, timeout=60, check=True)
            
            # Read results
            with open('/tmp/gauplus_results.txt', 'r') as f:
                urls = [line.strip() for line in f if line.strip()]
            
            # Filter for potential LFI targets
            lfi_urls = [url for url in urls if self._has_lfi_potential(url)]
            return lfi_urls[:max_results]
            
        except Exception as e:
            print(f"Error running GAU+: {e}")
            return []
    
    def _has_lfi_potential(self, url: str) -> bool:
        """Check if URL has potential for LFI"""
        lfi_indicators = [
            'file=', 'page=', 'path=', 'doc=', 'folder=', 
            'inc=', 'locate=', 'menu=', 'include=', 'view='
        ]
        return any(indicator in url.lower() for indicator in lfi_indicators)

class GFPatternMatcher:
    """GF pattern matching for parameter discovery"""
    
    GF_PATTERNS = {
        'lfi': [
            'file', 'page', 'path', 'doc', 'folder', 'inc', 
            'locate', 'menu', 'include', 'view', 'template',
            'content', 'section', 'module', 'component'
        ],
        'rfi': [
            'url', 'link', 'src', 'source', 'include', 'file',
            'path', 'page', 'doc', 'folder', 'inc', 'locate'
        ],
        'ssti': [
            'template', 'view', 'page', 'content', 'section',
            'module', 'component', 'layout', 'theme', 'skin'
        ]
    }
    
    def __init__(self):
        self.gf_path = self._find_gf()
    
    def _find_gf(self) -> Optional[str]:
        """Find GF binary in system PATH"""
        try:
            result = subprocess.run(['which', 'gf'], capture_output=True, text=True)
            if result.returncode == 0:
                return result.gf_path
        except:
            pass
        return None
    
    def discover_parameters(self, url: str, pattern_type: str = 'lfi') -> List[str]:
        """Discover parameters using GF patterns"""
        if not self.gf_path:
            return []
        
        try:
            # Create temporary file with URL
            with open('/tmp/gf_input.txt', 'w') as f:
                f.write(url + '\n')
            
            # Run GF with pattern
            cmd = [self.gf_path, pattern_type, '/tmp/gf_input.txt']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                return result.stdout.strip().split('\n')
            
        except Exception as e:
            print(f"Error running GF: {e}")
        
        return []

class BugBountyTargetManager:
    """Manage bug bounty targets from ~/targets/scope/data"""
    
    def __init__(self, targets_dir: str = "~/targets/scope/data"):
        self.targets_dir = Path(targets_dir).expanduser()
        self.targets = self._load_targets()
    
    def _load_targets(self) -> Dict[str, List[Dict]]:
        """Load bug bounty targets from directory"""
        targets = {}
        
        if not self.targets_dir.exists():
            return targets
        
        for file_path in self.targets_dir.glob("*.json"):
            try:
                with open(file_path, 'r') as f:
                    data = json.load(f)
                    program_name = file_path.stem
                    targets[program_name] = data
            except Exception as e:
                print(f"Error loading {file_path}: {e}")
        
        return targets
    
    def get_targets_by_category(self, category: str = None) -> List[Dict]:
        """Get targets by category"""
        all_targets = []
        
        for program, targets in self.targets.items():
            for target in targets:
                if category is None or target.get('category', '').lower() == category.lower():
                    target['program'] = program
                    all_targets.append(target)
        
        return all_targets
    
    def get_random_targets(self, count: int = 10) -> List[Dict]:
        """Get random targets"""
        all_targets = []
        
        for program, targets in self.targets.items():
            for target in targets:
                target['program'] = program
                all_targets.append(target)
        
        return random.sample(all_targets, min(count, len(all_targets)))
    
    def get_targets_by_technology(self, technology: str) -> List[Dict]:
        """Get targets by technology"""
        all_targets = []
        
        for program, targets in self.targets.items():
            for target in targets:
                if technology.lower() in target.get('technology', '').lower():
                    target['program'] = program
                    all_targets.append(target)
        
        return all_targets

class TargetDiscoveryEngine:
    """Main target discovery engine"""
    
    def __init__(self):
        self.dorking = DorkingEngine()
        self.gauplus = GAUPlusIntegration()
        self.gf = GFPatternMatcher()
        self.bugbounty = BugBountyTargetManager()
        self.pagodo = PagodoIntegration()
    
    def discover_targets(self, 
                        method: DiscoveryMethod = DiscoveryMethod.DORKING,
                        domain: str = None,
                        category: str = None,
                        technology: str = None,
                        max_results: int = 50,
                        pagodo_category: int = None,
                        pagodo_proxies: List[str] = None,
                        use_proxychains: bool = False) -> List[TargetInfo]:
        """Discover targets using specified method"""
        
        targets = []
        
        if method == DiscoveryMethod.DORKING:
            targets = self._discover_via_dorking(max_results)
        elif method == DiscoveryMethod.GAUPLUS and domain:
            targets = self._discover_via_gauplus(domain, max_results)
        elif method == DiscoveryMethod.GF_PATTERNS and domain:
            targets = self._discover_via_gf_patterns(domain, max_results)
        elif method == DiscoveryMethod.BUG_BOUNTY:
            targets = self._discover_via_bugbounty(category, technology, max_results)
        elif method == DiscoveryMethod.PAGODO:
            targets = self._discover_via_pagodo(domain, pagodo_category, max_results, pagodo_proxies, use_proxychains)
        elif method == DiscoveryMethod.RANDOM:
            targets = self._discover_random(max_results)
        
        return targets
    
    def _discover_via_dorking(self, max_results: int) -> List[TargetInfo]:
        """Discover targets via dorking"""
        targets = []
        
        for query_type in ['lfi_basic', 'lfi_advanced', 'lfi_specific']:
            urls = self.dorking.search_dorks(query_type, max_results // 3)
            
            for url in urls:
                target = TargetInfo(
                    url=url,
                    method=DiscoveryMethod.DORKING,
                    confidence=0.7,
                    source=f"dorking_{query_type}",
                    category="web_application",
                    parameters=self._extract_parameters(url),
                    technology="php",
                    notes=f"Discovered via {query_type} dorking"
                )
                targets.append(target)
        
        return targets[:max_results]
    
    def _discover_via_gauplus(self, domain: str, max_results: int) -> List[TargetInfo]:
        """Discover targets via GAU+"""
        urls = self.gauplus.discover_urls(domain, max_results)
        targets = []
        
        for url in urls:
            target = TargetInfo(
                url=url,
                method=DiscoveryMethod.GAUPLUS,
                confidence=0.8,
                source="gauplus",
                category="web_application",
                parameters=self._extract_parameters(url),
                technology="php",
                notes=f"Discovered via GAU+ for {domain}"
            )
            targets.append(target)
        
        return targets
    
    def _discover_via_gf_patterns(self, domain: str, max_results: int) -> List[TargetInfo]:
        """Discover targets via GF patterns"""
        targets = []
        
        # First get URLs from GAU+
        urls = self.gauplus.discover_urls(domain, max_results)
        
        for url in urls:
            # Check for LFI parameters using GF
            lfi_params = self.gf.discover_parameters(url, 'lfi')
            
            if lfi_params:
                target = TargetInfo(
                    url=url,
                    method=DiscoveryMethod.GF_PATTERNS,
                    confidence=0.9,
                    source="gf_patterns",
                    category="web_application",
                    parameters=lfi_params,
                    technology="php",
                    notes=f"Discovered via GF patterns for {domain}"
                )
                targets.append(target)
        
        return targets[:max_results]
    
    def _discover_via_bugbounty(self, category: str, technology: str, max_results: int) -> List[TargetInfo]:
        """Discover targets via bug bounty data"""
        targets = []
        
        if category:
            bugbounty_targets = self.bugbounty.get_targets_by_category(category)
        elif technology:
            bugbounty_targets = self.bugbounty.get_targets_by_technology(technology)
        else:
            bugbounty_targets = self.bugbounty.get_random_targets(max_results)
        
        for target_data in bugbounty_targets[:max_results]:
            target = TargetInfo(
                url=target_data.get('url', ''),
                method=DiscoveryMethod.BUG_BOUNTY,
                confidence=0.9,
                source="bug_bounty",
                category=target_data.get('category', 'web_application'),
                parameters=self._extract_parameters(target_data.get('url', '')),
                technology=target_data.get('technology', 'php'),
                notes=f"From {target_data.get('program', 'unknown')} program"
            )
            targets.append(target)
        
        return targets
    
    def _discover_random(self, max_results: int) -> List[TargetInfo]:
        """Discover random targets"""
        targets = []
        
        # Mix different discovery methods
        dorking_targets = self._discover_via_dorking(max_results // 2)
        bugbounty_targets = self._discover_via_bugbounty(None, None, max_results // 2)
        
        targets.extend(dorking_targets)
        targets.extend(bugbounty_targets)
        
        # Shuffle and return
        random.shuffle(targets)
        return targets[:max_results]
    
    def _discover_via_pagodo(self, domain: str, category: int, max_results: int, proxies: List[str], use_proxychains: bool = False) -> List[TargetInfo]:
        """Discover targets via pagodo Google dorking"""
        targets = []
        
        if not self.pagodo.is_available():
            print("❌ Pagodo not available, falling back to basic dorking")
            return self._discover_via_dorking(max_results)
        
        try:
            # Get dorks by category or all dorks
            if category:
                dorks = self.pagodo.get_dorks_by_category(category)
            else:
                dorks = self.pagodo.get_dorks_by_category()
            
            if not dorks:
                print("❌ No dorks available from pagodo")
                return []
            
            # Search using pagodo
            results = self.pagodo.search_targets(
                domain=domain,
                dorks=dorks,
                max_results=max_results,
                proxies=proxies,
                use_proxychains=use_proxychains
            )
            
            if "error" in results:
                print(f"❌ Pagodo search failed: {results['error']}")
                return []
            
            # Convert results to TargetInfo objects
            for dork, dork_data in results.get("dorks", {}).items():
                for url in dork_data.get("urls", []):
                    target = TargetInfo(
                        url=url,
                        method=DiscoveryMethod.PAGODO,
                        confidence=0.8,
                        source="pagodo",
                        category="web_application",
                        parameters=self._extract_parameters(url),
                        technology="php",
                        notes=f"Discovered via pagodo dork: {dork}"
                    )
                    targets.append(target)
            
            # Also add URLs from the URL list
            for url in results.get("urls", []):
                target = TargetInfo(
                    url=url,
                    method=DiscoveryMethod.PAGODO,
                    confidence=0.7,
                    source="pagodo_urls",
                    category="web_application",
                    parameters=self._extract_parameters(url),
                    technology="php",
                    notes="Discovered via pagodo URL list"
                )
                targets.append(target)
            
            return targets[:max_results]
            
        except Exception as e:
            print(f"❌ Error in pagodo discovery: {e}")
            return []
    
    def _extract_parameters(self, url: str) -> List[str]:
        """Extract parameters from URL"""
        try:
            from urllib.parse import urlparse, parse_qs
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            return list(params.keys())
        except:
            return []
    
    def get_target_categories(self) -> List[str]:
        """Get available target categories"""
        categories = set()
        
        for program, targets in self.bugbounty.targets.items():
            for target in targets:
                if 'category' in target:
                    categories.add(target['category'])
        
        return list(categories)
    
    def get_target_technologies(self) -> List[str]:
        """Get available target technologies"""
        technologies = set()
        
        for program, targets in self.bugbounty.targets.items():
            for target in targets:
                if 'technology' in target:
                    technologies.add(target['technology'])
        
        return list(technologies)
    
    def get_pagodo_categories(self) -> Dict[int, str]:
        """Get available pagodo categories"""
        if self.pagodo.is_available():
            return self.pagodo.get_available_categories()
        return {}

class PagodoIntegration:
    """Integration with pagodo for advanced Google dorking"""
    
    def __init__(self, pagodo_dir: str = None):
        self.pagodo_dir = pagodo_dir or self._setup_pagodo()
        self.ghdb_scraper_path = None
        self.pagodo_path = None
        self.dorks_file = None
        self.proxychains_path = None
        self.proxychains_config = None
        self._initialize_paths()
        self._detect_proxychains()
    
    def _setup_pagodo(self) -> str:
        """Setup pagodo in a temporary directory"""
        temp_dir = tempfile.mkdtemp(prefix="pagodo_")
        pagodo_path = os.path.join(temp_dir, "pagodo")
        
        try:
            # Clone pagodo repository
            print("🔧 Setting up pagodo...")
            subprocess.run([
                "git", "clone", "https://github.com/opsdisk/pagodo.git", pagodo_path
            ], check=True, timeout=60)
            
            # Setup virtual environment
            venv_path = os.path.join(pagodo_path, ".venv")
            subprocess.run([
                "python3", "-m", "venv", venv_path
            ], cwd=pagodo_path, check=True)
            
            # Install requirements
            pip_path = os.path.join(venv_path, "bin", "pip")
            subprocess.run([
                pip_path, "install", "--upgrade", "pip", "setuptools"
            ], cwd=pagodo_path, check=True)
            
            # Install pagodo requirements
            requirements_file = os.path.join(pagodo_path, "requirements.txt")
            if os.path.exists(requirements_file):
                subprocess.run([
                    pip_path, "install", "-r", "requirements.txt"
                ], cwd=pagodo_path, check=True)
            
            print("✅ Pagodo setup completed successfully")
            return pagodo_path
            
        except Exception as e:
            print(f"❌ Error setting up pagodo: {e}")
            return None
    
    def _initialize_paths(self):
        """Initialize paths to pagodo scripts"""
        if not self.pagodo_dir or not os.path.exists(self.pagodo_dir):
            return
        
        self.ghdb_scraper_path = os.path.join(self.pagodo_dir, "ghdb_scraper.py")
        self.pagodo_path = os.path.join(self.pagodo_dir, "pagodo.py")
        self.dorks_file = os.path.join(self.pagodo_dir, "dorks", "all_google_dorks.txt")
    
    def _detect_proxychains(self):
        """Detect and configure proxychains3"""
        # Try to find proxychains3 binary
        for cmd in ['proxychains3', 'proxychains4', 'proxychains']:
            try:
                result = subprocess.run(['which', cmd], capture_output=True, text=True)
                if result.returncode == 0:
                    self.proxychains_path = result.stdout.strip()
                    print(f"✅ Found proxychains: {self.proxychains_path}")
                    break
            except:
                continue
        
        # Set default config path
        if self.proxychains_path:
            if 'proxychains3' in self.proxychains_path:
                self.proxychains_config = '/etc/proxychains3.conf'
            elif 'proxychains4' in self.proxychains_path:
                self.proxychains_config = '/etc/proxychains4.conf'
            else:
                self.proxychains_config = '/etc/proxychains.conf'
    
    def is_proxychains_available(self) -> bool:
        """Check if proxychains is available"""
        return self.proxychains_path is not None and os.path.exists(self.proxychains_path)
    
    def create_proxychains_config(self, proxies: List[str], config_path: str = None) -> str:
        """Create a proxychains configuration file"""
        if not config_path:
            config_path = os.path.join(tempfile.gettempdir(), "proxychains.conf")
        
        config_content = f"""# Proxychains configuration for pagodo
# Generated by Liffy Enhanced Target Discovery

# Dynamic - Each connection will be chained
# Random - Each connection will use a random proxy
# Round_robin - Each connection will use the next proxy in the list
dynamic_chain

# Proxy DNS requests - no leak for DNS data
proxy_dns

# Some timeouts in milliseconds
tcp_read_time_out 15000
tcp_connect_time_out 8000

# ProxyList format
# type host port [user pass]
# Values in [] are optional
# Examples:
# socks5 127.0.0.1 9050
# http 127.0.0.1 8080 user pass
# socks4 127.0.0.1 9050

[ProxyList]
"""
        
        # Add proxies to config
        for proxy in proxies:
            if proxy.startswith('http://'):
                config_content += f"http {proxy.replace('http://', '').split(':')[0]} {proxy.split(':')[-1]}\n"
            elif proxy.startswith('socks4://'):
                config_content += f"socks4 {proxy.replace('socks4://', '').split(':')[0]} {proxy.split(':')[-1]}\n"
            elif proxy.startswith('socks5://'):
                config_content += f"socks5 {proxy.replace('socks5://', '').split(':')[0]} {proxy.split(':')[-1]}\n"
            elif proxy.startswith('socks5h://'):
                config_content += f"socks5 {proxy.replace('socks5h://', '').split(':')[0]} {proxy.split(':')[-1]}\n"
            else:
                # Assume it's in host:port format
                if ':' in proxy:
                    host, port = proxy.split(':')
                    config_content += f"http {host} {port}\n"
        
        # Write config file
        with open(config_path, 'w') as f:
            f.write(config_content)
        
        return config_path
    
    def is_available(self) -> bool:
        """Check if pagodo is available and properly configured"""
        return (
            self.pagodo_dir and 
            os.path.exists(self.pagodo_dir) and
            os.path.exists(self.ghdb_scraper_path) and
            os.path.exists(self.pagodo_path)
        )
    
    def update_dorks(self, force_update: bool = False) -> bool:
        """Update Google dorks using ghdb_scraper.py"""
        if not self.is_available():
            print("❌ Pagodo not available")
            return False
        
        # Check if dorks file exists and is recent
        if not force_update and self.dorks_file and os.path.exists(self.dorks_file):
            # Check if file is less than 24 hours old
            file_age = time.time() - os.path.getmtime(self.dorks_file)
            if file_age < 86400:  # 24 hours
                print("✅ Dorks file is recent, skipping update")
                return True
        
        try:
            print("🔄 Updating Google dorks...")
            
            # Use virtual environment python
            venv_python = os.path.join(self.pagodo_dir, ".venv", "bin", "python")
            
            # Run ghdb_scraper with all options
            cmd = [
                venv_python, "ghdb_scraper.py", 
                "-s",  # Save all dorks to file
                "-j",  # Save JSON response
                "-i"   # Save individual categories
            ]
            
            result = subprocess.run(
                cmd, 
                cwd=self.pagodo_dir, 
                capture_output=True, 
                text=True, 
                timeout=300  # 5 minutes timeout
            )
            
            if result.returncode == 0:
                print("✅ Google dorks updated successfully")
                return True
            else:
                print(f"❌ Error updating dorks: {result.stderr}")
                return False
                
        except subprocess.TimeoutExpired:
            print("❌ Dork update timed out")
            return False
        except Exception as e:
            print(f"❌ Error updating dorks: {e}")
            return False
    
    def get_dorks_by_category(self, category: int = None) -> List[str]:
        """Get dorks by category or all dorks"""
        if not self.is_available():
            return []
        
        dorks = []
        
        try:
            if category:
                # Get specific category dorks
                category_file = os.path.join(
                    self.pagodo_dir, "dorks", f"category_{category}.txt"
                )
                if os.path.exists(category_file):
                    with open(category_file, 'r') as f:
                        dorks = [line.strip() for line in f if line.strip()]
            else:
                # Get all dorks
                if os.path.exists(self.dorks_file):
                    with open(self.dorks_file, 'r') as f:
                        dorks = [line.strip() for line in f if line.strip()]
            
            return dorks
            
        except Exception as e:
            print(f"❌ Error reading dorks: {e}")
            return []
    
    def search_targets(self, 
                      domain: str = None, 
                      dorks: List[str] = None,
                      max_results: int = 100,
                      min_delay: int = 2,
                      max_delay: int = 5,
                      proxies: List[str] = None,
                      use_proxychains: bool = False) -> Dict[str, Any]:
        """Search for targets using pagodo"""
        if not self.is_available():
            return {"error": "Pagodo not available"}
        
        # Update dorks if needed
        if not self.update_dorks():
            return {"error": "Failed to update dorks"}
        
        # Use provided dorks or get all dorks
        if not dorks:
            dorks = self.get_dorks_by_category()
            if not dorks:
                return {"error": "No dorks available"}
        
        # Limit dorks for testing
        dorks = dorks[:50]  # Limit to first 50 dorks for testing
        
        try:
            print(f"🔍 Searching with {len(dorks)} dorks...")
            
            # Create temporary dorks file
            temp_dorks_file = os.path.join(tempfile.gettempdir(), "temp_dorks.txt")
            with open(temp_dorks_file, 'w') as f:
                for dork in dorks:
                    f.write(dork + '\n')
            
            # Prepare pagodo command
            venv_python = os.path.join(self.pagodo_dir, ".venv", "bin", "python")
            cmd = [
                venv_python, "pagodo.py",
                "-g", temp_dorks_file,
                "-m", str(max_results),
                "-i", str(min_delay),
                "-x", str(max_delay),
                "-o", os.path.join(tempfile.gettempdir(), "pagodo_results.json"),
                "-s", os.path.join(tempfile.gettempdir(), "pagodo_urls.txt")
            ]
            
            # Add domain if specified
            if domain:
                cmd.extend(["-d", domain])
            
            # Handle proxy configuration
            if use_proxychains and self.is_proxychains_available() and proxies:
                # Use proxychains3 with custom config
                config_path = self.create_proxychains_config(proxies)
                cmd = [self.proxychains_path, "-f", config_path] + cmd
                print(f"🔗 Using proxychains3 with {len(proxies)} proxies")
            elif proxies:
                # Use pagodo's built-in proxy support
                proxy_string = ",".join(proxies)
                cmd.extend(["-p", proxy_string])
                print(f"🔗 Using pagodo built-in proxy support with {len(proxies)} proxies")
            
            # Run pagodo
            result = subprocess.run(
                cmd,
                cwd=self.pagodo_dir,
                capture_output=True,
                text=True,
                timeout=1800  # 30 minutes timeout
            )
            
            # Parse results
            results = self._parse_pagodo_results()
            
            # Cleanup
            try:
                os.remove(temp_dorks_file)
            except:
                pass
            
            return results
            
        except subprocess.TimeoutExpired:
            return {"error": "Search timed out"}
        except Exception as e:
            return {"error": f"Search failed: {e}"}
    
    def _parse_pagodo_results(self) -> Dict[str, Any]:
        """Parse pagodo results from output files"""
        results = {
            "dorks": {},
            "total_urls": 0,
            "initiation_timestamp": None,
            "completion_timestamp": None,
            "urls": []
        }
        
        try:
            # Parse JSON results
            json_file = os.path.join(tempfile.gettempdir(), "pagodo_results.json")
            if os.path.exists(json_file):
                with open(json_file, 'r') as f:
                    data = json.load(f)
                    results.update(data)
            
            # Parse URL list
            urls_file = os.path.join(tempfile.gettempdir(), "pagodo_urls.txt")
            if os.path.exists(urls_file):
                with open(urls_file, 'r') as f:
                    urls = [line.strip() for line in f if line.strip()]
                    results["urls"] = urls
                    results["total_urls"] = len(urls)
            
            return results
            
        except Exception as e:
            print(f"❌ Error parsing results: {e}")
            return results
    
    def get_available_categories(self) -> Dict[int, str]:
        """Get available dork categories"""
        return {
            1: "Footholds",
            2: "File Containing Usernames", 
            3: "Sensitives Directories",
            4: "Web Server Detection",
            5: "Vulnerable Files",
            6: "Vulnerable Servers",
            7: "Error Messages",
            8: "File Containing Juicy Info",
            9: "File Containing Passwords",
            10: "Sensitive Online Shopping Info",
            11: "Network or Vulnerability Data",
            12: "Pages Containing Login Portals",
            13: "Various Online devices",
            14: "Advisories and Vulnerabilities"
        }
    
    def test_proxychains(self, test_url: str = "http://httpbin.org/ip") -> bool:
        """Test proxychains3 configuration"""
        if not self.is_proxychains_available():
            print("❌ Proxychains not available")
            return False
        
        try:
            # Test with a simple curl command
            cmd = [self.proxychains_path, "curl", "-s", test_url]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                print("✅ Proxychains3 test successful")
                print(f"Response: {result.stdout.strip()}")
                return True
            else:
                print(f"❌ Proxychains3 test failed: {result.stderr}")
                return False
                
        except Exception as e:
            print(f"❌ Proxychains3 test error: {e}")
            return False
    
    def cleanup(self):
        """Cleanup temporary files and directories"""
        try:
            if self.pagodo_dir and os.path.exists(self.pagodo_dir):
                shutil.rmtree(self.pagodo_dir)
        except:
            pass

def main():
    """Test the target discovery system"""
    engine = TargetDiscoveryEngine()
    
    print("🔍 Target Discovery Engine Test")
    print("=" * 50)
    
    # Test dorking
    print("\n1. Testing Dorking Engine...")
    dorking_targets = engine.discover_targets(DiscoveryMethod.DORKING, max_results=5)
    print(f"Found {len(dorking_targets)} targets via dorking")
    
    # Test bug bounty
    print("\n2. Testing Bug Bounty Integration...")
    bugbounty_targets = engine.discover_targets(DiscoveryMethod.BUG_BOUNTY, max_results=5)
    print(f"Found {len(bugbounty_targets)} targets via bug bounty")
    
    # Test pagodo
    print("\n3. Testing Pagodo Integration...")
    if engine.pagodo.is_available():
        pagodo_targets = engine.discover_targets(DiscoveryMethod.PAGODO, max_results=5)
        print(f"Found {len(pagodo_targets)} targets via pagodo")
        
        # Show pagodo categories
        print("\n4. Available Pagodo Categories:")
        pagodo_categories = engine.get_pagodo_categories()
        for cat_id, cat_name in list(pagodo_categories.items())[:5]:
            print(f"  - {cat_id}: {cat_name}")
    else:
        print("❌ Pagodo not available")
    
    # Test random
    print("\n5. Testing Random Discovery...")
    random_targets = engine.discover_targets(DiscoveryMethod.RANDOM, max_results=5)
    print(f"Found {len(random_targets)} targets via random discovery")
    
    # Show categories
    print("\n6. Available Bug Bounty Categories:")
    categories = engine.get_target_categories()
    for category in categories[:10]:
        print(f"  - {category}")
    
    # Show technologies
    print("\n7. Available Technologies:")
    technologies = engine.get_target_technologies()
    for tech in technologies[:10]:
        print(f"  - {tech}")

if __name__ == "__main__":
    main()
