#!/usr/bin/env python3
"""
Liffy Ultimate - Advanced LFI Exploitation Framework
Metasploit-style CLI with comprehensive menu system
"""

__author__ = 'rotlogix'
__author__ = 'unicornFurnace'
__version__ = '3.0.0'
__codename__ = 'ShadowStrike'

import argparse
import sys
import os
import time
import json
import threading
import subprocess
from pathlib import Path
from typing import Optional, Dict, List, Any, Union
import datetime
import signal
import readline
import shutil
from dataclasses import dataclass
from enum import Enum

# Enhanced terminal colors and formatting
try:
    from blessings import Terminal
    t = Terminal()
except ImportError:
    class Terminal:
        def __getattr__(self, name):
            return lambda x: x
    t = Terminal()

# Import liffy modules
try:
    import core_enhanced
    import liffy_techniques
    import target_discovery
    import url_gatherer
    import hunt_mode
    import api_mode
except ImportError as e:
    print(f"[!] Error importing modules: {e}")
    print("[!] Make sure all required modules are available")
    sys.exit(1)

class ModuleType(Enum):
    EXPLOIT = "exploit"
    AUXILIARY = "auxiliary"
    POST = "post"
    ENCODER = "encoder"
    PAYLOAD = "payload"
    NOPS = "nops"

class ModuleCategory(Enum):
    LFI = "lfi"
    RFI = "rfi"
    LOG_POISONING = "log_poisoning"
    FILTER = "filter"
    DATA_WRAPPER = "data_wrapper"
    INPUT_WRAPPER = "input_wrapper"
    EXPECT_WRAPPER = "expect_wrapper"
    ENVIRON = "environ"
    ZIP_WRAPPER = "zip_wrapper"
    PHAR_WRAPPER = "phar_wrapper"
    COMPRESS_WRAPPER = "compress_wrapper"
    AUTO_DETECTION = "auto_detection"
    TARGET_DISCOVERY = "target_discovery"
    URL_GATHERING = "url_gathering"
    HUNTING = "hunting"
    API_MODE = "api_mode"

@dataclass
class Module:
    name: str
    description: str
    module_type: ModuleType
    category: ModuleCategory
    rank: str = "normal"
    author: str = "rotlogix"
    references: List[str] = None
    targets: List[str] = None
    options: Dict[str, Any] = None

class LiffyUltimate:
    """Main Liffy Ultimate Framework"""
    
    def __init__(self):
        self.terminal = t
        self.current_module = None
        self.modules = self._load_modules()
        self.history = []
        self.session_id = self._generate_session_id()
        self.running = True
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        
        # Setup readline for command history
        self._setup_readline()
        
    def _generate_session_id(self) -> str:
        """Generate unique session ID"""
        import uuid
        return str(uuid.uuid4())[:8]
    
    def _setup_readline(self):
        """Setup readline for command history"""
        histfile = os.path.expanduser("~/.liffy_history")
        try:
            readline.read_history_file(histfile)
        except FileNotFoundError:
            pass
        
        def save_history():
            readline.write_history_file(histfile)
        
        import atexit
        atexit.register(save_history)
    
    def _signal_handler(self, signum, frame):
        """Handle interrupt signals"""
        print(f"\n[{self.terminal.red('!')}] Interrupted by user")
        self.running = False
        sys.exit(0)
    
    def _load_modules(self) -> Dict[str, Module]:
        """Load all available modules"""
        modules = {}
        
        # LFI Exploit Modules
        modules['exploit/lfi/data'] = Module(
            name="exploit/lfi/data",
            description="LFI via data:// wrapper",
            module_type=ModuleType.EXPLOIT,
            category=ModuleCategory.DATA_WRAPPER,
            rank="excellent",
            author="rotlogix",
            references=["https://www.php.net/manual/en/wrappers.data.php"],
            targets=["PHP"],
            options={
                'URL': {'required': True, 'description': 'Target URL with LFI parameter'},
                'LHOST': {'required': True, 'description': 'Callback host for reverse shell'},
                'LPORT': {'required': True, 'description': 'Callback port for reverse shell'},
                'AUTO_IP': {'required': False, 'description': 'Auto-detect IP address', 'default': False},
                'AUTO_PORT': {'required': False, 'description': 'Auto-detect available port', 'default': False}
            }
        )
        
        modules['exploit/lfi/input'] = Module(
            name="exploit/lfi/input",
            description="LFI via php://input wrapper",
            module_type=ModuleType.EXPLOIT,
            category=ModuleCategory.INPUT_WRAPPER,
            rank="excellent",
            author="rotlogix",
            references=["https://www.php.net/manual/en/wrappers.php.php"],
            targets=["PHP"],
            options={
                'URL': {'required': True, 'description': 'Target URL with LFI parameter'},
                'LHOST': {'required': True, 'description': 'Callback host for reverse shell'},
                'LPORT': {'required': True, 'description': 'Callback port for reverse shell'},
                'AUTO_IP': {'required': False, 'description': 'Auto-detect IP address', 'default': False},
                'AUTO_PORT': {'required': False, 'description': 'Auto-detect available port', 'default': False}
            }
        )
        
        modules['exploit/lfi/expect'] = Module(
            name="exploit/lfi/expect",
            description="LFI via expect:// wrapper",
            module_type=ModuleType.EXPLOIT,
            category=ModuleCategory.EXPECT_WRAPPER,
            rank="good",
            author="rotlogix",
            references=["https://www.php.net/manual/en/wrappers.expect.php"],
            targets=["PHP with expect extension"],
            options={
                'URL': {'required': True, 'description': 'Target URL with LFI parameter'},
                'LHOST': {'required': True, 'description': 'Callback host for reverse shell'},
                'LPORT': {'required': True, 'description': 'Callback port for reverse shell'},
                'AUTO_IP': {'required': False, 'description': 'Auto-detect IP address', 'default': False},
                'AUTO_PORT': {'required': False, 'description': 'Auto-detect available port', 'default': False}
            }
        )
        
        modules['exploit/lfi/environ'] = Module(
            name="exploit/lfi/environ",
            description="LFI via /proc/self/environ",
            module_type=ModuleType.EXPLOIT,
            category=ModuleCategory.ENVIRON,
            rank="good",
            author="rotlogix",
            references=["https://www.kernel.org/doc/Documentation/filesystems/proc.txt"],
            targets=["Linux"],
            options={
                'URL': {'required': True, 'description': 'Target URL with LFI parameter'},
                'LHOST': {'required': True, 'description': 'Callback host for reverse shell'},
                'LPORT': {'required': True, 'description': 'Callback port for reverse shell'},
                'AUTO_IP': {'required': False, 'description': 'Auto-detect IP address', 'default': False},
                'AUTO_PORT': {'required': False, 'description': 'Auto-detect available port', 'default': False}
            }
        )
        
        modules['exploit/lfi/access_logs'] = Module(
            name="exploit/lfi/access_logs",
            description="LFI via Apache access log poisoning",
            module_type=ModuleType.EXPLOIT,
            category=ModuleCategory.LOG_POISONING,
            rank="good",
            author="rotlogix",
            references=["https://httpd.apache.org/docs/current/logs.html"],
            targets=["Apache"],
            options={
                'URL': {'required': True, 'description': 'Target URL with LFI parameter'},
                'LHOST': {'required': True, 'description': 'Callback host for reverse shell'},
                'LPORT': {'required': True, 'description': 'Callback port for reverse shell'},
                'LOCATION': {'required': False, 'description': 'Path to access log file', 'default': '/var/log/apache2/access.log'},
                'AUTO_IP': {'required': False, 'description': 'Auto-detect IP address', 'default': False},
                'AUTO_PORT': {'required': False, 'description': 'Auto-detect available port', 'default': False}
            }
        )
        
        modules['exploit/lfi/ssh_logs'] = Module(
            name="exploit/lfi/ssh_logs",
            description="LFI via SSH auth log poisoning",
            module_type=ModuleType.EXPLOIT,
            category=ModuleCategory.LOG_POISONING,
            rank="good",
            author="rotlogix",
            references=["https://www.openssh.com/"],
            targets=["Linux with SSH"],
            options={
                'URL': {'required': True, 'description': 'Target URL with LFI parameter'},
                'LHOST': {'required': True, 'description': 'Callback host for reverse shell'},
                'LPORT': {'required': True, 'description': 'Callback port for reverse shell'},
                'LOCATION': {'required': False, 'description': 'Path to SSH auth log file', 'default': '/var/log/auth.log'},
                'AUTO_IP': {'required': False, 'description': 'Auto-detect IP address', 'default': False},
                'AUTO_PORT': {'required': False, 'description': 'Auto-detect available port', 'default': False}
            }
        )
        
        modules['exploit/lfi/filter'] = Module(
            name="exploit/lfi/filter",
            description="LFI via php://filter wrapper",
            module_type=ModuleType.EXPLOIT,
            category=ModuleCategory.FILTER,
            rank="excellent",
            author="rotlogix",
            references=["https://www.php.net/manual/en/wrappers.php.php"],
            targets=["PHP"],
            options={
                'URL': {'required': True, 'description': 'Target URL with LFI parameter'},
                'FILE': {'required': True, 'description': 'File to read (e.g., /etc/passwd)'},
                'ENCODING': {'required': False, 'description': 'Filter encoding', 'default': 'base64-encode'}
            }
        )
        
        modules['exploit/lfi/zip'] = Module(
            name="exploit/lfi/zip",
            description="LFI via zip:// wrapper",
            module_type=ModuleType.EXPLOIT,
            category=ModuleCategory.ZIP_WRAPPER,
            rank="good",
            author="rotlogix",
            references=["https://www.php.net/manual/en/wrappers.compression.php"],
            targets=["PHP"],
            options={
                'URL': {'required': True, 'description': 'Target URL with LFI parameter'},
                'LHOST': {'required': True, 'description': 'Callback host for reverse shell'},
                'LPORT': {'required': True, 'description': 'Callback port for reverse shell'},
                'AUTO_IP': {'required': False, 'description': 'Auto-detect IP address', 'default': False},
                'AUTO_PORT': {'required': False, 'description': 'Auto-detect available port', 'default': False}
            }
        )
        
        modules['exploit/lfi/phar'] = Module(
            name="exploit/lfi/phar",
            description="LFI via phar:// wrapper",
            module_type=ModuleType.EXPLOIT,
            category=ModuleCategory.PHAR_WRAPPER,
            rank="good",
            author="rotlogix",
            references=["https://www.php.net/manual/en/intro.phar.php"],
            targets=["PHP"],
            options={
                'URL': {'required': True, 'description': 'Target URL with LFI parameter'},
                'LHOST': {'required': True, 'description': 'Callback host for reverse shell'},
                'LPORT': {'required': True, 'description': 'Callback port for reverse shell'},
                'AUTO_IP': {'required': False, 'description': 'Auto-detect IP address', 'default': False},
                'AUTO_PORT': {'required': False, 'description': 'Auto-detect available port', 'default': False}
            }
        )
        
        modules['exploit/lfi/compress'] = Module(
            name="exploit/lfi/compress",
            description="LFI via compress.zlib:// wrapper",
            module_type=ModuleType.EXPLOIT,
            category=ModuleCategory.COMPRESS_WRAPPER,
            rank="good",
            author="rotlogix",
            references=["https://www.php.net/manual/en/wrappers.compression.php"],
            targets=["PHP"],
            options={
                'URL': {'required': True, 'description': 'Target URL with LFI parameter'},
                'LHOST': {'required': True, 'description': 'Callback host for reverse shell'},
                'LPORT': {'required': True, 'description': 'Callback port for reverse shell'},
                'AUTO_IP': {'required': False, 'description': 'Auto-detect IP address', 'default': False},
                'AUTO_PORT': {'required': False, 'description': 'Auto-detect available port', 'default': False}
            }
        )
        
        modules['exploit/lfi/auto'] = Module(
            name="exploit/lfi/auto",
            description="Automatic LFI technique detection and exploitation",
            module_type=ModuleType.EXPLOIT,
            category=ModuleCategory.AUTO_DETECTION,
            rank="excellent",
            author="rotlogix",
            references=["https://owasp.org/www-community/attacks/File_Inclusion"],
            targets=["Multiple"],
            options={
                'URL': {'required': True, 'description': 'Target URL with LFI parameter'},
                'LHOST': {'required': True, 'description': 'Callback host for reverse shell'},
                'LPORT': {'required': True, 'description': 'Callback port for reverse shell'},
                'AUTO_IP': {'required': False, 'description': 'Auto-detect IP address', 'default': False},
                'AUTO_PORT': {'required': False, 'description': 'Auto-detect available port', 'default': False}
            }
        )
        
        # Auxiliary Modules
        modules['auxiliary/lfi/scanner'] = Module(
            name="auxiliary/lfi/scanner",
            description="LFI vulnerability scanner",
            module_type=ModuleType.AUXILIARY,
            category=ModuleCategory.LFI,
            rank="normal",
            author="rotlogix",
            references=["https://owasp.org/www-community/attacks/File_Inclusion"],
            targets=["Web Applications"],
            options={
                'URLS': {'required': True, 'description': 'File containing URLs to scan'},
                'THREADS': {'required': False, 'description': 'Number of threads', 'default': 10},
                'TIMEOUT': {'required': False, 'description': 'Request timeout', 'default': 30}
            }
        )
        
        modules['auxiliary/lfi/batch_exploit'] = Module(
            name="auxiliary/lfi/batch_exploit",
            description="Batch LFI exploitation with multiple techniques",
            module_type=ModuleType.AUXILIARY,
            category=ModuleCategory.LFI,
            rank="normal",
            author="rotlogix",
            references=["https://owasp.org/www-community/attacks/File_Inclusion"],
            targets=["Multiple"],
            options={
                'URLS': {'required': True, 'description': 'File containing URLs to exploit'},
                'TECHNIQUES': {'required': False, 'description': 'Comma-separated list of techniques', 'default': 'data,input,filter,auto'},
                'THREADS': {'required': False, 'description': 'Number of threads', 'default': 4},
                'OUTPUT': {'required': False, 'description': 'Output file for results', 'default': 'liffy_results.json'}
            }
        )
        
        # Target Discovery Modules
        modules['auxiliary/discovery/target_finder'] = Module(
            name="auxiliary/discovery/target_finder",
            description="Advanced target discovery and enumeration",
            module_type=ModuleType.AUXILIARY,
            category=ModuleCategory.TARGET_DISCOVERY,
            rank="normal",
            author="rotlogix",
            references=["https://github.com/OWASP/Amass"],
            targets=["Web Applications"],
            options={
                'DOMAIN': {'required': True, 'description': 'Target domain'},
                'SUBDOMAINS': {'required': False, 'description': 'Include subdomains', 'default': True},
                'THREADS': {'required': False, 'description': 'Number of threads', 'default': 10}
            }
        )
        
        modules['auxiliary/discovery/url_gatherer'] = Module(
            name="auxiliary/discovery/url_gatherer",
            description="URL gathering and parameter extraction",
            module_type=ModuleType.AUXILIARY,
            category=ModuleCategory.URL_GATHERING,
            rank="normal",
            author="rotlogix",
            references=["https://github.com/lc/gau"],
            targets=["Web Applications"],
            options={
                'DOMAIN': {'required': True, 'description': 'Target domain'},
                'OUTPUT': {'required': False, 'description': 'Output file for URLs', 'default': 'urls.txt'},
                'THREADS': {'required': False, 'description': 'Number of threads', 'default': 10}
            }
        )
        
        # Hunting Modules
        modules['auxiliary/hunting/lfi_hunter'] = Module(
            name="auxiliary/hunting/lfi_hunter",
            description="Automated LFI hunting and exploitation",
            module_type=ModuleType.AUXILIARY,
            category=ModuleCategory.HUNTING,
            rank="normal",
            author="rotlogix",
            references=["https://github.com/OWASP/Amass"],
            targets=["Web Applications"],
            options={
                'TARGET': {'required': True, 'description': 'Target domain or IP'},
                'TECHNIQUES': {'required': False, 'description': 'Comma-separated list of techniques', 'default': 'data,input,filter,auto'},
                'THREADS': {'required': False, 'description': 'Number of threads', 'default': 4},
                'OUTPUT': {'required': False, 'description': 'Output file for results', 'default': 'hunt_results.json'}
            }
        )
        
        # API Mode
        modules['auxiliary/api/rest_api'] = Module(
            name="auxiliary/api/rest_api",
            description="REST API server for Liffy Ultimate",
            module_type=ModuleType.AUXILIARY,
            category=ModuleCategory.API_MODE,
            rank="normal",
            author="rotlogix",
            references=["https://flask.palletsprojects.com/"],
            targets=["API Integration"],
            options={
                'HOST': {'required': False, 'description': 'API server host', 'default': '127.0.0.1'},
                'PORT': {'required': False, 'description': 'API server port', 'default': 8080},
                'DEBUG': {'required': False, 'description': 'Enable debug mode', 'default': False}
            }
        )
        
        return modules
    
    def banner(self):
        """Display the main banner"""
        banner = f"""
{self.terminal.bold_red('    ██╗     ██╗███████╗███████╗██╗   ██╗')}
{self.terminal.bold_red('    ██║     ██║██╔════╝██╔════╝╚██╗ ██╔╝')}
{self.terminal.bold_red('    ██║     ██║█████╗  █████╗   ╚████╔╝ ')}
{self.terminal.bold_red('    ██║     ██║██╔══╝  ██╔══╝    ╚██╔╝  ')}
{self.terminal.bold_red('    ███████╗██║██║     ███████╗   ██║   ')}
{self.terminal.bold_red('    ╚══════╝╚═╝╚═╝     ╚══════╝   ╚═╝   ')}
{self.terminal.bold_cyan('    ╔═══════════════════════════════════════╗')}
{self.terminal.bold_cyan('    ║           ULTIMATE FRAMEWORK          ║')}
{self.terminal.bold_cyan('    ║        Advanced LFI Exploitation      ║')}
{self.terminal.bold_cyan('    ╚═══════════════════════════════════════╝')}

{self.terminal.bold_green('Codename:')} {self.terminal.bold_white('ShadowStrike')} {self.terminal.bold_red('v3.0.0')}
{self.terminal.bold_green('Author:')} {self.terminal.bold_white('rotlogix & unicornFurnace')}
{self.terminal.bold_green('Session:')} {self.terminal.bold_white(self.session_id)}
{self.terminal.bold_green('Type:')} {self.terminal.bold_white('help')} {self.terminal.bold_red('or')} {self.terminal.bold_white('?')} {self.terminal.bold_red('for more commands')}
"""
        print(banner)
    
    def show_help(self):
        """Display help information"""
        help_text = f"""
{self.terminal.bold_cyan('Core Commands')}
===============
{self.terminal.bold_green('help')}                    Show this help message
{self.terminal.bold_green('exit')} / {self.terminal.bold_green('quit')}              Exit the framework
{self.terminal.bold_green('version')}                Show version information
{self.terminal.bold_green('banner')}                 Display banner
{self.terminal.bold_green('clear')} / {self.terminal.bold_green('cls')}              Clear screen

{self.terminal.bold_cyan('Module Commands')}
==================
{self.terminal.bold_green('use')} <module>            Use a module
{self.terminal.bold_green('search')} <keyword>        Search for modules
{self.terminal.bold_green('show')} <type>             Show modules by type
{self.terminal.bold_green('info')}                    Show current module info
{self.terminal.bold_green('back')}                    Exit current module

{self.terminal.bold_cyan('Module Options')}
==================
{self.terminal.bold_green('set')} <option> <value>    Set module option
{self.terminal.bold_green('unset')} <option>          Unset module option
{self.terminal.bold_green('show')} {self.terminal.bold_red('options')}              Show module options
{self.terminal.bold_green('run')} / {self.terminal.bold_green('exploit')}            Run the module

{self.terminal.bold_cyan('Utility Commands')}
==================
{self.terminal.bold_green('history')}                 Show command history
{self.terminal.bold_green('sessions')}                Show active sessions
{self.terminal.bold_green('jobs')}                    Show background jobs
{self.terminal.bold_green('kill')} <job_id>           Kill background job

{self.terminal.bold_cyan('Module Types')}
================
{self.terminal.bold_red('exploit')}                   LFI exploitation modules
{self.terminal.bold_red('auxiliary')}                 Auxiliary modules (scanners, etc.)
{self.terminal.bold_red('post')}                      Post-exploitation modules
{self.terminal.bold_red('payload')}                   Payload modules
{self.terminal.bold_red('encoder')}                   Encoder modules
{self.terminal.bold_red('nops')}                      NOP modules

{self.terminal.bold_cyan('Examples')}
===========
{self.terminal.bold_white('use exploit/lfi/data')}
{self.terminal.bold_white('set URL http://target/file.php?page=')}
{self.terminal.bold_white('set LHOST 192.168.1.100')}
{self.terminal.bold_white('set LPORT 4444')}
{self.terminal.bold_white('run')}

{self.terminal.bold_white('search filter')}
{self.terminal.bold_white('show auxiliary')}
{self.terminal.bold_white('use auxiliary/lfi/scanner')}
"""
        print(help_text)
    
    def show_version(self):
        """Show version information"""
        version_info = f"""
{self.terminal.bold_cyan('Liffy Ultimate Framework')}
{self.terminal.bold_red('Version:')} {self.terminal.bold_white(__version__)}
{self.terminal.bold_red('Codename:')} {self.terminal.bold_white(__codename__)}
{self.terminal.bold_red('Author:')} {self.terminal.bold_white(__author__)}
{self.terminal.bold_red('Python:')} {self.terminal.bold_white(sys.version.split()[0])}
{self.terminal.bold_red('Platform:')} {self.terminal.bold_white(sys.platform)}
{self.terminal.bold_red('Session ID:')} {self.terminal.bold_white(self.session_id)}
"""
        print(version_info)
    
    def search_modules(self, keyword: str):
        """Search for modules by keyword"""
        results = []
        keyword_lower = keyword.lower()
        
        for module_name, module in self.modules.items():
            if (keyword_lower in module_name.lower() or 
                keyword_lower in module.description.lower() or
                keyword_lower in module.category.value.lower()):
                results.append((module_name, module))
        
        if results:
            print(f"\n{self.terminal.bold_cyan('Matching modules:')}")
            print(f"{self.terminal.bold_cyan('=' * 50)}")
            for module_name, module in results:
                print(f"{self.terminal.bold_green(module_name):<30} {self.terminal.bold_white(module.description)}")
        else:
            print(f"{self.terminal.bold_red('No modules found matching:')} {keyword}")
    
    def show_modules(self, module_type: str = None):
        """Show modules by type"""
        if module_type:
            filtered_modules = {k: v for k, v in self.modules.items() 
                             if v.module_type.value == module_type}
        else:
            filtered_modules = self.modules
        
        if not filtered_modules:
            print(f"{self.terminal.bold_red('No modules found')}")
            return
        
        print(f"\n{self.terminal.bold_cyan('Available modules:')}")
        print(f"{self.terminal.bold_cyan('=' * 80)}")
        
        # Group by module type
        by_type = {}
        for module_name, module in filtered_modules.items():
            if module.module_type.value not in by_type:
                by_type[module.module_type.value] = []
            by_type[module.module_type.value].append((module_name, module))
        
        for module_type_name, modules in by_type.items():
            print(f"\n{self.terminal.bold_red(module_type_name.upper())}")
            print(f"{self.terminal.bold_red('-' * len(module_type_name))}")
            for module_name, module in modules:
                print(f"  {self.terminal.bold_green(module_name):<35} {self.terminal.bold_white(module.description)}")
    
    def use_module(self, module_name: str):
        """Use a specific module"""
        if module_name not in self.modules:
            print(f"{self.terminal.bold_red('Module not found:')} {module_name}")
            return False
        
        self.current_module = self.modules[module_name]
        print(f"{self.terminal.bold_green('Using module:')} {module_name}")
        return True
    
    def show_module_info(self):
        """Show current module information"""
        if not self.current_module:
            print(f"{self.terminal.bold_red('No module selected')}")
            return
        
        module = self.current_module
        print(f"\n{self.terminal.bold_cyan('Module Information')}")
        print(f"{self.terminal.bold_cyan('=' * 50)}")
        print(f"{self.terminal.bold_green('Name:')} {module.name}")
        print(f"{self.terminal.bold_green('Description:')} {module.description}")
        print(f"{self.terminal.bold_green('Type:')} {module.module_type.value}")
        print(f"{self.terminal.bold_green('Category:')} {module.category.value}")
        print(f"{self.terminal.bold_green('Rank:')} {module.rank}")
        print(f"{self.terminal.bold_green('Author:')} {module.author}")
        
        if module.references:
            print(f"{self.terminal.bold_green('References:')}")
            for ref in module.references:
                print(f"  {self.terminal.bold_white(ref)}")
        
        if module.targets:
            print(f"{self.terminal.bold_green('Targets:')} {', '.join(module.targets)}")
        
        if module.options:
            print(f"\n{self.terminal.bold_cyan('Module Options')}")
            print(f"{self.terminal.bold_cyan('=' * 30)}")
            for option, details in module.options.items():
                required = "Yes" if details.get('required', False) else "No"
                default = details.get('default', 'None')
                print(f"{self.terminal.bold_green(option):<15} {self.terminal.bold_white(required):<8} {self.terminal.bold_white(str(default)):<10} {details.get('description', '')}")
    
    def run_module(self):
        """Run the current module"""
        if not self.current_module:
            print(f"{self.terminal.bold_red('No module selected')}")
            return
        
        module = self.current_module
        print(f"{self.terminal.bold_green('Running module:')} {module.name}")
        
        # Check required options
        missing_options = []
        for option, details in module.options.items():
            if details.get('required', False) and option not in getattr(self, 'module_options', {}):
                missing_options.append(option)
        
        if missing_options:
            print(f"{self.terminal.bold_red('Missing required options:')} {', '.join(missing_options)}")
            return
        
        # Execute module based on type
        try:
            if module.category == ModuleCategory.DATA_WRAPPER:
                self._run_data_wrapper()
            elif module.category == ModuleCategory.INPUT_WRAPPER:
                self._run_input_wrapper()
            elif module.category == ModuleCategory.FILTER:
                self._run_filter_wrapper()
            elif module.category == ModuleCategory.AUTO_DETECTION:
                self._run_auto_detection()
            elif module.category == ModuleCategory.TARGET_DISCOVERY:
                self._run_target_discovery()
            elif module.category == ModuleCategory.URL_GATHERING:
                self._run_url_gathering()
            elif module.category == ModuleCategory.HUNTING:
                self._run_hunting()
            elif module.category == ModuleCategory.API_MODE:
                self._run_api_mode()
            else:
                print(f"{self.terminal.bold_red('Module type not implemented:')} {module.category.value}")
        except Exception as e:
            print(f"{self.terminal.bold_red('Error running module:')} {str(e)}")
    
    def _run_data_wrapper(self):
        """Run data wrapper module"""
        print(f"{self.terminal.bold_cyan('Executing data:// wrapper exploitation...')}")
        # Implementation for data wrapper
        pass
    
    def _run_input_wrapper(self):
        """Run input wrapper module"""
        print(f"{self.terminal.bold_cyan('Executing php://input wrapper exploitation...')}")
        # Implementation for input wrapper
        pass
    
    def _run_filter_wrapper(self):
        """Run filter wrapper module"""
        print(f"{self.terminal.bold_cyan('Executing php://filter wrapper exploitation...')}")
        # Implementation for filter wrapper
        pass
    
    def _run_auto_detection(self):
        """Run auto detection module"""
        print(f"{self.terminal.bold_cyan('Executing automatic LFI detection...')}")
        # Implementation for auto detection
        pass
    
    def _run_target_discovery(self):
        """Run target discovery module"""
        print(f"{self.terminal.bold_cyan('Executing target discovery...')}")
        # Implementation for target discovery
        pass
    
    def _run_url_gathering(self):
        """Run URL gathering module"""
        print(f"{self.terminal.bold_cyan('Executing URL gathering...')}")
        # Implementation for URL gathering
        pass
    
    def _run_hunting(self):
        """Run hunting module"""
        print(f"{self.terminal.bold_cyan('Executing LFI hunting...')}")
        # Implementation for hunting
        pass
    
    def _run_api_mode(self):
        """Run API mode module"""
        print(f"{self.terminal.bold_cyan('Starting API server...')}")
        # Implementation for API mode
        pass
    
    def run_interactive(self):
        """Run the interactive shell"""
        self.banner()
        
        while self.running:
            try:
                # Get current module context
                if self.current_module:
                    prompt = f"{self.terminal.bold_red('liffy')} {self.terminal.bold_white('(' + self.current_module.name + ')')} > "
                else:
                    prompt = f"{self.terminal.bold_red('liffy')} > "
                
                # Get user input
                command = input(prompt).strip()
                
                if not command:
                    continue
                
                # Add to history
                self.history.append(command)
                
                # Parse and execute command
                self._execute_command(command)
                
            except KeyboardInterrupt:
                print(f"\n{self.terminal.bold_red('Interrupted by user')}")
                break
            except EOFError:
                print(f"\n{self.terminal.bold_red('EOF received')}")
                break
            except Exception as e:
                print(f"{self.terminal.bold_red('Error:')} {str(e)}")
    
    def _execute_command(self, command: str):
        """Execute a command"""
        parts = command.split()
        if not parts:
            return
        
        cmd = parts[0].lower()
        args = parts[1:] if len(parts) > 1 else []
        
        if cmd in ['exit', 'quit']:
            self.running = False
        elif cmd in ['help', '?']:
            self.show_help()
        elif cmd == 'version':
            self.show_version()
        elif cmd in ['banner']:
            self.banner()
        elif cmd in ['clear', 'cls']:
            os.system('clear' if os.name == 'posix' else 'cls')
        elif cmd == 'search':
            if args:
                self.search_modules(' '.join(args))
            else:
                print(f"{self.terminal.bold_red('Usage:')} search <keyword>")
        elif cmd == 'show':
            if args:
                if args[0] in ['exploit', 'auxiliary', 'post', 'payload', 'encoder', 'nops']:
                    self.show_modules(args[0])
                elif args[0] == 'options':
                    self.show_module_info()
                else:
                    print(f"{self.terminal.bold_red('Unknown show type:')} {args[0]}")
            else:
                self.show_modules()
        elif cmd == 'use':
            if args:
                self.use_module(args[0])
            else:
                print(f"{self.terminal.bold_red('Usage:')} use <module>")
        elif cmd == 'info':
            self.show_module_info()
        elif cmd == 'back':
            self.current_module = None
            print(f"{self.terminal.bold_green('Returned to main context')}")
        elif cmd in ['run', 'exploit']:
            self.run_module()
        elif cmd == 'set':
            if len(args) >= 2:
                option = args[0]
                value = ' '.join(args[1:])
                if not hasattr(self, 'module_options'):
                    self.module_options = {}
                self.module_options[option] = value
                print(f"{self.terminal.bold_green('Set')} {option} = {value}")
            else:
                print(f"{self.terminal.bold_red('Usage:')} set <option> <value>")
        elif cmd == 'unset':
            if args:
                option = args[0]
                if hasattr(self, 'module_options') and option in self.module_options:
                    del self.module_options[option]
                    print(f"{self.terminal.bold_green('Unset')} {option}")
                else:
                    print(f"{self.terminal.bold_red('Option not set:')} {option}")
            else:
                print(f"{self.terminal.bold_red('Usage:')} unset <option>")
        elif cmd == 'history':
            print(f"\n{self.terminal.bold_cyan('Command History')}")
            print(f"{self.terminal.bold_cyan('=' * 30)}")
            for i, cmd in enumerate(self.history[-20:], 1):  # Show last 20 commands
                print(f"{i:3d}  {cmd}")
        else:
            print(f"{self.terminal.bold_red('Unknown command:')} {cmd}")
            print(f"{self.terminal.bold_cyan('Type')} help {self.terminal.bold_cyan('or')} ? {self.terminal.bold_cyan('for available commands')}")

def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description="Liffy Ultimate - Advanced LFI Exploitation Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 liffy_ultimate.py                    # Start interactive mode
  python3 liffy_ultimate.py --module exploit/lfi/data  # Use specific module
  python3 liffy_ultimate.py --batch urls.txt  # Batch mode
        """
    )
    
    parser.add_argument('--module', '-m', help='Module to use')
    parser.add_argument('--batch', '-b', help='Batch mode with URL file')
    parser.add_argument('--output', '-o', help='Output file')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    parser.add_argument('--quiet', '-q', action='store_true', help='Quiet mode')
    
    args = parser.parse_args()
    
    # Create framework instance
    framework = LiffyUltimate()
    
    try:
        if args.module:
            # Use specific module
            if framework.use_module(args.module):
                framework.show_module_info()
                if args.batch:
                    # Batch mode
                    pass
                else:
                    # Interactive mode for module
                    framework.run_interactive()
        else:
            # Start interactive mode
            framework.run_interactive()
    except KeyboardInterrupt:
        print(f"\n{framework.terminal.bold_red('Framework interrupted')}")
    except Exception as e:
        print(f"{framework.terminal.bold_red('Framework error:')} {str(e)}")
        if args.verbose:
            import traceback
            traceback.print_exc()

if __name__ == "__main__":
    main()