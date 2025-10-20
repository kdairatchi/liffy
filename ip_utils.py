#!/usr/bin/env python3
"""
IP Utilities for Liffy Enhanced
Handles automatic IP detection and network utilities
"""

import socket
import requests
import subprocess
import platform
import re
from typing import Optional, List, Dict, Any
from urllib.parse import urlparse

class IPDetector:
    """Automatic IP address detection utilities"""
    
    @staticmethod
    def get_local_ip() -> Optional[str]:
        """Get local IP address"""
        try:
            # Connect to a remote address to determine local IP
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                local_ip = s.getsockname()[0]
                return local_ip
        except Exception:
            return None
    
    @staticmethod
    def get_public_ip() -> Optional[str]:
        """Get public IP address"""
        try:
            response = requests.get("https://api.ipify.org", timeout=5)
            if response.status_code == 200:
                return response.text.strip()
        except Exception:
            pass
        
        # Fallback services
        services = [
            "https://ipinfo.io/ip",
            "https://icanhazip.com",
            "https://ifconfig.me/ip"
        ]
        
        for service in services:
            try:
                response = requests.get(service, timeout=5)
                if response.status_code == 200:
                    ip = response.text.strip()
                    if IPDetector.is_valid_ip(ip):
                        return ip
            except Exception:
                continue
        
        return None
    
    @staticmethod
    def get_network_interfaces() -> List[Dict[str, Any]]:
        """Get all network interfaces and their IPs"""
        interfaces = []
        
        try:
            if platform.system() == "Windows":
                # Windows implementation
                result = subprocess.run(
                    ["ipconfig"], 
                    capture_output=True, 
                    text=True, 
                    timeout=10
                )
                interfaces = IPDetector._parse_windows_ipconfig(result.stdout)
            else:
                # Linux/macOS implementation
                result = subprocess.run(
                    ["ip", "addr", "show"], 
                    capture_output=True, 
                    text=True, 
                    timeout=10
                )
                if result.returncode != 0:
                    # Fallback to ifconfig
                    result = subprocess.run(
                        ["ifconfig"], 
                        capture_output=True, 
                        text=True, 
                        timeout=10
                    )
                interfaces = IPDetector._parse_unix_ifconfig(result.stdout)
        except Exception:
            pass
        
        return interfaces
    
    @staticmethod
    def _parse_windows_ipconfig(output: str) -> List[Dict[str, Any]]:
        """Parse Windows ipconfig output"""
        interfaces = []
        current_interface = None
        
        for line in output.split('\n'):
            line = line.strip()
            if line and not line.startswith(' '):
                # New interface
                current_interface = {
                    'name': line,
                    'ips': [],
                    'type': 'unknown'
                }
                interfaces.append(current_interface)
            elif current_interface and 'IPv4' in line:
                # Extract IP address
                ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                if ip_match:
                    ip = ip_match.group(1)
                    if IPDetector.is_valid_ip(ip) and not ip.startswith('127.'):
                        current_interface['ips'].append(ip)
                        current_interface['type'] = 'ethernet' if 'Ethernet' in current_interface['name'] else 'wifi'
        
        return [iface for iface in interfaces if iface['ips']]
    
    @staticmethod
    def _parse_unix_ifconfig(output: str) -> List[Dict[str, Any]]:
        """Parse Unix ifconfig output"""
        interfaces = []
        current_interface = None
        
        for line in output.split('\n'):
            line = line.strip()
            if line and not line.startswith(' '):
                # New interface
                if ':' in line:
                    name = line.split(':')[0]
                    current_interface = {
                        'name': name,
                        'ips': [],
                        'type': 'unknown'
                    }
                    interfaces.append(current_interface)
            elif current_interface and 'inet ' in line:
                # Extract IP address
                ip_match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)', line)
                if ip_match:
                    ip = ip_match.group(1)
                    if IPDetector.is_valid_ip(ip) and not ip.startswith('127.'):
                        current_interface['ips'].append(ip)
                        # Determine interface type
                        if 'wlan' in current_interface['name'] or 'wifi' in current_interface['name']:
                            current_interface['type'] = 'wifi'
                        elif 'eth' in current_interface['name'] or 'en' in current_interface['name']:
                            current_interface['type'] = 'ethernet'
        
        return [iface for iface in interfaces if iface['ips']]
    
    @staticmethod
    def is_valid_ip(ip: str) -> bool:
        """Validate IP address"""
        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return False
            return all(0 <= int(part) <= 255 for part in parts)
        except (ValueError, AttributeError):
            return False
    
    @staticmethod
    def get_best_local_ip() -> Optional[str]:
        """Get the best local IP address for reverse shells"""
        interfaces = IPDetector.get_network_interfaces()
        
        if not interfaces:
            return IPDetector.get_local_ip()
        
        # Prefer ethernet over wifi
        for interface in interfaces:
            if interface['type'] == 'ethernet' and interface['ips']:
                return interface['ips'][0]
        
        # Fallback to any available IP
        for interface in interfaces:
            if interface['ips']:
                return interface['ips'][0]
        
        return IPDetector.get_local_ip()
    
    @staticmethod
    def get_target_network_ip(target_url: str) -> Optional[str]:
        """Get IP address in the same network as target"""
        try:
            parsed_url = urlparse(target_url)
            target_host = parsed_url.hostname
            
            if not target_host:
                return None
            
            # Get target IP
            target_ip = socket.gethostbyname(target_host)
            
            # Get local interfaces
            interfaces = IPDetector.get_network_interfaces()
            
            # Find interface in same subnet
            for interface in interfaces:
                for local_ip in interface['ips']:
                    if IPDetector._is_same_subnet(local_ip, target_ip):
                        return local_ip
            
            # Fallback to best local IP
            return IPDetector.get_best_local_ip()
            
        except Exception:
            return IPDetector.get_best_local_ip()
    
    @staticmethod
    def _is_same_subnet(ip1: str, ip2: str) -> bool:
        """Check if two IPs are in the same subnet"""
        try:
            def ip_to_int(ip):
                parts = ip.split('.')
                return int(parts[0]) << 24 | int(parts[1]) << 16 | int(parts[2]) << 8 | int(parts[3])
            
            def get_network(ip, mask_bits=24):
                return ip_to_int(ip) & (0xFFFFFFFF << (32 - mask_bits))
            
            return get_network(ip1) == get_network(ip2)
        except Exception:
            return False

class PortManager:
    """Port management utilities"""
    
    DEFAULT_PORTS = {
        'http': 80,
        'https': 443,
        'ssh': 22,
        'ftp': 21,
        'smtp': 25,
        'dns': 53,
        'pop3': 110,
        'imap': 143,
        'ldap': 389,
        'https_alt': 8443,
        'http_alt': 8080,
        'custom': 4444
    }
    
    @staticmethod
    def get_available_port(start_port: int = 4444, max_attempts: int = 100) -> Optional[int]:
        """Find an available port starting from start_port"""
        for port in range(start_port, start_port + max_attempts):
            if PortManager.is_port_available(port):
                return port
        return None
    
    @staticmethod
    def is_port_available(port: int) -> bool:
        """Check if a port is available"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(('', port))
                return True
        except OSError:
            return False
    
    @staticmethod
    def get_suggested_ports() -> List[int]:
        """Get list of suggested ports for reverse shells"""
        return [4444, 4445, 4446, 8080, 8081, 9000, 9001, 1234, 1235]
    
    @staticmethod
    def find_best_port() -> int:
        """Find the best available port for reverse shells"""
        suggested_ports = PortManager.get_suggested_ports()
        
        for port in suggested_ports:
            if PortManager.is_port_available(port):
                return port
        
        # Fallback to any available port
        return PortManager.get_available_port() or 4444

class NetworkUtils:
    """Network utility functions"""
    
    @staticmethod
    def get_network_info() -> Dict[str, Any]:
        """Get comprehensive network information"""
        return {
            'local_ip': IPDetector.get_local_ip(),
            'public_ip': IPDetector.get_public_ip(),
            'best_local_ip': IPDetector.get_best_local_ip(),
            'interfaces': IPDetector.get_network_interfaces(),
            'suggested_ports': PortManager.get_suggested_ports(),
            'best_port': PortManager.find_best_port()
        }
    
    @staticmethod
    def auto_detect_lhost_lport(target_url: Optional[str] = None) -> tuple[Optional[str], int]:
        """Auto-detect best lhost and lport"""
        lhost = None
        lport = PortManager.find_best_port()
        
        if target_url:
            lhost = IPDetector.get_target_network_ip(target_url)
        
        if not lhost:
            lhost = IPDetector.get_best_local_ip()
        
        return lhost, lport
