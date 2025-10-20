#!/usr/bin/env python3
"""
Comprehensive test suite for Liffy Enhanced
"""

import pytest
import asyncio
import tempfile
import os
import sys
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from liffy_enhanced import LiffyConfig, LiffyLogger, LiffyUI, LiffyValidator, LiffyExploiter
from core_enhanced import PayloadGenerator, MSFHandler, BaseExploit
from api_mode import LiffyAPI, APIConfig, APITechnique

class TestLiffyConfig:
    """Test LiffyConfig dataclass"""
    
    def test_config_creation(self):
        """Test basic config creation"""
        config = LiffyConfig(
            target_url="http://test.com/file.php?page=",
            technique="auto"
        )
        assert config.target_url == "http://test.com/file.php?page="
        assert config.technique == "auto"
        assert config.timeout == 30
        assert config.threads == 1
    
    def test_config_with_all_params(self):
        """Test config with all parameters"""
        config = LiffyConfig(
            target_url="http://test.com/file.php?page=",
            technique="data",
            lhost="192.168.1.100",
            lport=4444,
            cookies="PHPSESSID=abc123",
            location="/var/log/apache2/access.log",
            nostager=True,
            relative=True,
            verbose=True,
            output_file="test.log",
            timeout=60,
            user_agent="Mozilla/5.0",
            proxy="http://127.0.0.1:8080",
            threads=5,
            file="/etc/passwd"
        )
        assert config.lhost == "192.168.1.100"
        assert config.lport == 4444
        assert config.cookies == "PHPSESSID=abc123"
        assert config.nostager == True
        assert config.verbose == True

class TestLiffyValidator:
    """Test LiffyValidator class"""
    
    def test_validate_url_valid(self):
        """Test valid URL validation"""
        assert LiffyValidator.validate_url("http://example.com") == True
        assert LiffyValidator.validate_url("https://example.com/path") == True
        assert LiffyValidator.validate_url("http://192.168.1.1:8080/path") == True
    
    def test_validate_url_invalid(self):
        """Test invalid URL validation"""
        assert LiffyValidator.validate_url("not-a-url") == False
        assert LiffyValidator.validate_url("ftp://example.com") == False
        assert LiffyValidator.validate_url("") == False
        assert LiffyValidator.validate_url(None) == False
    
    def test_validate_port_valid(self):
        """Test valid port validation"""
        assert LiffyValidator.validate_port(80) == True
        assert LiffyValidator.validate_port(443) == True
        assert LiffyValidator.validate_port(8080) == True
        assert LiffyValidator.validate_port(65535) == True
    
    def test_validate_port_invalid(self):
        """Test invalid port validation"""
        assert LiffyValidator.validate_port(0) == False
        assert LiffyValidator.validate_port(-1) == False
        assert LiffyValidator.validate_port(65536) == False
        assert LiffyValidator.validate_port(99999) == False
    
    def test_validate_ip_valid(self):
        """Test valid IP validation"""
        assert LiffyValidator.validate_ip("192.168.1.1") == True
        assert LiffyValidator.validate_ip("127.0.0.1") == True
        assert LiffyValidator.validate_ip("10.0.0.1") == True
        assert LiffyValidator.validate_ip("255.255.255.255") == True
    
    def test_validate_ip_invalid(self):
        """Test invalid IP validation"""
        assert LiffyValidator.validate_ip("256.1.1.1") == False
        assert LiffyValidator.validate_ip("192.168.1") == False
        assert LiffyValidator.validate_ip("192.168.1.1.1") == False
        assert LiffyValidator.validate_ip("not-an-ip") == False

class TestPayloadGenerator:
    """Test PayloadGenerator class"""
    
    def test_generate_random_name_default_length(self):
        """Test random name generation with default length"""
        name = PayloadGenerator.generate_random_name()
        assert len(name) == 8
        assert name.isalnum()
        assert name.islower()
    
    def test_generate_random_name_custom_length(self):
        """Test random name generation with custom length"""
        name = PayloadGenerator.generate_random_name(12)
        assert len(name) == 12
        assert name.isalnum()
        assert name.islower()
    
    def test_generate_php_shell(self):
        """Test PHP shell generation"""
        shell = PayloadGenerator.generate_php_shell("192.168.1.100", 4444)
        assert "<?php" in shell
        assert "192.168.1.100" in shell
        assert "4444" in shell
        assert "fsockopen" in shell
        assert "proc_open" in shell
    
    def test_generate_php_meterpreter(self):
        """Test PHP Meterpreter generation"""
        meterpreter = PayloadGenerator.generate_php_meterpreter("192.168.1.100", 4444)
        assert "<?php" in meterpreter
        assert "192.168.1.100" in meterpreter
        assert "4444" in meterpreter
        assert "$lhost" in meterpreter
        assert "$lport" in meterpreter
    
    def test_generate_webshell(self):
        """Test webshell generation"""
        webshell = PayloadGenerator.generate_webshell()
        assert "<?php" in webshell
        assert "$_GET['cmd']" in webshell
        assert "system" in webshell

class TestMSFHandler:
    """Test MSFHandler class"""
    
    def test_msf_handler_creation(self):
        """Test MSFHandler creation"""
        logger = Mock()
        ui = Mock()
        handler = MSFHandler("192.168.1.100", 4444, logger, ui)
        assert handler.lhost == "192.168.1.100"
        assert handler.lport == 4444
        assert handler.logger == logger
        assert handler.ui == ui
    
    def test_generate_resource_file(self):
        """Test resource file generation"""
        logger = Mock()
        ui = Mock()
        handler = MSFHandler("192.168.1.100", 4444, logger, ui)
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.rc') as f:
            resource_file = handler.generate_resource_file("test_shell")
            assert os.path.exists(resource_file)
            
            with open(resource_file, 'r') as rf:
                content = rf.read()
                assert "use multi/handler" in content
                assert "set payload php/meterpreter/reverse_tcp" in content
                assert "set LHOST 192.168.1.100" in content
                assert "set LPORT 4444" in content
            
            os.unlink(resource_file)
    
    @patch('subprocess.run')
    def test_generate_payload_success(self, mock_run):
        """Test successful payload generation"""
        mock_run.return_value.returncode = 0
        mock_run.return_value.stderr = ""
        
        logger = Mock()
        ui = Mock()
        handler = MSFHandler("192.168.1.100", 4444, logger, ui)
        
        payload_file = handler.generate_payload("test_shell")
        assert payload_file is not None
        assert "test_shell.php" in payload_file
    
    @patch('subprocess.run')
    def test_generate_payload_failure(self, mock_run):
        """Test failed payload generation"""
        mock_run.return_value.returncode = 1
        mock_run.return_value.stderr = "msfvenom not found"
        
        logger = Mock()
        ui = Mock()
        handler = MSFHandler("192.168.1.100", 4444, logger, ui)
        
        payload_file = handler.generate_payload("test_shell")
        assert payload_file is None

class TestLiffyAPI:
    """Test LiffyAPI class"""
    
    @pytest.mark.asyncio
    async def test_api_config_creation(self):
        """Test API config creation"""
        config = APIConfig(
            target_url="http://test.com/file.php?page=",
            technique=APITechnique.AUTO
        )
        assert config.target_url == "http://test.com/file.php?page="
        assert config.technique == APITechnique.AUTO
    
    @pytest.mark.asyncio
    async def test_api_response_creation(self):
        """Test API response creation"""
        response = APIResponse(
            success=True,
            message="Test successful",
            data={"test": "data"},
            technique="auto",
            execution_time=1.5
        )
        assert response.success == True
        assert response.message == "Test successful"
        assert response.data == {"test": "data"}
        assert response.technique == "auto"
        assert response.execution_time == 1.5

class TestLiffyLogger:
    """Test LiffyLogger class"""
    
    def test_logger_creation(self):
        """Test logger creation"""
        logger = LiffyLogger(verbose=True, output_file="test.log")
        assert logger.verbose == True
        assert logger.output_file == "test.log"
        assert logger.logger is not None
    
    def test_logger_without_file(self):
        """Test logger without output file"""
        logger = LiffyLogger(verbose=False)
        assert logger.verbose == False
        assert logger.output_file is None
        assert logger.logger is not None

class TestLiffyUI:
    """Test LiffyUI class"""
    
    def test_ui_creation(self):
        """Test UI creation"""
        logger = Mock()
        ui = LiffyUI(logger)
        assert ui.logger == logger
    
    def test_ui_banner(self):
        """Test banner display"""
        logger = Mock()
        ui = LiffyUI(logger)
        # This should not raise an exception
        ui.banner()
    
    def test_ui_messages(self):
        """Test UI message methods"""
        logger = Mock()
        ui = LiffyUI(logger)
        
        # These should not raise exceptions
        ui.success("Test success")
        ui.error("Test error")
        ui.warning("Test warning")
        ui.info("Test info")

class TestIntegration:
    """Integration tests"""
    
    def test_import_all_modules(self):
        """Test that all modules can be imported"""
        import liffy_enhanced
        import core_enhanced
        import api_mode
        import config
        import http_server
        
        # If we get here, imports were successful
        assert True
    
    def test_config_serialization(self):
        """Test config serialization"""
        from config import LiffyConfig as ConfigLiffyConfig, ConfigManager
        
        config = ConfigLiffyConfig(
            target_url="http://test.com/file.php?page=",
            technique="auto"
        )
        
        # Test that config can be converted to dict
        config_dict = {
            "target_url": config.target_url,
            "technique": config.technique,
            "lhost": config.lhost,
            "lport": config.lport,
            "cookies": config.cookies,
            "location": config.location,
            "nostager": config.nostager,
            "relative": config.relative,
            "verbose": config.verbose,
            "output_file": config.output_file,
            "timeout": config.timeout,
            "user_agent": config.user_agent,
            "proxy": config.proxy,
            "threads": config.threads,
            "file": config.file
        }
        
        assert config_dict["target_url"] == "http://test.com/file.php?page="
        assert config_dict["technique"] == "auto"

# Pytest configuration
@pytest.fixture
def sample_config():
    """Sample configuration for tests"""
    return LiffyConfig(
        target_url="http://test.com/file.php?page=",
        technique="auto",
        lhost="192.168.1.100",
        lport=4444
    )

@pytest.fixture
def sample_api_config():
    """Sample API configuration for tests"""
    return APIConfig(
        target_url="http://test.com/file.php?page=",
        technique=APITechnique.AUTO,
        lhost="192.168.1.100",
        lport=4444
    )

# Test discovery
if __name__ == "__main__":
    pytest.main([__file__, "-v"])
