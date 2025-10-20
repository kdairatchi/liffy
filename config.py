#!/usr/bin/env python3
"""
Configuration management for Liffy Enhanced
"""

import json
import os
from pathlib import Path
from typing import Dict, Any, Optional
from dataclasses import dataclass, asdict

@dataclass
class LiffyConfig:
    """Configuration class for Liffy"""
    target_url: str
    technique: str
    lhost: Optional[str] = None
    lport: Optional[int] = None
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
    file: Optional[str] = None

class ConfigManager:
    """Configuration manager for Liffy"""
    
    def __init__(self, config_file: str = "liffy_config.json"):
        self.config_file = Path(config_file)
        self.config = None
    
    def load_config(self) -> Optional[LiffyConfig]:
        """Load configuration from file"""
        if not self.config_file.exists():
            return None
        
        try:
            with open(self.config_file, 'r') as f:
                config_data = json.load(f)
            
            return LiffyConfig(**config_data)
        except Exception as e:
            print(f"Error loading config: {e}")
            return None
    
    def save_config(self, config: LiffyConfig) -> bool:
        """Save configuration to file"""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(asdict(config), f, indent=2)
            return True
        except Exception as e:
            print(f"Error saving config: {e}")
            return False
    
    def create_default_config(self) -> LiffyConfig:
        """Create default configuration"""
        return LiffyConfig(
            target_url="",
            technique="auto",
            timeout=30,
            threads=1
        )
