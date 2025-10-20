#!/usr/bin/env python3
"""
Tool Setup Module for Liffy Enhanced
Handles automatic setup of required tools and templates
"""

import os
import subprocess
import sys
from pathlib import Path
from typing import List, Dict, Any, Optional
import shutil
import requests
import zipfile
import tarfile

class ToolSetup:
    """Handles setup of required tools and templates"""
    
    def __init__(self):
        self.work_dir = Path.home() / "MyWork"
        self.tools_dir = self.work_dir / "tools"
        self.templates_dir = self.work_dir / "templates"
        self.conf_dir = Path.home() / ".config" / "liffy"
        
    def setup_environment(self):
        """Setup the working environment"""
        print("🔧 Setting up Liffy Enhanced environment...")
        
        # Create directories
        self.work_dir.mkdir(exist_ok=True)
        self.tools_dir.mkdir(exist_ok=True)
        self.templates_dir.mkdir(exist_ok=True)
        self.conf_dir.mkdir(exist_ok=True)
        
        print(f"✅ Created work directory: {self.work_dir}")
        print(f"✅ Created tools directory: {self.tools_dir}")
        print(f"✅ Created templates directory: {self.templates_dir}")
        print(f"✅ Created config directory: {self.conf_dir}")
    
    def setup_log4j_scan(self):
        """Setup log4j-scan tool"""
        print("\n🔍 Setting up log4j-scan...")
        
        log4j_dir = self.tools_dir / "log4j-scan"
        
        if log4j_dir.exists():
            print("✅ log4j-scan already exists")
            return str(log4j_dir)
        
        try:
            # Clone log4j-scan
            cmd = ["git", "clone", "https://github.com/hktalent/log4j-scan", str(log4j_dir)]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                print("✅ Successfully cloned log4j-scan")
                
                # Install requirements
                requirements_file = log4j_dir / "requirements.txt"
                if requirements_file.exists():
                    cmd = [sys.executable, "-m", "pip", "install", "-r", str(requirements_file)]
                    subprocess.run(cmd, capture_output=True, text=True, timeout=120)
                    print("✅ Installed log4j-scan requirements")
                
                return str(log4j_dir)
            else:
                print(f"❌ Failed to clone log4j-scan: {result.stderr}")
                return None
                
        except Exception as e:
            print(f"❌ Error setting up log4j-scan: {e}")
            return None
    
    def setup_nuclei_templates(self):
        """Setup nuclei templates"""
        print("\n🎯 Setting up nuclei templates...")
        
        nuclei_dir = self.templates_dir / "cent-nuclei-templates/nucleihub-templates"
        
        if nuclei_dir.exists():
            print("✅ nuclei-templates already exists")
            return str(nuclei_dir)
        
        try:
            # Clone nuclei-templates
            cmd = ["git", "clone", "https://github.com/projectdiscovery/nuclei-templates", str(nuclei_dir)]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            
            if result.returncode == 0:
                print("✅ Successfully cloned nuclei-templates")
                
                # Setup custom templates directory
                custom_dir = nuclei_dir / "custom"
                custom_dir.mkdir(exist_ok=True)
                
                # Create LFI-specific templates
                self._create_lfi_templates(custom_dir)
                
                return str(nuclei_dir)
            else:
                print(f"❌ Failed to clone nuclei-templates: {result.stderr}")
                return None
                
        except Exception as e:
            print(f"❌ Error setting up nuclei-templates: {e}")
            return None
    
    def _create_lfi_templates(self, custom_dir: Path):
        """Create custom LFI nuclei templates"""
        print("📝 Creating custom LFI nuclei templates...")
        
        # LFI Basic Detection Template
        lfi_basic_template = """id: lfi-basic-detection

info:
  name: Local File Inclusion - Basic Detection
  author: Liffy Enhanced
  severity: high
  description: Detects basic local file inclusion vulnerabilities
  reference:
    - https://owasp.org/www-community/attacks/File_Inclusion
  classification:
    cvss-metrics: CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
    cvss-score: 9.8
    cwe-id: CWE-98

requests:
  - method: GET
    path:
      - "{{BaseURL}}&file=../../../../etc/passwd"
      - "{{BaseURL}}&page=../../../../etc/passwd"
      - "{{BaseURL}}&path=../../../../etc/passwd"
      - "{{BaseURL}}&doc=../../../../etc/passwd"
      - "{{BaseURL}}&folder=../../../../etc/passwd"
      - "{{BaseURL}}&inc=../../../../etc/passwd"
      - "{{BaseURL}}&locate=../../../../etc/passwd"
      - "{{BaseURL}}&menu=../../../../etc/passwd"

    matchers-condition: and
    matchers:
      - type: word
        words:
          - "root:x:0:0:"
          - "daemon:x:1:1:"
        condition: or

      - type: status
        status:
          - 200

    extractors:
      - type: regex
        part: body
        group: 1
        regex:
          - "root:x:0:0:([^:]+)"
"""
        
        # LFI Advanced Detection Template
        lfi_advanced_template = """id: lfi-advanced-detection

info:
  name: Local File Inclusion - Advanced Detection
  author: Liffy Enhanced
  severity: critical
  description: Detects advanced local file inclusion vulnerabilities with multiple techniques
  reference:
    - https://owasp.org/www-community/attacks/File_Inclusion
  classification:
    cvss-metrics: CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
    cvss-score: 9.8
    cwe-id: CWE-98

requests:
  - method: GET
    path:
      - "{{BaseURL}}&file=....//....//....//....//etc/passwd"
      - "{{BaseURL}}&page=....//....//....//....//etc/passwd"
      - "{{BaseURL}}&path=....//....//....//....//etc/passwd"
      - "{{BaseURL}}&doc=....//....//....//....//etc/passwd"
      - "{{BaseURL}}&folder=....//....//....//....//etc/passwd"
      - "{{BaseURL}}&inc=....//....//....//....//etc/passwd"
      - "{{BaseURL}}&locate=....//....//....//....//etc/passwd"
      - "{{BaseURL}}&menu=....//....//....//....//etc/passwd"

    matchers-condition: and
    matchers:
      - type: word
        words:
          - "root:x:0:0:"
          - "daemon:x:1:1:"
        condition: or

      - type: status
        status:
          - 200

    extractors:
      - type: regex
        part: body
        group: 1
        regex:
          - "root:x:0:0:([^:]+)"
"""
        
        # LFI PHP Filter Template
        lfi_php_filter_template = """id: lfi-php-filter

info:
  name: Local File Inclusion - PHP Filter
  author: Liffy Enhanced
  severity: high
  description: Detects LFI using PHP filter technique
  reference:
    - https://owasp.org/www-community/attacks/File_Inclusion
  classification:
    cvss-metrics: CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
    cvss-score: 9.8
    cwe-id: CWE-98

requests:
  - method: GET
    path:
      - "{{BaseURL}}&file=php://filter/read=convert.base64-encode/resource=../../../../etc/passwd"
      - "{{BaseURL}}&page=php://filter/read=convert.base64-encode/resource=../../../../etc/passwd"
      - "{{BaseURL}}&path=php://filter/read=convert.base64-encode/resource=../../../../etc/passwd"
      - "{{BaseURL}}&doc=php://filter/read=convert.base64-encode/resource=../../../../etc/passwd"
      - "{{BaseURL}}&folder=php://filter/read=convert.base64-encode/resource=../../../../etc/passwd"
      - "{{BaseURL}}&inc=php://filter/read=convert.base64-encode/resource=../../../../etc/passwd"
      - "{{BaseURL}}&locate=php://filter/read=convert.base64-encode/resource=../../../../etc/passwd"
      - "{{BaseURL}}&menu=php://filter/read=convert.base64-encode/resource=../../../../etc/passwd"

    matchers-condition: and
    matchers:
      - type: word
        words:
          - "cm9vdDp4OjA6MDo="
          - "ZGFlbW9uOng6MToxOg=="
        condition: or

      - type: status
        status:
          - 200

    extractors:
      - type: regex
        part: body
        group: 1
        regex:
          - "cm9vdDp4OjA6MDo([A-Za-z0-9+/=]+)"
"""
        
        # Write templates
        templates = {
            "lfi-basic-detection.yaml": lfi_basic_template,
            "lfi-advanced-detection.yaml": lfi_advanced_template,
            "lfi-php-filter.yaml": lfi_php_filter_template
        }
        
        for filename, content in templates.items():
            template_file = custom_dir / filename
            with open(template_file, 'w') as f:
                f.write(content)
        
        print("✅ Created custom LFI nuclei templates")
    
    def setup_config(self):
        """Setup configuration files"""
        print("\n⚙️ Setting up configuration...")
        
        # Create nuclei config
        nuclei_config = {
            "templates": [
                str(self.templates_dir / "nuclei-templates"),
                str(self.templates_dir / "nuclei-templates" / "custom")
            ],
            "output": str(self.work_dir / "nuclei-results"),
            "severity": ["critical", "high", "medium"],
            "tags": ["lfi", "file-inclusion", "rce"]
        }
        
        config_file = self.conf_dir / "nuclei-config.json"
        with open(config_file, 'w') as f:
            import json
            json.dump(nuclei_config, f, indent=2)
        
        # Create liffy config
        liffy_config = {
            "work_dir": str(self.work_dir),
            "tools_dir": str(self.tools_dir),
            "templates_dir": str(self.templates_dir),
            "log4j_scan_path": str(self.tools_dir / "log4j-scan" / "log4j-scan.py"),
            "nuclei_templates_path": str(self.templates_dir / "nuclei-templates"),
            "custom_templates_path": str(self.templates_dir / "nuclei-templates" / "custom"),
            "auto_setup": True,
            "dry_run_mode": True
        }
        
        liffy_config_file = self.conf_dir / "liffy-config.json"
        with open(liffy_config_file, 'w') as f:
            import json
            json.dump(liffy_config, f, indent=2)
        
        print("✅ Created configuration files")
    
    def check_dependencies(self):
        """Check if required dependencies are installed"""
        print("\n🔍 Checking dependencies...")
        
        dependencies = [
            ("git", "Git version control"),
            ("python3", "Python 3 interpreter"),
            ("pip", "Python package manager"),
            ("nuclei", "Nuclei scanner"),
            ("gauplus", "GAU+ URL discovery"),
            ("gf", "GF pattern matcher")
        ]
        
        missing = []
        
        for dep, description in dependencies:
            if shutil.which(dep):
                print(f"✅ {dep} - {description}")
            else:
                print(f"❌ {dep} - {description} (missing)")
                missing.append(dep)
        
        if missing:
            print(f"\n⚠️ Missing dependencies: {', '.join(missing)}")
            print("Please install missing dependencies before using Liffy Enhanced")
            return False
        
        return True
    
    def setup_all(self):
        """Setup all tools and configurations"""
        print("🚀 Setting up Liffy Enhanced environment...")
        print("=" * 50)
        
        # Check dependencies
        if not self.check_dependencies():
            print("\n❌ Setup failed due to missing dependencies")
            return False
        
        # Setup environment
        self.setup_environment()
        
        # Setup tools
        log4j_path = self.setup_log4j_scan()
        nuclei_path = self.setup_nuclei_templates()
        
        if not log4j_path or not nuclei_path:
            print("\n❌ Setup failed")
            return False
        
        # Setup configuration
        self.setup_config()
        
        print("\n🎉 Setup completed successfully!")
        print(f"📁 Work directory: {self.work_dir}")
        print(f"🔧 Tools directory: {self.tools_dir}")
        print(f"📋 Templates directory: {self.templates_dir}")
        print(f"⚙️ Config directory: {self.conf_dir}")
        
        return True

def main():
    """Main setup function"""
    setup = ToolSetup()
    setup.setup_all()

if __name__ == "__main__":
    main()
