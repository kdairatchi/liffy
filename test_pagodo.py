#!/usr/bin/env python3
"""
Test script for pagodo integration
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from target_discovery import TargetDiscoveryEngine, DiscoveryMethod

def test_pagodo_integration():
    """Test pagodo integration"""
    print("🔍 Testing Pagodo Integration")
    print("=" * 50)
    
    # Initialize engine
    engine = TargetDiscoveryEngine()
    
    # Check if pagodo is available
    if not engine.pagodo.is_available():
        print("❌ Pagodo not available, setting up...")
        # This will trigger the setup process
        engine.pagodo = engine.pagodo.__class__()
    
    if engine.pagodo.is_available():
        print("✅ Pagodo is available")
        
        # Test dork update
        print("\n🔄 Testing dork update...")
        if engine.pagodo.update_dorks():
            print("✅ Dorks updated successfully")
        else:
            print("❌ Failed to update dorks")
        
        # Test getting dorks by category
        print("\n📋 Testing dork categories...")
        categories = engine.pagodo.get_available_categories()
        print(f"Available categories: {len(categories)}")
        for cat_id, cat_name in list(categories.items())[:3]:
            print(f"  - {cat_id}: {cat_name}")
        
        # Test getting dorks
        print("\n🔍 Testing dork retrieval...")
        dorks = engine.pagodo.get_dorks_by_category(5)  # Vulnerable Files
        print(f"Found {len(dorks)} dorks in category 5 (Vulnerable Files)")
        if dorks:
            print("Sample dorks:")
            for dork in dorks[:3]:
                print(f"  - {dork}")
        
        # Test proxychains3
        print("\n🔗 Testing proxychains3...")
        if engine.pagodo.is_proxychains_available():
            print("✅ Proxychains3 is available")
            # Test with sample proxies (these are just examples)
            test_proxies = [
                "127.0.0.1:9050",  # Tor proxy example
                "127.0.0.1:9051"   # Another Tor proxy example
            ]
            print(f"Testing with {len(test_proxies)} sample proxies...")
            # Note: This will fail if no actual proxy is running, but shows the functionality
        else:
            print("❌ Proxychains3 not available")
        
        # Test target discovery
        print("\n🎯 Testing target discovery...")
        targets = engine.discover_targets(
            method=DiscoveryMethod.PAGODO,
            domain="example.com",
            max_results=5
        )
        print(f"Found {len(targets)} targets via pagodo")
        
        for target in targets[:3]:
            print(f"  - {target.url} (confidence: {target.confidence})")
        
        # Test target discovery with proxychains3
        print("\n🎯 Testing target discovery with proxychains3...")
        if engine.pagodo.is_proxychains_available():
            targets_proxy = engine.discover_targets(
                method=DiscoveryMethod.PAGODO,
                domain="example.com",
                max_results=3,
                pagodo_proxies=["127.0.0.1:9050"],  # Example proxy
                use_proxychains=True
            )
            print(f"Found {len(targets_proxy)} targets via pagodo with proxychains3")
        else:
            print("❌ Skipping proxychains3 test - not available")
    
    else:
        print("❌ Pagodo setup failed")

if __name__ == "__main__":
    test_pagodo_integration()