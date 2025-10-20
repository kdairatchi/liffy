#!/usr/bin/env python3
"""
Comprehensive example of pagodo integration with proxychains3 support
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from target_discovery import TargetDiscoveryEngine, DiscoveryMethod

def main():
    """Main example function"""
    print("🚀 Pagodo Integration with Proxychains3 Example")
    print("=" * 60)
    
    # Initialize the target discovery engine
    engine = TargetDiscoveryEngine()
    
    # Check pagodo availability
    if not engine.pagodo.is_available():
        print("❌ Pagodo not available, setting up...")
        return
    
    print("✅ Pagodo is available")
    
    # Show available categories
    print("\n📋 Available Pagodo Categories:")
    categories = engine.get_pagodo_categories()
    for cat_id, cat_name in list(categories.items())[:5]:
        print(f"  {cat_id}: {cat_name}")
    
    # Example 1: Basic pagodo search
    print("\n🔍 Example 1: Basic Pagodo Search")
    print("-" * 40)
    
    targets = engine.discover_targets(
        method=DiscoveryMethod.PAGODO,
        domain="example.com",
        pagodo_category=5,  # Vulnerable Files
        max_results=10
    )
    
    print(f"Found {len(targets)} targets")
    for i, target in enumerate(targets[:3], 1):
        print(f"  {i}. {target.url}")
        print(f"     Confidence: {target.confidence}")
        print(f"     Parameters: {target.parameters}")
        print(f"     Notes: {target.notes}")
        print()
    
    # Example 2: Pagodo with built-in proxy support
    print("\n🔍 Example 2: Pagodo with Built-in Proxy Support")
    print("-" * 50)
    
    # Example proxy list (replace with real proxies)
    example_proxies = [
        "http://proxy1.example.com:8080",
        "http://proxy2.example.com:8080",
        "socks5://127.0.0.1:9050"
    ]
    
    print(f"Using {len(example_proxies)} proxies:")
    for proxy in example_proxies:
        print(f"  - {proxy}")
    
    targets_proxy = engine.discover_targets(
        method=DiscoveryMethod.PAGODO,
        domain="example.com",
        pagodo_proxies=example_proxies,
        max_results=5
    )
    
    print(f"Found {len(targets_proxy)} targets with built-in proxy support")
    
    # Example 3: Pagodo with proxychains3
    print("\n🔍 Example 3: Pagodo with Proxychains3")
    print("-" * 45)
    
    if engine.pagodo.is_proxychains_available():
        print("✅ Proxychains3 is available")
        
        # Test proxychains3 configuration
        print("Testing proxychains3 configuration...")
        if engine.pagodo.test_proxychains():
            print("✅ Proxychains3 test successful")
        else:
            print("❌ Proxychains3 test failed")
        
        # Example with proxychains3
        targets_proxychains = engine.discover_targets(
            method=DiscoveryMethod.PAGODO,
            domain="example.com",
            pagodo_proxies=example_proxies,
            use_proxychains=True,
            max_results=5
        )
        
        print(f"Found {len(targets_proxychains)} targets with proxychains3")
    else:
        print("❌ Proxychains3 not available")
        print("To install: sudo apt install proxychains3")
    
    # Example 4: Different dork categories
    print("\n🔍 Example 4: Different Dork Categories")
    print("-" * 45)
    
    interesting_categories = [5, 6, 7, 8, 9]  # Vulnerable Files, Servers, Error Messages, etc.
    
    for cat_id in interesting_categories:
        cat_name = categories.get(cat_id, f"Category {cat_id}")
        print(f"\nTesting category {cat_id}: {cat_name}")
        
        # Get dorks for this category
        dorks = engine.pagodo.get_dorks_by_category(cat_id)
        print(f"  Found {len(dorks)} dorks")
        
        if dorks:
            print("  Sample dorks:")
            for dork in dorks[:2]:
                print(f"    - {dork}")
    
    # Example 5: Advanced configuration
    print("\n🔍 Example 5: Advanced Configuration")
    print("-" * 45)
    
    # Custom search with specific parameters
    custom_targets = engine.discover_targets(
        method=DiscoveryMethod.PAGODO,
        domain="github.com",
        pagodo_category=12,  # Login Portals
        max_results=20,
        pagodo_proxies=example_proxies,
        use_proxychains=False  # Use built-in proxy support
    )
    
    print(f"Found {len(custom_targets)} login portals on GitHub")
    
    # Show summary
    print("\n📊 Summary")
    print("-" * 20)
    print(f"Total targets discovered: {len(targets) + len(targets_proxy) + len(custom_targets)}")
    print(f"Pagodo available: {'✅' if engine.pagodo.is_available() else '❌'}")
    print(f"Proxychains3 available: {'✅' if engine.pagodo.is_proxychains_available() else '❌'}")
    print(f"Available categories: {len(categories)}")
    
    # Cleanup
    print("\n🧹 Cleaning up...")
    engine.pagodo.cleanup()
    print("✅ Cleanup completed")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n❌ Interrupted by user")
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()