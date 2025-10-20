#!/usr/bin/env python3
"""
Liffy Enhanced Dry Run Mode
Simple wrapper that starts hunt mode when no arguments are provided
"""

import sys
import os

def main():
    """Main function for dry run mode"""
    if len(sys.argv) == 1:
        print("🚀 Liffy Enhanced - Dry Run Mode")
        print("=" * 50)
        print("No arguments provided. Starting automatic target hunting...")
        print("This will discover targets using dorking, GAU+, GF patterns, and bug bounty data.")
        print("Then scan them with nuclei and perform fuzzing.")
        print()
        
        try:
            from hunt_mode import HuntMode
            hunt = HuntMode()
            hunt.run_hunt()
        except ImportError as e:
            print(f"❌ Error importing hunt mode: {e}")
            print("Please ensure hunt_mode.py is in the same directory.")
            sys.exit(1)
        except Exception as e:
            print(f"❌ Error running hunt mode: {e}")
            sys.exit(1)
    else:
        # Import and run the original liffy_enhanced
        try:
            import liffy_enhanced
            liffy_enhanced.main()
        except Exception as e:
            print(f"❌ Error running liffy_enhanced: {e}")
            sys.exit(1)

if __name__ == "__main__":
    main()
