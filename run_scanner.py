#!/usr/bin/env python3
"""
Infinite LLM Scanner Launcher
Automatically installs dependencies and runs the scanner.
"""
import subprocess
import sys
import os

def install_requirements():
    """Install required Python packages."""
    print("[*] Installing Python requirements...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
        print("[+] Requirements installed successfully!")
    except subprocess.CalledProcessError as e:
        print(f"[!] Failed to install requirements: {e}")
        print("[*] Try running: pip install aiohttp>=3.9.0")
        sys.exit(1)

def main():
    # Check if requirements are installed
    try:
        import aiohttp
    except ImportError:
        print("[*] aiohttp not found. Installing...")
        install_requirements()

    # Run the scanner
    print("[*] Starting Infinite LLM Scanner...")
    os.system("python infinite_scanner.py " + " ".join(sys.argv[1:]))

if __name__ == "__main__":
    main()
