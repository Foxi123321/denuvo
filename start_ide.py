#!/usr/bin/env python3
"""
DRM Slayer IDE Startup Script
Automatically installs dependencies and launches the IDE
"""

import os
import sys
import subprocess
import importlib.util

def check_dependency(package_name):
    """Check if a package is installed"""
    return importlib.util.find_spec(package_name) is not None

def install_dependencies():
    """Install required dependencies"""
    print("🔍 Checking dependencies...")
    
    required_packages = [
        'flask',
        'flask_socketio', 
        'flask_cors',
        'psutil',
        'requests',
        'websockets',
        'python_socketio',
        'eventlet',
        'gevent',
        'gevent_websocket'
    ]
    
    missing_packages = []
    for package in required_packages:
        if not check_dependency(package.replace('_', '')):
            missing_packages.append(package)
    
    if missing_packages:
        print(f"📦 Installing missing packages: {', '.join(missing_packages)}")
        try:
            subprocess.check_call([
                sys.executable, '-m', 'pip', 'install', '-r', 'requirements.txt'
            ])
            print("✅ Dependencies installed successfully!")
        except subprocess.CalledProcessError:
            print("❌ Failed to install dependencies. Please install manually:")
            print("pip install -r requirements.txt")
            return False
    else:
        print("✅ All dependencies are already installed!")
    
    return True

def check_optional_dependencies():
    """Check for optional advanced dependencies"""
    print("\n🔍 Checking optional dependencies...")
    
    optional_packages = {
        'lief': 'Advanced binary analysis (LIEF)',
        'capstone': 'Disassembly engine (Capstone)'
    }
    
    for package, description in optional_packages.items():
        if check_dependency(package):
            print(f"✅ {description}")
        else:
            print(f"⚠️  {description} - not installed (some features will be limited)")

def main():
    print("🚀 DRM Slayer IDE - Advanced Analysis Environment")
    print("=" * 50)
    
    # Check if we're in the right directory
    if not os.path.exists('drm_slayer.py'):
        print("❌ Error: drm_slayer.py not found!")
        print("Please run this script from the DRM Slayer project directory.")
        sys.exit(1)
    
    # Install dependencies
    if not install_dependencies():
        sys.exit(1)
    
    # Check optional dependencies
    check_optional_dependencies()
    
    print("\n🎯 Starting DRM Slayer IDE...")
    print("📱 Open your browser and navigate to: http://localhost:5000")
    print("⌨️  Press Ctrl+C to stop the server")
    print("=" * 50)
    
    try:
        # Import and run the IDE
        from drm_ide import DRMIDE
        ide = DRMIDE()
        ide.run(host='0.0.0.0', port=5000, debug=False)
    except KeyboardInterrupt:
        print("\n👋 DRM Slayer IDE stopped.")
    except Exception as e:
        print(f"\n❌ Error starting IDE: {e}")
        print("Please check that all dependencies are installed correctly.")
        sys.exit(1)

if __name__ == '__main__':
    main()