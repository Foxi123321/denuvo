#!/usr/bin/env python3
"""
DRM Slayer IDE - Advanced Web-Based Development Environment
A modern, feature-rich IDE for DRM analysis and research

Features:
- Real-time file analysis
- Live DRM detection dashboard
- Binary visualization
- Collaborative editing
- Plugin system
- Advanced debugging tools
"""

import os
import sys
import json
import time
import threading
import asyncio
import base64
import hashlib
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime

from flask import Flask, render_template, request, jsonify, send_from_directory
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_cors import CORS
import psutil

# Import our DRM Slayer core
from drm_slayer import DRMSlayer, ProcessVirtualizationLayer, LicenseEmulator, NetworkManipulator

class DRMIDE:
    def __init__(self):
        self.app = Flask(__name__)
        self.app.config['SECRET_KEY'] = 'drm_slayer_ide_secret_key_2025'
        self.socketio = SocketIO(self.app, cors_allowed_origins="*", async_mode='eventlet')
        CORS(self.app)
        
        # Initialize core components
        self.drm_slayer = DRMSlayer()
        self.virtualization = ProcessVirtualizationLayer()
        self.license_emulator = LicenseEmulator()
        self.network_manipulator = NetworkManipulator()
        
        # IDE state
        self.active_sessions = {}
        self.file_watchers = {}
        self.analysis_cache = {}
        self.plugins = {}
        
        # Setup routes and socket events
        self.setup_routes()
        self.setup_socket_events()
        
    def setup_routes(self):
        @self.app.route('/')
        def index():
            return render_template('index.html')
            
        @self.app.route('/api/scan', methods=['POST'])
        def api_scan():
            data = request.get_json()
            path = data.get('path', '')
            drm_types = data.get('drm_types', None)
            
            try:
                results = self.drm_slayer.scan(path, drm_types)
                return jsonify({'success': True, 'results': results})
            except Exception as e:
                return jsonify({'success': False, 'error': str(e)})
                
        @self.app.route('/api/files')
        def api_files():
            path = request.args.get('path', '.')
            try:
                files = self.get_file_tree(path)
                return jsonify({'success': True, 'files': files})
            except Exception as e:
                return jsonify({'success': False, 'error': str(e)})
                
        @self.app.route('/api/analyze', methods=['POST'])
        def api_analyze():
            data = request.get_json()
            file_path = data.get('file_path', '')
            
            try:
                analysis = self.analyze_file(file_path)
                return jsonify({'success': True, 'analysis': analysis})
            except Exception as e:
                return jsonify({'success': False, 'error': str(e)})
                
        @self.app.route('/api/virtualization', methods=['POST'])
        def api_virtualization():
            data = request.get_json()
            action = data.get('action', '')
            profile = data.get('profile', 'default')
            
            try:
                if action == 'enable':
                    success = self.virtualization.enable_virtualization()
                    return jsonify({'success': success})
                elif action == 'disable':
                    success = self.virtualization.disable_virtualization()
                    return jsonify({'success': success})
                elif action == 'set_profile':
                    success = self.virtualization.set_hardware_profile(profile)
                    return jsonify({'success': success})
                else:
                    return jsonify({'success': False, 'error': 'Invalid action'})
            except Exception as e:
                return jsonify({'success': False, 'error': str(e)})
                
        @self.app.route('/api/network', methods=['POST'])
        def api_network():
            data = request.get_json()
            action = data.get('action', '')
            
            try:
                if action == 'start_proxy':
                    protocol = data.get('protocol', 'tcp')
                    local_port = data.get('local_port', 8080)
                    remote_host = data.get('remote_host', 'localhost')
                    remote_port = data.get('remote_port', 80)
                    
                    success = self.network_manipulator.start_proxy(
                        protocol, local_port, remote_host, remote_port
                    )
                    return jsonify({'success': success})
                else:
                    return jsonify({'success': False, 'error': 'Invalid action'})
            except Exception as e:
                return jsonify({'success': False, 'error': str(e)})
                
        @self.app.route('/api/system')
        def api_system():
            try:
                system_info = {
                    'cpu_percent': psutil.cpu_percent(interval=1),
                    'memory_percent': psutil.virtual_memory().percent,
                    'disk_usage': psutil.disk_usage('/').percent,
                    'active_sessions': len(self.active_sessions),
                    'cached_analyses': len(self.analysis_cache),
                    'loaded_plugins': len(self.plugins)
                }
                return jsonify({'success': True, 'system_info': system_info})
            except Exception as e:
                return jsonify({'success': False, 'error': str(e)})
    
    def setup_socket_events(self):
        @self.socketio.on('connect')
        def handle_connect():
            session_id = request.sid
            self.active_sessions[session_id] = {
                'connected_at': datetime.now(),
                'last_activity': datetime.now(),
                'current_file': None,
                'analysis_mode': False
            }
            emit('connected', {'session_id': session_id})
            
        @self.socketio.on('disconnect')
        def handle_disconnect():
            session_id = request.sid
            if session_id in self.active_sessions:
                del self.active_sessions[session_id]
                
        @self.socketio.on('join_analysis')
        def handle_join_analysis(data):
            session_id = request.sid
            file_path = data.get('file_path', '')
            
            if session_id in self.active_sessions:
                self.active_sessions[session_id]['current_file'] = file_path
                self.active_sessions[session_id]['analysis_mode'] = True
                
            join_room(f'analysis_{file_path}')
            emit('joined_analysis', {'file_path': file_path})
            
        @self.socketio.on('real_time_scan')
        def handle_real_time_scan(data):
            file_path = data.get('file_path', '')
            
            # Start real-time analysis
            def run_analysis():
                try:
                    results = self.drm_slayer.scan(file_path)
                    self.socketio.emit('scan_results', {
                        'file_path': file_path,
                        'results': results,
                        'timestamp': datetime.now().isoformat()
                    }, room=f'analysis_{file_path}')
                except Exception as e:
                    self.socketio.emit('scan_error', {
                        'file_path': file_path,
                        'error': str(e),
                        'timestamp': datetime.now().isoformat()
                    }, room=f'analysis_{file_path}')
                    
            threading.Thread(target=run_analysis).start()
            
        @self.socketio.on('watch_file')
        def handle_watch_file(data):
            file_path = data.get('file_path', '')
            session_id = request.sid
            
            if file_path not in self.file_watchers:
                self.file_watchers[file_path] = set()
            self.file_watchers[file_path].add(session_id)
            
            # Start file watching
            self.start_file_watcher(file_path)
            
    def get_file_tree(self, path: str) -> List[Dict[str, Any]]:
        """Get file tree structure for the file explorer"""
        files = []
        try:
            for item in os.listdir(path):
                item_path = os.path.join(path, item)
                if os.path.isdir(item_path):
                    files.append({
                        'name': item,
                        'type': 'directory',
                        'path': item_path,
                        'size': None,
                        'modified': datetime.fromtimestamp(os.path.getmtime(item_path)).isoformat()
                    })
                else:
                    files.append({
                        'name': item,
                        'type': 'file',
                        'path': item_path,
                        'size': os.path.getsize(item_path),
                        'modified': datetime.fromtimestamp(os.path.getmtime(item_path)).isoformat()
                    })
        except Exception as e:
            print(f"Error getting file tree: {e}")
            
        return sorted(files, key=lambda x: (x['type'] == 'file', x['name'].lower()))
        
    def analyze_file(self, file_path: str) -> Dict[str, Any]:
        """Perform comprehensive file analysis"""
        if file_path in self.analysis_cache:
            return self.analysis_cache[file_path]
            
        analysis = {
            'file_info': {},
            'drm_analysis': {},
            'binary_analysis': {},
            'security_analysis': {},
            'metadata': {}
        }
        
        try:
            # Basic file info
            stat = os.stat(file_path)
            analysis['file_info'] = {
                'size': stat.st_size,
                'created': datetime.fromtimestamp(stat.st_ctime).isoformat(),
                'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                'permissions': oct(stat.st_mode)[-3:]
            }
            
            # DRM analysis
            drm_results = self.drm_slayer.scan(file_path)
            analysis['drm_analysis'] = drm_results
            
            # Binary analysis (if applicable)
            if self.is_binary_file(file_path):
                analysis['binary_analysis'] = self.analyze_binary(file_path)
                
            # Security analysis
            analysis['security_analysis'] = self.analyze_security(file_path)
            
            # Cache the results
            self.analysis_cache[file_path] = analysis
            
        except Exception as e:
            analysis['error'] = str(e)
            
        return analysis
        
    def is_binary_file(self, file_path: str) -> bool:
        """Check if file is binary"""
        try:
            with open(file_path, 'rb') as f:
                chunk = f.read(1024)
                return b'\x00' in chunk
        except:
            return False
            
    def analyze_binary(self, file_path: str) -> Dict[str, Any]:
        """Analyze binary file structure"""
        analysis = {}
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
                
            # Basic binary analysis
            analysis['entropy'] = self.calculate_entropy(data)
            analysis['magic_bytes'] = data[:8].hex()
            analysis['file_signature'] = self.detect_file_signature(data)
            
        except Exception as e:
            analysis['error'] = str(e)
            
        return analysis
        
    def calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data"""
        if not data:
            return 0.0
            
        entropy = 0
        for x in range(256):
            p_x = data.count(x) / len(data)
            if p_x > 0:
                entropy += -p_x * (p_x.bit_length() - 1)
        return entropy
        
    def detect_file_signature(self, data: bytes) -> str:
        """Detect file type from magic bytes"""
        signatures = {
            b'MZ': 'PE/EXE',
            b'\x7fELF': 'ELF',
            b'\xfe\xed\xfa': 'Mach-O',
            b'PK\x03\x04': 'ZIP',
            b'\x1f\x8b\x08': 'GZIP',
            b'RIFF': 'RIFF/WAV',
            b'\xff\xd8\xff': 'JPEG',
            b'\x89PNG': 'PNG'
        }
        
        for sig, file_type in signatures.items():
            if data.startswith(sig):
                return file_type
        return 'Unknown'
        
    def analyze_security(self, file_path: str) -> Dict[str, Any]:
        """Analyze file security characteristics"""
        security = {}
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
                
            # Check for suspicious patterns
            security['suspicious_patterns'] = self.find_suspicious_patterns(data)
            security['encrypted_sections'] = self.detect_encrypted_sections(data)
            security['anti_debug_features'] = self.detect_anti_debug(data)
            
        except Exception as e:
            security['error'] = str(e)
            
        return security
        
    def find_suspicious_patterns(self, data: bytes) -> List[str]:
        """Find suspicious byte patterns"""
        patterns = []
        
        # Common malware patterns
        suspicious = [
            (b'\x90\x90\x90', 'NOP sled'),
            (b'\xcc\xcc\xcc', 'INT3 sled'),
            (b'\xeb\xfe', 'Infinite loop'),
            (b'\x0f\x31', 'RDTSC instruction'),
            (b'\x0f\xa2', 'CPUID instruction')
        ]
        
        for pattern, description in suspicious:
            if pattern in data:
                patterns.append(f"{description}: {data.count(pattern)} occurrences")
                
        return patterns
        
    def detect_encrypted_sections(self, data: bytes) -> List[Dict[str, Any]]:
        """Detect potentially encrypted sections"""
        sections = []
        chunk_size = 1024
        
        for i in range(0, len(data), chunk_size):
            chunk = data[i:i+chunk_size]
            entropy = self.calculate_entropy(chunk)
            
            if entropy > 7.5:  # High entropy suggests encryption
                sections.append({
                    'offset': i,
                    'size': len(chunk),
                    'entropy': entropy,
                    'confidence': 'high' if entropy > 7.8 else 'medium'
                })
                
        return sections
        
    def detect_anti_debug(self, data: bytes) -> List[str]:
        """Detect anti-debugging techniques"""
        techniques = []
        
        # Common anti-debug patterns
        anti_debug_patterns = [
            (b'\x64\xa1\x30\x00\x00\x00', 'PEB anti-debug'),
            (b'\x64\x8b\x0d\x30\x00\x00\x00', 'PEB access'),
            (b'\x0f\x31', 'RDTSC timing check'),
            (b'\x0f\xa2', 'CPUID check'),
            (b'\x64\x8b\x05\x18\x00\x00\x00', 'TEB access')
        ]
        
        for pattern, technique in anti_debug_patterns:
            if pattern in data:
                techniques.append(technique)
                
        return techniques
        
    def start_file_watcher(self, file_path: str):
        """Start watching a file for changes"""
        def watch_file():
            last_modified = os.path.getmtime(file_path)
            while file_path in self.file_watchers:
                try:
                    current_modified = os.path.getmtime(file_path)
                    if current_modified > last_modified:
                        # File changed, notify watchers
                        self.socketio.emit('file_changed', {
                            'file_path': file_path,
                            'timestamp': datetime.now().isoformat()
                        }, room=f'watch_{file_path}')
                        last_modified = current_modified
                    time.sleep(1)
                except:
                    break
                    
        threading.Thread(target=watch_file, daemon=True).start()
        
    def run(self, host='0.0.0.0', port=5000, debug=True):
        """Run the IDE server"""
        print(f"🚀 Starting DRM Slayer IDE on http://{host}:{port}")
        print("✨ Features:")
        print("   - Real-time DRM analysis")
        print("   - Live file monitoring")
        print("   - Binary visualization")
        print("   - Network manipulation")
        print("   - Hardware virtualization")
        print("   - Collaborative editing")
        
        self.socketio.run(self.app, host=host, port=port, debug=debug)

if __name__ == '__main__':
    ide = DRMIDE()
    ide.run()