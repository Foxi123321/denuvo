#!/usr/bin/env python3
"""
DRM Slayer IDE - Simplified Version
A lightweight web-based IDE for DRM analysis that works with minimal dependencies
"""

import os
import sys
import json
import time
import threading
import base64
import hashlib
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime
import http.server
import socketserver
import urllib.parse
import mimetypes

# Try to import optional dependencies
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    print("⚠️  psutil not available - system monitoring will be limited")

# Import our DRM Slayer core
try:
    from drm_slayer import DRMSlayer
    DRM_SLAYER_AVAILABLE = True
except ImportError as e:
    print(f"⚠️  DRM Slayer core not available: {e}")
    DRM_SLAYER_AVAILABLE = False

class SimpleDRMIDE:
    def __init__(self):
        self.port = 8080
        self.host = '0.0.0.0'
        self.static_dir = 'static'
        self.templates_dir = 'templates'
        
        # Initialize core components if available
        self.drm_slayer = None
        if DRM_SLAYER_AVAILABLE:
            try:
                self.drm_slayer = DRMSlayer()
            except Exception as e:
                print(f"⚠️  Failed to initialize DRM Slayer: {e}")
        
        # IDE state
        self.active_sessions = {}
        self.analysis_cache = {}
        
    def get_system_info(self) -> Dict[str, Any]:
        """Get basic system information"""
        info = {
            'timestamp': datetime.now().isoformat(),
            'active_sessions': len(self.active_sessions),
            'cached_analyses': len(self.analysis_cache)
        }
        
        if PSUTIL_AVAILABLE:
            try:
                info['cpu_percent'] = psutil.cpu_percent(interval=1)
                info['memory_percent'] = psutil.virtual_memory().percent
                info['disk_usage'] = psutil.disk_usage('/').percent
            except:
                pass
        
        return info
    
    def get_file_tree(self, path: str) -> List[Dict[str, Any]]:
        """Get file tree structure"""
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
        """Perform basic file analysis"""
        if file_path in self.analysis_cache:
            return self.analysis_cache[file_path]
            
        analysis = {
            'file_info': {},
            'drm_analysis': {},
            'binary_analysis': {},
            'security_analysis': {},
            'error': None
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
            
            # DRM analysis if available
            if self.drm_slayer:
                try:
                    drm_results = self.drm_slayer.scan(file_path)
                    analysis['drm_analysis'] = drm_results
                except Exception as e:
                    analysis['drm_analysis'] = {'error': str(e)}
            
            # Basic binary analysis
            if self.is_binary_file(file_path):
                analysis['binary_analysis'] = self.analyze_binary(file_path)
                
            # Basic security analysis
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

class IDEHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, ide_instance=None, **kwargs):
        self.ide = ide_instance
        super().__init__(*args, **kwargs)
    
    def do_GET(self):
        """Handle GET requests"""
        parsed_path = urllib.parse.urlparse(self.path)
        path = parsed_path.path
        
        # API endpoints
        if path.startswith('/api/'):
            self.handle_api_request(path, parsed_path.query)
            return
        
        # Serve static files
        if path.startswith('/static/'):
            self.serve_static_file(path)
            return
        
        # Serve main page
        if path == '/' or path == '/index.html':
            self.serve_main_page()
            return
        
        # Default to static file serving
        super().do_GET()
    
    def do_POST(self):
        """Handle POST requests"""
        parsed_path = urllib.parse.urlparse(self.path)
        path = parsed_path.path
        
        if path.startswith('/api/'):
            self.handle_api_post(path)
            return
        
        self.send_error(404, "Not found")
    
    def handle_api_request(self, path: str, query: str):
        """Handle API GET requests"""
        try:
            if path == '/api/system':
                response = self.ide.get_system_info()
                self.send_json_response(response)
                
            elif path == '/api/files':
                params = urllib.parse.parse_qs(query)
                file_path = params.get('path', ['.'])[0]
                files = self.ide.get_file_tree(file_path)
                self.send_json_response({'success': True, 'files': files})
                
            else:
                self.send_error(404, "API endpoint not found")
                
        except Exception as e:
            self.send_json_response({'error': str(e)}, status=500)
    
    def handle_api_post(self, path: str):
        """Handle API POST requests"""
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length)
            data = json.loads(post_data.decode('utf-8'))
            
            if path == '/api/analyze':
                file_path = data.get('file_path', '')
                analysis = self.ide.analyze_file(file_path)
                self.send_json_response({'success': True, 'analysis': analysis})
                
            elif path == '/api/scan':
                scan_path = data.get('path', '.')
                if self.ide.drm_slayer:
                    results = self.ide.drm_slayer.scan(scan_path)
                    self.send_json_response({'success': True, 'results': results})
                else:
                    self.send_json_response({'success': False, 'error': 'DRM Slayer not available'})
                    
            else:
                self.send_error(404, "API endpoint not found")
                
        except Exception as e:
            self.send_json_response({'error': str(e)}, status=500)
    
    def send_json_response(self, data: Dict[str, Any], status: int = 200):
        """Send JSON response"""
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()
        
        response = json.dumps(data, indent=2)
        self.wfile.write(response.encode('utf-8'))
    
    def serve_static_file(self, path: str):
        """Serve static files"""
        file_path = path[1:]  # Remove leading slash
        
        if os.path.exists(file_path):
            with open(file_path, 'rb') as f:
                content = f.read()
            
            # Determine MIME type
            mime_type, _ = mimetypes.guess_type(file_path)
            if mime_type is None:
                mime_type = 'application/octet-stream'
            
            self.send_response(200)
            self.send_header('Content-Type', mime_type)
            self.end_headers()
            self.wfile.write(content)
        else:
            self.send_error(404, "File not found")
    
    def serve_main_page(self):
        """Serve the main HTML page"""
        html_content = self.get_main_html()
        
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        self.wfile.write(html_content.encode('utf-8'))
    
    def get_main_html(self) -> str:
        """Get the main HTML content"""
        return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DRM Slayer IDE - Simplified</title>
    <style>
        /* Simplified CSS for basic functionality */
        body {
            font-family: Arial, sans-serif;
            background: #0a0a0a;
            color: #ffffff;
            margin: 0;
            padding: 20px;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        .header {
            text-align: center;
            margin-bottom: 30px;
        }
        .header h1 {
            color: #00ff88;
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        .tabs {
            display: flex;
            margin-bottom: 20px;
            border-bottom: 1px solid #333;
        }
        .tab {
            padding: 10px 20px;
            background: #1a1a1a;
            border: none;
            color: #fff;
            cursor: pointer;
            margin-right: 5px;
        }
        .tab.active {
            background: #00ff88;
            color: #000;
        }
        .tab-content {
            display: none;
            background: #1a1a1a;
            padding: 20px;
            border-radius: 5px;
        }
        .tab-content.active {
            display: block;
        }
        .btn {
            padding: 8px 16px;
            background: #00ff88;
            color: #000;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            margin: 5px;
        }
        .btn:hover {
            background: #00cc6a;
        }
        .file-list {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
            gap: 10px;
        }
        .file-item {
            background: #2a2a2a;
            padding: 10px;
            border-radius: 4px;
            cursor: pointer;
        }
        .file-item:hover {
            background: #3a3a3a;
        }
        .status {
            background: #2a2a2a;
            padding: 15px;
            border-radius: 4px;
            margin: 10px 0;
        }
        .analysis-result {
            background: #2a2a2a;
            padding: 15px;
            border-radius: 4px;
            margin: 10px 0;
        }
        input, select {
            padding: 8px;
            background: #2a2a2a;
            border: 1px solid #333;
            color: #fff;
            border-radius: 4px;
            margin: 5px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ DRM Slayer IDE</h1>
            <p>Simplified Web-Based Analysis Environment</p>
        </div>
        
        <div class="tabs">
            <button class="tab active" onclick="switchTab('dashboard')">Dashboard</button>
            <button class="tab" onclick="switchTab('files')">File Explorer</button>
            <button class="tab" onclick="switchTab('analysis')">Analysis</button>
            <button class="tab" onclick="switchTab('scan')">DRM Scan</button>
        </div>
        
        <div id="dashboard" class="tab-content active">
            <h2>System Dashboard</h2>
            <div class="status" id="system-status">
                <h3>System Information</h3>
                <div id="system-info">Loading...</div>
            </div>
            <div class="status">
                <h3>Quick Actions</h3>
                <button class="btn" onclick="loadFiles()">Browse Files</button>
                <button class="btn" onclick="switchTab('scan')">Start DRM Scan</button>
            </div>
        </div>
        
        <div id="files" class="tab-content">
            <h2>File Explorer</h2>
            <div>
                <input type="text" id="path-input" value="." placeholder="Enter path">
                <button class="btn" onclick="loadFiles()">Load</button>
                <button class="btn" onclick="goBack()">Back</button>
            </div>
            <div class="file-list" id="file-list">
                Loading files...
            </div>
        </div>
        
        <div id="analysis" class="tab-content">
            <h2>File Analysis</h2>
            <div>
                <input type="file" id="file-input" multiple>
                <button class="btn" onclick="analyzeFiles()">Analyze</button>
            </div>
            <div id="analysis-results">
                Select files to analyze...
            </div>
        </div>
        
        <div id="scan" class="tab-content">
            <h2>DRM Scanner</h2>
            <div>
                <input type="text" id="scan-path" value="." placeholder="Path to scan">
                <select id="scan-type">
                    <option value="all">All DRM Types</option>
                    <option value="denuvo">Denuvo Only</option>
                    <option value="steam">Steam Only</option>
                </select>
                <button class="btn" onclick="startScan()">Start Scan</button>
            </div>
            <div id="scan-results">
                Ready to scan...
            </div>
        </div>
    </div>
    
    <script>
        let currentPath = '.';
        
        function switchTab(tabName) {
            // Hide all tabs
            document.querySelectorAll('.tab-content').forEach(tab => {
                tab.classList.remove('active');
            });
            document.querySelectorAll('.tab').forEach(tab => {
                tab.classList.remove('active');
            });
            
            // Show selected tab
            document.getElementById(tabName).classList.add('active');
            event.target.classList.add('active');
            
            // Load tab-specific content
            if (tabName === 'files') {
                loadFiles();
            } else if (tabName === 'dashboard') {
                updateSystemInfo();
            }
        }
        
        async function updateSystemInfo() {
            try {
                const response = await fetch('/api/system');
                const data = await response.json();
                
                let info = '<div>';
                for (const [key, value] of Object.entries(data)) {
                    if (key !== 'timestamp') {
                        info += `<div><strong>${key}:</strong> ${value}</div>`;
                    }
                }
                info += '</div>';
                
                document.getElementById('system-info').innerHTML = info;
            } catch (error) {
                document.getElementById('system-info').innerHTML = 'Error loading system info';
            }
        }
        
        async function loadFiles() {
            const path = document.getElementById('path-input').value || currentPath;
            currentPath = path;
            
            try {
                const response = await fetch(`/api/files?path=${encodeURIComponent(path)}`);
                const data = await response.json();
                
                if (data.success) {
                    renderFileList(data.files);
                } else {
                    document.getElementById('file-list').innerHTML = 'Error loading files';
                }
            } catch (error) {
                document.getElementById('file-list').innerHTML = 'Error loading files';
            }
        }
        
        function renderFileList(files) {
            const fileList = document.getElementById('file-list');
            let html = '';
            
            files.forEach(file => {
                const icon = file.type === 'directory' ? '📁' : '📄';
                const size = file.size ? formatFileSize(file.size) : '';
                html += `
                    <div class="file-item" onclick="handleFileClick('${file.path}', '${file.type}')">
                        <div>${icon} ${file.name}</div>
                        <div style="font-size: 0.8em; color: #888;">
                            ${size} • ${new Date(file.modified).toLocaleDateString()}
                        </div>
                    </div>
                `;
            });
            
            fileList.innerHTML = html;
        }
        
        function formatFileSize(bytes) {
            if (bytes === 0) return '0 B';
            const k = 1024;
            const sizes = ['B', 'KB', 'MB', 'GB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        }
        
        function handleFileClick(path, type) {
            if (type === 'directory') {
                document.getElementById('path-input').value = path;
                loadFiles();
            } else {
                analyzeFile(path);
            }
        }
        
        function goBack() {
            const pathParts = currentPath.split('/');
            if (pathParts.length > 1) {
                pathParts.pop();
                const newPath = pathParts.join('/') || '.';
                document.getElementById('path-input').value = newPath;
                loadFiles();
            }
        }
        
        async function analyzeFiles() {
            const fileInput = document.getElementById('file-input');
            if (fileInput.files.length > 0) {
                for (const file of fileInput.files) {
                    await analyzeFile(file.name);
                }
            } else {
                document.getElementById('analysis-results').innerHTML = 'Please select files to analyze';
            }
        }
        
        async function analyzeFile(filePath) {
            try {
                const response = await fetch('/api/analyze', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ file_path: filePath })
                });
                
                const data = await response.json();
                
                if (data.success) {
                    displayAnalysisResults(data.analysis);
                } else {
                    document.getElementById('analysis-results').innerHTML = 'Analysis failed';
                }
            } catch (error) {
                document.getElementById('analysis-results').innerHTML = 'Analysis error';
            }
        }
        
        function displayAnalysisResults(analysis) {
            let html = '<h3>Analysis Results</h3>';
            
            if (analysis.file_info) {
                html += '<div class="analysis-result">';
                html += '<h4>File Information</h4>';
                html += `<div>Size: ${formatFileSize(analysis.file_info.size)}</div>`;
                html += `<div>Created: ${new Date(analysis.file_info.created).toLocaleString()}</div>`;
                html += `<div>Modified: ${new Date(analysis.file_info.modified).toLocaleString()}</div>`;
                html += '</div>';
            }
            
            if (analysis.binary_analysis && analysis.binary_analysis.entropy !== undefined) {
                html += '<div class="analysis-result">';
                html += '<h4>Binary Analysis</h4>';
                html += `<div>Entropy: ${analysis.binary_analysis.entropy.toFixed(2)}</div>`;
                html += `<div>File Type: ${analysis.binary_analysis.file_signature}</div>`;
                html += '</div>';
            }
            
            if (analysis.security_analysis) {
                html += '<div class="analysis-result">';
                html += '<h4>Security Analysis</h4>';
                if (analysis.security_analysis.suspicious_patterns) {
                    html += '<div>Suspicious Patterns: ' + analysis.security_analysis.suspicious_patterns.length + '</div>';
                }
                if (analysis.security_analysis.anti_debug_features) {
                    html += '<div>Anti-Debug Features: ' + analysis.security_analysis.anti_debug_features.length + '</div>';
                }
                html += '</div>';
            }
            
            document.getElementById('analysis-results').innerHTML = html;
        }
        
        async function startScan() {
            const path = document.getElementById('scan-path').value;
            const type = document.getElementById('scan-type').value;
            
            document.getElementById('scan-results').innerHTML = 'Scanning...';
            
            try {
                const response = await fetch('/api/scan', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ path: path, drm_types: type === 'all' ? null : [type] })
                });
                
                const data = await response.json();
                
                if (data.success) {
                    displayScanResults(data.results);
                } else {
                    document.getElementById('scan-results').innerHTML = 'Scan failed: ' + data.error;
                }
            } catch (error) {
                document.getElementById('scan-results').innerHTML = 'Scan error';
            }
        }
        
        function displayScanResults(results) {
            let html = '<h3>Scan Results</h3>';
            
            if (results.files && Object.keys(results.files).length > 0) {
                Object.entries(results.files).forEach(([filePath, fileResults]) => {
                    html += '<div class="analysis-result">';
                    html += `<h4>${filePath}</h4>`;
                    if (fileResults.length > 0) {
                        fileResults.forEach(result => {
                            html += `<div>• ${result.drm_type} (${result.confidence}%)</div>`;
                        });
                    } else {
                        html += '<div>No DRM detected</div>';
                    }
                    html += '</div>';
                });
            } else {
                html += '<div>No files scanned or no results available</div>';
            }
            
            document.getElementById('scan-results').innerHTML = html;
        }
        
        // Initialize
        updateSystemInfo();
        setInterval(updateSystemInfo, 5000);
    </script>
</body>
</html>
        """
    
    def log_message(self, format, *args):
        """Override to reduce logging noise"""
        pass

def main():
    print("🚀 DRM Slayer IDE - Simplified Version")
    print("=" * 50)
    
    # Check if we're in the right directory
    if not os.path.exists('drm_slayer.py'):
        print("⚠️  Warning: drm_slayer.py not found - some features will be limited")
    
    # Create IDE instance
    ide = SimpleDRMIDE()
    
    # Create custom request handler
    class CustomHandler(IDEHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, ide_instance=ide, **kwargs)
    
    # Start server
    with socketserver.TCPServer((ide.host, ide.port), CustomHandler) as httpd:
        print(f"🎯 Starting DRM Slayer IDE on http://{ide.host}:{ide.port}")
        print("📱 Open your browser and navigate to the URL above")
        print("⌨️  Press Ctrl+C to stop the server")
        print("=" * 50)
        
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n👋 DRM Slayer IDE stopped.")

if __name__ == '__main__':
    main()