// DRM Slayer IDE - Interactive JavaScript
class DRMIDE {
    constructor() {
        this.socket = null;
        this.currentTab = 'dashboard';
        this.currentPath = '.';
        this.analysisResults = {};
        this.systemChart = null;
        this.updateInterval = null;
        
        this.init();
    }
    
    init() {
        this.setupSocket();
        this.setupEventListeners();
        this.setupCharts();
        this.startSystemMonitoring();
        this.loadFileExplorer();
        this.addActivity('IDE initialized successfully');
    }
    
    setupSocket() {
        this.socket = io();
        
        this.socket.on('connect', (data) => {
            console.log('Connected to DRM Slayer IDE');
            this.addActivity('Connected to server');
        });
        
        this.socket.on('disconnect', () => {
            console.log('Disconnected from DRM Slayer IDE');
            this.addActivity('Disconnected from server', 'warning');
        });
        
        this.socket.on('scan_results', (data) => {
            this.handleScanResults(data);
        });
        
        this.socket.on('scan_error', (data) => {
            this.handleScanError(data);
        });
        
        this.socket.on('file_changed', (data) => {
            this.handleFileChanged(data);
        });
    }
    
    setupEventListeners() {
        // Navigation
        document.querySelectorAll('.nav-item').forEach(item => {
            item.addEventListener('click', (e) => {
                e.preventDefault();
                const tab = item.getAttribute('data-tab');
                this.switchTab(tab);
            });
        });
        
        // Top bar actions
        document.getElementById('scan-btn').addEventListener('click', () => {
            this.showScanModal();
        });
        
        document.getElementById('virtualize-btn').addEventListener('click', () => {
            this.enableVirtualization();
        });
        
        document.getElementById('network-btn').addEventListener('click', () => {
            this.switchTab('network');
        });
        
        // File explorer
        document.getElementById('back-btn').addEventListener('click', () => {
            this.navigateBack();
        });
        
        document.getElementById('refresh-btn').addEventListener('click', () => {
            this.loadFileExplorer();
        });
        
        document.getElementById('path-input').addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                this.navigateToPath(e.target.value);
            }
        });
        
        // Analysis
        document.getElementById('analyze-btn').addEventListener('click', () => {
            this.analyzeSelectedFiles();
        });
        
        document.getElementById('real-time-btn').addEventListener('click', () => {
            this.toggleRealTimeAnalysis();
        });
        
        // Analysis tabs
        document.querySelectorAll('.analysis-tab').forEach(tab => {
            tab.addEventListener('click', (e) => {
                this.switchAnalysisTab(e.target.getAttribute('data-tab'));
            });
        });
        
        // Virtualization
        document.getElementById('enable-virtualization').addEventListener('click', () => {
            this.enableVirtualization();
        });
        
        document.getElementById('disable-virtualization').addEventListener('click', () => {
            this.disableVirtualization();
        });
        
        document.getElementById('hw-profile').addEventListener('change', (e) => {
            this.setHardwareProfile(e.target.value);
        });
        
        // Network
        document.getElementById('start-proxy').addEventListener('click', () => {
            this.startProxy();
        });
        
        document.getElementById('stop-proxy').addEventListener('click', () => {
            this.stopProxy();
        });
        
        // Modal
        document.getElementById('start-scan').addEventListener('click', () => {
            this.startScan();
        });
        
        document.getElementById('cancel-scan').addEventListener('click', () => {
            this.hideScanModal();
        });
        
        document.querySelector('.close').addEventListener('click', () => {
            this.hideScanModal();
        });
        
        // View options
        document.querySelectorAll('[data-view]').forEach(btn => {
            btn.addEventListener('click', (e) => {
                this.changeView(e.target.getAttribute('data-view'));
            });
        });
    }
    
    setupCharts() {
        const ctx = document.getElementById('system-chart').getContext('2d');
        this.systemChart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    label: 'CPU Usage',
                    data: [],
                    borderColor: '#00ff88',
                    backgroundColor: 'rgba(0, 255, 136, 0.1)',
                    tension: 0.4
                }, {
                    label: 'Memory Usage',
                    data: [],
                    borderColor: '#0088ff',
                    backgroundColor: 'rgba(0, 136, 255, 0.1)',
                    tension: 0.4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        labels: {
                            color: '#ffffff'
                        }
                    }
                },
                scales: {
                    x: {
                        ticks: {
                            color: '#b0b0b0'
                        },
                        grid: {
                            color: '#333333'
                        }
                    },
                    y: {
                        ticks: {
                            color: '#b0b0b0'
                        },
                        grid: {
                            color: '#333333'
                        }
                    }
                }
            }
        });
    }
    
    startSystemMonitoring() {
        this.updateInterval = setInterval(() => {
            this.updateSystemInfo();
        }, 2000);
    }
    
    async updateSystemInfo() {
        try {
            const response = await fetch('/api/system');
            const data = await response.json();
            
            if (data.success) {
                const info = data.system_info;
                
                // Update status values
                document.getElementById('cpu-usage').textContent = `${info.cpu_percent}%`;
                document.getElementById('ram-usage').textContent = `${info.memory_percent}%`;
                document.getElementById('active-sessions').textContent = info.active_sessions;
                
                // Update chart
                const now = new Date().toLocaleTimeString();
                this.systemChart.data.labels.push(now);
                this.systemChart.data.datasets[0].data.push(info.cpu_percent);
                this.systemChart.data.datasets[1].data.push(info.memory_percent);
                
                // Keep only last 20 points
                if (this.systemChart.data.labels.length > 20) {
                    this.systemChart.data.labels.shift();
                    this.systemChart.data.datasets[0].data.shift();
                    this.systemChart.data.datasets[1].data.shift();
                }
                
                this.systemChart.update('none');
            }
        } catch (error) {
            console.error('Failed to update system info:', error);
        }
    }
    
    switchTab(tabName) {
        // Update navigation
        document.querySelectorAll('.nav-item').forEach(item => {
            item.classList.remove('active');
        });
        document.querySelector(`[data-tab="${tabName}"]`).classList.add('active');
        
        // Update content
        document.querySelectorAll('.tab-content').forEach(content => {
            content.classList.remove('active');
        });
        document.getElementById(tabName).classList.add('active');
        
        // Update breadcrumb
        document.getElementById('breadcrumb').innerHTML = `<span>DRM Slayer IDE / ${tabName.charAt(0).toUpperCase() + tabName.slice(1)}</span>`;
        
        this.currentTab = tabName;
        
        // Load tab-specific content
        if (tabName === 'file-explorer') {
            this.loadFileExplorer();
        }
    }
    
    async loadFileExplorer() {
        try {
            const response = await fetch(`/api/files?path=${encodeURIComponent(this.currentPath)}`);
            const data = await response.json();
            
            if (data.success) {
                this.renderFileList(data.files);
            } else {
                this.addAlert('Failed to load files', 'error');
            }
        } catch (error) {
            console.error('Failed to load files:', error);
            this.addAlert('Failed to load files', 'error');
        }
    }
    
    renderFileList(files) {
        const fileList = document.getElementById('file-list');
        fileList.innerHTML = '';
        
        files.forEach(file => {
            const fileItem = document.createElement('div');
            fileItem.className = `file-item ${file.type}`;
            fileItem.innerHTML = `
                <div class="file-icon">
                    <i class="fas ${file.type === 'directory' ? 'fa-folder' : 'fa-file'}"></i>
                </div>
                <div class="file-info">
                    <div class="file-name">${file.name}</div>
                    <div class="file-details">
                        ${file.type === 'file' ? this.formatFileSize(file.size) : ''}
                        <span class="file-date">${new Date(file.modified).toLocaleDateString()}</span>
                    </div>
                </div>
            `;
            
            fileItem.addEventListener('click', () => {
                if (file.type === 'directory') {
                    this.navigateToPath(file.path);
                } else {
                    this.selectFile(file);
                }
            });
            
            fileList.appendChild(fileItem);
        });
    }
    
    formatFileSize(bytes) {
        if (bytes === null || bytes === undefined) return '';
        
        const sizes = ['B', 'KB', 'MB', 'GB'];
        if (bytes === 0) return '0 B';
        
        const i = Math.floor(Math.log(bytes) / Math.log(1024));
        return Math.round(bytes / Math.pow(1024, i) * 100) / 100 + ' ' + sizes[i];
    }
    
    navigateToPath(path) {
        this.currentPath = path;
        document.getElementById('path-input').value = path;
        this.loadFileExplorer();
        this.addActivity(`Navigated to: ${path}`);
    }
    
    navigateBack() {
        const pathParts = this.currentPath.split('/');
        if (pathParts.length > 1) {
            pathParts.pop();
            this.navigateToPath(pathParts.join('/') || '.');
        }
    }
    
    selectFile(file) {
        this.switchTab('analysis');
        this.analyzeFile(file.path);
    }
    
    async analyzeFile(filePath) {
        try {
            this.addActivity(`Analyzing: ${filePath}`);
            
            const response = await fetch('/api/analyze', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ file_path: filePath })
            });
            
            const data = await response.json();
            
            if (data.success) {
                this.analysisResults = data.analysis;
                this.displayAnalysisResults();
                this.addActivity(`Analysis completed for: ${filePath}`);
            } else {
                this.addAlert(`Analysis failed: ${data.error}`, 'error');
            }
        } catch (error) {
            console.error('Analysis failed:', error);
            this.addAlert('Analysis failed', 'error');
        }
    }
    
    displayAnalysisResults() {
        // Overview
        const overview = document.getElementById('overview');
        if (this.analysisResults.file_info) {
            overview.innerHTML = `
                <h4>File Information</h4>
                <div class="info-grid">
                    <div class="info-item">
                        <label>Size:</label>
                        <span>${this.formatFileSize(this.analysisResults.file_info.size)}</span>
                    </div>
                    <div class="info-item">
                        <label>Created:</label>
                        <span>${new Date(this.analysisResults.file_info.created).toLocaleString()}</span>
                    </div>
                    <div class="info-item">
                        <label>Modified:</label>
                        <span>${new Date(this.analysisResults.file_info.modified).toLocaleString()}</span>
                    </div>
                    <div class="info-item">
                        <label>Permissions:</label>
                        <span>${this.analysisResults.file_info.permissions}</span>
                    </div>
                </div>
            `;
        }
        
        // DRM Analysis
        const drmResults = document.getElementById('drm-results');
        if (this.analysisResults.drm_analysis) {
            drmResults.innerHTML = this.renderDRMAnalysis(this.analysisResults.drm_analysis);
        }
        
        // Binary Analysis
        const binaryResults = document.getElementById('binary-results');
        if (this.analysisResults.binary_analysis) {
            binaryResults.innerHTML = this.renderBinaryAnalysis(this.analysisResults.binary_analysis);
        }
        
        // Security Analysis
        const securityResults = document.getElementById('security-results');
        if (this.analysisResults.security_analysis) {
            securityResults.innerHTML = this.renderSecurityAnalysis(this.analysisResults.security_analysis);
        }
    }
    
    renderDRMAnalysis(drmData) {
        let html = '<h4>DRM Analysis Results</h4>';
        
        if (drmData.files && Object.keys(drmData.files).length > 0) {
            Object.entries(drmData.files).forEach(([filePath, results]) => {
                html += `<div class="drm-file-results">`;
                html += `<h5>${filePath}</h5>`;
                
                if (results.length > 0) {
                    results.forEach(result => {
                        html += `
                            <div class="drm-result-item">
                                <div class="drm-type">${result.drm_type}</div>
                                <div class="drm-confidence">${result.confidence}%</div>
                                <div class="drm-description">${result.description}</div>
                            </div>
                        `;
                    });
                } else {
                    html += '<p>No DRM detected</p>';
                }
                
                html += `</div>`;
            });
        } else {
            html += '<p>No DRM analysis data available</p>';
        }
        
        return html;
    }
    
    renderBinaryAnalysis(binaryData) {
        let html = '<h4>Binary Analysis</h4>';
        
        if (binaryData.entropy !== undefined) {
            html += `<div class="binary-info">`;
            html += `<div class="info-item"><label>Entropy:</label><span>${binaryData.entropy.toFixed(2)}</span></div>`;
            html += `<div class="info-item"><label>Magic Bytes:</label><span>${binaryData.magic_bytes}</span></div>`;
            html += `<div class="info-item"><label>File Type:</label><span>${binaryData.file_signature}</span></div>`;
            html += `</div>`;
        } else {
            html += '<p>No binary analysis data available</p>';
        }
        
        return html;
    }
    
    renderSecurityAnalysis(securityData) {
        let html = '<h4>Security Analysis</h4>';
        
        if (securityData.suspicious_patterns && securityData.suspicious_patterns.length > 0) {
            html += '<h5>Suspicious Patterns</h5>';
            html += '<ul>';
            securityData.suspicious_patterns.forEach(pattern => {
                html += `<li>${pattern}</li>`;
            });
            html += '</ul>';
        }
        
        if (securityData.encrypted_sections && securityData.encrypted_sections.length > 0) {
            html += '<h5>Encrypted Sections</h5>';
            securityData.encrypted_sections.forEach(section => {
                html += `
                    <div class="encrypted-section">
                        <div>Offset: ${section.offset}</div>
                        <div>Size: ${section.size}</div>
                        <div>Entropy: ${section.entropy.toFixed(2)}</div>
                        <div>Confidence: ${section.confidence}</div>
                    </div>
                `;
            });
        }
        
        if (securityData.anti_debug_features && securityData.anti_debug_features.length > 0) {
            html += '<h5>Anti-Debug Features</h5>';
            html += '<ul>';
            securityData.anti_debug_features.forEach(feature => {
                html += `<li>${feature}</li>`;
            });
            html += '</ul>';
        }
        
        return html;
    }
    
    switchAnalysisTab(tabName) {
        document.querySelectorAll('.analysis-tab').forEach(tab => {
            tab.classList.remove('active');
        });
        document.querySelector(`[data-tab="${tabName}"]`).classList.add('active');
        
        document.querySelectorAll('.analysis-panel').forEach(panel => {
            panel.classList.remove('active');
        });
        document.getElementById(tabName).classList.add('active');
    }
    
    async enableVirtualization() {
        try {
            const response = await fetch('/api/virtualization', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ action: 'enable' })
            });
            
            const data = await response.json();
            
            if (data.success) {
                document.getElementById('virtualization-status').textContent = 'Enabled';
                document.getElementById('virtualization-status').style.color = '#00ff88';
                this.addActivity('Hardware virtualization enabled');
                this.addAlert('Virtualization enabled successfully', 'info');
            } else {
                this.addAlert('Failed to enable virtualization', 'error');
            }
        } catch (error) {
            console.error('Virtualization failed:', error);
            this.addAlert('Virtualization failed', 'error');
        }
    }
    
    async disableVirtualization() {
        try {
            const response = await fetch('/api/virtualization', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ action: 'disable' })
            });
            
            const data = await response.json();
            
            if (data.success) {
                document.getElementById('virtualization-status').textContent = 'Disabled';
                document.getElementById('virtualization-status').style.color = '#ff4444';
                this.addActivity('Hardware virtualization disabled');
                this.addAlert('Virtualization disabled successfully', 'info');
            } else {
                this.addAlert('Failed to disable virtualization', 'error');
            }
        } catch (error) {
            console.error('Virtualization failed:', error);
            this.addAlert('Virtualization failed', 'error');
        }
    }
    
    async setHardwareProfile(profile) {
        try {
            const response = await fetch('/api/virtualization', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ action: 'set_profile', profile: profile })
            });
            
            const data = await response.json();
            
            if (data.success) {
                document.getElementById('current-profile').textContent = profile;
                this.addActivity(`Hardware profile set to: ${profile}`);
            } else {
                this.addAlert('Failed to set hardware profile', 'error');
            }
        } catch (error) {
            console.error('Profile setting failed:', error);
            this.addAlert('Profile setting failed', 'error');
        }
    }
    
    async startProxy() {
        const protocol = document.getElementById('protocol-select').value;
        const localPort = document.getElementById('local-port').value;
        const remoteHost = document.getElementById('remote-host').value;
        const remotePort = document.getElementById('remote-port').value;
        
        try {
            const response = await fetch('/api/network', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    action: 'start_proxy',
                    protocol: protocol,
                    local_port: parseInt(localPort),
                    remote_host: remoteHost,
                    remote_port: parseInt(remotePort)
                })
            });
            
            const data = await response.json();
            
            if (data.success) {
                this.addActivity(`Proxy started: ${protocol}://${remoteHost}:${remotePort} -> localhost:${localPort}`);
                this.addAlert('Proxy started successfully', 'info');
            } else {
                this.addAlert('Failed to start proxy', 'error');
            }
        } catch (error) {
            console.error('Proxy failed:', error);
            this.addAlert('Proxy failed', 'error');
        }
    }
    
    stopProxy() {
        this.addActivity('Proxy stopped');
        this.addAlert('Proxy stopped', 'info');
    }
    
    showScanModal() {
        document.getElementById('scan-modal').style.display = 'block';
    }
    
    hideScanModal() {
        document.getElementById('scan-modal').style.display = 'none';
    }
    
    async startScan() {
        const scanType = document.getElementById('scan-type').value;
        const scanPath = document.getElementById('scan-path').value;
        const recursive = document.getElementById('recursive-scan').checked;
        
        this.hideScanModal();
        this.addActivity(`Starting scan: ${scanType} on ${scanPath}`);
        
        try {
            const response = await fetch('/api/scan', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    path: scanPath,
                    drm_types: scanType === 'all' ? null : [scanType]
                })
            });
            
            const data = await response.json();
            
            if (data.success) {
                this.handleScanResults(data.results);
                this.addActivity('Scan completed successfully');
            } else {
                this.addAlert(`Scan failed: ${data.error}`, 'error');
            }
        } catch (error) {
            console.error('Scan failed:', error);
            this.addAlert('Scan failed', 'error');
        }
    }
    
    handleScanResults(results) {
        // Update statistics
        if (results.statistics) {
            document.getElementById('drm-detected').textContent = results.statistics.drm_detected || 0;
            document.getElementById('files-scanned').textContent = results.statistics.files_scanned || 0;
            document.getElementById('success-rate').textContent = `${results.statistics.success_rate || 0}%`;
        }
        
        // Display results
        if (this.currentTab === 'analysis') {
            this.analysisResults.drm_analysis = results;
            this.displayAnalysisResults();
        }
        
        this.addActivity('Scan results received');
    }
    
    handleScanError(data) {
        this.addAlert(`Scan error: ${data.error}`, 'error');
    }
    
    handleFileChanged(data) {
        this.addActivity(`File changed: ${data.file_path}`);
    }
    
    changeView(viewType) {
        document.querySelectorAll('[data-view]').forEach(btn => {
            btn.classList.remove('active');
        });
        document.querySelector(`[data-view="${viewType}"]`).classList.add('active');
        
        const fileList = document.getElementById('file-list');
        fileList.className = `file-list view-${viewType}`;
    }
    
    addActivity(text, type = 'info') {
        const activityLog = document.getElementById('activity-log');
        const activityItem = document.createElement('div');
        activityItem.className = 'activity-item';
        
        const time = new Date().toLocaleTimeString();
        activityItem.innerHTML = `
            <span class="activity-time">${time}</span>
            <span class="activity-text">${text}</span>
        `;
        
        activityLog.appendChild(activityItem);
        activityLog.scrollTop = activityLog.scrollHeight;
        
        // Keep only last 50 activities
        while (activityLog.children.length > 50) {
            activityLog.removeChild(activityLog.firstChild);
        }
    }
    
    addAlert(text, type = 'info') {
        const alertsList = document.getElementById('alerts-list');
        const alertItem = document.createElement('div');
        alertItem.className = `alert-item ${type}`;
        
        const icon = type === 'error' ? 'fa-exclamation-circle' : 
                    type === 'warning' ? 'fa-exclamation-triangle' : 'fa-info-circle';
        
        alertItem.innerHTML = `
            <i class="fas ${icon}"></i>
            <span>${text}</span>
        `;
        
        alertsList.appendChild(alertItem);
        
        // Auto-remove after 5 seconds
        setTimeout(() => {
            if (alertItem.parentNode) {
                alertItem.parentNode.removeChild(alertItem);
            }
        }, 5000);
    }
    
    toggleRealTimeAnalysis() {
        const btn = document.getElementById('real-time-btn');
        const isActive = btn.classList.contains('active');
        
        if (isActive) {
            btn.classList.remove('active');
            btn.innerHTML = '<i class="fas fa-play"></i> Real-time';
            this.addActivity('Real-time analysis stopped');
        } else {
            btn.classList.add('active');
            btn.innerHTML = '<i class="fas fa-pause"></i> Stop';
            this.addActivity('Real-time analysis started');
        }
    }
    
    analyzeSelectedFiles() {
        const fileInput = document.getElementById('file-input');
        if (fileInput.files.length > 0) {
            Array.from(fileInput.files).forEach(file => {
                this.analyzeFile(file.path);
            });
        } else {
            this.addAlert('Please select files to analyze', 'warning');
        }
    }
}

// Initialize the IDE when the page loads
document.addEventListener('DOMContentLoaded', () => {
    window.drmIDE = new DRMIDE();
});

// Close modal when clicking outside
window.addEventListener('click', (event) => {
    const modal = document.getElementById('scan-modal');
    if (event.target === modal) {
        modal.style.display = 'none';
    }
});

// Keyboard shortcuts
document.addEventListener('keydown', (e) => {
    if (e.ctrlKey || e.metaKey) {
        switch (e.key) {
            case '1':
                e.preventDefault();
                window.drmIDE.switchTab('dashboard');
                break;
            case '2':
                e.preventDefault();
                window.drmIDE.switchTab('file-explorer');
                break;
            case '3':
                e.preventDefault();
                window.drmIDE.switchTab('analysis');
                break;
            case '4':
                e.preventDefault();
                window.drmIDE.switchTab('virtualization');
                break;
            case '5':
                e.preventDefault();
                window.drmIDE.switchTab('network');
                break;
            case 's':
                e.preventDefault();
                window.drmIDE.showScanModal();
                break;
        }
    }
});