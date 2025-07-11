/**
 * CrazyIDE - Main Application Controller
 * Handles application initialization and core functionality
 */

class CrazyIDE {
    constructor() {
        this.editors = new Map();
        this.activeEditor = null;
        this.currentTheme = localStorage.getItem('theme') || 'dark';
        this.fileSystem = new FileSystemManager();
        this.terminal = new Terminal();
        this.gitManager = new GitManager();
        this.extensionManager = new ExtensionManager();
        this.aiAssistant = new AIAssistant();
        this.themeManager = new ThemeManager();
        
        this.shortcuts = new Map();
        this.commandPalette = {
            isOpen: false,
            commands: new Map(),
            selectedIndex: 0
        };
        
        this.notifications = [];
        this.contextMenu = null;
        this.modal = null;
        
        this.init();
    }

    async init() {
        console.log('🚀 Initializing CrazyIDE...');
        
        // Set initial theme
        this.themeManager.setTheme(this.currentTheme);
        
        // Initialize components
        await this.initializeComponents();
        
        // Setup event listeners
        this.setupEventListeners();
        
        // Register keyboard shortcuts
        this.registerShortcuts();
        
        // Register command palette commands
        this.registerCommands();
        
        // Load workspace
        await this.loadWorkspace();
        
        // Initialize file tree
        await this.fileSystem.refreshFileTree();
        
        // Initialize Monaco Editor
        await this.initializeMonaco();
        
        // Show welcome screen
        this.showWelcomeScreen();
        
        console.log('✅ CrazyIDE initialized successfully!');
        this.showNotification('Welcome to CrazyIDE!', 'success');
    }

    async initializeComponents() {
        // Initialize all managers
        await this.fileSystem.init();
        await this.terminal.init();
        await this.gitManager.init();
        await this.extensionManager.init();
        await this.aiAssistant.init();
    }

    async initializeMonaco() {
        return new Promise((resolve) => {
            require.config({ paths: { vs: 'https://cdnjs.cloudflare.com/ajax/libs/monaco-editor/0.44.0/min/vs' } });
            require(['vs/editor/editor.main'], () => {
                // Configure Monaco themes
                monaco.editor.defineTheme('crazyide-dark', {
                    base: 'vs-dark',
                    inherit: true,
                    rules: [
                        { token: 'comment', foreground: '6A9955' },
                        { token: 'keyword', foreground: '569CD6' },
                        { token: 'string', foreground: 'CE9178' },
                        { token: 'number', foreground: 'B5CEA8' },
                        { token: 'type', foreground: '4EC9B0' },
                        { token: 'function', foreground: 'DCDCAA' },
                        { token: 'variable', foreground: '9CDCFE' }
                    ],
                    colors: {
                        'editor.background': '#1e1e1e',
                        'editor.foreground': '#cccccc',
                        'editor.lineHighlightBackground': '#2d2d30',
                        'editor.selectionBackground': '#264f78',
                        'editor.inactiveSelectionBackground': '#3a3d41'
                    }
                });

                monaco.editor.defineTheme('crazyide-light', {
                    base: 'vs',
                    inherit: true,
                    rules: [
                        { token: 'comment', foreground: '008000' },
                        { token: 'keyword', foreground: '0000FF' },
                        { token: 'string', foreground: 'A31515' },
                        { token: 'number', foreground: '098658' },
                        { token: 'type', foreground: '267F99' },
                        { token: 'function', foreground: '795E26' },
                        { token: 'variable', foreground: '001080' }
                    ],
                    colors: {
                        'editor.background': '#ffffff',
                        'editor.foreground': '#000000',
                        'editor.lineHighlightBackground': '#f0f0f0',
                        'editor.selectionBackground': '#ADD6FF',
                        'editor.inactiveSelectionBackground': '#E5EBF1'
                    }
                });

                // Set default theme
                monaco.editor.setTheme(this.currentTheme === 'dark' ? 'crazyide-dark' : 'crazyide-light');
                
                resolve();
            });
        });
    }

    setupEventListeners() {
        // Menu interactions
        this.setupMenuEvents();
        
        // Sidebar interactions
        this.setupSidebarEvents();
        
        // Tab interactions
        this.setupTabEvents();
        
        // Bottom panel interactions
        this.setupBottomPanelEvents();
        
        // Global events
        this.setupGlobalEvents();
        
        // Theme toggle
        document.getElementById('theme-toggle').addEventListener('click', () => {
            this.toggleTheme();
        });
        
        // Command palette
        document.addEventListener('keydown', (e) => {
            if ((e.ctrlKey || e.metaKey) && e.shiftKey && e.key === 'P') {
                e.preventDefault();
                this.toggleCommandPalette();
            }
        });
        
        // Context menu
        document.addEventListener('contextmenu', (e) => {
            e.preventDefault();
            this.showContextMenu(e.clientX, e.clientY, this.getContextMenuItems(e.target));
        });
        
        // Click outside to close menus
        document.addEventListener('click', (e) => {
            this.closeContextMenu();
            this.closeCommandPalette();
        });
    }

    setupMenuEvents() {
        // File menu actions
        document.querySelectorAll('[data-action]').forEach(element => {
            element.addEventListener('click', (e) => {
                e.stopPropagation();
                const action = e.target.closest('[data-action]').dataset.action;
                this.executeAction(action);
            });
        });
    }

    setupSidebarEvents() {
        // Sidebar tab switching
        document.querySelectorAll('.sidebar-tab').forEach(tab => {
            tab.addEventListener('click', () => {
                this.switchSidebarPanel(tab.dataset.panel);
            });
        });
        
        // File tree interactions
        document.getElementById('file-tree').addEventListener('click', (e) => {
            const fileItem = e.target.closest('.file-item');
            const folderItem = e.target.closest('.folder-item');
            
            if (fileItem) {
                this.openFile(fileItem.dataset.path);
            } else if (folderItem) {
                this.toggleFolder(folderItem);
            }
        });
    }

    setupTabEvents() {
        // Tab switching and closing
        document.getElementById('tabs').addEventListener('click', (e) => {
            const tab = e.target.closest('.tab');
            if (!tab) return;
            
            if (e.target.closest('.tab-close')) {
                this.closeTab(tab.dataset.fileId);
            } else {
                this.switchTab(tab.dataset.fileId);
            }
        });
        
        // Tab actions
        document.querySelectorAll('.tab-actions .btn-icon').forEach(btn => {
            btn.addEventListener('click', () => {
                const action = btn.dataset.action;
                if (action === 'split-horizontal') {
                    this.splitEditor('horizontal');
                } else if (action === 'split-vertical') {
                    this.splitEditor('vertical');
                }
            });
        });
    }

    setupBottomPanelEvents() {
        // Bottom panel tab switching
        document.querySelectorAll('.bottom-tab').forEach(tab => {
            tab.addEventListener('click', () => {
                this.switchBottomPanel(tab.dataset.panel);
            });
        });
    }

    setupGlobalEvents() {
        // Window resize
        window.addEventListener('resize', () => {
            this.resizeEditors();
        });
        
        // Prevent default drag and drop
        document.addEventListener('dragover', (e) => e.preventDefault());
        document.addEventListener('drop', (e) => {
            e.preventDefault();
            this.handleFileDrop(e);
        });
        
        // Save on Ctrl+S
        document.addEventListener('keydown', (e) => {
            if ((e.ctrlKey || e.metaKey) && e.key === 's') {
                e.preventDefault();
                this.saveCurrentFile();
            }
        });
    }

    registerShortcuts() {
        const shortcuts = [
            { key: 'Ctrl+N', action: 'new-file' },
            { key: 'Ctrl+O', action: 'open-file' },
            { key: 'Ctrl+S', action: 'save' },
            { key: 'Ctrl+Shift+S', action: 'save-as' },
            { key: 'Ctrl+Z', action: 'undo' },
            { key: 'Ctrl+Y', action: 'redo' },
            { key: 'Ctrl+F', action: 'find' },
            { key: 'Ctrl+H', action: 'replace' },
            { key: 'F5', action: 'run-file' },
            { key: 'F9', action: 'debug' },
            { key: 'Ctrl+Shift+B', action: 'build' },
            { key: 'Ctrl+`', action: 'toggle-terminal' },
            { key: 'Ctrl+Shift+P', action: 'command-palette' }
        ];

        shortcuts.forEach(shortcut => {
            this.shortcuts.set(shortcut.key, shortcut.action);
        });
    }

    registerCommands() {
        const commands = [
            { id: 'file.new', name: 'File: New File', icon: 'fas fa-file', action: () => this.createNewFile() },
            { id: 'file.open', name: 'File: Open File', icon: 'fas fa-folder-open', action: () => this.openFileDialog() },
            { id: 'file.save', name: 'File: Save', icon: 'fas fa-save', action: () => this.saveCurrentFile() },
            { id: 'view.toggle-sidebar', name: 'View: Toggle Sidebar', icon: 'fas fa-bars', action: () => this.toggleSidebar() },
            { id: 'view.toggle-terminal', name: 'View: Toggle Terminal', icon: 'fas fa-terminal', action: () => this.toggleTerminal() },
            { id: 'view.toggle-minimap', name: 'View: Toggle Minimap', icon: 'fas fa-map', action: () => this.toggleMinimap() },
            { id: 'theme.toggle', name: 'Theme: Toggle Dark/Light', icon: 'fas fa-palette', action: () => this.toggleTheme() },
            { id: 'git.commit', name: 'Git: Commit', icon: 'fas fa-check', action: () => this.gitManager.commit() },
            { id: 'git.push', name: 'Git: Push', icon: 'fas fa-arrow-up', action: () => this.gitManager.push() },
            { id: 'git.pull', name: 'Git: Pull', icon: 'fas fa-arrow-down', action: () => this.gitManager.pull() },
            { id: 'run.file', name: 'Run: Run File', icon: 'fas fa-play', action: () => this.runCurrentFile() },
            { id: 'debug.start', name: 'Debug: Start Debugging', icon: 'fas fa-bug', action: () => this.startDebugging() }
        ];

        commands.forEach(command => {
            this.commandPalette.commands.set(command.id, command);
        });
    }

    executeAction(action) {
        switch (action) {
            case 'new-file':
                this.createNewFile();
                break;
            case 'new-folder':
                this.createNewFolder();
                break;
            case 'open-file':
                this.openFileDialog();
                break;
            case 'open-folder':
                this.openFolderDialog();
                break;
            case 'save':
                this.saveCurrentFile();
                break;
            case 'save-as':
                this.saveAsDialog();
                break;
            case 'toggle-sidebar':
                this.toggleSidebar();
                break;
            case 'toggle-terminal':
                this.toggleTerminal();
                break;
            case 'toggle-minimap':
                this.toggleMinimap();
                break;
            case 'run-file':
                this.runCurrentFile();
                break;
            case 'debug':
                this.startDebugging();
                break;
            case 'build':
                this.buildProject();
                break;
            default:
                console.warn(`Unknown action: ${action}`);
        }
    }

    // File Management
    async createNewFile() {
        const fileName = prompt('Enter file name:');
        if (!fileName) return;
        
        const content = '';
        const fileId = this.generateFileId();
        
        this.createTab(fileId, fileName, content);
        this.switchTab(fileId);
        
        this.showNotification(`Created new file: ${fileName}`, 'success');
    }

    async openFile(filePath) {
        try {
            const content = await this.fileSystem.readFile(filePath);
            const fileName = filePath.split('/').pop();
            const fileId = this.generateFileId();
            
            this.createTab(fileId, fileName, content, filePath);
            this.switchTab(fileId);
            
            this.showNotification(`Opened: ${fileName}`, 'success');
        } catch (error) {
            this.showNotification(`Failed to open file: ${error.message}`, 'error');
        }
    }

    async saveCurrentFile() {
        if (!this.activeEditor) {
            this.showNotification('No file is currently open', 'warning');
            return;
        }

        const content = this.activeEditor.getValue();
        const filePath = this.activeEditor.filePath;
        
        if (!filePath) {
            this.saveAsDialog();
            return;
        }

        try {
            await this.fileSystem.writeFile(filePath, content);
            this.showNotification('File saved successfully', 'success');
            
            // Update tab to show saved state
            const tab = document.querySelector(`[data-file-id="${this.activeEditor.fileId}"]`);
            if (tab) {
                tab.classList.remove('modified');
            }
        } catch (error) {
            this.showNotification(`Failed to save file: ${error.message}`, 'error');
        }
    }

    // Tab Management
    createTab(fileId, fileName, content, filePath = null) {
        const tabsContainer = document.getElementById('tabs');
        
        const tab = document.createElement('div');
        tab.className = 'tab';
        tab.dataset.fileId = fileId;
        
        const icon = this.getFileIcon(fileName);
        
        tab.innerHTML = `
            <i class="tab-icon ${icon}"></i>
            <span class="tab-name">${fileName}</span>
            <button class="tab-close" title="Close">
                <i class="fas fa-times"></i>
            </button>
        `;
        
        tabsContainer.appendChild(tab);
        
        // Create Monaco editor
        const editorContainer = document.createElement('div');
        editorContainer.className = 'editor-instance';
        editorContainer.dataset.fileId = fileId;
        editorContainer.style.display = 'none';
        
        document.getElementById('editor-container').appendChild(editorContainer);
        
        const editor = monaco.editor.create(editorContainer, {
            value: content,
            language: this.getLanguageFromFileName(fileName),
            theme: this.currentTheme === 'dark' ? 'crazyide-dark' : 'crazyide-light',
            automaticLayout: true,
            minimap: { enabled: true },
            fontSize: 14,
            fontFamily: 'JetBrains Mono, Fira Code, Consolas, monospace',
            lineNumbers: 'on',
            wordWrap: 'on',
            scrollBeyondLastLine: false,
            renderWhitespace: 'selection',
            cursorBlinking: 'smooth',
            cursorSmoothCaretAnimation: true
        });
        
        // Store editor reference
        editor.fileId = fileId;
        editor.fileName = fileName;
        editor.filePath = filePath;
        this.editors.set(fileId, editor);
        
        // Track changes
        editor.onDidChangeModelContent(() => {
            const tab = document.querySelector(`[data-file-id="${fileId}"]`);
            if (tab) {
                tab.classList.add('modified');
            }
        });
        
        return fileId;
    }

    switchTab(fileId) {
        // Hide current editor
        if (this.activeEditor) {
            const currentContainer = document.querySelector(`[data-file-id="${this.activeEditor.fileId}"]`);
            if (currentContainer) {
                currentContainer.style.display = 'none';
            }
        }
        
        // Update tab states
        document.querySelectorAll('.tab').forEach(tab => {
            tab.classList.remove('active');
        });
        
        const activeTab = document.querySelector(`[data-file-id="${fileId}"]`);
        if (activeTab) {
            activeTab.classList.add('active');
        }
        
        // Show new editor
        const editorContainer = document.querySelector(`.editor-instance[data-file-id="${fileId}"]`);
        if (editorContainer) {
            editorContainer.style.display = 'block';
            
            // Hide welcome screen
            const welcomeScreen = document.getElementById('welcome-screen');
            if (welcomeScreen) {
                welcomeScreen.style.display = 'none';
            }
        }
        
        // Set active editor
        this.activeEditor = this.editors.get(fileId);
        
        // Focus editor
        if (this.activeEditor) {
            this.activeEditor.focus();
        }
    }

    closeTab(fileId) {
        const tab = document.querySelector(`[data-file-id="${fileId}"]`);
        const editorContainer = document.querySelector(`.editor-instance[data-file-id="${fileId}"]`);
        const editor = this.editors.get(fileId);
        
        if (tab) tab.remove();
        if (editorContainer) editorContainer.remove();
        if (editor) {
            editor.dispose();
            this.editors.delete(fileId);
        }
        
        // If this was the active editor, switch to another tab or show welcome
        if (this.activeEditor && this.activeEditor.fileId === fileId) {
            const remainingTabs = document.querySelectorAll('.tab');
            if (remainingTabs.length > 0) {
                this.switchTab(remainingTabs[remainingTabs.length - 1].dataset.fileId);
            } else {
                this.activeEditor = null;
                this.showWelcomeScreen();
            }
        }
    }

    // UI Management
    showWelcomeScreen() {
        const welcomeScreen = document.getElementById('welcome-screen');
        if (welcomeScreen) {
            welcomeScreen.style.display = 'flex';
        }
        
        // Hide editor instances
        document.querySelectorAll('.editor-instance').forEach(instance => {
            instance.style.display = 'none';
        });
    }

    toggleSidebar() {
        const sidebar = document.getElementById('sidebar');
        sidebar.classList.toggle('collapsed');
        
        setTimeout(() => {
            this.resizeEditors();
        }, 300);
    }

    toggleTerminal() {
        const bottomPanel = document.getElementById('bottom-panel');
        bottomPanel.classList.toggle('collapsed');
        
        setTimeout(() => {
            this.resizeEditors();
        }, 300);
    }

    toggleMinimap() {
        const minimap = document.getElementById('minimap');
        minimap.classList.toggle('visible');
        
        // Update Monaco editor minimap setting
        this.editors.forEach(editor => {
            editor.updateOptions({
                minimap: { enabled: minimap.classList.contains('visible') }
            });
        });
    }

    switchSidebarPanel(panelId) {
        // Update tab states
        document.querySelectorAll('.sidebar-tab').forEach(tab => {
            tab.classList.remove('active');
        });
        document.querySelector(`[data-panel="${panelId}"]`).classList.add('active');
        
        // Update panel visibility
        document.querySelectorAll('.sidebar-panel').forEach(panel => {
            panel.classList.remove('active');
        });
        document.getElementById(`${panelId}-panel`).classList.add('active');
    }

    switchBottomPanel(panelId) {
        // Update tab states
        document.querySelectorAll('.bottom-tab').forEach(tab => {
            tab.classList.remove('active');
        });
        document.querySelector(`[data-panel="${panelId}"]`).classList.add('active');
        
        // Update panel visibility
        document.querySelectorAll('.bottom-panel-content').forEach(panel => {
            panel.classList.remove('active');
        });
        document.getElementById(`${panelId}-panel`).classList.add('active');
    }

    toggleTheme() {
        this.currentTheme = this.currentTheme === 'dark' ? 'light' : 'dark';
        this.themeManager.setTheme(this.currentTheme);
        
        // Update Monaco editor themes
        monaco.editor.setTheme(this.currentTheme === 'dark' ? 'crazyide-dark' : 'crazyide-light');
        
        // Update theme toggle icon
        const themeToggle = document.getElementById('theme-toggle');
        const icon = themeToggle.querySelector('i');
        icon.className = this.currentTheme === 'dark' ? 'fas fa-sun' : 'fas fa-moon';
        
        // Store preference
        localStorage.setItem('theme', this.currentTheme);
        
        this.showNotification(`Switched to ${this.currentTheme} theme`, 'success');
    }

    // Utility functions
    generateFileId() {
        return 'file_' + Math.random().toString(36).substr(2, 9);
    }

    getFileIcon(fileName) {
        const ext = fileName.split('.').pop().toLowerCase();
        const iconMap = {
            'js': 'fab fa-js-square',
            'ts': 'fab fa-js-square',
            'html': 'fab fa-html5',
            'css': 'fab fa-css3-alt',
            'py': 'fab fa-python',
            'java': 'fab fa-java',
            'cpp': 'fas fa-code',
            'c': 'fas fa-code',
            'php': 'fab fa-php',
            'rb': 'fas fa-gem',
            'go': 'fas fa-code',
            'rs': 'fas fa-code',
            'json': 'fas fa-brackets-curly',
            'xml': 'fas fa-code',
            'md': 'fab fa-markdown',
            'txt': 'fas fa-file-alt',
            'yml': 'fas fa-file-code',
            'yaml': 'fas fa-file-code'
        };
        
        return iconMap[ext] || 'fas fa-file';
    }

    getLanguageFromFileName(fileName) {
        const ext = fileName.split('.').pop().toLowerCase();
        const langMap = {
            'js': 'javascript',
            'ts': 'typescript',
            'html': 'html',
            'css': 'css',
            'py': 'python',
            'java': 'java',
            'cpp': 'cpp',
            'c': 'c',
            'php': 'php',
            'rb': 'ruby',
            'go': 'go',
            'rs': 'rust',
            'json': 'json',
            'xml': 'xml',
            'md': 'markdown',
            'yml': 'yaml',
            'yaml': 'yaml',
            'sh': 'shell',
            'sql': 'sql'
        };
        
        return langMap[ext] || 'plaintext';
    }

    resizeEditors() {
        this.editors.forEach(editor => {
            editor.layout();
        });
    }

    showNotification(message, type = 'info', duration = 3000) {
        const notifications = document.getElementById('notifications');
        
        const notification = document.createElement('div');
        notification.className = `notification ${type}`;
        
        const iconMap = {
            'success': 'fas fa-check-circle',
            'warning': 'fas fa-exclamation-triangle',
            'error': 'fas fa-times-circle',
            'info': 'fas fa-info-circle'
        };
        
        notification.innerHTML = `
            <i class="${iconMap[type]}"></i>
            <div class="notification-content">
                <div class="notification-message">${message}</div>
            </div>
            <button class="notification-close">
                <i class="fas fa-times"></i>
            </button>
        `;
        
        notifications.appendChild(notification);
        
        // Show notification
        setTimeout(() => {
            notification.classList.add('visible');
        }, 100);
        
        // Auto-remove notification
        setTimeout(() => {
            notification.classList.remove('visible');
            setTimeout(() => {
                if (notification.parentNode) {
                    notification.remove();
                }
            }, 300);
        }, duration);
        
        // Manual close
        notification.querySelector('.notification-close').addEventListener('click', () => {
            notification.classList.remove('visible');
            setTimeout(() => {
                if (notification.parentNode) {
                    notification.remove();
                }
            }, 300);
        });
    }

    async loadWorkspace() {
        // Load recent files, settings, etc.
        console.log('Loading workspace...');
    }
}

// Initialize the IDE when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.ide = new CrazyIDE();
});

// Export for module use
if (typeof module !== 'undefined' && module.exports) {
    module.exports = CrazyIDE;
}