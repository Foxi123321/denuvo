/**
 * Terminal - Web-based terminal emulator for the IDE
 */

class Terminal {
    constructor() {
        this.history = [];
        this.historyIndex = -1;
        this.currentCommand = '';
        this.workingDirectory = '/';
        this.environment = {
            'USER': 'developer',
            'HOME': '/home/developer',
            'PATH': '/usr/local/bin:/usr/bin:/bin',
            'SHELL': '/bin/bash',
            'TERM': 'xterm-256color'
        };
        this.commands = new Map();
        this.aliases = new Map();
        this.isReady = false;
        this.prompt = '$ ';
        this.output = [];
        
        this.initializeCommands();
    }

    async init() {
        console.log('Initializing Terminal...');
        
        // Get terminal container
        this.container = document.getElementById('terminal');
        if (!this.container) {
            console.error('Terminal container not found');
            return;
        }

        // Initialize terminal UI
        this.setupTerminalUI();
        
        // Add welcome message
        this.addOutput('Welcome to CrazyIDE Terminal! 🚀', 'info');
        this.addOutput('Type "help" to see available commands.', 'info');
        this.addOutput('', 'normal');
        
        this.isReady = true;
        this.showPrompt();
    }

    setupTerminalUI() {
        this.container.innerHTML = '';
        this.container.style.fontFamily = 'JetBrains Mono, Fira Code, Consolas, monospace';
        this.container.style.fontSize = '14px';
        this.container.style.lineHeight = '1.4';
        this.container.style.padding = '12px';
        this.container.style.backgroundColor = '#000';
        this.container.style.color = '#fff';
        this.container.style.overflow = 'auto';
        this.container.style.whiteSpace = 'pre-wrap';
        this.container.style.wordBreak = 'break-word';
        
        // Add input handling
        this.container.addEventListener('click', () => {
            this.focus();
        });
        
        // Handle keyboard input
        document.addEventListener('keydown', (e) => {
            if (this.isActive()) {
                this.handleKeyboard(e);
            }
        });
        
        // Create output area
        this.outputArea = document.createElement('div');
        this.outputArea.style.minHeight = '100%';
        this.container.appendChild(this.outputArea);
    }

    isActive() {
        // Check if terminal panel is active
        const terminalPanel = document.getElementById('terminal-panel');
        return terminalPanel && terminalPanel.classList.contains('active');
    }

    focus() {
        this.container.focus();
    }

    handleKeyboard(e) {
        if (!this.isReady) return;

        switch (e.key) {
            case 'Enter':
                e.preventDefault();
                this.executeCommand();
                break;
                
            case 'ArrowUp':
                e.preventDefault();
                this.navigateHistory(-1);
                break;
                
            case 'ArrowDown':
                e.preventDefault();
                this.navigateHistory(1);
                break;
                
            case 'Backspace':
                e.preventDefault();
                this.backspace();
                break;
                
            case 'Tab':
                e.preventDefault();
                this.autocomplete();
                break;
                
            case 'c':
                if (e.ctrlKey) {
                    e.preventDefault();
                    this.interrupt();
                }
                break;
                
            case 'l':
                if (e.ctrlKey) {
                    e.preventDefault();
                    this.clear();
                }
                break;
                
            default:
                if (e.key.length === 1 && !e.ctrlKey && !e.altKey && !e.metaKey) {
                    e.preventDefault();
                    this.addChar(e.key);
                }
                break;
        }
    }

    addChar(char) {
        this.currentCommand += char;
        this.updatePrompt();
    }

    backspace() {
        if (this.currentCommand.length > 0) {
            this.currentCommand = this.currentCommand.slice(0, -1);
            this.updatePrompt();
        }
    }

    navigateHistory(direction) {
        if (this.history.length === 0) return;
        
        if (direction === -1) {
            // Go back in history
            if (this.historyIndex === -1) {
                this.historyIndex = this.history.length - 1;
            } else if (this.historyIndex > 0) {
                this.historyIndex--;
            }
        } else {
            // Go forward in history
            if (this.historyIndex < this.history.length - 1) {
                this.historyIndex++;
            } else {
                this.historyIndex = -1;
                this.currentCommand = '';
                this.updatePrompt();
                return;
            }
        }
        
        this.currentCommand = this.history[this.historyIndex] || '';
        this.updatePrompt();
    }

    autocomplete() {
        const parts = this.currentCommand.split(' ');
        const lastPart = parts[parts.length - 1];
        
        if (parts.length === 1) {
            // Command completion
            const matches = Array.from(this.commands.keys()).filter(cmd => 
                cmd.startsWith(lastPart)
            );
            
            if (matches.length === 1) {
                this.currentCommand = matches[0];
                this.updatePrompt();
            } else if (matches.length > 1) {
                this.addOutput('', 'normal');
                this.addOutput(matches.join('  '), 'info');
                this.showPrompt();
            }
        }
    }

    interrupt() {
        this.addOutput('^C', 'error');
        this.currentCommand = '';
        this.showPrompt();
    }

    clear() {
        this.outputArea.innerHTML = '';
        this.showPrompt();
    }

    async executeCommand() {
        const command = this.currentCommand.trim();
        
        if (command) {
            // Add to history
            this.history.push(command);
            this.historyIndex = -1;
            
            // Show command in output
            this.addOutput(this.getPromptText() + command, 'command');
            
            // Execute command
            await this.runCommand(command);
        }
        
        this.currentCommand = '';
        this.showPrompt();
    }

    async runCommand(commandLine) {
        const parts = commandLine.split(' ').filter(part => part.length > 0);
        const command = parts[0];
        const args = parts.slice(1);
        
        // Check for aliases
        const actualCommand = this.aliases.get(command) || command;
        
        // Find and execute command
        const commandFunc = this.commands.get(actualCommand);
        if (commandFunc) {
            try {
                await commandFunc.call(this, args);
            } catch (error) {
                this.addOutput(`Error: ${error.message}`, 'error');
            }
        } else {
            this.addOutput(`Command not found: ${command}`, 'error');
            this.addOutput(`Type "help" to see available commands.`, 'info');
        }
    }

    showPrompt() {
        const promptElement = document.createElement('span');
        promptElement.innerHTML = this.getPromptText();
        promptElement.style.color = '#4ade80';
        
        const line = document.createElement('div');
        line.appendChild(promptElement);
        
        this.outputArea.appendChild(line);
        this.currentLine = line;
        this.updatePrompt();
        
        // Scroll to bottom
        this.container.scrollTop = this.container.scrollHeight;
    }

    updatePrompt() {
        if (this.currentLine) {
            const promptText = this.getPromptText();
            this.currentLine.innerHTML = `<span style="color: #4ade80">${promptText}</span>${this.currentCommand}<span class="cursor" style="background: #fff; color: #000;">█</span>`;
        }
    }

    getPromptText() {
        return `developer@crazyide:${this.workingDirectory}$ `;
    }

    addOutput(text, type = 'normal') {
        const line = document.createElement('div');
        
        switch (type) {
            case 'error':
                line.style.color = '#ef4444';
                break;
            case 'info':
                line.style.color = '#3b82f6';
                break;
            case 'success':
                line.style.color = '#10b981';
                break;
            case 'warning':
                line.style.color = '#f59e0b';
                break;
            case 'command':
                line.style.color = '#a3a3a3';
                break;
            default:
                line.style.color = '#fff';
        }
        
        line.textContent = text;
        this.outputArea.appendChild(line);
        
        // Scroll to bottom
        this.container.scrollTop = this.container.scrollHeight;
    }

    initializeCommands() {
        // Basic commands
        this.commands.set('help', this.cmdHelp);
        this.commands.set('clear', this.cmdClear);
        this.commands.set('ls', this.cmdLs);
        this.commands.set('pwd', this.cmdPwd);
        this.commands.set('cd', this.cmdCd);
        this.commands.set('cat', this.cmdCat);
        this.commands.set('echo', this.cmdEcho);
        this.commands.set('env', this.cmdEnv);
        this.commands.set('history', this.cmdHistory);
        this.commands.set('alias', this.cmdAlias);
        this.commands.set('whoami', this.cmdWhoami);
        this.commands.set('date', this.cmdDate);
        this.commands.set('uname', this.cmdUname);
        
        // File operations
        this.commands.set('touch', this.cmdTouch);
        this.commands.set('mkdir', this.cmdMkdir);
        this.commands.set('rm', this.cmdRm);
        this.commands.set('cp', this.cmdCp);
        this.commands.set('mv', this.cmdMv);
        this.commands.set('find', this.cmdFind);
        this.commands.set('grep', this.cmdGrep);
        
        // Development commands
        this.commands.set('git', this.cmdGit);
        this.commands.set('npm', this.cmdNpm);
        this.commands.set('node', this.cmdNode);
        this.commands.set('python', this.cmdPython);
        this.commands.set('python3', this.cmdPython);
        this.commands.set('pip', this.cmdPip);
        
        // IDE specific commands
        this.commands.set('open', this.cmdOpen);
        this.commands.set('edit', this.cmdEdit);
        this.commands.set('save', this.cmdSave);
        this.commands.set('close', this.cmdClose);
        this.commands.set('theme', this.cmdTheme);
        this.commands.set('run', this.cmdRun);
        this.commands.set('build', this.cmdBuild);
        
        // Fun commands
        this.commands.set('cowsay', this.cmdCowsay);
        this.commands.set('fortune', this.cmdFortune);
        this.commands.set('matrix', this.cmdMatrix);
        
        // Aliases
        this.aliases.set('ll', 'ls -la');
        this.aliases.set('la', 'ls -la');
        this.aliases.set('..', 'cd ..');
        this.aliases.set('...', 'cd ../..');
        this.aliases.set('cls', 'clear');
        this.aliases.set('dir', 'ls');
    }

    // Command implementations
    async cmdHelp(args) {
        this.addOutput('Available commands:', 'info');
        this.addOutput('');
        
        const commands = [
            'help          - Show this help',
            'clear         - Clear terminal',
            'ls            - List files',
            'pwd           - Print working directory',
            'cd <dir>      - Change directory',
            'cat <file>    - Display file content',
            'echo <text>   - Print text',
            'touch <file>  - Create file',
            'mkdir <dir>   - Create directory',
            'rm <file>     - Remove file',
            'find <name>   - Find files',
            'grep <text>   - Search in files',
            'git <cmd>     - Git commands',
            'npm <cmd>     - NPM commands',
            'open <file>   - Open file in editor',
            'theme <name>  - Change theme',
            'run           - Run current file',
            'cowsay <text> - ASCII cow',
            'matrix        - Matrix effect'
        ];
        
        commands.forEach(cmd => this.addOutput(cmd, 'normal'));
    }

    async cmdClear(args) {
        this.clear();
    }

    async cmdLs(args) {
        const fileSystem = window.ide?.fileSystem;
        if (!fileSystem) {
            this.addOutput('File system not available', 'error');
            return;
        }
        
        try {
            const files = fileSystem.fileTree.get(this.workingDirectory) || [];
            
            if (files.length === 0) {
                this.addOutput('Directory is empty', 'info');
                return;
            }
            
            files.forEach(file => {
                const icon = file.type === 'directory' ? '📁' : '📄';
                const size = file.size ? ` (${this.formatSize(file.size)})` : '';
                this.addOutput(`${icon} ${file.name}${size}`, 'normal');
            });
        } catch (error) {
            this.addOutput(`Error listing files: ${error.message}`, 'error');
        }
    }

    async cmdPwd(args) {
        this.addOutput(this.workingDirectory, 'normal');
    }

    async cmdCd(args) {
        if (args.length === 0) {
            this.workingDirectory = this.environment.HOME;
            return;
        }
        
        let targetDir = args[0];
        
        if (targetDir === '..') {
            if (this.workingDirectory !== '/') {
                const parts = this.workingDirectory.split('/').filter(p => p);
                parts.pop();
                this.workingDirectory = '/' + parts.join('/');
                if (this.workingDirectory !== '/') {
                    this.workingDirectory = this.workingDirectory || '/';
                }
            }
        } else if (targetDir === '.') {
            // Stay in current directory
        } else if (targetDir.startsWith('/')) {
            this.workingDirectory = targetDir;
        } else {
            this.workingDirectory = this.workingDirectory === '/' ? 
                `/${targetDir}` : `${this.workingDirectory}/${targetDir}`;
        }
        
        // Normalize path
        this.workingDirectory = this.workingDirectory.replace(/\/+/g, '/');
        if (this.workingDirectory !== '/' && this.workingDirectory.endsWith('/')) {
            this.workingDirectory = this.workingDirectory.slice(0, -1);
        }
    }

    async cmdCat(args) {
        if (args.length === 0) {
            this.addOutput('Usage: cat <filename>', 'error');
            return;
        }
        
        const fileName = args[0];
        const fileSystem = window.ide?.fileSystem;
        
        if (!fileSystem) {
            this.addOutput('File system not available', 'error');
            return;
        }
        
        try {
            const filePath = fileName.startsWith('/') ? fileName : `${this.workingDirectory}/${fileName}`;
            const content = await fileSystem.readFile(filePath);
            this.addOutput(content, 'normal');
        } catch (error) {
            this.addOutput(`cat: ${fileName}: No such file or directory`, 'error');
        }
    }

    async cmdEcho(args) {
        this.addOutput(args.join(' '), 'normal');
    }

    async cmdEnv(args) {
        Object.entries(this.environment).forEach(([key, value]) => {
            this.addOutput(`${key}=${value}`, 'normal');
        });
    }

    async cmdHistory(args) {
        this.history.forEach((cmd, index) => {
            this.addOutput(`${index + 1}  ${cmd}`, 'normal');
        });
    }

    async cmdWhoami(args) {
        this.addOutput(this.environment.USER, 'normal');
    }

    async cmdDate(args) {
        this.addOutput(new Date().toString(), 'normal');
    }

    async cmdUname(args) {
        this.addOutput('CrazyIDE 1.0 (Web Terminal)', 'normal');
    }

    async cmdGit(args) {
        if (args.length === 0) {
            this.addOutput('Usage: git <command>', 'error');
            return;
        }
        
        const gitManager = window.ide?.gitManager;
        if (!gitManager) {
            this.addOutput('Git not available', 'error');
            return;
        }
        
        const command = args[0];
        
        switch (command) {
            case 'status':
                this.addOutput('On branch main', 'normal');
                this.addOutput('Your branch is up to date with origin/main.', 'normal');
                break;
            case 'add':
                this.addOutput(`Added ${args.slice(1).join(' ')}`, 'success');
                break;
            case 'commit':
                this.addOutput('Changes committed successfully', 'success');
                break;
            case 'push':
                this.addOutput('Pushed to remote repository', 'success');
                break;
            case 'pull':
                this.addOutput('Already up to date.', 'info');
                break;
            default:
                this.addOutput(`git: '${command}' is not a git command.`, 'error');
        }
    }

    async cmdOpen(args) {
        if (args.length === 0) {
            this.addOutput('Usage: open <filename>', 'error');
            return;
        }
        
        const fileName = args[0];
        const filePath = fileName.startsWith('/') ? fileName : `${this.workingDirectory}/${fileName}`;
        
        if (window.ide) {
            await window.ide.openFile(filePath);
            this.addOutput(`Opened ${fileName} in editor`, 'success');
        } else {
            this.addOutput('IDE not available', 'error');
        }
    }

    async cmdTheme(args) {
        if (args.length === 0) {
            this.addOutput('Available themes: dark, light, monokai, dracula', 'info');
            return;
        }
        
        const themeName = args[0];
        if (window.ide?.themeManager) {
            const success = window.ide.themeManager.setTheme(themeName);
            if (success) {
                this.addOutput(`Theme changed to ${themeName}`, 'success');
            } else {
                this.addOutput(`Theme '${themeName}' not found`, 'error');
            }
        } else {
            this.addOutput('Theme manager not available', 'error');
        }
    }

    async cmdCowsay(args) {
        const text = args.join(' ') || 'Hello from CrazyIDE!';
        const cow = `
 ${'_'.repeat(text.length + 2)}
< ${text} >
 ${'-'.repeat(text.length + 2)}
        \\   ^__^
         \\  (oo)\\_______
            (__)\\       )\\/\\
                ||----w |
                ||     ||`;
        
        this.addOutput(cow, 'normal');
    }

    async cmdMatrix(args) {
        this.addOutput('Entering the Matrix...', 'success');
        
        // Simple matrix effect
        const chars = '01';
        const columns = 80;
        const rows = 10;
        
        for (let i = 0; i < rows; i++) {
            let line = '';
            for (let j = 0; j < columns; j++) {
                line += chars[Math.floor(Math.random() * chars.length)];
            }
            this.addOutput(line, 'success');
            
            // Add delay for effect
            await new Promise(resolve => setTimeout(resolve, 100));
        }
        
        this.addOutput('Welcome to the real world.', 'info');
    }

    // Utility methods
    formatSize(bytes) {
        const sizes = ['B', 'KB', 'MB', 'GB'];
        if (bytes === 0) return '0 B';
        const i = Math.floor(Math.log(bytes) / Math.log(1024));
        return Math.round(bytes / Math.pow(1024, i) * 100) / 100 + ' ' + sizes[i];
    }
}

// Export for module use
if (typeof module !== 'undefined' && module.exports) {
    module.exports = Terminal;
}