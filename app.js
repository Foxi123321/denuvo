// FreeAI IDE - Main Application
class FreeAIIDE {
    constructor() {
        this.editor = null;
        this.currentFile = null;
        this.files = new Map();
        this.projectStructure = {};
        this.tabs = [];
        this.currentModel = 'claude-sonnet-4';
        this.terminalHistory = [];
        this.aiTools = {
            createFile: true,
            extractCode: true,
            autoDetectLanguage: true,
            suggestFileNames: true,
            autoSaveGeneratedFiles: true
        };
        this.buildConfigs = {
            react: {
                build: 'npm run build',
                dev: 'npm start',
                install: 'npm install'
            },
            node: {
                build: 'npm run build',
                dev: 'npm run dev',
                install: 'npm install'
            },
            python: {
                build: 'python setup.py build',
                dev: 'python app.py',
                install: 'pip install -r requirements.txt'
            },
            android: {
                build: './gradlew build',
                dev: './gradlew installDebug',
                install: './gradlew dependencies'
            }
        };
        
        this.init();
    }

    async init() {
        this.initEditor();
        this.setupEventListeners();
        this.loadSampleProject();
        
        // Initialize puter.js properly
        await this.initializePuter();
    }

    async initializePuter() {
        try {
            // Wait for puter to be available
            if (typeof puter === 'undefined') {
                console.error('Puter.js not loaded');
                this.addChatMessage('System', 'Warning: AI features may not work properly. Please refresh the page.');
                return;
            }

            // Check if user is signed in, if not, they'll be prompted when making first AI request
            console.log('Puter.js loaded successfully!');
            this.addChatMessage('AI', 'Welcome to FreeAI IDE! 🚀 I\'m your AI coding assistant powered by puter.js.');
            this.addChatMessage('AI', '✨ <strong>How it works:</strong><br>• No API keys needed!<br>• When you first use AI features, you\'ll be prompted to sign in to puter.com<br>• After that, enjoy unlimited free AI assistance!<br>• Try asking me anything or press Ctrl+K for inline help');
            this.addChatMessage('AI', '🛠️ <strong>NEW: AI Tools!</strong><br>• I can automatically create files from code I generate<br>• Smart file naming based on code content<br>• Extract only code parts (like qodo-ai/pr-agent)<br>• Toggle these features in the sidebar<br>• Try: "Create a Python snake game"');
            
            // Test connection with a simple ping (but don't show errors to user)
            try {
                await this.testPuterConnection();
                this.addChatMessage('AI', '✅ AI connection test successful! I\'m ready to help with your coding.');
            } catch (error) {
                console.log('Puter test connection failed, but this is normal before first use:', error);
                // Don't show error to user, it's expected before sign-in
            }
            
        } catch (error) {
            console.error('Puter initialization error:', error);
            this.addChatMessage('System', 'AI initialization failed. Please refresh the page.');
        }
    }

    async testPuterConnection() {
        // Simple test to see if puter is working
        const response = await puter.ai.chat('Hello', { model: 'gpt-4o' });
        console.log('Puter connection test successful:', response);
        return response;
    }

    initEditor() {
        const editorElement = document.getElementById('codeEditor');
        this.editor = CodeMirror.fromTextArea(editorElement, {
            lineNumbers: true,
            theme: 'dracula',
            mode: 'javascript',
            autoCloseBrackets: true,
            matchBrackets: true,
            indentUnit: 2,
            tabSize: 2,
            lineWrapping: true,
            extraKeys: {
                'Ctrl-K': () => this.showAIInlineHelp(),
                'Ctrl-S': () => this.saveFile(),
                'Ctrl-N': () => this.newFile(),
                'Ctrl-O': () => this.openFile(),
                'Ctrl-/': 'toggleComment',
                'Tab': 'indentMore',
                'Shift-Tab': 'indentLess'
            }
        });

        this.editor.on('change', () => {
            this.markFileAsModified();
        });

        this.editor.on('cursorActivity', () => {
            this.debounce(() => this.aiCodeHints(), 1000);
        });
    }

    setupEventListeners() {
        // Terminal input
        document.getElementById('terminalInput').addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                this.executeTerminalCommand(e.target.value);
                e.target.value = '';
            }
        });

        // Chat input
        document.getElementById('chatInput').addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                this.sendChatMessage();
            }
        });

        // Model selector
        document.getElementById('aiModel').addEventListener('change', (e) => {
            this.currentModel = e.target.value;
            const modelNames = {
                'claude-sonnet-4': 'Claude Sonnet 4 🧠',
                'claude-opus-4': 'Claude Opus 4 🎯', 
                'gpt-4o': 'GPT-4o ⚡',
                'claude-3-5-sonnet': 'Claude 3.5 Sonnet 📝',
                'gpt-4.1': 'GPT-4.1 🚀',
                'meta-llama/Meta-Llama-3.1-70B-Instruct-Turbo': 'Llama 3.1 🦙',
                'deepseek-chat': 'DeepSeek Chat 🔍'
            };
            const modelName = modelNames[e.target.value] || e.target.value;
            this.addChatMessage('System', `🔄 Switched to ${modelName}`);
        });

        // Keyboard shortcuts
        document.addEventListener('keydown', (e) => {
            if (e.ctrlKey || e.metaKey) {
                switch (e.key) {
                    case 'k':
                        if (e.shiftKey) {
                            e.preventDefault();
                            this.showCommandPalette();
                        }
                        break;
                    case 'b':
                        e.preventDefault();
                        this.buildProject();
                        break;
                }
            }
        });
    }

    loadSampleProject() {
        const sampleFiles = {
            'index.html': `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>My App</title>
</head>
<body>
    <h1>Hello World!</h1>
    <script src="app.js"></script>
</body>
</html>`,
            'app.js': `// Welcome to FreeAI IDE!
console.log('Hello from FreeAI IDE!');

function greet(name) {
    return \`Hello, \${name}!\`;
}

// Try asking the AI to help you with your code!
// Press Ctrl+K for inline AI assistance
greet('Developer');`,
            'styles.css': `body {
    font-family: Arial, sans-serif;
    margin: 0;
    padding: 20px;
    background-color: #f5f5f5;
}

h1 {
    color: #333;
    text-align: center;
}`
        };

        Object.entries(sampleFiles).forEach(([filename, content]) => {
            this.files.set(filename, {
                content,
                modified: false,
                language: this.getLanguageFromExtension(filename)
            });
        });

        this.updateFileTree();
        this.openFileInEditor('app.js');
    }

    // File Management
    newFile() {
        const filename = prompt('Enter filename:');
        if (filename) {
            this.files.set(filename, {
                content: '',
                modified: false,
                language: this.getLanguageFromExtension(filename)
            });
            this.updateFileTree();
            this.openFileInEditor(filename);
        }
    }

    openFile() {
        const input = document.createElement('input');
        input.type = 'file';
        input.accept = '.js,.ts,.html,.css,.py,.java,.cpp,.c,.json,.md';
        input.onchange = async (e) => {
            const file = e.target.files[0];
            if (file) {
                const content = await file.text();
                this.files.set(file.name, {
                    content,
                    modified: false,
                    language: this.getLanguageFromExtension(file.name)
                });
                this.updateFileTree();
                this.openFileInEditor(file.name);
            }
        };
        input.click();
    }

    saveFile() {
        if (this.currentFile) {
            const fileData = this.files.get(this.currentFile);
            fileData.content = this.editor.getValue();
            fileData.modified = false;
            
            // Save to browser storage
            localStorage.setItem(`freeai_ide_${this.currentFile}`, fileData.content);
            
            this.updateTabTitle(this.currentFile);
            this.addToOutput(`Saved: ${this.currentFile}`, 'success');
        }
    }

    openFileInEditor(filename) {
        const fileData = this.files.get(filename);
        if (fileData) {
            this.currentFile = filename;
            this.editor.setValue(fileData.content);
            this.editor.setOption('mode', fileData.language);
            this.addTab(filename);
            this.updateFileTree();
        }
    }

    // Tab Management
    addTab(filename) {
        if (!this.tabs.includes(filename)) {
            this.tabs.push(filename);
        }
        this.updateTabBar();
        this.setActiveTab(filename);
    }

    updateTabBar() {
        const tabBar = document.getElementById('tabBar');
        tabBar.innerHTML = '';
        
        this.tabs.forEach(filename => {
            const tab = document.createElement('div');
            tab.className = 'tab';
            tab.innerHTML = `
                <span>${filename}</span>
                <span class="tab-close" onclick="closeTab('${filename}')">&times;</span>
            `;
            tab.onclick = (e) => {
                if (!e.target.classList.contains('tab-close')) {
                    this.openFileInEditor(filename);
                }
            };
            tabBar.appendChild(tab);
        });
    }

    setActiveTab(filename) {
        document.querySelectorAll('.tab').forEach((tab, index) => {
            tab.classList.toggle('active', this.tabs[index] === filename);
        });
    }

    closeTab(filename) {
        const index = this.tabs.indexOf(filename);
        if (index > -1) {
            this.tabs.splice(index, 1);
            
            if (this.currentFile === filename) {
                if (this.tabs.length > 0) {
                    this.openFileInEditor(this.tabs[0]);
                } else {
                    this.currentFile = null;
                    this.editor.setValue('');
                }
            }
            
            this.updateTabBar();
        }
    }

    // AI-Powered Features
    async showAIInlineHelp() {
        const selectedText = this.editor.getSelection();
        const cursorPos = this.editor.getCursor();
        const currentLine = this.editor.getLine(cursorPos.line);
        
        let prompt = '';
        if (selectedText) {
            prompt = `Explain this code: ${selectedText}`;
        } else if (currentLine.trim()) {
            prompt = `Complete this code: ${currentLine}`;
        } else {
            prompt = 'Help me write code here';
        }

        try {
            this.showLoading(true);
            const response = await this.callAI(prompt);
            this.showAISuggestion(response);
        } catch (error) {
            console.error('AI Error:', error);
            this.addChatMessage('System', 'AI request failed. Please try again.');
        } finally {
            this.showLoading(false);
        }
    }

    async aiCodeComplete() {
        const cursor = this.editor.getCursor();
        const currentLine = this.editor.getLine(cursor.line);
        const previousLines = [];
        
        for (let i = Math.max(0, cursor.line - 5); i < cursor.line; i++) {
            previousLines.push(this.editor.getLine(i));
        }
        
        const context = previousLines.join('\n') + '\n' + currentLine;
        const prompt = `Complete this code:\n${context}\n\nProvide only the completion, no explanations:`;

        try {
            this.showLoading(true);
            const response = await this.callAI(prompt);
            this.showAISuggestion(response);
        } catch (error) {
            console.error('AI Error:', error);
        } finally {
            this.showLoading(false);
        }
    }

    async aiExplainCode() {
        const selectedText = this.editor.getSelection();
        if (!selectedText) {
            this.addChatMessage('System', 'Please select some code to explain.');
            return;
        }

        const prompt = `Explain this code in detail:\n${selectedText}`;
        
        try {
            this.showLoading(true);
            const response = await this.callAI(prompt);
            this.addChatMessage('AI', response);
        } catch (error) {
            console.error('AI Error:', error);
        } finally {
            this.showLoading(false);
        }
    }

    async aiRefactorCode() {
        const selectedText = this.editor.getSelection();
        if (!selectedText) {
            this.addChatMessage('System', 'Please select some code to refactor.');
            return;
        }

        const prompt = `Refactor this code to make it cleaner and more efficient:\n${selectedText}\n\nProvide only the refactored code:`;
        
        try {
            this.showLoading(true);
            const response = await this.callAI(prompt);
            this.showAISuggestion(response);
        } catch (error) {
            console.error('AI Error:', error);
        } finally {
            this.showLoading(false);
        }
    }

    async aiGenerateTests() {
        const selectedText = this.editor.getSelection() || this.editor.getValue();
        const prompt = `Generate unit tests for this code:\n${selectedText}`;
        
        try {
            this.showLoading(true);
            const response = await this.callAI(prompt);
            
            // Create a new test file
            const testFilename = `${this.currentFile?.replace(/\.[^/.]+$/, "") || 'test'}.test.js`;
            this.files.set(testFilename, {
                content: response,
                modified: true,
                language: 'javascript'
            });
            this.updateFileTree();
            this.openFileInEditor(testFilename);
        } catch (error) {
            console.error('AI Error:', error);
        } finally {
            this.showLoading(false);
        }
    }

    async callAI(prompt, useStream = false, retryCount = 0) {
        if (typeof puter === 'undefined') {
            throw new Error('Puter.js not available. Please refresh the page.');
        }

        try {
            console.log(`Making AI request with model: ${this.currentModel} (attempt ${retryCount + 1})`, { prompt: prompt.substring(0, 100) + '...' });

            if (useStream) {
                const response = await puter.ai.chat(prompt, {
                    model: this.currentModel,
                    stream: true
                });
                
                let fullResponse = '';
                for await (const part of response) {
                    if (part?.text) {
                        fullResponse += part.text;
                    } else if (part?.delta?.content) {
                        fullResponse += part.delta.content;
                    } else if (typeof part === 'string') {
                        fullResponse += part;
                    }
                }
                return fullResponse || 'No response received from AI.';
            } else {
                const response = await puter.ai.chat(prompt, {
                    model: this.currentModel
                });
                
                console.log('AI Response received:', response);
                
                // Handle different response formats from puter.js
                if (typeof response === 'string') {
                    return response;
                } else if (response.message?.content) {
                    if (Array.isArray(response.message.content)) {
                        return response.message.content[0]?.text || response.message.content[0];
                    }
                    return response.message.content;
                } else if (response.choices?.[0]?.message?.content) {
                    return response.choices[0].message.content;
                } else if (response.content) {
                    return response.content;
                } else if (response.text) {
                    return response.text;
                }
                
                // Fallback: try to extract text from any part of the response
                const responseStr = JSON.stringify(response);
                console.warn('Unexpected response format:', response);
                return `AI responded but format was unexpected. Response: ${responseStr.substring(0, 200)}...`;
            }
        } catch (error) {
            console.error('AI API Error:', error);
            
            // Handle specific puter.js errors
            if (error.message?.includes('auth') || error.message?.includes('sign') || error.message?.includes('login')) {
                throw new Error('Please sign in to puter.com to use AI features. The sign-in dialog should appear automatically.');
            } else if (error.message?.includes('network') || error.message?.includes('fetch') || error.message?.includes('connection')) {
                throw new Error('Network error. Please check your internet connection.');
            } else if (error.message?.includes('rate') || error.message?.includes('limit')) {
                throw new Error('Rate limit reached. Please wait a moment and try again.');
            } else if (error.message?.includes('model') || error.message?.includes('unsupported')) {
                throw new Error(`Model ${this.currentModel} may not be available. Try switching to a different AI model.`);
            } else if (error.message?.includes('timeout')) {
                throw new Error('Request timeout. The AI model may be busy. Please try again.');
            } else if (error.status === 401 || error.status === 403) {
                throw new Error('Authentication error. Please sign in to puter.com.');
            } else if (error.status === 429) {
                throw new Error('Too many requests. Please wait a moment before trying again.');
            } else if (error.status === 500) {
                throw new Error('Server error. The AI service may be temporarily unavailable.');
            }
            
            // Retry logic for temporary errors
            if (retryCount < 2 && (
                error.message?.includes('timeout') || 
                error.message?.includes('network') || 
                error.status === 500 || 
                error.status === 502 || 
                error.status === 503
            )) {
                console.log(`Retrying AI request in 2 seconds... (attempt ${retryCount + 2})`);
                await new Promise(resolve => setTimeout(resolve, 2000));
                return this.callAI(prompt, useStream, retryCount + 1);
            }

            // More detailed error message
            const errorMsg = error.message || error.toString() || 'Unknown error';
            const statusMsg = error.status ? ` (Status: ${error.status})` : '';
            throw new Error(`AI request failed: ${errorMsg}${statusMsg}. Try switching AI models or check your connection.`);
        }
    }

    // Chat System
    async sendChatMessage() {
        const input = document.getElementById('chatInput');
        const message = input.value.trim();
        if (!message) return;

        this.addChatMessage('User', message);
        input.value = '';

        // Enhanced AI context with file information and AI tools capabilities
        let contextualPrompt = this.buildEnhancedPrompt(message);

        try {
            this.showLoading(true);
            const response = await this.callAI(contextualPrompt, true);
            this.addChatMessage('AI', response);
        } catch (error) {
            console.error('Chat AI Error:', error);
            
            // Show user-friendly error message
            if (error.message.includes('sign in') || error.message.includes('auth')) {
                this.addChatMessage('System', '🔐 Please sign in to puter.com to use AI features. A sign-in dialog should appear automatically when you make your first AI request.');
            } else if (error.message.includes('network')) {
                this.addChatMessage('System', '🌐 Network error. Please check your internet connection and try again.');
            } else {
                this.addChatMessage('System', `❌ AI request failed: ${error.message}. Please try again.`);
            }
        } finally {
            this.showLoading(false);
        }
    }

    buildEnhancedPrompt(userMessage) {
        let prompt = '';
        
        // Add AI tools context
        prompt += `You are an AI coding assistant in FreeAI IDE with special file creation capabilities. When you provide code:
- Wrap code in proper markdown code blocks with language tags (e.g., \`\`\`python, \`\`\`javascript, etc.)
- I can automatically create files from your code blocks
- Suggest appropriate filenames when providing complete files
- For substantial code (>5 lines), I'll auto-create files if enabled

`;

        // Add current project context
        if (this.files.size > 0) {
            prompt += `Current project files:\n`;
            Array.from(this.files.keys()).forEach(filename => {
                prompt += `- ${filename}\n`;
            });
            prompt += '\n';
        }

        // Add current file context
        if (this.currentFile && this.editor.getValue()) {
            prompt += `Currently editing: ${this.currentFile}\n\nCurrent code:\n${this.editor.getValue()}\n\n`;
        }

        // Add user's actual question
        prompt += `User request: ${userMessage}`;

        return prompt;
    }

    addChatMessage(sender, message) {
        const chatMessages = document.getElementById('chatMessages');
        const messageDiv = document.createElement('div');
        messageDiv.className = sender === 'User' ? 'user-message' : 'ai-message';
        
        // Add timestamp for better UX
        const timestamp = new Date().toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'});
        const icon = sender === 'User' ? '<i class="fas fa-user"></i>' : '<i class="fas fa-robot"></i>';
        
        // Check for code blocks and add AI tools if it's an AI message
        const codeBlocks = this.extractCodeBlocks(message);
        const hasCode = codeBlocks.length > 0;
        
        messageDiv.innerHTML = `
            ${icon}
            <div class="message-content">
                ${this.formatMessage(message)}
                ${hasCode && sender === 'AI' ? this.createCodeActionButtons(codeBlocks) : ''}
                <div class="message-timestamp">${timestamp}</div>
            </div>
        `;
        
        // Add fade-in animation
        messageDiv.style.opacity = '0';
        messageDiv.style.transform = 'translateY(10px)';
        chatMessages.appendChild(messageDiv);
        
        // Animate in
        setTimeout(() => {
            messageDiv.style.transition = 'opacity 0.3s ease, transform 0.3s ease';
            messageDiv.style.opacity = '1';
            messageDiv.style.transform = 'translateY(0)';
        }, 50);
        
        // Auto-scroll to bottom, but preserve user's scroll position if they've scrolled up
        const isScrolledToBottom = chatMessages.scrollTop + chatMessages.clientHeight >= chatMessages.scrollHeight - 50;
        
        if (isScrolledToBottom || sender === 'User') {
            // Smooth scroll to bottom with a slight delay to ensure rendering
            setTimeout(() => {
                chatMessages.scrollTo({
                    top: chatMessages.scrollHeight,
                    behavior: 'smooth'
                });
            }, 100);
        }

        // Auto-create files if enabled and code is detected
        if (hasCode && sender === 'AI' && this.aiTools.autoSaveGeneratedFiles) {
            setTimeout(() => this.autoCreateFiles(codeBlocks), 1000);
        }
    }

    formatMessage(message) {
        // Basic markdown support
        return message
            .replace(/```(.*?)```/gs, '<pre><code>$1</code></pre>')
            .replace(/`([^`]+)`/g, '<code>$1</code>')
            .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
            .replace(/\*(.*?)\*/g, '<em>$1</em>')
            .replace(/\n/g, '<br>');
    }

    // AI Tools - Code Extraction and File Creation
    extractCodeBlocks(message) {
        const codeBlocks = [];
        
        // Extract code blocks with language hints
        const codeBlockRegex = /```(\w+)?\n?([\s\S]*?)```/g;
        let match;
        
        while ((match = codeBlockRegex.exec(message)) !== null) {
            const language = match[1] || 'text';
            const code = match[2].trim();
            
            if (code) {
                codeBlocks.push({
                    language: language,
                    code: code,
                    suggestedFileName: this.suggestFileName(code, language)
                });
            }
        }
        
        // Also check for single-line code that looks like complete files
        if (codeBlocks.length === 0) {
            const lines = message.split('\n');
            const codeLines = lines.filter(line => 
                line.trim() && 
                (line.includes('def ') || line.includes('function ') || 
                 line.includes('class ') || line.includes('import ') ||
                 line.includes('<!DOCTYPE') || line.includes('<html'))
            );
            
            if (codeLines.length > 3) {
                const code = lines.join('\n');
                const language = this.detectLanguage(code);
                codeBlocks.push({
                    language: language,
                    code: code,
                    suggestedFileName: this.suggestFileName(code, language)
                });
            }
        }
        
        return codeBlocks;
    }

    suggestFileName(code, language) {
        // Extract function/class names for better file naming
        let baseName = 'untitled';
        
        // Python
        if (language === 'python' || language === 'py') {
            const classMatch = code.match(/class\s+(\w+)/);
            const funcMatch = code.match(/def\s+(\w+)/);
            if (classMatch) baseName = classMatch[1].toLowerCase();
            else if (funcMatch) baseName = funcMatch[1];
            return `${baseName}.py`;
        }
        
        // JavaScript
        if (language === 'javascript' || language === 'js') {
            const funcMatch = code.match(/function\s+(\w+)|const\s+(\w+)\s*=|let\s+(\w+)\s*=/);
            const classMatch = code.match(/class\s+(\w+)/);
            if (classMatch) baseName = classMatch[1].toLowerCase();
            else if (funcMatch) baseName = funcMatch[1] || funcMatch[2] || funcMatch[3];
            return `${baseName}.js`;
        }
        
        // HTML
        if (language === 'html') {
            const titleMatch = code.match(/<title>(.*?)<\/title>/i);
            if (titleMatch) baseName = titleMatch[1].toLowerCase().replace(/\s+/g, '_');
            return `${baseName}.html`;
        }
        
        // CSS
        if (language === 'css') {
            return 'styles.css';
        }
        
        // Java
        if (language === 'java') {
            const classMatch = code.match(/public\s+class\s+(\w+)/);
            if (classMatch) baseName = classMatch[1];
            return `${baseName}.java`;
        }
        
        // Default extensions
        const extensions = {
            'cpp': 'cpp', 'c': 'c', 'json': 'json', 'xml': 'xml',
            'yaml': 'yml', 'sql': 'sql', 'bash': 'sh', 'shell': 'sh'
        };
        
        return `${baseName}.${extensions[language] || language || 'txt'}`;
    }

    detectLanguage(code) {
        // Simple language detection based on patterns
        if (code.includes('def ') && code.includes('import ')) return 'python';
        if (code.includes('function ') || code.includes('const ') || code.includes('=>')) return 'javascript';
        if (code.includes('<!DOCTYPE') || code.includes('<html')) return 'html';
        if (code.includes('public class') && code.includes('{')) return 'java';
        if (code.includes('#include') && code.includes('int main')) return 'cpp';
        if (code.includes('body {') || code.includes('@media')) return 'css';
        return 'text';
    }

    createCodeActionButtons(codeBlocks) {
        const buttons = codeBlocks.map((block, index) => {
            const fileName = block.suggestedFileName;
            const codeId = `code_${Date.now()}_${index}`;
            
            // Store code in a temporary variable to avoid escaping issues
            window[codeId] = block.code;
            
            return `
                <div class="code-actions">
                    <small>📄 Detected: ${block.language} code (${block.code.split('\n').length} lines)</small>
                    <div class="action-buttons">
                        <button class="code-action-btn" onclick="ide.createFileFromCode(${index}, '${fileName}', window['${codeId}'])">
                            <i class="fas fa-file-plus"></i> Create ${fileName}
                        </button>
                        <button class="code-action-btn" onclick="ide.insertCodeIntoEditor(window['${codeId}'])">
                            <i class="fas fa-edit"></i> Insert into Editor
                        </button>
                        <button class="code-action-btn" onclick="ide.copyCodeToClipboard(window['${codeId}'])">
                            <i class="fas fa-copy"></i> Copy Code
                        </button>
                    </div>
                </div>
            `;
        }).join('');
        
        return buttons;
    }

    async autoCreateFiles(codeBlocks) {
        if (!this.aiTools.autoSaveGeneratedFiles) return;
        
        for (const block of codeBlocks) {
            // Only auto-create for substantial code blocks
            if (block.code.split('\n').length > 5) {
                const fileName = block.suggestedFileName;
                
                // Check if file already exists
                if (!this.files.has(fileName)) {
                    this.createFileFromCode(0, fileName, block.code, true);
                    this.addToOutput(`🤖 Auto-created: ${fileName}`, 'success');
                }
            }
        }
    }

    createFileFromCode(index, fileName, code, silent = false) {
        // Clean the code (remove extra whitespace, etc.)
        const cleanCode = code.trim();
        
        // Create the file
        this.files.set(fileName, {
            content: cleanCode,
            modified: true,
            language: this.getLanguageFromExtension(fileName)
        });
        
        this.updateFileTree();
        
        if (!silent) {
            this.openFileInEditor(fileName);
            this.addChatMessage('System', `✅ Created file: ${fileName}`);
            this.addToOutput(`Created file: ${fileName}`, 'success');
        }
    }

    insertCodeIntoEditor(code) {
        if (this.editor) {
            const cursor = this.editor.getCursor();
            this.editor.replaceRange(code, cursor);
            this.addChatMessage('System', '✅ Code inserted into editor');
        }
    }

    async copyCodeToClipboard(code) {
        try {
            await navigator.clipboard.writeText(code);
            this.addChatMessage('System', '✅ Code copied to clipboard');
        } catch (error) {
            console.error('Failed to copy to clipboard:', error);
            this.addChatMessage('System', '❌ Failed to copy to clipboard');
        }
    }

    // Terminal System
    async executeTerminalCommand(command) {
        this.addTerminalLine(`$ ${command}`);
        this.terminalHistory.push(command);

        // Check if it's a natural language command
        if (this.isNaturalLanguage(command)) {
            try {
                this.showLoading(true);
                const prompt = `Convert this natural language request to a terminal command: "${command}". Provide only the command, no explanations.`;
                const aiCommand = await this.callAI(prompt);
                const cleanCommand = aiCommand.replace(/```[\s\S]*?```/g, '').replace(/`([^`]+)`/g, '$1').trim();
                
                this.addTerminalLine(`AI suggests: ${cleanCommand}`);
                this.addTerminalLine('Execute? (y/n):');
                
                // For demo, we'll simulate execution
                setTimeout(() => {
                    this.simulateCommand(cleanCommand);
                }, 1000);
                
            } catch (error) {
                this.addTerminalLine('Error: Could not convert natural language to command');
            } finally {
                this.showLoading(false);
            }
        } else {
            this.simulateCommand(command);
        }
    }

    isNaturalLanguage(command) {
        const naturalIndicators = ['install', 'create', 'build', 'run', 'start', 'stop', 'list', 'show', 'make'];
        const hasSpaces = command.includes(' ') && !command.startsWith('npm ') && !command.startsWith('git ') && !command.startsWith('python ');
        const hasNaturalWords = naturalIndicators.some(word => command.toLowerCase().includes(word));
        
        return hasSpaces && hasNaturalWords && !command.includes('/') && !command.includes('--');
    }

    simulateCommand(command) {
        // Simulate common commands
        const cmd = command.toLowerCase().trim();
        
        if (cmd === 'ls' || cmd === 'dir') {
            const files = Array.from(this.files.keys());
            files.forEach(file => this.addTerminalLine(file));
        } else if (cmd.startsWith('cat ')) {
            const filename = cmd.substring(4);
            const fileData = this.files.get(filename);
            if (fileData) {
                this.addTerminalLine(fileData.content);
            } else {
                this.addTerminalLine(`cat: ${filename}: No such file or directory`);
            }
        } else if (cmd === 'npm install') {
            this.addTerminalLine('Installing dependencies...');
            setTimeout(() => {
                this.addTerminalLine('Dependencies installed successfully!');
            }, 2000);
        } else if (cmd === 'npm start' || cmd === 'npm run dev') {
            this.addTerminalLine('Starting development server...');
            this.addTerminalLine('Server running on http://localhost:3000');
        } else if (cmd === 'git status') {
            this.addTerminalLine('On branch main');
            this.addTerminalLine('Changes not staged for commit:');
            this.files.forEach((data, filename) => {
                if (data.modified) {
                    this.addTerminalLine(`\tmodified: ${filename}`);
                }
            });
        } else {
            this.addTerminalLine(`${command}: command not found (simulated)`);
        }
    }

    addTerminalLine(text, type = 'output') {
        const terminal = document.getElementById('terminalContent');
        const line = document.createElement('div');
        line.className = `terminal-line ${type}`;
        line.textContent = text;
        terminal.appendChild(line);
        terminal.scrollTop = terminal.scrollHeight;
    }

    // Build System
    async buildProject() {
        const projectType = this.detectProjectType();
        const config = this.buildConfigs[projectType];
        
        if (!config) {
            this.addToOutput('Unknown project type. Cannot build.', 'error');
            return;
        }

        this.addToOutput(`Building ${projectType} project...`, 'info');
        
        // Simulate build process
        this.addToOutput('Checking dependencies...', 'info');
        await this.sleep(1000);
        
        this.addToOutput('Compiling...', 'info');
        await this.sleep(2000);
        
        this.addToOutput('Optimizing...', 'info');
        await this.sleep(1500);
        
        // Check for common errors in code
        const hasErrors = this.checkForErrors();
        
        if (hasErrors) {
            this.addToOutput('Build failed with errors!', 'error');
        } else {
            this.addToOutput('Build completed successfully!', 'success');
            this.addToOutput(`Output: ./dist/${this.currentFile || 'index.html'}`, 'success');
        }
    }

    detectProjectType() {
        const fileExtensions = Array.from(this.files.keys()).map(f => f.split('.').pop());
        
        if (this.files.has('package.json')) {
            const packageContent = this.files.get('package.json')?.content || '';
            if (packageContent.includes('react')) return 'react';
            if (packageContent.includes('express')) return 'node';
        }
        
        if (fileExtensions.includes('py') || this.files.has('requirements.txt')) {
            return 'python';
        }
        
        if (this.files.has('build.gradle') || this.files.has('AndroidManifest.xml')) {
            return 'android';
        }
        
        return 'web'; // Default
    }

    checkForErrors() {
        // Simple syntax checking
        const jsFiles = Array.from(this.files.entries()).filter(([name]) => name.endsWith('.js'));
        
        for (const [filename, data] of jsFiles) {
            try {
                new Function(data.content);
            } catch (error) {
                this.addToOutput(`Error in ${filename}: ${error.message}`, 'error');
                return true;
            }
        }
        
        return false;
    }

    // Project Templates
    createNewProject() {
        document.getElementById('projectModal').style.display = 'flex';
    }

    async createProject(type) {
        this.closeModal('projectModal');
        this.showLoading(true);
        
        try {
            const templates = await this.getProjectTemplate(type);
            
            // Clear current files
            this.files.clear();
            this.tabs = [];
            
            // Add template files
            Object.entries(templates).forEach(([filename, content]) => {
                this.files.set(filename, {
                    content,
                    modified: false,
                    language: this.getLanguageFromExtension(filename)
                });
            });
            
            this.updateFileTree();
            this.updateTabBar();
            
            // Open main file
            const mainFile = type === 'react' ? 'src/App.js' : 
                             type === 'python' ? 'app.py' : 
                             type === 'android' ? 'app/src/main/java/MainActivity.kt' :
                             'index.html';
            
            if (this.files.has(mainFile)) {
                this.openFileInEditor(mainFile);
            } else {
                // Open first available file
                const firstFile = Array.from(this.files.keys())[0];
                if (firstFile) this.openFileInEditor(firstFile);
            }
            
            this.addToOutput(`Created new ${type} project!`, 'success');
            
        } catch (error) {
            console.error('Project creation error:', error);
            this.addToOutput('Failed to create project', 'error');
        } finally {
            this.showLoading(false);
        }
    }

    async getProjectTemplate(type) {
        // Use AI to generate project templates
        const prompt = `Generate a complete ${type} project template with multiple files. Include package.json, main files, and basic configuration. Return as a JSON object where keys are file paths and values are file contents.`;
        
        try {
            const response = await this.callAI(prompt);
            
            // Try to parse JSON from response
            const jsonMatch = response.match(/\{[\s\S]*\}/);
            if (jsonMatch) {
                return JSON.parse(jsonMatch[0]);
            }
            
            // Fallback templates
            return this.getFallbackTemplate(type);
            
        } catch (error) {
            console.error('AI template generation failed:', error);
            return this.getFallbackTemplate(type);
        }
    }

    getFallbackTemplate(type) {
        const templates = {
            react: {
                'package.json': JSON.stringify({
                    name: 'react-app',
                    version: '1.0.0',
                    dependencies: {
                        'react': '^18.0.0',
                        'react-dom': '^18.0.0'
                    },
                    scripts: {
                        'start': 'react-scripts start',
                        'build': 'react-scripts build'
                    }
                }, null, 2),
                'src/App.js': `import React from 'react';
import './App.css';

function App() {
  return (
    <div className="App">
      <h1>Hello React!</h1>
      <p>Welcome to your new React app built with FreeAI IDE!</p>
    </div>
  );
}

export default App;`,
                'src/App.css': `.App {
  text-align: center;
  margin: 50px;
}

h1 {
  color: #007acc;
}`,
                'public/index.html': `<!DOCTYPE html>
<html>
<head>
    <title>React App</title>
</head>
<body>
    <div id="root"></div>
</body>
</html>`
            },
            python: {
                'app.py': `from flask import Flask, render_template, jsonify

app = Flask(__name__)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/api/hello')
def hello():
    return jsonify({'message': 'Hello from Python!'})

if __name__ == '__main__':
    app.run(debug=True)`,
                'requirements.txt': `Flask==2.3.3
python-dotenv==1.0.0`,
                'templates/index.html': `<!DOCTYPE html>
<html>
<head>
    <title>Python App</title>
</head>
<body>
    <h1>Hello Python!</h1>
    <p>Your Flask app is running!</p>
</body>
</html>`
            },
            node: {
                'package.json': JSON.stringify({
                    name: 'node-api',
                    version: '1.0.0',
                    main: 'server.js',
                    dependencies: {
                        'express': '^4.18.0',
                        'cors': '^2.8.5'
                    },
                    scripts: {
                        'start': 'node server.js',
                        'dev': 'nodemon server.js'
                    }
                }, null, 2),
                'server.js': `const express = require('express');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

app.get('/', (req, res) => {
    res.json({ message: 'Hello from Node.js API!' });
});

app.listen(PORT, () => {
    console.log(\`Server running on port \${PORT}\`);
});`
            }
        };
        
        return templates[type] || templates.react;
    }

    // Utility Functions
    updateFileTree() {
        const fileTree = document.getElementById('fileTree');
        fileTree.innerHTML = '';
        
        Array.from(this.files.keys()).forEach(filename => {
            const fileItem = document.createElement('div');
            fileItem.className = 'file-item';
            if (filename === this.currentFile) {
                fileItem.classList.add('active');
            }
            
            const icon = this.getFileIcon(filename);
            const modifiedIndicator = this.files.get(filename).modified ? ' •' : '';
            
            fileItem.innerHTML = `
                <i class="${icon}"></i>
                <span>${filename}${modifiedIndicator}</span>
            `;
            
            fileItem.onclick = () => this.openFileInEditor(filename);
            fileTree.appendChild(fileItem);
        });
    }

    getFileIcon(filename) {
        const ext = filename.split('.').pop().toLowerCase();
        const icons = {
            'js': 'fab fa-js-square',
            'ts': 'fab fa-js-square',
            'html': 'fab fa-html5',
            'css': 'fab fa-css3-alt',
            'py': 'fab fa-python',
            'java': 'fab fa-java',
            'cpp': 'fas fa-code',
            'c': 'fas fa-code',
            'json': 'fas fa-file-code',
            'md': 'fab fa-markdown'
        };
        return icons[ext] || 'fas fa-file';
    }

    getLanguageFromExtension(filename) {
        const ext = filename.split('.').pop().toLowerCase();
        const languages = {
            'js': 'javascript',
            'ts': 'javascript',
            'html': 'htmlmixed',
            'css': 'css',
            'py': 'python',
            'java': 'text/x-java',
            'cpp': 'text/x-c++src',
            'c': 'text/x-csrc',
            'json': 'application/json',
            'md': 'markdown'
        };
        return languages[ext] || 'text';
    }

    markFileAsModified() {
        if (this.currentFile) {
            const fileData = this.files.get(this.currentFile);
            if (fileData) {
                fileData.modified = true;
                this.updateFileTree();
                this.updateTabTitle(this.currentFile);
            }
        }
    }

    updateTabTitle(filename) {
        const tabs = document.querySelectorAll('.tab');
        const tabIndex = this.tabs.indexOf(filename);
        if (tabs[tabIndex]) {
            const fileData = this.files.get(filename);
            const modifiedIndicator = fileData.modified ? ' •' : '';
            tabs[tabIndex].querySelector('span').textContent = filename + modifiedIndicator;
        }
    }

    addToOutput(message, type = 'info') {
        const output = document.getElementById('buildOutput');
        const line = document.createElement('div');
        line.className = `output-line ${type}`;
        line.textContent = `[${new Date().toLocaleTimeString()}] ${message}`;
        output.appendChild(line);
        output.scrollTop = output.scrollHeight;
    }

    showAISuggestion(suggestion) {
        const suggestionsDiv = document.getElementById('aiSuggestions');
        const contentDiv = document.getElementById('suggestionContent');
        
        contentDiv.textContent = suggestion;
        suggestionsDiv.style.display = 'block';
        
        // Store suggestion for accept/reject
        this.currentSuggestion = suggestion;
    }

    acceptAISuggestion() {
        if (this.currentSuggestion) {
            const cursor = this.editor.getCursor();
            this.editor.replaceRange(this.currentSuggestion, cursor);
            this.hideAISuggestion();
        }
    }

    rejectAISuggestion() {
        this.hideAISuggestion();
    }

    hideAISuggestion() {
        document.getElementById('aiSuggestions').style.display = 'none';
        this.currentSuggestion = null;
    }

    showLoading(show) {
        document.getElementById('loadingOverlay').style.display = show ? 'flex' : 'none';
    }

    closeModal(modalId) {
        document.getElementById(modalId).style.display = 'none';
    }

    clearTerminal() {
        document.getElementById('terminalContent').innerHTML = '';
    }

    clearOutput() {
        document.getElementById('buildOutput').innerHTML = '';
    }

    toggleTerminal() {
        const terminal = document.querySelector('.terminal-container');
        terminal.style.display = terminal.style.display === 'none' ? 'flex' : 'none';
    }

    debounce(func, wait) {
        clearTimeout(this.debounceTimer);
        this.debounceTimer = setTimeout(func, wait);
    }

    sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    async aiCodeHints() {
        // Auto-suggest code improvements (disabled by default to avoid spam)
        // This could be enabled with a toggle in settings
        return;
    }
}

// Global Functions (for HTML onclick handlers)
window.newFile = () => ide.newFile();
window.openFile = () => ide.openFile();
window.saveFile = () => ide.saveFile();
window.buildProject = () => ide.buildProject();
window.createNewProject = () => ide.createNewProject();
window.createProject = (type) => ide.createProject(type);
window.closeModal = (modalId) => ide.closeModal(modalId);
window.closeTab = (filename) => ide.closeTab(filename);
window.clearTerminal = () => ide.clearTerminal();
window.clearOutput = () => ide.clearOutput();
window.toggleTerminal = () => ide.toggleTerminal();
window.acceptAISuggestion = () => ide.acceptAISuggestion();
window.rejectAISuggestion = () => ide.rejectAISuggestion();
window.sendChatMessage = () => ide.sendChatMessage();
window.aiCodeComplete = () => ide.aiCodeComplete();
window.aiExplainCode = () => ide.aiExplainCode();
window.aiRefactorCode = () => ide.aiRefactorCode();
window.aiGenerateTests = () => ide.aiGenerateTests();
window.toggleAIAgent = () => {
    const rightPanel = document.querySelector('.right-panel');
    rightPanel.style.display = rightPanel.style.display === 'none' ? 'flex' : 'none';
};

window.handleChatKeyPress = (event) => {
    if (event.key === 'Enter') {
        ide.sendChatMessage();
    }
};

window.handleTerminalKeyPress = (event) => {
    if (event.key === 'Enter') {
        ide.executeTerminalCommand(event.target.value);
        event.target.value = '';
    }
};

window.testAIConnection = async () => {
    try {
        ide.showLoading(true);
        ide.addChatMessage('System', '🔌 Testing AI connection...');
        
        const response = await ide.callAI('Hello! Please respond with "AI connection successful!"');
        ide.addChatMessage('AI', response);
        ide.addChatMessage('System', '✅ AI connection test completed successfully!');
    } catch (error) {
        console.error('AI connection test failed:', error);
        if (error.message.includes('sign in') || error.message.includes('auth')) {
            ide.addChatMessage('System', '🔐 Please sign in to puter.com to use AI features. The sign-in dialog should appear automatically.');
        } else if (error.message.includes('model') || error.message.includes('unsupported')) {
            ide.addChatMessage('System', `⚠️ ${ide.currentModel} may not be available. Trying GPT-4o instead...`);
            try {
                const oldModel = ide.currentModel;
                ide.currentModel = 'gpt-4o';
                document.getElementById('aiModel').value = 'gpt-4o';
                const response = await ide.callAI('Hello! Please respond with "AI connection successful with GPT-4o!"');
                ide.addChatMessage('AI', response);
                ide.addChatMessage('System', `✅ Switched to GPT-4o successfully! (${oldModel} was not available)`);
            } catch (fallbackError) {
                ide.addChatMessage('System', `❌ Both ${ide.currentModel} and GPT-4o failed. Please try a different model.`);
            }
        } else {
            ide.addChatMessage('System', `❌ AI connection test failed: ${error.message}`);
            ide.addChatMessage('System', '💡 Try: 1) Switching AI models 2) Refreshing the page 3) Checking your internet connection');
        }
    } finally {
        ide.showLoading(false);
    }
};

window.toggleAITool = (toolName, enabled) => {
    ide.aiTools[toolName] = enabled;
    const toolNames = {
        'autoSaveGeneratedFiles': 'Auto-create files',
        'extractCode': 'Extract code blocks', 
        'suggestFileNames': 'Smart file naming'
    };
    ide.addChatMessage('System', `🔧 ${toolNames[toolName]} ${enabled ? 'enabled' : 'disabled'}`);
};

// Initialize IDE when page loads
let ide;
document.addEventListener('DOMContentLoaded', () => {
    ide = new FreeAIIDE();
});