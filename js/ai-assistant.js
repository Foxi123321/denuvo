/**
 * AI Assistant - Provides AI-powered code assistance and chat
 */

class AIAssistant {
    constructor() {
        this.isEnabled = true;
        this.isInitialized = false;
        this.chatHistory = [];
        this.suggestions = [];
        this.currentContext = null;
    }

    async init() {
        console.log('Initializing AI Assistant...');
        
        // Initialize chat interface
        this.setupChatInterface();
        
        // Setup code completion
        this.setupCodeCompletion();
        
        this.isInitialized = true;
        
        // Add welcome message
        this.addChatMessage('AI Assistant', 'Hello! I\'m your AI coding assistant. I can help you with code completion, explanations, debugging, and more! 🤖', 'assistant');
    }

    setupChatInterface() {
        // Add AI chat panel to sidebar
        const sidebar = document.querySelector('.sidebar-content');
        if (!sidebar) return;

        // Add AI tab
        const sidebarTabs = document.querySelector('.sidebar-tabs');
        if (sidebarTabs) {
            const aiTab = document.createElement('div');
            aiTab.className = 'sidebar-tab';
            aiTab.dataset.panel = 'ai';
            aiTab.innerHTML = `
                <i class="fas fa-robot"></i>
                <span>AI Assistant</span>
            `;
            sidebarTabs.appendChild(aiTab);

            // Add click handler
            aiTab.addEventListener('click', () => {
                window.ide?.switchSidebarPanel('ai');
            });
        }

        // Add AI panel
        const aiPanel = document.createElement('div');
        aiPanel.className = 'sidebar-panel';
        aiPanel.id = 'ai-panel';
        aiPanel.innerHTML = `
            <div class="panel-header">
                <h3>AI Assistant</h3>
                <div class="panel-actions">
                    <button class="btn-icon" onclick="window.ide.aiAssistant.clearChat()" title="Clear Chat">
                        <i class="fas fa-trash"></i>
                    </button>
                    <button class="btn-icon" onclick="window.ide.aiAssistant.toggleAssistant()" title="Toggle AI">
                        <i class="fas fa-power-off"></i>
                    </button>
                </div>
            </div>
            <div class="ai-chat" id="ai-chat">
                <!-- Chat messages will be added here -->
            </div>
            <div class="ai-input-container">
                <input type="text" 
                       class="ai-input" 
                       id="ai-input" 
                       placeholder="Ask me anything about your code..."
                       onkeypress="if(event.key==='Enter') window.ide.aiAssistant.sendMessage()">
                <button class="btn-icon" onclick="window.ide.aiAssistant.sendMessage()" title="Send">
                    <i class="fas fa-paper-plane"></i>
                </button>
            </div>
        `;

        sidebar.appendChild(aiPanel);
    }

    setupCodeCompletion() {
        // This would integrate with Monaco Editor's completion provider
        // For now, we'll simulate AI-powered suggestions
        console.log('AI code completion enabled');
    }

    async sendMessage() {
        const input = document.getElementById('ai-input');
        if (!input || !input.value.trim()) return;

        const message = input.value.trim();
        input.value = '';

        // Add user message
        this.addChatMessage('You', message, 'user');

        // Show typing indicator
        this.showTypingIndicator();

        // Simulate AI response
        setTimeout(async () => {
            this.hideTypingIndicator();
            const response = await this.generateAIResponse(message);
            this.addChatMessage('AI Assistant', response, 'assistant');
        }, 1000 + Math.random() * 2000);
    }

    async generateAIResponse(message) {
        // Simulate AI responses based on message content
        const lowerMessage = message.toLowerCase();

        if (lowerMessage.includes('help') || lowerMessage.includes('what can you do')) {
            return `I can help you with:
• Code completion and suggestions
• Explaining code functionality  
• Debugging assistance
• Code optimization tips
• Writing documentation
• Refactoring suggestions
• Language-specific best practices

Just ask me anything about your code!`;
        }

        if (lowerMessage.includes('bug') || lowerMessage.includes('error') || lowerMessage.includes('debug')) {
            return `I'd be happy to help debug your code! Here are some tips:

1. Check the console for error messages
2. Use console.log() to trace variable values
3. Verify function parameters and return types
4. Look for typos in variable/function names
5. Check for missing semicolons or brackets

Share your code and I can provide more specific help!`;
        }

        if (lowerMessage.includes('javascript') || lowerMessage.includes('js')) {
            return `JavaScript is awesome! Here are some modern best practices:

• Use const/let instead of var
• Prefer arrow functions for callbacks
• Use template literals for string interpolation
• Implement error handling with try/catch
• Use async/await for asynchronous operations
• Leverage ES6+ features like destructuring

Need help with a specific JavaScript concept?`;
        }

        if (lowerMessage.includes('python')) {
            return `Python is great for rapid development! Some tips:

• Follow PEP 8 style guidelines
• Use list comprehensions for concise code
• Leverage context managers (with statements)
• Use f-strings for string formatting
• Write docstrings for functions and classes
• Consider type hints for better code clarity

What Python topic would you like to explore?`;
        }

        if (lowerMessage.includes('html') || lowerMessage.includes('css')) {
            return `Frontend development tips:

HTML:
• Use semantic elements (header, nav, main, section)
• Always include alt attributes for images
• Structure content logically

CSS:
• Use CSS Grid and Flexbox for layouts
• Follow mobile-first responsive design
• Use CSS custom properties (variables)
• Optimize for performance and accessibility

Need specific help with styling or layout?`;
        }

        if (lowerMessage.includes('optimize') || lowerMessage.includes('performance')) {
            return `Performance optimization strategies:

• Minimize HTTP requests
• Optimize images and assets
• Use efficient algorithms and data structures
• Implement lazy loading
• Cache frequently used data
• Profile your code to identify bottlenecks
• Use CDNs for static assets

Would you like me to analyze specific code for optimization opportunities?`;
        }

        if (lowerMessage.includes('git') || lowerMessage.includes('version control')) {
            return `Git best practices:

• Write clear, descriptive commit messages
• Use feature branches for new development
• Review code before merging
• Keep commits atomic and focused
• Use .gitignore to exclude unnecessary files
• Regularly push to remote repositories

Need help with a specific Git workflow?`;
        }

        // Default responses
        const defaultResponses = [
            "That's an interesting question! Could you provide more context about what you're working on?",
            "I'd love to help! Can you share some code or describe the specific problem you're facing?",
            "Great question! What programming language are you using, and what's your specific goal?",
            "I'm here to assist! Feel free to paste code snippets and I'll help explain or improve them.",
            "Excellent! What would you like me to help you code today?",
            "I can definitely help with that! What's the specific challenge you're encountering?"
        ];

        return defaultResponses[Math.floor(Math.random() * defaultResponses.length)];
    }

    addChatMessage(sender, message, type) {
        const chatContainer = document.getElementById('ai-chat');
        if (!chatContainer) return;

        const messageElement = document.createElement('div');
        messageElement.className = `chat-message ${type}`;
        
        messageElement.innerHTML = `
            <div class="message-header">
                <span class="message-sender">${sender}</span>
                <span class="message-time">${new Date().toLocaleTimeString()}</span>
            </div>
            <div class="message-content">${this.formatMessage(message)}</div>
        `;

        chatContainer.appendChild(messageElement);
        chatContainer.scrollTop = chatContainer.scrollHeight;

        // Store in history
        this.chatHistory.push({ sender, message, type, timestamp: new Date() });
    }

    formatMessage(message) {
        // Simple markdown-like formatting
        return message
            .replace(/```([\s\S]*?)```/g, '<pre><code>$1</code></pre>')
            .replace(/`([^`]+)`/g, '<code>$1</code>')
            .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
            .replace(/\*(.*?)\*/g, '<em>$1</em>')
            .replace(/\n/g, '<br>');
    }

    showTypingIndicator() {
        const chatContainer = document.getElementById('ai-chat');
        if (!chatContainer) return;

        const indicator = document.createElement('div');
        indicator.className = 'typing-indicator';
        indicator.id = 'typing-indicator';
        indicator.innerHTML = `
            <div class="chat-message assistant">
                <div class="message-header">
                    <span class="message-sender">AI Assistant</span>
                </div>
                <div class="message-content">
                    <div class="typing-dots">
                        <span></span>
                        <span></span>
                        <span></span>
                    </div>
                </div>
            </div>
        `;

        chatContainer.appendChild(indicator);
        chatContainer.scrollTop = chatContainer.scrollHeight;
    }

    hideTypingIndicator() {
        const indicator = document.getElementById('typing-indicator');
        if (indicator) {
            indicator.remove();
        }
    }

    clearChat() {
        const chatContainer = document.getElementById('ai-chat');
        if (chatContainer) {
            chatContainer.innerHTML = '';
        }
        this.chatHistory = [];
        
        // Add welcome message back
        this.addChatMessage('AI Assistant', 'Chat cleared! How can I help you today? 🤖', 'assistant');
    }

    toggleAssistant() {
        this.isEnabled = !this.isEnabled;
        const status = this.isEnabled ? 'enabled' : 'disabled';
        window.ide?.showNotification(`AI Assistant ${status}`, this.isEnabled ? 'success' : 'warning');
        
        // Update AI status in menu bar
        const aiStatus = document.querySelector('.ai-status span');
        if (aiStatus) {
            aiStatus.textContent = this.isEnabled ? 'AI Ready' : 'AI Disabled';
        }
    }

    // Code analysis features
    async analyzeCode(code, language) {
        if (!this.isEnabled) return null;

        // Simulate code analysis
        const analysis = {
            complexity: Math.floor(Math.random() * 10) + 1,
            suggestions: [
                'Consider extracting this logic into a separate function',
                'This variable could be declared as const',
                'Add error handling for this operation'
            ],
            issues: [
                { line: 5, type: 'warning', message: 'Unused variable detected' },
                { line: 12, type: 'info', message: 'Consider using arrow function syntax' }
            ]
        };

        return analysis;
    }

    async getCodeCompletion(context, position) {
        if (!this.isEnabled) return [];

        // Simulate AI-powered code completions
        const completions = [
            {
                label: 'console.log',
                kind: 'Function',
                insertText: 'console.log(${1:message});',
                documentation: 'Log a message to the console'
            },
            {
                label: 'async function',
                kind: 'Snippet',
                insertText: 'async function ${1:name}(${2:params}) {\n\t${3:// TODO: implement}\n}',
                documentation: 'Create an async function'
            },
            {
                label: 'try/catch',
                kind: 'Snippet',
                insertText: 'try {\n\t${1:// code}\n} catch (error) {\n\t${2:// handle error}\n}',
                documentation: 'Try/catch error handling block'
            }
        ];

        return completions;
    }

    // Export chat history
    exportChatHistory() {
        const data = {
            timestamp: new Date().toISOString(),
            messages: this.chatHistory
        };

        const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        
        const a = document.createElement('a');
        a.href = url;
        a.download = `ai-chat-history-${new Date().toISOString().split('T')[0]}.json`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        
        URL.revokeObjectURL(url);
    }
}

// Export for module use
if (typeof module !== 'undefined' && module.exports) {
    module.exports = AIAssistant;
}