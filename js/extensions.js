/**
 * Extension Manager - Handles plugins and extensions for the IDE
 */

class ExtensionManager {
    constructor() {
        this.extensions = new Map();
        this.activeExtensions = new Set();
        this.isInitialized = false;
    }

    async init() {
        console.log('Initializing Extension Manager...');
        this.loadDefaultExtensions();
        this.isInitialized = true;
        await this.updateUI();
    }

    loadDefaultExtensions() {
        const defaultExtensions = [
            {
                id: 'prettier',
                name: 'Prettier Code Formatter',
                version: '1.0.0',
                description: 'Code formatter for JavaScript, TypeScript, HTML, CSS',
                author: 'CrazyIDE Team',
                category: 'Formatters',
                icon: 'fas fa-magic',
                enabled: true,
                builtin: true
            },
            {
                id: 'eslint',
                name: 'ESLint',
                version: '1.0.0',
                description: 'JavaScript and TypeScript linter',
                author: 'CrazyIDE Team',
                category: 'Linters',
                icon: 'fas fa-check-circle',
                enabled: true,
                builtin: true
            },
            {
                id: 'emmet',
                name: 'Emmet',
                version: '1.0.0',
                description: 'Essential toolkit for web developers',
                author: 'CrazyIDE Team',
                category: 'Productivity',
                icon: 'fas fa-rocket',
                enabled: true,
                builtin: true
            }
        ];

        defaultExtensions.forEach(ext => {
            this.extensions.set(ext.id, ext);
            if (ext.enabled) {
                this.activeExtensions.add(ext.id);
            }
        });
    }

    async updateUI() {
        const extensionsPanel = document.getElementById('extensions-list');
        if (!extensionsPanel) return;

        extensionsPanel.innerHTML = '';

        const installedSection = document.createElement('div');
        installedSection.className = 'extensions-section';
        installedSection.innerHTML = '<h4>Installed Extensions</h4>';

        Array.from(this.extensions.values()).forEach(ext => {
            const item = this.createExtensionItem(ext);
            installedSection.appendChild(item);
        });

        extensionsPanel.appendChild(installedSection);
    }

    createExtensionItem(extension) {
        const item = document.createElement('div');
        item.className = 'extension-item';
        const isActive = this.activeExtensions.has(extension.id);

        item.innerHTML = `
            <div class="extension-info">
                <i class="${extension.icon}"></i>
                <div>
                    <div class="extension-name">${extension.name}</div>
                    <div class="extension-description">${extension.description}</div>
                    <small>by ${extension.author} • v${extension.version}</small>
                </div>
            </div>
            <div class="extension-actions">
                <button class="btn-icon ${isActive ? 'active' : ''}" 
                        onclick="window.ide.extensionManager.${isActive ? 'deactivate' : 'activate'}Extension('${extension.id}')"
                        title="${isActive ? 'Disable' : 'Enable'}">
                    <i class="fas fa-power-off"></i>
                </button>
            </div>
        `;

        return item;
    }

    async activateExtension(extensionId) {
        this.activeExtensions.add(extensionId);
        const extension = this.extensions.get(extensionId);
        if (extension) {
            extension.enabled = true;
        }
        await this.updateUI();
        window.ide?.showNotification(`Activated ${extension?.name}`, 'success');
    }

    async deactivateExtension(extensionId) {
        this.activeExtensions.delete(extensionId);
        const extension = this.extensions.get(extensionId);
        if (extension) {
            extension.enabled = false;
        }
        await this.updateUI();
        window.ide?.showNotification(`Deactivated ${extension?.name}`, 'info');
    }
}

// Export for module use
if (typeof module !== 'undefined' && module.exports) {
    module.exports = ExtensionManager;
}