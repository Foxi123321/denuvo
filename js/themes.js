/**
 * Theme Manager - Handles theme switching and management
 */

class ThemeManager {
    constructor() {
        this.themes = new Map();
        this.currentTheme = 'dark';
        this.customThemes = [];
        
        this.initializeDefaultThemes();
    }

    initializeDefaultThemes() {
        // Dark theme
        this.themes.set('dark', {
            name: 'Dark',
            type: 'dark',
            colors: {
                primary: '#1e1e1e',
                secondary: '#252526',
                tertiary: '#2d2d30',
                sidebar: '#252526',
                menu: '#1e1e1e',
                editor: '#1e1e1e',
                textPrimary: '#cccccc',
                textSecondary: '#969696',
                textMuted: '#6a6a6a',
                border: '#3e3e42',
                accent: '#0078d4',
                accentHover: '#106ebe',
                success: '#16a759',
                warning: '#f9c23c',
                danger: '#e64c3c'
            }
        });

        // Light theme
        this.themes.set('light', {
            name: 'Light',
            type: 'light',
            colors: {
                primary: '#ffffff',
                secondary: '#f8f9fa',
                tertiary: '#e9ecef',
                sidebar: '#f5f5f5',
                menu: '#ffffff',
                editor: '#ffffff',
                textPrimary: '#212529',
                textSecondary: '#6c757d',
                textMuted: '#adb5bd',
                border: '#dee2e6',
                accent: '#007bff',
                accentHover: '#0056b3',
                success: '#28a745',
                warning: '#ffc107',
                danger: '#dc3545'
            }
        });

        // High contrast theme
        this.themes.set('high-contrast', {
            name: 'High Contrast',
            type: 'dark',
            colors: {
                primary: '#000000',
                secondary: '#000000',
                tertiary: '#1a1a1a',
                sidebar: '#000000',
                menu: '#000000',
                editor: '#000000',
                textPrimary: '#ffffff',
                textSecondary: '#ffffff',
                textMuted: '#cccccc',
                border: '#ffffff',
                accent: '#ffff00',
                accentHover: '#ffcc00',
                success: '#00ff00',
                warning: '#ffff00',
                danger: '#ff0000'
            }
        });

        // Monokai theme
        this.themes.set('monokai', {
            name: 'Monokai',
            type: 'dark',
            colors: {
                primary: '#272822',
                secondary: '#2e2f2a',
                tertiary: '#3e3f3a',
                sidebar: '#2e2f2a',
                menu: '#272822',
                editor: '#272822',
                textPrimary: '#f8f8f2',
                textSecondary: '#75715e',
                textMuted: '#49483e',
                border: '#49483e',
                accent: '#66d9ef',
                accentHover: '#52c7ea',
                success: '#a6e22e',
                warning: '#e6db74',
                danger: '#f92672'
            }
        });

        // Solarized Dark
        this.themes.set('solarized-dark', {
            name: 'Solarized Dark',
            type: 'dark',
            colors: {
                primary: '#002b36',
                secondary: '#073642',
                tertiary: '#0d4752',
                sidebar: '#073642',
                menu: '#002b36',
                editor: '#002b36',
                textPrimary: '#839496',
                textSecondary: '#586e75',
                textMuted: '#073642',
                border: '#073642',
                accent: '#268bd2',
                accentHover: '#2075c7',
                success: '#859900',
                warning: '#b58900',
                danger: '#dc322f'
            }
        });

        // Dracula theme
        this.themes.set('dracula', {
            name: 'Dracula',
            type: 'dark',
            colors: {
                primary: '#282a36',
                secondary: '#44475a',
                tertiary: '#6272a4',
                sidebar: '#44475a',
                menu: '#282a36',
                editor: '#282a36',
                textPrimary: '#f8f8f2',
                textSecondary: '#6272a4',
                textMuted: '#44475a',
                border: '#44475a',
                accent: '#bd93f9',
                accentHover: '#a674f4',
                success: '#50fa7b',
                warning: '#f1fa8c',
                danger: '#ff5555'
            }
        });
    }

    setTheme(themeName) {
        const theme = this.themes.get(themeName);
        if (!theme) {
            console.warn(`Theme '${themeName}' not found`);
            return false;
        }

        this.currentTheme = themeName;
        this.applyTheme(theme);
        
        // Store theme preference
        localStorage.setItem('theme', themeName);
        
        return true;
    }

    applyTheme(theme) {
        const root = document.documentElement;
        
        // Set theme data attribute
        root.setAttribute('data-theme', theme.type);
        
        // Apply CSS custom properties
        Object.entries(theme.colors).forEach(([key, value]) => {
            const cssVar = this.camelToKebab(key);
            root.style.setProperty(`--${cssVar}`, value);
        });

        // Dispatch theme change event
        window.dispatchEvent(new CustomEvent('themeChanged', {
            detail: { theme: theme.name, type: theme.type }
        }));
    }

    getCurrentTheme() {
        return this.themes.get(this.currentTheme);
    }

    getAvailableThemes() {
        return Array.from(this.themes.entries()).map(([id, theme]) => ({
            id,
            name: theme.name,
            type: theme.type
        }));
    }

    createCustomTheme(name, baseTheme, customColors) {
        const base = this.themes.get(baseTheme);
        if (!base) {
            throw new Error(`Base theme '${baseTheme}' not found`);
        }

        const customTheme = {
            name,
            type: base.type,
            colors: { ...base.colors, ...customColors },
            isCustom: true
        };

        const id = this.generateThemeId(name);
        this.themes.set(id, customTheme);
        this.customThemes.push(id);
        
        return id;
    }

    exportTheme(themeName) {
        const theme = this.themes.get(themeName);
        if (!theme) {
            throw new Error(`Theme '${themeName}' not found`);
        }

        return JSON.stringify({
            name: theme.name,
            type: theme.type,
            colors: theme.colors
        }, null, 2);
    }

    importTheme(themeData) {
        try {
            const theme = JSON.parse(themeData);
            const id = this.generateThemeId(theme.name);
            
            this.themes.set(id, {
                ...theme,
                isCustom: true
            });
            
            this.customThemes.push(id);
            return id;
        } catch (error) {
            throw new Error('Invalid theme data');
        }
    }

    deleteCustomTheme(themeId) {
        const theme = this.themes.get(themeId);
        if (!theme || !theme.isCustom) {
            return false;
        }

        this.themes.delete(themeId);
        this.customThemes = this.customThemes.filter(id => id !== themeId);
        
        // Switch to default theme if current theme was deleted
        if (this.currentTheme === themeId) {
            this.setTheme('dark');
        }
        
        return true;
    }

    generateColorPalette(baseColor) {
        // Generate a color palette based on a base color
        const hsl = this.hexToHsl(baseColor);
        
        return {
            primary: baseColor,
            light: this.hslToHex(hsl.h, hsl.s, Math.min(hsl.l + 20, 100)),
            dark: this.hslToHex(hsl.h, hsl.s, Math.max(hsl.l - 20, 0)),
            complementary: this.hslToHex((hsl.h + 180) % 360, hsl.s, hsl.l),
            triadic1: this.hslToHex((hsl.h + 120) % 360, hsl.s, hsl.l),
            triadic2: this.hslToHex((hsl.h + 240) % 360, hsl.s, hsl.l)
        };
    }

    // Utility functions
    camelToKebab(str) {
        return str.replace(/([a-z0-9]|(?=[A-Z]))([A-Z])/g, '$1-$2').toLowerCase();
    }

    generateThemeId(name) {
        return name.toLowerCase().replace(/[^a-z0-9]/g, '-') + '-' + Date.now();
    }

    hexToHsl(hex) {
        const r = parseInt(hex.slice(1, 3), 16) / 255;
        const g = parseInt(hex.slice(3, 5), 16) / 255;
        const b = parseInt(hex.slice(5, 7), 16) / 255;

        const max = Math.max(r, g, b);
        const min = Math.min(r, g, b);
        let h, s, l = (max + min) / 2;

        if (max === min) {
            h = s = 0;
        } else {
            const d = max - min;
            s = l > 0.5 ? d / (2 - max - min) : d / (max + min);
            switch (max) {
                case r: h = (g - b) / d + (g < b ? 6 : 0); break;
                case g: h = (b - r) / d + 2; break;
                case b: h = (r - g) / d + 4; break;
            }
            h /= 6;
        }

        return { h: h * 360, s: s * 100, l: l * 100 };
    }

    hslToHex(h, s, l) {
        l /= 100;
        const a = s * Math.min(l, 1 - l) / 100;
        const f = n => {
            const k = (n + h / 30) % 12;
            const color = l - a * Math.max(Math.min(k - 3, 9 - k, 1), -1);
            return Math.round(255 * color).toString(16).padStart(2, '0');
        };
        return `#${f(0)}${f(8)}${f(4)}`;
    }

    // Theme builder UI helpers
    createThemeEditor() {
        return {
            showEditor: () => this.showThemeEditor(),
            hideEditor: () => this.hideThemeEditor(),
            getColorInputs: () => this.getThemeColorInputs(),
            previewTheme: (colors) => this.previewTheme(colors),
            saveTheme: (name, colors) => this.saveCustomTheme(name, colors)
        };
    }

    showThemeEditor() {
        // Create and show theme editor modal
        const modal = document.createElement('div');
        modal.className = 'modal-overlay visible';
        modal.id = 'theme-editor-modal';
        
        modal.innerHTML = this.getThemeEditorHTML();
        document.body.appendChild(modal);
        
        // Setup event listeners
        this.setupThemeEditorEvents(modal);
    }

    getThemeEditorHTML() {
        const currentTheme = this.getCurrentTheme();
        
        return `
            <div class="modal">
                <div class="modal-header">
                    <h2 class="modal-title">Theme Editor</h2>
                    <button class="modal-close" onclick="this.closest('.modal-overlay').remove()">
                        <i class="fas fa-times"></i>
                    </button>
                </div>
                <div class="modal-body">
                    <div class="theme-editor">
                        <div class="theme-controls">
                            <label>
                                Theme Name:
                                <input type="text" id="theme-name" placeholder="My Custom Theme">
                            </label>
                            <label>
                                Base Theme:
                                <select id="base-theme">
                                    ${this.getAvailableThemes().map(theme => 
                                        `<option value="${theme.id}">${theme.name}</option>`
                                    ).join('')}
                                </select>
                            </label>
                        </div>
                        <div class="color-inputs">
                            ${Object.entries(currentTheme.colors).map(([key, value]) => `
                                <label>
                                    ${this.formatColorName(key)}:
                                    <input type="color" data-color="${key}" value="${value}">
                                </label>
                            `).join('')}
                        </div>
                        <div class="theme-preview">
                            <h3>Preview</h3>
                            <div class="preview-container">
                                <!-- Theme preview content -->
                            </div>
                        </div>
                    </div>
                </div>
                <div class="modal-footer">
                    <button class="btn-secondary" onclick="this.closest('.modal-overlay').remove()">
                        Cancel
                    </button>
                    <button class="btn-primary" onclick="window.ide.themeManager.saveThemeFromEditor()">
                        Save Theme
                    </button>
                </div>
            </div>
        `;
    }

    formatColorName(name) {
        return name.replace(/([A-Z])/g, ' $1').replace(/^./, str => str.toUpperCase());
    }

    setupThemeEditorEvents(modal) {
        // Color input changes
        modal.querySelectorAll('input[type="color"]').forEach(input => {
            input.addEventListener('change', () => {
                this.updatePreview();
            });
        });

        // Base theme change
        modal.querySelector('#base-theme').addEventListener('change', (e) => {
            this.loadBaseThemeColors(e.target.value);
        });
    }

    saveThemeFromEditor() {
        const modal = document.getElementById('theme-editor-modal');
        const name = modal.querySelector('#theme-name').value;
        const baseTheme = modal.querySelector('#base-theme').value;
        
        if (!name) {
            alert('Please enter a theme name');
            return;
        }

        const colors = {};
        modal.querySelectorAll('input[type="color"]').forEach(input => {
            colors[input.dataset.color] = input.value;
        });

        const themeId = this.createCustomTheme(name, baseTheme, colors);
        this.setTheme(themeId);
        
        modal.remove();
        
        // Show success notification
        window.ide?.showNotification(`Theme '${name}' created successfully!`, 'success');
    }
}

// Export for module use
if (typeof module !== 'undefined' && module.exports) {
    module.exports = ThemeManager;
}