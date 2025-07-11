/**
 * File System Manager - Handles file operations and directory browsing
 */

class FileSystemManager {
    constructor() {
        this.currentDirectory = '/';
        this.fileTree = new Map();
        this.watchedFiles = new Set();
        this.fileCache = new Map();
        this.isInitialized = false;
    }

    async init() {
        console.log('Initializing File System Manager...');
        this.isInitialized = true;
        
        // Initialize with current project files
        await this.loadProjectFiles();
    }

    async loadProjectFiles() {
        // In a real implementation, this would connect to a backend API
        // For demo purposes, we'll simulate some files
        const mockFiles = [
            { name: 'index.html', type: 'file', path: '/index.html', size: 2048 },
            { name: 'styles.css', type: 'file', path: '/styles.css', size: 15360 },
            { name: 'README.md', type: 'file', path: '/README.md', size: 1024 },
            { name: 'drm_slayer.py', type: 'file', path: '/drm_slayer.py', size: 166000 },
            { name: 'js', type: 'directory', path: '/js', children: [
                { name: 'app.js', type: 'file', path: '/js/app.js', size: 8192 },
                { name: 'themes.js', type: 'file', path: '/js/themes.js', size: 4096 },
                { name: 'file-system.js', type: 'file', path: '/js/file-system.js', size: 6144 }
            ]},
            { name: 'assets', type: 'directory', path: '/assets', children: [
                { name: 'images', type: 'directory', path: '/assets/images', children: [] },
                { name: 'fonts', type: 'directory', path: '/assets/fonts', children: [] }
            ]},
            { name: 'docs', type: 'directory', path: '/docs', children: [
                { name: 'api.md', type: 'file', path: '/docs/api.md', size: 2048 },
                { name: 'setup.md', type: 'file', path: '/docs/setup.md', size: 1536 }
            ]}
        ];

        this.fileTree.set('/', mockFiles);
        await this.refreshFileTree();
    }

    async refreshFileTree() {
        const container = document.getElementById('file-tree');
        if (!container) return;

        container.innerHTML = '';
        
        const rootFiles = this.fileTree.get('/') || [];
        this.renderFileTree(rootFiles, container, '/');
    }

    renderFileTree(files, container, basePath = '') {
        files.forEach(file => {
            const item = document.createElement('div');
            
            if (file.type === 'directory') {
                item.className = 'folder-item';
                item.dataset.path = file.path;
                
                item.innerHTML = `
                    <i class="fas fa-chevron-right"></i>
                    <i class="fas fa-folder" style="color: #dcb67a;"></i>
                    <span>${file.name}</span>
                `;
                
                // Add click handler for folder expansion
                item.addEventListener('click', () => {
                    this.toggleFolder(item, file);
                });
                
            } else {
                item.className = 'file-item';
                item.dataset.path = file.path;
                
                const icon = this.getFileIcon(file.name);
                item.innerHTML = `
                    <i class="${icon}"></i>
                    <span>${file.name}</span>
                `;
                
                // Add click handler for file opening
                item.addEventListener('click', () => {
                    window.ide?.openFile(file.path);
                });
            }
            
            container.appendChild(item);
        });
    }

    toggleFolder(folderElement, folderData) {
        const isExpanded = folderElement.classList.contains('expanded');
        
        if (isExpanded) {
            // Collapse folder
            folderElement.classList.remove('expanded');
            const contents = folderElement.nextElementSibling;
            if (contents && contents.classList.contains('folder-contents')) {
                contents.remove();
            }
        } else {
            // Expand folder
            folderElement.classList.add('expanded');
            
            const contents = document.createElement('div');
            contents.className = 'folder-contents';
            
            if (folderData.children && folderData.children.length > 0) {
                this.renderFileTree(folderData.children, contents, folderData.path);
            }
            
            folderElement.insertAdjacentElement('afterend', contents);
        }
    }

    async readFile(filePath) {
        // Check cache first
        if (this.fileCache.has(filePath)) {
            return this.fileCache.get(filePath);
        }

        try {
            // In a real implementation, this would make an API call to read the file
            // For demo purposes, we'll return sample content based on file type
            let content = await this.generateSampleContent(filePath);
            
            // Cache the content
            this.fileCache.set(filePath, content);
            
            return content;
        } catch (error) {
            throw new Error(`Failed to read file: ${error.message}`);
        }
    }

    async writeFile(filePath, content) {
        try {
            // In a real implementation, this would make an API call to save the file
            // For demo purposes, we'll just update the cache
            this.fileCache.set(filePath, content);
            
            console.log(`File saved: ${filePath}`);
            return true;
        } catch (error) {
            throw new Error(`Failed to write file: ${error.message}`);
        }
    }

    async createFile(fileName, parentPath = '/') {
        const filePath = this.joinPath(parentPath, fileName);
        
        try {
            await this.writeFile(filePath, '');
            
            // Add to file tree
            const parentFiles = this.fileTree.get(parentPath) || [];
            parentFiles.push({
                name: fileName,
                type: 'file',
                path: filePath,
                size: 0
            });
            
            this.fileTree.set(parentPath, parentFiles);
            await this.refreshFileTree();
            
            return filePath;
        } catch (error) {
            throw new Error(`Failed to create file: ${error.message}`);
        }
    }

    async createDirectory(dirName, parentPath = '/') {
        const dirPath = this.joinPath(parentPath, dirName);
        
        try {
            // Add to file tree
            const parentFiles = this.fileTree.get(parentPath) || [];
            parentFiles.push({
                name: dirName,
                type: 'directory',
                path: dirPath,
                children: []
            });
            
            this.fileTree.set(parentPath, parentFiles);
            this.fileTree.set(dirPath, []);
            
            await this.refreshFileTree();
            
            return dirPath;
        } catch (error) {
            throw new Error(`Failed to create directory: ${error.message}`);
        }
    }

    async deleteFile(filePath) {
        try {
            // Remove from cache
            this.fileCache.delete(filePath);
            
            // Remove from file tree
            const parentPath = this.getParentPath(filePath);
            const parentFiles = this.fileTree.get(parentPath) || [];
            const updatedFiles = parentFiles.filter(file => file.path !== filePath);
            
            this.fileTree.set(parentPath, updatedFiles);
            await this.refreshFileTree();
            
            return true;
        } catch (error) {
            throw new Error(`Failed to delete file: ${error.message}`);
        }
    }

    async renameFile(oldPath, newName) {
        try {
            const parentPath = this.getParentPath(oldPath);
            const newPath = this.joinPath(parentPath, newName);
            
            // Update file tree
            const parentFiles = this.fileTree.get(parentPath) || [];
            const fileIndex = parentFiles.findIndex(file => file.path === oldPath);
            
            if (fileIndex !== -1) {
                parentFiles[fileIndex].name = newName;
                parentFiles[fileIndex].path = newPath;
                
                // Update cache
                if (this.fileCache.has(oldPath)) {
                    const content = this.fileCache.get(oldPath);
                    this.fileCache.delete(oldPath);
                    this.fileCache.set(newPath, content);
                }
                
                await this.refreshFileTree();
                return newPath;
            }
            
            throw new Error('File not found');
        } catch (error) {
            throw new Error(`Failed to rename file: ${error.message}`);
        }
    }

    async uploadFile(file, targetPath = '/') {
        const filePath = this.joinPath(targetPath, file.name);
        
        try {
            const content = await this.readFileAsText(file);
            await this.writeFile(filePath, content);
            
            // Add to file tree
            const parentFiles = this.fileTree.get(targetPath) || [];
            parentFiles.push({
                name: file.name,
                type: 'file',
                path: filePath,
                size: file.size
            });
            
            this.fileTree.set(targetPath, parentFiles);
            await this.refreshFileTree();
            
            return filePath;
        } catch (error) {
            throw new Error(`Failed to upload file: ${error.message}`);
        }
    }

    async downloadFile(filePath) {
        try {
            const content = await this.readFile(filePath);
            const fileName = this.getFileName(filePath);
            
            // Create download link
            const blob = new Blob([content], { type: 'text/plain' });
            const url = URL.createObjectURL(blob);
            
            const a = document.createElement('a');
            a.href = url;
            a.download = fileName;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            
            URL.revokeObjectURL(url);
            
            return true;
        } catch (error) {
            throw new Error(`Failed to download file: ${error.message}`);
        }
    }

    // Search functionality
    async searchFiles(query, options = {}) {
        const {
            caseSensitive = false,
            wholeWord = false,
            useRegex = false,
            includeContent = true,
            maxResults = 100
        } = options;

        const results = [];
        
        try {
            // Search in file names
            const nameResults = await this.searchFileNames(query, { caseSensitive, wholeWord, useRegex });
            results.push(...nameResults);
            
            // Search in file content if requested
            if (includeContent) {
                const contentResults = await this.searchFileContent(query, { caseSensitive, wholeWord, useRegex });
                results.push(...contentResults);
            }
            
            // Remove duplicates and limit results
            const uniqueResults = results.filter((result, index, self) => 
                index === self.findIndex(r => r.file === result.file)
            ).slice(0, maxResults);
            
            return uniqueResults;
        } catch (error) {
            throw new Error(`Search failed: ${error.message}`);
        }
    }

    async searchFileNames(query, options) {
        const results = [];
        const searchRegex = this.createSearchRegex(query, options);
        
        const searchInTree = (files) => {
            files.forEach(file => {
                if (searchRegex.test(file.name)) {
                    results.push({
                        file: file.path,
                        name: file.name,
                        type: 'filename',
                        match: file.name
                    });
                }
                
                if (file.type === 'directory' && file.children) {
                    searchInTree(file.children);
                }
            });
        };
        
        const rootFiles = this.fileTree.get('/') || [];
        searchInTree(rootFiles);
        
        return results;
    }

    async searchFileContent(query, options) {
        const results = [];
        const searchRegex = this.createSearchRegex(query, options);
        
        // Get all files from cache
        for (const [filePath, content] of this.fileCache.entries()) {
            const matches = this.findMatches(content, searchRegex);
            
            matches.forEach(match => {
                results.push({
                    file: filePath,
                    name: this.getFileName(filePath),
                    type: 'content',
                    line: match.line,
                    column: match.column,
                    match: match.text,
                    context: match.context
                });
            });
        }
        
        return results;
    }

    createSearchRegex(query, options) {
        let pattern = query;
        
        if (!options.useRegex) {
            pattern = query.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        }
        
        if (options.wholeWord) {
            pattern = `\\b${pattern}\\b`;
        }
        
        const flags = options.caseSensitive ? 'g' : 'gi';
        return new RegExp(pattern, flags);
    }

    findMatches(content, regex) {
        const matches = [];
        const lines = content.split('\n');
        
        lines.forEach((line, lineIndex) => {
            let match;
            regex.lastIndex = 0; // Reset regex state
            
            while ((match = regex.exec(line)) !== null) {
                matches.push({
                    line: lineIndex + 1,
                    column: match.index + 1,
                    text: match[0],
                    context: this.getLineContext(lines, lineIndex, 2)
                });
                
                // Prevent infinite loop on empty matches
                if (match.index === regex.lastIndex) {
                    regex.lastIndex++;
                }
            }
        });
        
        return matches;
    }

    getLineContext(lines, lineIndex, contextLines) {
        const start = Math.max(0, lineIndex - contextLines);
        const end = Math.min(lines.length, lineIndex + contextLines + 1);
        
        return {
            before: lines.slice(start, lineIndex),
            current: lines[lineIndex],
            after: lines.slice(lineIndex + 1, end)
        };
    }

    // Utility functions
    joinPath(...paths) {
        return paths.join('/').replace(/\/+/g, '/');
    }

    getParentPath(filePath) {
        const parts = filePath.split('/');
        parts.pop();
        return parts.join('/') || '/';
    }

    getFileName(filePath) {
        return filePath.split('/').pop();
    }

    getFileExtension(fileName) {
        const parts = fileName.split('.');
        return parts.length > 1 ? parts.pop().toLowerCase() : '';
    }

    getFileIcon(fileName) {
        const ext = this.getFileExtension(fileName);
        const iconMap = {
            'js': 'fab fa-js-square text-yellow-400',
            'ts': 'fab fa-js-square text-blue-400',
            'html': 'fab fa-html5 text-orange-500',
            'css': 'fab fa-css3-alt text-blue-500',
            'py': 'fab fa-python text-blue-400',
            'java': 'fab fa-java text-red-500',
            'cpp': 'fas fa-code text-blue-600',
            'c': 'fas fa-code text-blue-600',
            'php': 'fab fa-php text-purple-500',
            'rb': 'fas fa-gem text-red-500',
            'go': 'fas fa-code text-cyan-400',
            'rs': 'fas fa-code text-orange-600',
            'json': 'fas fa-brackets-curly text-yellow-500',
            'xml': 'fas fa-code text-green-500',
            'md': 'fab fa-markdown text-gray-600',
            'txt': 'fas fa-file-alt text-gray-500',
            'yml': 'fas fa-file-code text-red-400',
            'yaml': 'fas fa-file-code text-red-400',
            'sh': 'fas fa-terminal text-gray-600',
            'sql': 'fas fa-database text-blue-600',
            'pdf': 'fas fa-file-pdf text-red-600',
            'doc': 'fas fa-file-word text-blue-600',
            'docx': 'fas fa-file-word text-blue-600',
            'xls': 'fas fa-file-excel text-green-600',
            'xlsx': 'fas fa-file-excel text-green-600',
            'ppt': 'fas fa-file-powerpoint text-orange-600',
            'pptx': 'fas fa-file-powerpoint text-orange-600',
            'zip': 'fas fa-file-archive text-yellow-600',
            'rar': 'fas fa-file-archive text-yellow-600',
            '7z': 'fas fa-file-archive text-yellow-600',
            'tar': 'fas fa-file-archive text-yellow-600',
            'gz': 'fas fa-file-archive text-yellow-600',
            'png': 'fas fa-file-image text-purple-500',
            'jpg': 'fas fa-file-image text-purple-500',
            'jpeg': 'fas fa-file-image text-purple-500',
            'gif': 'fas fa-file-image text-purple-500',
            'svg': 'fas fa-file-image text-purple-500',
            'mp3': 'fas fa-file-audio text-green-500',
            'wav': 'fas fa-file-audio text-green-500',
            'mp4': 'fas fa-file-video text-red-500',
            'avi': 'fas fa-file-video text-red-500',
            'mov': 'fas fa-file-video text-red-500'
        };
        
        return iconMap[ext] || 'fas fa-file text-gray-400';
    }

    async generateSampleContent(filePath) {
        const ext = this.getFileExtension(filePath);
        const fileName = this.getFileName(filePath);
        
        // Return actual file content for known files
        if (fileName === 'index.html') {
            return await fetch('./index.html').then(r => r.text()).catch(() => 
                '<!DOCTYPE html>\n<html>\n<head>\n    <title>Sample HTML</title>\n</head>\n<body>\n    <h1>Hello World!</h1>\n</body>\n</html>'
            );
        }
        
        if (fileName === 'styles.css') {
            return await fetch('./styles.css').then(r => r.text()).catch(() => 
                '/* Sample CSS */\nbody {\n    font-family: Arial, sans-serif;\n    margin: 0;\n    padding: 20px;\n}\n\nh1 {\n    color: #333;\n}'
            );
        }
        
        // Generate sample content based on file type
        const sampleContent = {
            'js': '// JavaScript file\nconsole.log("Hello, World!");\n\nfunction greet(name) {\n    return `Hello, ${name}!`;\n}',
            'ts': '// TypeScript file\ninterface User {\n    name: string;\n    age: number;\n}\n\nconst user: User = {\n    name: "John",\n    age: 30\n};',
            'py': '# Python file\ndef hello_world():\n    print("Hello, World!")\n\nif __name__ == "__main__":\n    hello_world()',
            'html': '<!DOCTYPE html>\n<html>\n<head>\n    <title>Sample Page</title>\n</head>\n<body>\n    <h1>Welcome</h1>\n</body>\n</html>',
            'css': '/* CSS file */\nbody {\n    margin: 0;\n    padding: 0;\n    font-family: Arial, sans-serif;\n}',
            'json': '{\n  "name": "sample-project",\n  "version": "1.0.0",\n  "description": "A sample project"\n}',
            'md': '# Sample Markdown\n\nThis is a **sample** markdown file.\n\n## Features\n\n- Item 1\n- Item 2\n- Item 3'
        };
        
        return sampleContent[ext] || `// ${fileName}\n// This is a sample file`;
    }

    async readFileAsText(file) {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onload = e => resolve(e.target.result);
            reader.onerror = reject;
            reader.readAsText(file);
        });
    }

    // File watching
    watchFile(filePath) {
        this.watchedFiles.add(filePath);
    }

    unwatchFile(filePath) {
        this.watchedFiles.delete(filePath);
    }

    // File statistics
    getFileStats(filePath) {
        const content = this.fileCache.get(filePath);
        if (!content) return null;
        
        const lines = content.split('\n');
        const words = content.split(/\s+/).filter(word => word.length > 0);
        const chars = content.length;
        const charsNoSpaces = content.replace(/\s/g, '').length;
        
        return {
            lines: lines.length,
            words: words.length,
            characters: chars,
            charactersNoSpaces: charsNoSpaces,
            size: new Blob([content]).size
        };
    }
}

// Export for module use
if (typeof module !== 'undefined' && module.exports) {
    module.exports = FileSystemManager;
}