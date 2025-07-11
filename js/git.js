/**
 * Git Manager - Handles version control operations
 */

class GitManager {
    constructor() {
        this.repository = null;
        this.currentBranch = 'main';
        this.isInitialized = false;
        this.changes = new Map();
        this.commits = [];
        this.branches = ['main'];
        this.remotes = new Map();
        this.status = {
            ahead: 0,
            behind: 0,
            staged: [],
            modified: [],
            untracked: [],
            deleted: []
        };
    }

    async init() {
        console.log('Initializing Git Manager...');
        
        // Initialize mock repository
        this.repository = {
            name: 'crazyide-project',
            path: '/',
            initialized: true,
            remote: 'origin'
        };
        
        // Add default remote
        this.remotes.set('origin', {
            name: 'origin',
            url: 'https://github.com/user/crazyide-project.git',
            fetch: '+refs/heads/*:refs/remotes/origin/*'
        });
        
        // Create initial commit
        this.commits.push({
            hash: this.generateCommitHash(),
            message: 'Initial commit',
            author: 'Developer <dev@crazyide.com>',
            date: new Date(),
            files: ['README.md', 'index.html', 'styles.css']
        });
        
        this.isInitialized = true;
        await this.updateStatus();
        await this.updateUI();
    }

    async updateStatus() {
        // Simulate git status check
        this.status = {
            ahead: 0,
            behind: 0,
            staged: [],
            modified: [],
            untracked: [],
            deleted: []
        };
        
        // Check for changes (mock implementation)
        const fileSystem = window.ide?.fileSystem;
        if (fileSystem) {
            // Simulate some modified files
            this.status.modified = ['js/app.js', 'styles.css'];
            this.status.untracked = ['temp.txt'];
        }
        
        await this.updateUI();
    }

    async updateUI() {
        // Update git status in sidebar
        const gitPanel = document.getElementById('git-changes');
        if (!gitPanel) return;
        
        gitPanel.innerHTML = '';
        
        // Show current branch
        const branchInfo = document.createElement('div');
        branchInfo.className = 'git-branch-info';
        branchInfo.innerHTML = `
            <div class="current-branch">
                <i class="fab fa-git-alt"></i>
                <span>${this.currentBranch}</span>
                ${this.status.ahead > 0 ? `<span class="ahead">↑${this.status.ahead}</span>` : ''}
                ${this.status.behind > 0 ? `<span class="behind">↓${this.status.behind}</span>` : ''}
            </div>
        `;
        gitPanel.appendChild(branchInfo);
        
        // Show changes
        const changesContainer = document.createElement('div');
        changesContainer.className = 'git-changes-list';
        
        // Staged changes
        if (this.status.staged.length > 0) {
            const stagedSection = this.createChangeSection('Staged Changes', this.status.staged, 'staged');
            changesContainer.appendChild(stagedSection);
        }
        
        // Modified files
        if (this.status.modified.length > 0) {
            const modifiedSection = this.createChangeSection('Modified Files', this.status.modified, 'modified');
            changesContainer.appendChild(modifiedSection);
        }
        
        // Untracked files
        if (this.status.untracked.length > 0) {
            const untrackedSection = this.createChangeSection('Untracked Files', this.status.untracked, 'untracked');
            changesContainer.appendChild(untrackedSection);
        }
        
        // Deleted files
        if (this.status.deleted.length > 0) {
            const deletedSection = this.createChangeSection('Deleted Files', this.status.deleted, 'deleted');
            changesContainer.appendChild(deletedSection);
        }
        
        if (this.getTotalChanges() === 0) {
            const noChanges = document.createElement('div');
            noChanges.className = 'no-changes';
            noChanges.innerHTML = '<i class="fas fa-check-circle"></i> No changes';
            changesContainer.appendChild(noChanges);
        }
        
        gitPanel.appendChild(changesContainer);
        
        // Update git branch indicator in status bar
        const gitBranchElement = document.getElementById('git-branch');
        if (gitBranchElement) {
            gitBranchElement.textContent = this.currentBranch;
        }
    }

    createChangeSection(title, files, type) {
        const section = document.createElement('div');
        section.className = 'change-section';
        
        const header = document.createElement('div');
        header.className = 'section-header';
        header.innerHTML = `
            <i class="fas fa-chevron-right collapse-icon"></i>
            <span>${title} (${files.length})</span>
        `;
        
        const fileList = document.createElement('div');
        fileList.className = 'file-list';
        
        files.forEach(file => {
            const fileItem = document.createElement('div');
            fileItem.className = `file-change ${type}`;
            
            const icon = this.getChangeIcon(type);
            const actions = this.getFileActions(file, type);
            
            fileItem.innerHTML = `
                <div class="file-info">
                    <i class="${icon}"></i>
                    <span class="file-name">${file}</span>
                </div>
                <div class="file-actions">
                    ${actions}
                </div>
            `;
            
            fileList.appendChild(fileItem);
        });
        
        // Toggle collapse
        header.addEventListener('click', () => {
            const isCollapsed = fileList.style.display === 'none';
            fileList.style.display = isCollapsed ? 'block' : 'none';
            header.querySelector('.collapse-icon').style.transform = 
                isCollapsed ? 'rotate(90deg)' : 'rotate(0deg)';
        });
        
        section.appendChild(header);
        section.appendChild(fileList);
        
        return section;
    }

    getChangeIcon(type) {
        const icons = {
            'staged': 'fas fa-plus text-green-500',
            'modified': 'fas fa-edit text-yellow-500',
            'untracked': 'fas fa-question text-blue-500',
            'deleted': 'fas fa-minus text-red-500'
        };
        return icons[type] || 'fas fa-file';
    }

    getFileActions(file, type) {
        switch (type) {
            case 'modified':
            case 'untracked':
                return `
                    <button class="btn-icon" onclick="window.ide.gitManager.stageFile('${file}')" title="Stage">
                        <i class="fas fa-plus"></i>
                    </button>
                    <button class="btn-icon" onclick="window.ide.gitManager.discardFile('${file}')" title="Discard">
                        <i class="fas fa-undo"></i>
                    </button>
                `;
            case 'staged':
                return `
                    <button class="btn-icon" onclick="window.ide.gitManager.unstageFile('${file}')" title="Unstage">
                        <i class="fas fa-minus"></i>
                    </button>
                `;
            default:
                return '';
        }
    }

    getTotalChanges() {
        return this.status.staged.length + 
               this.status.modified.length + 
               this.status.untracked.length + 
               this.status.deleted.length;
    }

    // Git operations
    async stageFile(filePath) {
        // Move file from modified/untracked to staged
        if (this.status.modified.includes(filePath)) {
            this.status.modified = this.status.modified.filter(f => f !== filePath);
            this.status.staged.push(filePath);
        } else if (this.status.untracked.includes(filePath)) {
            this.status.untracked = this.status.untracked.filter(f => f !== filePath);
            this.status.staged.push(filePath);
        }
        
        await this.updateUI();
        window.ide?.showNotification(`Staged: ${filePath}`, 'success');
    }

    async unstageFile(filePath) {
        // Move file from staged back to modified
        if (this.status.staged.includes(filePath)) {
            this.status.staged = this.status.staged.filter(f => f !== filePath);
            this.status.modified.push(filePath);
        }
        
        await this.updateUI();
        window.ide?.showNotification(`Unstaged: ${filePath}`, 'info');
    }

    async discardFile(filePath) {
        // Remove file from modified/untracked
        const confirmed = confirm(`Are you sure you want to discard changes to ${filePath}?`);
        if (!confirmed) return;
        
        this.status.modified = this.status.modified.filter(f => f !== filePath);
        this.status.untracked = this.status.untracked.filter(f => f !== filePath);
        
        await this.updateUI();
        window.ide?.showNotification(`Discarded changes: ${filePath}`, 'warning');
    }

    async stageAll() {
        // Stage all modified and untracked files
        this.status.staged.push(...this.status.modified, ...this.status.untracked);
        this.status.modified = [];
        this.status.untracked = [];
        
        await this.updateUI();
        window.ide?.showNotification('Staged all changes', 'success');
    }

    async commit(message) {
        if (!message || message.trim().length === 0) {
            throw new Error('Commit message is required');
        }
        
        if (this.status.staged.length === 0) {
            throw new Error('No staged changes to commit');
        }
        
        const commit = {
            hash: this.generateCommitHash(),
            message: message.trim(),
            author: 'Developer <dev@crazyide.com>',
            date: new Date(),
            files: [...this.status.staged]
        };
        
        this.commits.unshift(commit);
        this.status.staged = [];
        this.status.ahead++;
        
        await this.updateUI();
        window.ide?.showNotification(`Committed: ${message}`, 'success');
        
        return commit;
    }

    async push(remote = 'origin', branch = null) {
        const targetBranch = branch || this.currentBranch;
        
        if (this.status.ahead === 0) {
            window.ide?.showNotification('No commits to push', 'info');
            return;
        }
        
        // Simulate push
        await this.simulateNetworkOperation('Pushing to remote...');
        
        this.status.ahead = 0;
        await this.updateUI();
        
        window.ide?.showNotification(`Pushed to ${remote}/${targetBranch}`, 'success');
    }

    async pull(remote = 'origin', branch = null) {
        const targetBranch = branch || this.currentBranch;
        
        // Simulate pull
        await this.simulateNetworkOperation('Pulling from remote...');
        
        // Simulate receiving commits
        if (Math.random() > 0.7) {
            const incomingCommit = {
                hash: this.generateCommitHash(),
                message: 'Remote changes',
                author: 'Remote User <remote@example.com>',
                date: new Date(),
                files: ['remote-file.txt']
            };
            
            this.commits.unshift(incomingCommit);
            window.ide?.showNotification('Pulled new changes', 'success');
        } else {
            window.ide?.showNotification('Already up to date', 'info');
        }
        
        this.status.behind = 0;
        await this.updateUI();
    }

    async fetch(remote = 'origin') {
        await this.simulateNetworkOperation('Fetching from remote...');
        
        // Simulate fetching remote refs
        window.ide?.showNotification('Fetched latest refs', 'success');
    }

    async createBranch(branchName) {
        if (this.branches.includes(branchName)) {
            throw new Error(`Branch '${branchName}' already exists`);
        }
        
        this.branches.push(branchName);
        window.ide?.showNotification(`Created branch: ${branchName}`, 'success');
    }

    async switchBranch(branchName) {
        if (!this.branches.includes(branchName)) {
            throw new Error(`Branch '${branchName}' does not exist`);
        }
        
        if (this.getTotalChanges() > 0) {
            const confirmed = confirm('You have uncommitted changes. Continue?');
            if (!confirmed) return;
        }
        
        this.currentBranch = branchName;
        await this.updateUI();
        
        window.ide?.showNotification(`Switched to branch: ${branchName}`, 'success');
    }

    async deleteBranch(branchName) {
        if (branchName === 'main' || branchName === 'master') {
            throw new Error('Cannot delete main branch');
        }
        
        if (branchName === this.currentBranch) {
            throw new Error('Cannot delete current branch');
        }
        
        this.branches = this.branches.filter(b => b !== branchName);
        window.ide?.showNotification(`Deleted branch: ${branchName}`, 'warning');
    }

    async mergeBranch(branchName) {
        if (!this.branches.includes(branchName)) {
            throw new Error(`Branch '${branchName}' does not exist`);
        }
        
        if (branchName === this.currentBranch) {
            throw new Error('Cannot merge branch into itself');
        }
        
        // Simulate merge
        const mergeCommit = {
            hash: this.generateCommitHash(),
            message: `Merge branch '${branchName}' into ${this.currentBranch}`,
            author: 'Developer <dev@crazyide.com>',
            date: new Date(),
            files: [],
            type: 'merge'
        };
        
        this.commits.unshift(mergeCommit);
        await this.updateUI();
        
        window.ide?.showNotification(`Merged branch: ${branchName}`, 'success');
    }

    // Repository management
    async clone(url, name) {
        await this.simulateNetworkOperation(`Cloning ${url}...`);
        
        this.repository = {
            name: name || this.extractRepoName(url),
            path: '/',
            url: url,
            initialized: true
        };
        
        window.ide?.showNotification(`Cloned repository: ${this.repository.name}`, 'success');
    }

    async addRemote(name, url) {
        this.remotes.set(name, {
            name: name,
            url: url,
            fetch: `+refs/heads/*:refs/remotes/${name}/*`
        });
        
        window.ide?.showNotification(`Added remote: ${name}`, 'success');
    }

    async removeRemote(name) {
        if (!this.remotes.has(name)) {
            throw new Error(`Remote '${name}' does not exist`);
        }
        
        this.remotes.delete(name);
        window.ide?.showNotification(`Removed remote: ${name}`, 'warning');
    }

    // History and diff
    getCommitHistory(limit = 20) {
        return this.commits.slice(0, limit);
    }

    async showDiff(filePath) {
        // Simulate showing diff
        const diff = `
--- a/${filePath}
+++ b/${filePath}
@@ -1,4 +1,6 @@
 line 1
-line 2
+line 2 modified
 line 3
+line 4 added
 line 5
+line 6 added
        `;
        
        return diff;
    }

    // Utility methods
    generateCommitHash() {
        return Math.random().toString(36).substring(2, 15) + 
               Math.random().toString(36).substring(2, 15);
    }

    extractRepoName(url) {
        const match = url.match(/\/([^\/]+)\.git$/);
        return match ? match[1] : 'repository';
    }

    async simulateNetworkOperation(message) {
        window.ide?.showNotification(message, 'info');
        
        // Simulate network delay
        await new Promise(resolve => setTimeout(resolve, 1000 + Math.random() * 2000));
    }

    // Git configuration
    getConfig() {
        return {
            'user.name': 'Developer',
            'user.email': 'dev@crazyide.com',
            'core.autocrlf': 'false',
            'core.editor': 'crazyide',
            'init.defaultBranch': 'main'
        };
    }

    setConfig(key, value) {
        // In a real implementation, this would persist git config
        window.ide?.showNotification(`Set ${key} = ${value}`, 'success');
    }

    // Branch management UI
    showBranchManager() {
        const modal = document.createElement('div');
        modal.className = 'modal-overlay visible';
        modal.id = 'branch-manager-modal';
        
        modal.innerHTML = `
            <div class="modal">
                <div class="modal-header">
                    <h2 class="modal-title">Branch Manager</h2>
                    <button class="modal-close" onclick="this.closest('.modal-overlay').remove()">
                        <i class="fas fa-times"></i>
                    </button>
                </div>
                <div class="modal-body">
                    <div class="branch-manager">
                        <div class="branch-actions">
                            <input type="text" id="new-branch-name" placeholder="New branch name">
                            <button class="btn-primary" onclick="window.ide.gitManager.createBranchFromUI()">
                                Create Branch
                            </button>
                        </div>
                        <div class="branch-list">
                            ${this.branches.map(branch => `
                                <div class="branch-item ${branch === this.currentBranch ? 'current' : ''}">
                                    <div class="branch-info">
                                        <i class="fab fa-git-alt"></i>
                                        <span>${branch}</span>
                                        ${branch === this.currentBranch ? '<span class="current-indicator">current</span>' : ''}
                                    </div>
                                    <div class="branch-actions">
                                        ${branch !== this.currentBranch ? `
                                            <button class="btn-icon" onclick="window.ide.gitManager.switchBranch('${branch}')" title="Switch">
                                                <i class="fas fa-code-branch"></i>
                                            </button>
                                            <button class="btn-icon" onclick="window.ide.gitManager.mergeBranch('${branch}')" title="Merge">
                                                <i class="fas fa-code-merge"></i>
                                            </button>
                                            ${branch !== 'main' ? `
                                                <button class="btn-icon text-red-500" onclick="window.ide.gitManager.deleteBranch('${branch}')" title="Delete">
                                                    <i class="fas fa-trash"></i>
                                                </button>
                                            ` : ''}
                                        ` : ''}
                                    </div>
                                </div>
                            `).join('')}
                        </div>
                    </div>
                </div>
            </div>
        `;
        
        document.body.appendChild(modal);
    }

    async createBranchFromUI() {
        const input = document.getElementById('new-branch-name');
        const branchName = input.value.trim();
        
        if (!branchName) {
            window.ide?.showNotification('Branch name is required', 'error');
            return;
        }
        
        try {
            await this.createBranch(branchName);
            input.value = '';
            
            // Refresh modal
            document.getElementById('branch-manager-modal').remove();
            this.showBranchManager();
        } catch (error) {
            window.ide?.showNotification(error.message, 'error');
        }
    }
}

// Export for module use
if (typeof module !== 'undefined' && module.exports) {
    module.exports = GitManager;
}