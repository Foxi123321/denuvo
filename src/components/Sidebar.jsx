import React, { useState, useRef } from 'react'
import './Sidebar.css'

const Sidebar = ({ files, workspaceDir, onFileSelect, onCreateFile, onCreateFolder, onLoadFiles }) => {
  const [expandedFolders, setExpandedFolders] = useState(new Set())
  const [contextMenu, setContextMenu] = useState(null)
  const [newItemInput, setNewItemInput] = useState(null)
  const fileInputRef = useRef(null)

  const getFileIcon = (file) => {
    if (file.isDirectory) return '📁'
    
    const extension = file.name.split('.').pop()?.toLowerCase()
    const iconMap = {
      'js': '🟨',
      'jsx': '⚛️',
      'ts': '🔷',
      'tsx': '⚛️',
      'py': '🐍',
      'html': '🌐',
      'css': '🎨',
      'scss': '🎨',
      'json': '📄',
      'md': '📝',
      'txt': '📄',
      'yml': '⚙️',
      'yaml': '⚙️',
      'xml': '📄',
      'php': '🐘',
      'java': '☕',
      'c': '⚙️',
      'cpp': '⚙️',
      'cs': '💎',
      'go': '🐹',
      'rs': '🦀',
      'rb': '💎',
      'sql': '🗃️',
      'sh': '📜',
      'dockerfile': '🐳',
      'gitignore': '📋',
      'env': '⚙️',
      'lock': '🔒',
      'log': '📋'
    }
    
    return iconMap[extension] || '📄'
  }

  const toggleFolder = (folderPath) => {
    setExpandedFolders(prev => {
      const newSet = new Set(prev)
      if (newSet.has(folderPath)) {
        newSet.delete(folderPath)
      } else {
        newSet.add(folderPath)
      }
      return newSet
    })
  }

  const handleContextMenu = (e, file) => {
    e.preventDefault()
    setContextMenu({
      x: e.clientX,
      y: e.clientY,
      file
    })
  }

  const closeContextMenu = () => {
    setContextMenu(null)
  }

  const handleNewFile = (folder = null) => {
    const basePath = folder || workspaceDir
    setNewItemInput({
      type: 'file',
      basePath,
      path: basePath + '/'
    })
    closeContextMenu()
  }

  const handleNewFolder = (folder = null) => {
    const basePath = folder || workspaceDir
    setNewItemInput({
      type: 'folder',
      basePath,
      path: basePath + '/'
    })
    closeContextMenu()
  }

  const confirmNewItem = async () => {
    if (!newItemInput?.path || newItemInput.path.endsWith('/')) return

    try {
      if (newItemInput.type === 'file') {
        await onCreateFile(newItemInput.path)
      } else {
        await onCreateFolder(newItemInput.path)
      }
      setNewItemInput(null)
      onLoadFiles()
    } catch (error) {
      console.error('Failed to create item:', error)
    }
  }

  const cancelNewItem = () => {
    setNewItemInput(null)
  }

  const refreshFiles = () => {
    onLoadFiles()
    closeContextMenu()
  }

  const openInSystemExplorer = () => {
    // This would need to be implemented with the backend
    console.log('Open in system explorer:', contextMenu?.file?.path)
    closeContextMenu()
  }

  const sortFiles = (files) => {
    return [...files].sort((a, b) => {
      // Directories first
      if (a.isDirectory && !b.isDirectory) return -1
      if (!a.isDirectory && b.isDirectory) return 1
      
      // Then alphabetically
      return a.name.localeCompare(b.name)
    })
  }

  const formatFileSize = (bytes) => {
    if (bytes === 0) return '0 B'
    const k = 1024
    const sizes = ['B', 'KB', 'MB', 'GB']
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i]
  }

  const formatDate = (date) => {
    return new Date(date).toLocaleDateString()
  }

  return (
    <div className="sidebar" onClick={closeContextMenu}>
      <div className="sidebar-header">
        <h3>📁 Explorer</h3>
        <div className="sidebar-actions">
          <button 
            className="sidebar-action-btn"
            onClick={() => handleNewFile()}
            title="New File"
          >
            📄
          </button>
          <button 
            className="sidebar-action-btn"
            onClick={() => handleNewFolder()}
            title="New Folder"
          >
            📁
          </button>
          <button 
            className="sidebar-action-btn"
            onClick={refreshFiles}
            title="Refresh"
          >
            🔄
          </button>
        </div>
      </div>

      <div className="workspace-info">
        <div className="workspace-path" title={workspaceDir}>
          📂 {workspaceDir.split('/').pop() || workspaceDir}
        </div>
      </div>

      <div className="file-tree">
        {files.length === 0 ? (
          <div className="empty-workspace">
            <p>No files found</p>
            <button onClick={() => handleNewFile()}>Create First File</button>
          </div>
        ) : (
          sortFiles(files).map((file) => (
            <div key={file.path}>
              <div
                className={`file-item ${file.isDirectory ? 'directory' : 'file'}`}
                onClick={() => {
                  if (file.isDirectory) {
                    toggleFolder(file.path)
                  } else {
                    onFileSelect(file.path)
                  }
                }}
                onContextMenu={(e) => handleContextMenu(e, file)}
              >
                <div className="file-info">
                  <div className="file-icon-name">
                    {file.isDirectory && (
                      <span className={`folder-arrow ${expandedFolders.has(file.path) ? 'expanded' : ''}`}>
                        ▶
                      </span>
                    )}
                    <span className="file-icon">{getFileIcon(file)}</span>
                    <span className="file-name">{file.name}</span>
                  </div>
                  
                  {!file.isDirectory && (
                    <div className="file-meta">
                      <span className="file-size">{formatFileSize(file.size)}</span>
                    </div>
                  )}
                </div>
              </div>

              {/* New item input */}
              {newItemInput && newItemInput.basePath === file.path && (
                <div className="new-item-input">
                  <input
                    type="text"
                    value={newItemInput.path}
                    onChange={(e) => setNewItemInput(prev => ({ ...prev, path: e.target.value }))}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter') confirmNewItem()
                      if (e.key === 'Escape') cancelNewItem()
                    }}
                    onBlur={cancelNewItem}
                    autoFocus
                    placeholder={`New ${newItemInput.type} name`}
                  />
                </div>
              )}
            </div>
          ))
        )}

        {/* New item input at root level */}
        {newItemInput && newItemInput.basePath === workspaceDir && (
          <div className="new-item-input">
            <span className="file-icon">{newItemInput.type === 'file' ? '📄' : '📁'}</span>
            <input
              type="text"
              value={newItemInput.path.replace(workspaceDir + '/', '')}
              onChange={(e) => setNewItemInput(prev => ({ 
                ...prev, 
                path: prev.basePath + '/' + e.target.value 
              }))}
              onKeyDown={(e) => {
                if (e.key === 'Enter') confirmNewItem()
                if (e.key === 'Escape') cancelNewItem()
              }}
              onBlur={cancelNewItem}
              autoFocus
              placeholder={`New ${newItemInput.type} name`}
            />
          </div>
        )}
      </div>

      {/* AI Quick Actions */}
      <div className="ai-shortcuts">
        <h4>🤖 AI Quick Actions</h4>
        <button className="ai-action-btn" onClick={() => onCreateFile('README.md', '# Project\n\nGenerated by FreeAI IDE')}>
          📝 Create README
        </button>
        <button className="ai-action-btn" onClick={() => onCreateFile('package.json', '{\n  "name": "my-project",\n  "version": "1.0.0"\n}')}>
          📦 Create package.json
        </button>
        <button className="ai-action-btn" onClick={() => onCreateFile('.gitignore', 'node_modules/\n.env\n*.log\n')}>
          🚫 Create .gitignore
        </button>
      </div>

      {/* Context Menu */}
      {contextMenu && (
        <div 
          className="context-menu"
          style={{ 
            position: 'fixed',
            left: contextMenu.x,
            top: contextMenu.y,
            zIndex: 1000
          }}
          onClick={(e) => e.stopPropagation()}
        >
          <div className="context-menu-item" onClick={() => onFileSelect(contextMenu.file.path)}>
            📂 Open
          </div>
          
          {contextMenu.file.isDirectory && (
            <>
              <div className="context-menu-item" onClick={() => handleNewFile(contextMenu.file.path)}>
                📄 New File
              </div>
              <div className="context-menu-item" onClick={() => handleNewFolder(contextMenu.file.path)}>
                📁 New Folder
              </div>
            </>
          )}
          
          <div className="context-menu-separator"></div>
          
          <div className="context-menu-item" onClick={refreshFiles}>
            🔄 Refresh
          </div>
          
          <div className="context-menu-item" onClick={openInSystemExplorer}>
            🗂️ Reveal in Explorer
          </div>
          
          <div className="context-menu-separator"></div>
          
          <div className="context-menu-item danger">
            🗑️ Delete
          </div>
        </div>
      )}

      {/* Hidden file input for file uploads */}
      <input
        ref={fileInputRef}
        type="file"
        multiple
        style={{ display: 'none' }}
        onChange={(e) => {
          Array.from(e.target.files).forEach(file => {
            const reader = new FileReader()
            reader.onload = (e) => {
              onCreateFile(`${workspaceDir}/${file.name}`, e.target.result)
            }
            reader.readAsText(file)
          })
        }}
      />
    </div>
  )
}

export default Sidebar