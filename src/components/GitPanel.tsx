import React, { useState, useEffect } from 'react'
import axios from 'axios'
import { 
  GitBranch, 
  Plus, 
  Minus, 
  FileText, 
  GitCommit, 
  RefreshCw,
  Upload,
  Download,
  Check
} from 'lucide-react'
import { GitStatus } from '../types'

export default function GitPanel() {
  const [gitStatus, setGitStatus] = useState<GitStatus | null>(null)
  const [loading, setLoading] = useState(false)
  const [commitMessage, setCommitMessage] = useState('')
  const [selectedFiles, setSelectedFiles] = useState<Set<string>>(new Set())

  useEffect(() => {
    loadGitStatus()
  }, [])

  const loadGitStatus = async () => {
    setLoading(true)
    try {
      const response = await axios.get('/git/status')
      setGitStatus(response.data)
    } catch (error) {
      console.error('Failed to load git status:', error)
    } finally {
      setLoading(false)
    }
  }

  const addFiles = async (files: string[]) => {
    try {
      await axios.post('/git/add', { files })
      loadGitStatus()
    } catch (error) {
      console.error('Failed to add files:', error)
    }
  }

  const commitChanges = async () => {
    if (!commitMessage.trim()) return
    
    try {
      await axios.post('/git/commit', null, {
        params: { message: commitMessage }
      })
      setCommitMessage('')
      loadGitStatus()
    } catch (error) {
      console.error('Failed to commit:', error)
    }
  }

  const toggleFileSelection = (file: string) => {
    setSelectedFiles(prev => {
      const newSet = new Set(prev)
      if (newSet.has(file)) {
        newSet.delete(file)
      } else {
        newSet.add(file)
      }
      return newSet
    })
  }

  const addSelectedFiles = () => {
    if (selectedFiles.size > 0) {
      addFiles(Array.from(selectedFiles))
      setSelectedFiles(new Set())
    }
  }

  const selectAllUnstaged = () => {
    if (gitStatus) {
      setSelectedFiles(new Set([...gitStatus.unstaged, ...gitStatus.untracked]))
    }
  }

  const getFileIcon = (file: string) => {
    return <FileText className="h-4 w-4 text-blue-500" />
  }

  const getStatusColor = (status: 'staged' | 'unstaged' | 'untracked') => {
    switch (status) {
      case 'staged': return 'text-green-500'
      case 'unstaged': return 'text-yellow-500'
      case 'untracked': return 'text-red-500'
      default: return 'text-muted-foreground'
    }
  }

  const getStatusIcon = (status: 'staged' | 'unstaged' | 'untracked') => {
    switch (status) {
      case 'staged': return <Plus className="h-3 w-3" />
      case 'unstaged': return <Minus className="h-3 w-3" />
      case 'untracked': return <FileText className="h-3 w-3" />
      default: return null
    }
  }

  return (
    <div className="h-full flex flex-col bg-card">
      {/* Header */}
      <div className="p-3 border-b border-border">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <GitBranch className="h-5 w-5" />
            <h3 className="font-medium text-sm">Source Control</h3>
          </div>
          <button
            onClick={loadGitStatus}
            className="p-1 rounded hover:bg-muted"
            title="Refresh"
          >
            <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
          </button>
        </div>
        
        {gitStatus && (
          <div className="mt-2 text-xs text-muted-foreground">
            Branch: <span className="font-medium">{gitStatus.branch}</span>
          </div>
        )}
      </div>

      {/* Content */}
      <div className="flex-1 overflow-auto">
        {loading && !gitStatus ? (
          <div className="flex items-center justify-center py-8">
            <RefreshCw className="h-6 w-6 animate-spin" />
          </div>
        ) : gitStatus ? (
          <div className="p-2 space-y-4">
            {/* Staged Changes */}
            {gitStatus.staged.length > 0 && (
              <div>
                <div className="flex items-center justify-between mb-2">
                  <h4 className="text-sm font-medium flex items-center space-x-1">
                    <span>Staged Changes</span>
                    <span className="text-xs bg-green-500 text-white px-2 py-0.5 rounded-full">
                      {gitStatus.staged.length}
                    </span>
                  </h4>
                </div>
                <div className="space-y-1">
                  {gitStatus.staged.map(file => (
                    <div key={file} className="flex items-center space-x-2 p-2 rounded hover:bg-muted text-sm">
                      <div className={`${getStatusColor('staged')}`}>
                        {getStatusIcon('staged')}
                      </div>
                      {getFileIcon(file)}
                      <span className="flex-1 truncate">{file}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Changes (Unstaged) */}
            {gitStatus.unstaged.length > 0 && (
              <div>
                <div className="flex items-center justify-between mb-2">
                  <h4 className="text-sm font-medium flex items-center space-x-1">
                    <span>Changes</span>
                    <span className="text-xs bg-yellow-500 text-white px-2 py-0.5 rounded-full">
                      {gitStatus.unstaged.length}
                    </span>
                  </h4>
                  <button
                    onClick={selectAllUnstaged}
                    className="text-xs text-muted-foreground hover:text-foreground"
                  >
                    Select All
                  </button>
                </div>
                <div className="space-y-1">
                  {gitStatus.unstaged.map(file => (
                    <div 
                      key={file} 
                      className={`flex items-center space-x-2 p-2 rounded hover:bg-muted cursor-pointer text-sm ${
                        selectedFiles.has(file) ? 'bg-primary/10' : ''
                      }`}
                      onClick={() => toggleFileSelection(file)}
                    >
                      <div className={`${getStatusColor('unstaged')}`}>
                        {getStatusIcon('unstaged')}
                      </div>
                      {getFileIcon(file)}
                      <span className="flex-1 truncate">{file}</span>
                      {selectedFiles.has(file) && (
                        <Check className="h-3 w-3 text-primary" />
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Untracked Files */}
            {gitStatus.untracked.length > 0 && (
              <div>
                <div className="flex items-center justify-between mb-2">
                  <h4 className="text-sm font-medium flex items-center space-x-1">
                    <span>Untracked Files</span>
                    <span className="text-xs bg-red-500 text-white px-2 py-0.5 rounded-full">
                      {gitStatus.untracked.length}
                    </span>
                  </h4>
                </div>
                <div className="space-y-1">
                  {gitStatus.untracked.map(file => (
                    <div 
                      key={file} 
                      className={`flex items-center space-x-2 p-2 rounded hover:bg-muted cursor-pointer text-sm ${
                        selectedFiles.has(file) ? 'bg-primary/10' : ''
                      }`}
                      onClick={() => toggleFileSelection(file)}
                    >
                      <div className={`${getStatusColor('untracked')}`}>
                        {getStatusIcon('untracked')}
                      </div>
                      {getFileIcon(file)}
                      <span className="flex-1 truncate">{file}</span>
                      {selectedFiles.has(file) && (
                        <Check className="h-3 w-3 text-primary" />
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Stage Selected Files */}
            {selectedFiles.size > 0 && (
              <div className="pt-2 border-t border-border">
                <button
                  onClick={addSelectedFiles}
                  className="w-full flex items-center justify-center space-x-2 py-2 px-3 bg-primary text-primary-foreground rounded-md hover:bg-primary/90 text-sm"
                >
                  <Plus className="h-4 w-4" />
                  <span>Stage {selectedFiles.size} file{selectedFiles.size > 1 ? 's' : ''}</span>
                </button>
              </div>
            )}

            {/* Commit Section */}
            {gitStatus.staged.length > 0 && (
              <div className="pt-2 border-t border-border">
                <div className="space-y-2">
                  <textarea
                    value={commitMessage}
                    onChange={(e) => setCommitMessage(e.target.value)}
                    placeholder="Commit message..."
                    className="w-full p-2 border border-input rounded-md bg-background text-foreground placeholder-muted-foreground focus:outline-none focus:ring-2 focus:ring-ring focus:border-transparent text-sm resize-none"
                    rows={3}
                  />
                  <button
                    onClick={commitChanges}
                    disabled={!commitMessage.trim()}
                    className="w-full flex items-center justify-center space-x-2 py-2 px-3 bg-green-600 text-white rounded-md hover:bg-green-700 disabled:opacity-50 disabled:cursor-not-allowed text-sm"
                  >
                    <GitCommit className="h-4 w-4" />
                    <span>Commit</span>
                  </button>
                </div>
              </div>
            )}

            {/* Empty State */}
            {gitStatus.staged.length === 0 && gitStatus.unstaged.length === 0 && gitStatus.untracked.length === 0 && (
              <div className="flex items-center justify-center py-8 text-muted-foreground">
                <div className="text-center">
                  <GitBranch className="h-8 w-8 mx-auto mb-2 opacity-50" />
                  <p className="text-sm">No changes</p>
                  <p className="text-xs mt-1">Your working tree is clean</p>
                </div>
              </div>
            )}
          </div>
        ) : (
          <div className="flex items-center justify-center py-8 text-muted-foreground">
            <div className="text-center">
              <GitBranch className="h-8 w-8 mx-auto mb-2 opacity-50" />
              <p className="text-sm">No repository</p>
              <p className="text-xs mt-1">Initialize a git repository to get started</p>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}