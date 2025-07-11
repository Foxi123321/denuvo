import React, { useState, useEffect } from 'react'
import axios from 'axios'
import { 
  File, 
  Folder, 
  FolderOpen, 
  Plus, 
  FolderPlus, 
  Trash2, 
  RefreshCw,
  ChevronRight,
  ChevronDown
} from 'lucide-react'
import { FileItem } from '../types'

interface FileExplorerProps {
  onFileSelect: (file: FileItem) => void
}

export default function FileExplorer({ onFileSelect }: FileExplorerProps) {
  const [files, setFiles] = useState<FileItem[]>([])
  const [expandedDirs, setExpandedDirs] = useState<Set<string>>(new Set())
  const [loading, setLoading] = useState(false)
  const [selectedPath, setSelectedPath] = useState<string>('')
  const [currentPath, setCurrentPath] = useState('.')

  useEffect(() => {
    loadFiles(currentPath)
  }, [currentPath])

  const loadFiles = async (path: string) => {
    setLoading(true)
    try {
      const response = await axios.get(`/files?path=${encodeURIComponent(path)}`)
      setFiles(response.data)
    } catch (error) {
      console.error('Failed to load files:', error)
    } finally {
      setLoading(false)
    }
  }

  const handleFileClick = async (file: FileItem) => {
    if (file.type === 'directory') {
      const isExpanded = expandedDirs.has(file.path)
      if (isExpanded) {
        setExpandedDirs(prev => {
          const newSet = new Set(prev)
          newSet.delete(file.path)
          return newSet
        })
      } else {
        setExpandedDirs(prev => new Set([...prev, file.path]))
        // Load directory contents if not loaded
        if (!file.children) {
          try {
            const response = await axios.get(`/files?path=${encodeURIComponent(file.path)}`)
            file.children = response.data
            setFiles([...files]) // Trigger re-render
          } catch (error) {
            console.error('Failed to load directory:', error)
          }
        }
      }
    } else {
      setSelectedPath(file.path)
      onFileSelect(file)
    }
  }

  const createFile = async () => {
    const name = prompt('Enter file name:')
    if (name) {
      try {
        await axios.post('/files/create', null, {
          params: { path: `${currentPath}/${name}`, is_directory: false }
        })
        loadFiles(currentPath)
      } catch (error) {
        console.error('Failed to create file:', error)
      }
    }
  }

  const createFolder = async () => {
    const name = prompt('Enter folder name:')
    if (name) {
      try {
        await axios.post('/files/create', null, {
          params: { path: `${currentPath}/${name}`, is_directory: true }
        })
        loadFiles(currentPath)
      } catch (error) {
        console.error('Failed to create folder:', error)
      }
    }
  }

  const deleteFile = async (file: FileItem, e: React.MouseEvent) => {
    e.stopPropagation()
    if (confirm(`Are you sure you want to delete ${file.name}?`)) {
      try {
        await axios.delete('/files/delete', {
          params: { path: file.path }
        })
        loadFiles(currentPath)
      } catch (error) {
        console.error('Failed to delete file:', error)
      }
    }
  }

  const renderFileTree = (items: FileItem[], depth = 0) => {
    return items.map(file => (
      <div key={file.path} className="select-none">
        <div
          className={`file-tree-item flex items-center space-x-1 py-1 px-2 cursor-pointer hover:bg-muted rounded text-sm ${
            selectedPath === file.path ? 'bg-primary/10' : ''
          }`}
          style={{ paddingLeft: `${depth * 16 + 8}px` }}
          onClick={() => handleFileClick(file)}
        >
          {file.type === 'directory' && (
            <div className="w-4 h-4 flex items-center justify-center">
              {expandedDirs.has(file.path) ? (
                <ChevronDown className="h-3 w-3" />
              ) : (
                <ChevronRight className="h-3 w-3" />
              )}
            </div>
          )}
          
          <div className="w-4 h-4 flex items-center justify-center">
            {file.type === 'directory' ? (
              expandedDirs.has(file.path) ? (
                <FolderOpen className="h-4 w-4 text-blue-500" />
              ) : (
                <Folder className="h-4 w-4 text-blue-500" />
              )
            ) : (
              <File className="h-4 w-4 text-gray-500" />
            )}
          </div>
          
          <span className="flex-1 truncate">{file.name}</span>
          
          <button
            onClick={(e) => deleteFile(file, e)}
            className="w-4 h-4 opacity-0 group-hover:opacity-100 hover:text-red-500"
          >
            <Trash2 className="h-3 w-3" />
          </button>
        </div>
        
        {file.type === 'directory' && expandedDirs.has(file.path) && file.children && (
          <div>
            {renderFileTree(file.children, depth + 1)}
          </div>
        )}
      </div>
    ))
  }

  return (
    <div className="h-full flex flex-col bg-card">
      {/* Header */}
      <div className="p-3 border-b border-border">
        <div className="flex items-center justify-between">
          <h3 className="font-medium text-sm">Explorer</h3>
          <div className="flex items-center space-x-1">
            <button
              onClick={createFile}
              className="p-1 rounded hover:bg-muted"
              title="New File"
            >
              <Plus className="h-4 w-4" />
            </button>
            <button
              onClick={createFolder}
              className="p-1 rounded hover:bg-muted"
              title="New Folder"
            >
              <FolderPlus className="h-4 w-4" />
            </button>
            <button
              onClick={() => loadFiles(currentPath)}
              className="p-1 rounded hover:bg-muted"
              title="Refresh"
            >
              <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
            </button>
          </div>
        </div>
      </div>

      {/* File Tree */}
      <div className="flex-1 overflow-auto p-2">
        {loading && files.length === 0 ? (
          <div className="flex items-center justify-center py-8">
            <RefreshCw className="h-6 w-6 animate-spin" />
          </div>
        ) : (
          <div className="space-y-1">
            {renderFileTree(files)}
          </div>
        )}
      </div>
    </div>
  )
}