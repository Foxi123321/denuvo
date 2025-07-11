import React, { useState, useEffect } from 'react'
import { io } from 'socket.io-client'
import Sidebar from './components/Sidebar'
import Editor from './components/Editor'
import Terminal from './components/Terminal'
import Chat from './components/Chat'
import MenuBar from './components/MenuBar'
import StatusBar from './components/StatusBar'
import './App.css'

function App() {
  const [socket, setSocket] = useState(null)
  const [currentFile, setCurrentFile] = useState(null)
  const [openFiles, setOpenFiles] = useState([])
  const [fileContent, setFileContent] = useState('')
  const [workspaceDir, setWorkspaceDir] = useState('')
  const [files, setFiles] = useState([])
  const [aiModel, setAiModel] = useState('claude-sonnet-4')
  const [theme, setTheme] = useState('dark')
  const [isTerminalVisible, setIsTerminalVisible] = useState(true)
  const [isChatVisible, setIsChatVisible] = useState(true)
  const [statusMessage, setStatusMessage] = useState('Ready')

  useEffect(() => {
    // Initialize socket connection
    const newSocket = io('http://localhost:3001')
    setSocket(newSocket)
    
    // Set initial workspace directory
    setWorkspaceDir(window.localStorage.getItem('workspaceDir') || process.cwd?.() || '/workspace')

    return () => newSocket.close()
  }, [])

  useEffect(() => {
    if (socket) {
      // File watching
      socket.on('file:changed', ({ path }) => {
        setStatusMessage(`File changed: ${path}`)
        // Refresh file list if needed
        loadFiles()
      })

      socket.on('file:added', ({ path }) => {
        setStatusMessage(`File added: ${path}`)
        loadFiles()
      })

      socket.on('file:deleted', ({ path }) => {
        setStatusMessage(`File deleted: ${path}`)
        loadFiles()
        // Close file if it was open
        if (currentFile === path) {
          setCurrentFile(null)
          setFileContent('')
        }
        setOpenFiles(prev => prev.filter(file => file.path !== path))
      })
    }
  }, [socket, currentFile])

  const loadFiles = async (dir = workspaceDir) => {
    try {
      const response = await fetch(`/api/files?dir=${encodeURIComponent(dir)}`)
      const data = await response.json()
      setFiles(data)
    } catch (error) {
      console.error('Failed to load files:', error)
      setStatusMessage('Failed to load files')
    }
  }

  const openFile = async (filePath) => {
    try {
      const response = await fetch(`/api/file/content?path=${encodeURIComponent(filePath)}`)
      const data = await response.json()
      
      if (response.ok) {
        setCurrentFile(filePath)
        setFileContent(data.content)
        
        // Add to open files if not already open
        if (!openFiles.find(f => f.path === filePath)) {
          const fileName = filePath.split('/').pop()
          setOpenFiles(prev => [...prev, { path: filePath, name: fileName, modified: false }])
        }
        
        setStatusMessage(`Opened: ${filePath}`)
      } else {
        setStatusMessage(`Failed to open: ${filePath}`)
      }
    } catch (error) {
      console.error('Failed to open file:', error)
      setStatusMessage('Failed to open file')
    }
  }

  const saveFile = async (filePath = currentFile, content = fileContent) => {
    try {
      const response = await fetch('/api/file/save', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ path: filePath, content })
      })
      
      if (response.ok) {
        // Mark file as not modified
        setOpenFiles(prev => prev.map(file => 
          file.path === filePath ? { ...file, modified: false } : file
        ))
        setStatusMessage(`Saved: ${filePath}`)
      } else {
        setStatusMessage(`Failed to save: ${filePath}`)
      }
    } catch (error) {
      console.error('Failed to save file:', error)
      setStatusMessage('Failed to save file')
    }
  }

  const createFile = async (filePath, content = '', isDirectory = false) => {
    try {
      const response = await fetch('/api/file/create', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ path: filePath, content, isDirectory })
      })
      
      if (response.ok) {
        loadFiles()
        if (!isDirectory) {
          openFile(filePath)
        }
        setStatusMessage(`Created: ${filePath}`)
      } else {
        setStatusMessage(`Failed to create: ${filePath}`)
      }
    } catch (error) {
      console.error('Failed to create file:', error)
      setStatusMessage('Failed to create file')
    }
  }

  const runCommand = async (command, cwd = workspaceDir) => {
    try {
      const response = await fetch('/api/command/run', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ command, cwd })
      })
      
      const result = await response.json()
      return result
    } catch (error) {
      console.error('Failed to run command:', error)
      return { success: false, stderr: error.message }
    }
  }

  const createProject = async (name, template) => {
    try {
      const response = await fetch('/api/project/create', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, template, path: workspaceDir })
      })
      
      const result = await response.json()
      if (result.success) {
        setWorkspaceDir(result.path)
        window.localStorage.setItem('workspaceDir', result.path)
        loadFiles(result.path)
        setStatusMessage(`Created project: ${name}`)
      }
    } catch (error) {
      console.error('Failed to create project:', error)
      setStatusMessage('Failed to create project')
    }
  }

  const closeFile = (filePath) => {
    setOpenFiles(prev => prev.filter(file => file.path !== filePath))
    
    if (currentFile === filePath) {
      const remaining = openFiles.filter(file => file.path !== filePath)
      if (remaining.length > 0) {
        openFile(remaining[0].path)
      } else {
        setCurrentFile(null)
        setFileContent('')
      }
    }
  }

  const onContentChange = (newContent) => {
    setFileContent(newContent)
    
    // Mark file as modified
    if (currentFile) {
      setOpenFiles(prev => prev.map(file => 
        file.path === currentFile ? { ...file, modified: true } : file
      ))
    }
  }

  // Load files on mount
  useEffect(() => {
    if (workspaceDir) {
      loadFiles()
      // Start watching the workspace
      if (socket) {
        socket.emit('files:watch', { path: workspaceDir })
      }
    }
  }, [workspaceDir, socket])

  return (
    <div className={`app ${theme}`}>
      <MenuBar 
        onNewFile={() => createFile('untitled.txt')}
        onOpenFile={() => document.getElementById('file-input')?.click()}
        onSaveFile={() => saveFile()}
        onCreateProject={createProject}
        onToggleTheme={() => setTheme(prev => prev === 'dark' ? 'light' : 'dark')}
        aiModel={aiModel}
        onModelChange={setAiModel}
      />
      
      <div className="main-layout">
        <Sidebar 
          files={files}
          workspaceDir={workspaceDir}
          onFileSelect={openFile}
          onCreateFile={createFile}
          onCreateFolder={(path) => createFile(path, '', true)}
          onLoadFiles={loadFiles}
        />
        
        <div className="editor-area">
          <Editor 
            currentFile={currentFile}
            fileContent={fileContent}
            openFiles={openFiles}
            onContentChange={onContentChange}
            onSaveFile={saveFile}
            onCloseFile={closeFile}
            onFileSelect={openFile}
            aiModel={aiModel}
          />
          
          {isTerminalVisible && (
            <Terminal 
              socket={socket}
              workspaceDir={workspaceDir}
              onCommandRun={runCommand}
              onClose={() => setIsTerminalVisible(false)}
            />
          )}
        </div>
        
        {isChatVisible && (
          <Chat 
            aiModel={aiModel}
            currentFile={currentFile}
            fileContent={fileContent}
            onCreateFile={createFile}
            onClose={() => setIsChatVisible(false)}
          />
        )}
      </div>
      
      <StatusBar 
        message={statusMessage}
        currentFile={currentFile}
        aiModel={aiModel}
        onToggleTerminal={() => setIsTerminalVisible(prev => !prev)}
        onToggleChat={() => setIsChatVisible(prev => !prev)}
      />
      
      <input 
        id="file-input"
        type="file"
        style={{ display: 'none' }}
        onChange={(e) => {
          const file = e.target.files[0]
          if (file) {
            const reader = new FileReader()
            reader.onload = (e) => {
              createFile(file.name, e.target.result)
            }
            reader.readAsText(file)
          }
        }}
      />
    </div>
  )
}

export default App