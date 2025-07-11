import React, { useState, useEffect } from 'react'
import { ResizableBox } from 'react-resizable'
import FileExplorer from './FileExplorer'
import CodeEditor from './CodeEditor'
import Terminal from './Terminal'
import Header from './Header'
import AIChat from './AIChat'
import SearchPanel from './SearchPanel'
import GitPanel from './GitPanel'
import { FileItem } from '../types'
import 'react-resizable/css/styles.css'

export default function IDE() {
  const [selectedFile, setSelectedFile] = useState<FileItem | null>(null)
  const [openFiles, setOpenFiles] = useState<FileItem[]>([])
  const [activePanel, setActivePanel] = useState<'files' | 'search' | 'git' | 'ai'>('files')
  const [showTerminal, setShowTerminal] = useState(false)
  const [sidebarWidth, setSidebarWidth] = useState(300)
  const [terminalHeight, setTerminalHeight] = useState(300)

  const handleFileSelect = (file: FileItem) => {
    setSelectedFile(file)
    if (!openFiles.find(f => f.path === file.path)) {
      setOpenFiles(prev => [...prev, file])
    }
  }

  const handleFileClose = (file: FileItem) => {
    const newOpenFiles = openFiles.filter(f => f.path !== file.path)
    setOpenFiles(newOpenFiles)
    
    if (selectedFile?.path === file.path) {
      setSelectedFile(newOpenFiles[newOpenFiles.length - 1] || null)
    }
  }

  const renderSidePanel = () => {
    switch (activePanel) {
      case 'files':
        return <FileExplorer onFileSelect={handleFileSelect} />
      case 'search':
        return <SearchPanel onFileSelect={handleFileSelect} />
      case 'git':
        return <GitPanel />
      case 'ai':
        return <AIChat />
      default:
        return <FileExplorer onFileSelect={handleFileSelect} />
    }
  }

  return (
    <div className="h-screen flex flex-col bg-background">
      <Header 
        activePanel={activePanel}
        setActivePanel={setActivePanel}
        showTerminal={showTerminal}
        setShowTerminal={setShowTerminal}
      />
      
      <div className="flex flex-1 overflow-hidden">
        {/* Sidebar */}
        <ResizableBox
          width={sidebarWidth}
          height={Infinity}
          axis="x"
          minConstraints={[200, Infinity]}
          maxConstraints={[600, Infinity]}
          onResize={(e, data) => setSidebarWidth(data.size.width)}
          className="border-r border-border"
        >
          <div className="h-full overflow-hidden">
            {renderSidePanel()}
          </div>
        </ResizableBox>

        {/* Main Content Area */}
        <div className="flex-1 flex flex-col">
          {/* Editor Area */}
          <div className="flex-1 relative">
            <CodeEditor
              selectedFile={selectedFile}
              openFiles={openFiles}
              onFileSelect={setSelectedFile}
              onFileClose={handleFileClose}
            />
          </div>

          {/* Terminal */}
          {showTerminal && (
            <ResizableBox
              width={Infinity}
              height={terminalHeight}
              axis="y"
              minConstraints={[Infinity, 200]}
              maxConstraints={[Infinity, 600]}
              onResize={(e, data) => setTerminalHeight(data.size.height)}
              className="border-t border-border"
            >
              <Terminal />
            </ResizableBox>
          )}
        </div>
      </div>
    </div>
  )
}