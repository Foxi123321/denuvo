import React, { useState, useEffect, useRef } from 'react'
import { Editor } from '@monaco-editor/react'
import axios from 'axios'
import { 
  X, 
  Save, 
  Settings, 
  Download, 
  Copy, 
  RotateCcw,
  Search,
  ZoomIn,
  ZoomOut
} from 'lucide-react'
import { FileItem, FileContent } from '../types'
import { useTheme } from '../contexts/ThemeContext'

interface CodeEditorProps {
  selectedFile: FileItem | null
  openFiles: FileItem[]
  onFileSelect: (file: FileItem) => void
  onFileClose: (file: FileItem) => void
}

export default function CodeEditor({ 
  selectedFile, 
  openFiles, 
  onFileSelect, 
  onFileClose 
}: CodeEditorProps) {
  const { theme } = useTheme()
  const [fileContents, setFileContents] = useState<Map<string, FileContent>>(new Map())
  const [loading, setLoading] = useState(false)
  const [saved, setSaved] = useState(true)
  const [fontSize, setFontSize] = useState(14)
  const editorRef = useRef<any>(null)

  useEffect(() => {
    if (selectedFile && selectedFile.type === 'file') {
      loadFileContent(selectedFile)
    }
  }, [selectedFile])

  const loadFileContent = async (file: FileItem) => {
    if (fileContents.has(file.path)) {
      return // Already loaded
    }

    setLoading(true)
    try {
      const response = await axios.get('/files/content', {
        params: { path: file.path }
      })
      setFileContents(prev => new Map(prev.set(file.path, response.data)))
    } catch (error) {
      console.error('Failed to load file:', error)
    } finally {
      setLoading(false)
    }
  }

  const saveFile = async () => {
    if (!selectedFile || !editorRef.current) return

    const content = editorRef.current.getValue()
    
    try {
      await axios.post('/files/save', null, {
        params: { path: selectedFile.path, content }
      })
      setSaved(true)
      
      // Update file contents
      const currentContent = fileContents.get(selectedFile.path)
      if (currentContent) {
        setFileContents(prev => new Map(prev.set(selectedFile.path, {
          ...currentContent,
          content
        })))
      }
    } catch (error) {
      console.error('Failed to save file:', error)
    }
  }

  const handleEditorChange = (value: string | undefined) => {
    setSaved(false)
  }

  const handleEditorMount = (editor: any) => {
    editorRef.current = editor
    
    // Add keyboard shortcuts
    editor.addCommand(monaco.KeyMod.CtrlCmd | monaco.KeyCode.KeyS, () => {
      saveFile()
    })
  }

  const formatCode = async () => {
    if (!selectedFile || !editorRef.current) return
    
    const content = editorRef.current.getValue()
    const fileContent = fileContents.get(selectedFile.path)
    
    try {
      const response = await axios.post('/code/format', {
        content,
        language: fileContent?.language || 'text'
      })
      
      if (response.data.formatted_content) {
        editorRef.current.setValue(response.data.formatted_content)
      }
    } catch (error) {
      console.error('Failed to format code:', error)
    }
  }

  const copyContent = () => {
    if (editorRef.current) {
      const content = editorRef.current.getValue()
      navigator.clipboard.writeText(content)
    }
  }

  const downloadFile = () => {
    if (!selectedFile || !editorRef.current) return
    
    const content = editorRef.current.getValue()
    const blob = new Blob([content], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = selectedFile.name
    a.click()
    URL.revokeObjectURL(url)
  }

  const currentContent = selectedFile ? fileContents.get(selectedFile.path) : null

  return (
    <div className="h-full flex flex-col bg-card">
      {/* Tab Bar */}
      <div className="flex items-center border-b border-border bg-muted/30">
        <div className="flex-1 flex items-center overflow-x-auto">
          {openFiles.map(file => (
            <div
              key={file.path}
              className={`flex items-center space-x-1 px-3 py-2 border-r border-border cursor-pointer text-sm ${
                selectedFile?.path === file.path
                  ? 'bg-card text-foreground'
                  : 'text-muted-foreground hover:text-foreground hover:bg-muted/50'
              }`}
              onClick={() => onFileSelect(file)}
            >
              <span className="truncate max-w-32">{file.name}</span>
              {!saved && selectedFile?.path === file.path && (
                <span className="w-2 h-2 bg-orange-500 rounded-full" />
              )}
              <button
                onClick={(e) => {
                  e.stopPropagation()
                  onFileClose(file)
                }}
                className="p-0.5 rounded hover:bg-muted"
              >
                <X className="h-3 w-3" />
              </button>
            </div>
          ))}
        </div>

        {/* Editor Controls */}
        {selectedFile && (
          <div className="flex items-center space-x-1 px-2">
            <button
              onClick={saveFile}
              className="p-1.5 rounded hover:bg-muted"
              title="Save (Ctrl+S)"
              disabled={saved}
            >
              <Save className={`h-4 w-4 ${saved ? 'text-muted-foreground' : 'text-green-500'}`} />
            </button>
            
            <button
              onClick={formatCode}
              className="p-1.5 rounded hover:bg-muted"
              title="Format Code"
            >
              <RotateCcw className="h-4 w-4" />
            </button>
            
            <button
              onClick={copyContent}
              className="p-1.5 rounded hover:bg-muted"
              title="Copy Content"
            >
              <Copy className="h-4 w-4" />
            </button>
            
            <button
              onClick={downloadFile}
              className="p-1.5 rounded hover:bg-muted"
              title="Download File"
            >
              <Download className="h-4 w-4" />
            </button>

            <div className="flex items-center space-x-1">
              <button
                onClick={() => setFontSize(prev => Math.max(8, prev - 1))}
                className="p-1 rounded hover:bg-muted"
                title="Decrease Font Size"
              >
                <ZoomOut className="h-3 w-3" />
              </button>
              <span className="text-xs px-1">{fontSize}px</span>
              <button
                onClick={() => setFontSize(prev => Math.min(32, prev + 1))}
                className="p-1 rounded hover:bg-muted"
                title="Increase Font Size"
              >
                <ZoomIn className="h-3 w-3" />
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Editor Content */}
      <div className="flex-1 relative">
        {!selectedFile ? (
          <div className="h-full flex items-center justify-center text-muted-foreground">
            <div className="text-center">
              <Settings className="h-12 w-12 mx-auto mb-4 opacity-50" />
              <p className="text-lg">Select a file to start editing</p>
              <p className="text-sm mt-2">Choose a file from the explorer to begin coding</p>
            </div>
          </div>
        ) : loading ? (
          <div className="h-full flex items-center justify-center">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary" />
          </div>
        ) : (
          <Editor
            height="100%"
            language={currentContent?.language || 'text'}
            value={currentContent?.content || ''}
            theme={theme === 'dark' ? 'vs-dark' : 'light'}
            onChange={handleEditorChange}
            onMount={handleEditorMount}
            options={{
              fontSize,
              minimap: { enabled: true },
              wordWrap: 'on',
              automaticLayout: true,
              scrollBeyondLastLine: false,
              renderWhitespace: 'selection',
              rulers: [80, 120],
              bracketPairColorization: { enabled: true },
              guides: {
                bracketPairs: true,
                indentation: true
              },
              suggest: {
                showInlineDetails: true
              },
              quickSuggestions: true,
              parameterHints: { enabled: true },
              formatOnPaste: true,
              formatOnType: true
            }}
          />
        )}
      </div>
    </div>
  )
}