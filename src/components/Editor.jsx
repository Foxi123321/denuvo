import React, { useRef, useEffect, useState } from 'react'
import * as monaco from 'monaco-editor'
import './Editor.css'

const Editor = ({ 
  currentFile, 
  fileContent, 
  openFiles, 
  onContentChange, 
  onSaveFile, 
  onCloseFile,
  onFileSelect,
  aiModel 
}) => {
  const editorRef = useRef(null)
  const monacoRef = useRef(null)
  const [aiSuggestion, setAiSuggestion] = useState(null)
  const [isLoading, setIsLoading] = useState(false)

  useEffect(() => {
    // Initialize Monaco Editor
    if (editorRef.current && !monacoRef.current) {
      monacoRef.current = monaco.editor.create(editorRef.current, {
        value: '',
        language: 'javascript',
        theme: 'vs-dark',
        fontFamily: 'Fira Code, Monaco, Consolas, monospace',
        fontSize: 14,
        lineHeight: 1.5,
        minimap: { enabled: true },
        scrollBeyondLastLine: false,
        automaticLayout: true,
        wordWrap: 'on',
        tabSize: 2,
        insertSpaces: true,
        formatOnPaste: true,
        formatOnType: true,
        quickSuggestions: true,
        suggestOnTriggerCharacters: true,
        acceptSuggestionOnEnter: 'on',
        snippetSuggestions: 'top',
        wordBasedSuggestions: true,
        parameterHints: { enabled: true },
        hover: { enabled: true },
        folding: true,
        foldingStrategy: 'auto',
        showFoldingControls: 'always',
        unfoldOnClickAfterEndOfLine: false,
        contextmenu: true,
        mouseWheelZoom: true,
        multiCursorModifier: 'ctrlCmd',
        accessibilitySupport: 'auto'
      })

      // Add keyboard shortcuts
      monacoRef.current.addCommand(monaco.KeyMod.CtrlCmd | monaco.KeyCode.KeyS, () => {
        onSaveFile()
      })

      monacoRef.current.addCommand(monaco.KeyMod.CtrlCmd | monaco.KeyCode.KeyK, () => {
        showAIInlineHelp()
      })

      monacoRef.current.addCommand(monaco.KeyMod.CtrlCmd | monaco.KeyMod.Shift | monaco.KeyCode.KeyP, () => {
        showCommandPalette()
      })

      // Listen for content changes
      monacoRef.current.onDidChangeModelContent(() => {
        const value = monacoRef.current.getValue()
        onContentChange(value)
      })

      // Listen for cursor position changes for AI hints
      monacoRef.current.onDidChangeCursorPosition(debounce(() => {
        // Trigger AI hints when appropriate
        const position = monacoRef.current.getPosition()
        const model = monacoRef.current.getModel()
        if (model && position) {
          const lineContent = model.getLineContent(position.lineNumber)
          if (lineContent.trim() && shouldTriggerAIHint(lineContent)) {
            // Could show AI hints here
          }
        }
      }, 1000))

      // Register AI completion provider
      monaco.languages.registerCompletionItemProvider('javascript', {
        provideCompletionItems: async (model, position) => {
          const suggestions = await getAICompletions(model, position)
          return { suggestions }
        }
      })

      // Register AI hover provider
      monaco.languages.registerHoverProvider('javascript', {
        provideHover: async (model, position) => {
          const word = model.getWordAtPosition(position)
          if (word) {
            const hover = await getAIHover(word.word, model, position)
            return hover
          }
        }
      })
    }

    return () => {
      if (monacoRef.current) {
        monacoRef.current.dispose()
        monacoRef.current = null
      }
    }
  }, [])

  useEffect(() => {
    // Update editor content when file changes
    if (monacoRef.current && fileContent !== undefined) {
      const currentValue = monacoRef.current.getValue()
      if (currentValue !== fileContent) {
        monacoRef.current.setValue(fileContent)
      }
    }
  }, [fileContent])

  useEffect(() => {
    // Update language based on file extension
    if (monacoRef.current && currentFile) {
      const language = getLanguageFromFile(currentFile)
      const model = monacoRef.current.getModel()
      if (model) {
        monaco.editor.setModelLanguage(model, language)
      }
    }
  }, [currentFile])

  const getLanguageFromFile = (filePath) => {
    const extension = filePath.split('.').pop()?.toLowerCase()
    const languageMap = {
      'js': 'javascript',
      'jsx': 'javascript',
      'ts': 'typescript',
      'tsx': 'typescript',
      'py': 'python',
      'html': 'html',
      'css': 'css',
      'scss': 'scss',
      'json': 'json',
      'md': 'markdown',
      'yml': 'yaml',
      'yaml': 'yaml',
      'xml': 'xml',
      'php': 'php',
      'java': 'java',
      'c': 'c',
      'cpp': 'cpp',
      'cs': 'csharp',
      'go': 'go',
      'rs': 'rust',
      'rb': 'ruby',
      'sql': 'sql',
      'sh': 'shell',
      'dockerfile': 'dockerfile'
    }
    return languageMap[extension] || 'plaintext'
  }

  const showAIInlineHelp = async () => {
    if (!monacoRef.current) return

    const selection = monacoRef.current.getSelection()
    const model = monacoRef.current.getModel()
    
    let prompt = ''
    if (selection && !selection.isEmpty()) {
      const selectedText = model.getValueInRange(selection)
      prompt = `Explain this code: ${selectedText}`
    } else {
      const position = monacoRef.current.getPosition()
      const lineContent = model.getLineContent(position.lineNumber)
      prompt = `Help me complete this code: ${lineContent}`
    }

    try {
      setIsLoading(true)
      const response = await callAI(prompt)
      setAiSuggestion({
        content: response,
        position: monacoRef.current.getPosition()
      })
    } catch (error) {
      console.error('AI help failed:', error)
    } finally {
      setIsLoading(false)
    }
  }

  const showCommandPalette = () => {
    // Monaco has built-in command palette
    monacoRef.current.trigger('', 'editor.action.quickCommand')
  }

  const getAICompletions = async (model, position) => {
    try {
      const lineContent = model.getLineContent(position.lineNumber)
      const textBeforeCursor = lineContent.substring(0, position.column - 1)
      
      if (textBeforeCursor.trim().length < 3) return []

      const response = await callAI(`Complete this code: ${textBeforeCursor}`)
      
      return [{
        label: 'AI Completion',
        kind: monaco.languages.CompletionItemKind.Snippet,
        insertText: response,
        documentation: 'AI-generated completion',
        range: {
          startLineNumber: position.lineNumber,
          endLineNumber: position.lineNumber,
          startColumn: position.column,
          endColumn: position.column
        }
      }]
    } catch (error) {
      console.error('AI completion failed:', error)
      return []
    }
  }

  const getAIHover = async (word, model, position) => {
    try {
      const response = await callAI(`Explain what "${word}" means in this context`)
      
      return {
        range: {
          startLineNumber: position.lineNumber,
          endLineNumber: position.lineNumber,
          startColumn: position.column,
          endColumn: position.column + word.length
        },
        contents: [
          { value: '**AI Explanation**' },
          { value: response }
        ]
      }
    } catch (error) {
      console.error('AI hover failed:', error)
      return null
    }
  }

  const callAI = async (prompt) => {
    const response = await fetch('https://js.puter.com/v2/ai/chat', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: aiModel,
        messages: [{ role: 'user', content: prompt }]
      })
    })
    
    if (!response.ok) throw new Error('AI request failed')
    
    const data = await response.json()
    return data.choices?.[0]?.message?.content || 'No response'
  }

  const shouldTriggerAIHint = (lineContent) => {
    // Trigger hints for function definitions, complex expressions, etc.
    return lineContent.includes('function') || 
           lineContent.includes('const') ||
           lineContent.includes('import') ||
           lineContent.includes('export')
  }

  const debounce = (func, delay) => {
    let timeoutId
    return (...args) => {
      clearTimeout(timeoutId)
      timeoutId = setTimeout(() => func.apply(null, args), delay)
    }
  }

  const acceptAISuggestion = () => {
    if (aiSuggestion && monacoRef.current) {
      const position = aiSuggestion.position
      monacoRef.current.executeEdits('', [{
        range: {
          startLineNumber: position.lineNumber,
          startColumn: position.column,
          endLineNumber: position.lineNumber,
          endColumn: position.column
        },
        text: aiSuggestion.content
      }])
      setAiSuggestion(null)
    }
  }

  const rejectAISuggestion = () => {
    setAiSuggestion(null)
  }

  return (
    <div className="editor-container">
      {/* Tab Bar */}
      <div className="tab-bar">
        {openFiles.map((file) => (
          <div 
            key={file.path}
            className={`tab ${currentFile === file.path ? 'active' : ''}`}
            onClick={() => onFileSelect(file.path)}
          >
            <span className="tab-name">
              {file.name}
              {file.modified && <span className="modified-indicator">●</span>}
            </span>
            <button 
              className="tab-close"
              onClick={(e) => {
                e.stopPropagation()
                onCloseFile(file.path)
              }}
            >
              ×
            </button>
          </div>
        ))}
      </div>

      {/* Monaco Editor */}
      <div className="editor-wrapper">
        <div ref={editorRef} className="monaco-editor" />
        
        {/* AI Loading Indicator */}
        {isLoading && (
          <div className="ai-loading">
            <div className="spinner"></div>
            <span>AI is thinking...</span>
          </div>
        )}

        {/* AI Suggestion Overlay */}
        {aiSuggestion && (
          <div className="ai-suggestion-overlay">
            <div className="ai-suggestion-content">
              <div className="ai-suggestion-header">
                <span>🤖 AI Suggestion</span>
                <div className="ai-suggestion-actions">
                  <button onClick={acceptAISuggestion}>Accept</button>
                  <button onClick={rejectAISuggestion}>Reject</button>
                </div>
              </div>
              <div className="ai-suggestion-text">
                {aiSuggestion.content}
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Welcome Screen */}
      {!currentFile && (
        <div className="welcome-screen">
          <div className="welcome-content">
            <h1>🚀 FreeAI IDE</h1>
            <p>Your forever-free AI-powered development environment</p>
            <div className="welcome-actions">
              <button onClick={() => onFileSelect('README.md')}>
                📝 Create New File
              </button>
              <button onClick={() => document.getElementById('file-input')?.click()}>
                📂 Open File
              </button>
            </div>
            <div className="welcome-features">
              <div className="feature">
                <h3>🤖 AI Assistant</h3>
                <p>Unlimited AI help with Claude, GPT-4o, and more</p>
              </div>
              <div className="feature">
                <h3>⚡ Smart Features</h3>
                <p>Code completion, refactoring, and explanations</p>
              </div>
              <div className="feature">
                <h3>🎯 Like Cursor</h3>
                <p>All the features you love, completely free</p>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

export default Editor