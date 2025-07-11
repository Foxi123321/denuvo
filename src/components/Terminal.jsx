import React, { useRef, useEffect, useState } from 'react'
import { Terminal as XTerm } from 'xterm'
import { FitAddon } from 'xterm-addon-fit'
import { WebLinksAddon } from 'xterm-addon-web-links'
import 'xterm/css/xterm.css'
import './Terminal.css'

const Terminal = ({ socket, workspaceDir, onCommandRun, onClose }) => {
  const terminalRef = useRef(null)
  const xtermRef = useRef(null)
  const fitAddonRef = useRef(null)
  const [terminalId] = useState(() => `terminal_${Date.now()}`)
  const [isConnected, setIsConnected] = useState(false)
  const [commandHistory, setCommandHistory] = useState([])
  const [historyIndex, setHistoryIndex] = useState(-1)
  const [currentCommand, setCurrentCommand] = useState('')

  useEffect(() => {
    if (terminalRef.current && !xtermRef.current) {
      // Initialize xterm.js
      xtermRef.current = new XTerm({
        theme: {
          background: '#1e1e1e',
          foreground: '#d4d4d4',
          cursor: '#ffffff',
          black: '#000000',
          red: '#f48771',
          green: '#4ec9b0',
          yellow: '#dcdcaa',
          blue: '#569cd6',
          magenta: '#c586c0',
          cyan: '#9cdcfe',
          white: '#d4d4d4',
          brightBlack: '#898989',
          brightRed: '#f48771',
          brightGreen: '#4ec9b0',
          brightYellow: '#dcdcaa',
          brightBlue: '#569cd6',
          brightMagenta: '#c586c0',
          brightCyan: '#9cdcfe',
          brightWhite: '#ffffff'
        },
        fontFamily: 'Fira Code, Monaco, Consolas, monospace',
        fontSize: 14,
        lineHeight: 1.2,
        cursorBlink: true,
        cursorStyle: 'block',
        scrollback: 10000,
        tabStopWidth: 4,
        bellStyle: 'none'
      })

      // Add addons
      fitAddonRef.current = new FitAddon()
      xtermRef.current.loadAddon(fitAddonRef.current)
      xtermRef.current.loadAddon(new WebLinksAddon())

      // Open terminal
      xtermRef.current.open(terminalRef.current)
      fitAddonRef.current.fit()

      // Handle input
      xtermRef.current.onData((data) => {
        if (socket && isConnected) {
          socket.emit('terminal:input', { id: terminalId, data })
        } else {
          // Fallback to simple command execution
          handleLocalInput(data)
        }
      })

      // Handle paste
      xtermRef.current.onPaste((data) => {
        if (socket && isConnected) {
          socket.emit('terminal:input', { id: terminalId, data })
        }
      })

      // Handle resize
      const resizeObserver = new ResizeObserver(() => {
        if (fitAddonRef.current) {
          fitAddonRef.current.fit()
          if (socket && isConnected) {
            const { cols, rows } = xtermRef.current
            socket.emit('terminal:resize', { id: terminalId, cols, rows })
          }
        }
      })
      resizeObserver.observe(terminalRef.current)

      // Welcome message
      xtermRef.current.writeln('🚀 FreeAI IDE Terminal')
      xtermRef.current.writeln('Type commands or use natural language - AI will help!')
      xtermRef.current.writeln('')
      xtermRef.current.write('$ ')

      return () => {
        resizeObserver.disconnect()
        if (xtermRef.current) {
          xtermRef.current.dispose()
          xtermRef.current = null
        }
      }
    }
  }, [])

  useEffect(() => {
    if (socket) {
      // Create terminal on server
      socket.emit('terminal:create', { id: terminalId, cwd: workspaceDir })

      // Listen for terminal events
      socket.on('terminal:created', ({ id }) => {
        if (id === terminalId) {
          setIsConnected(true)
        }
      })

      socket.on('terminal:data', ({ id, data }) => {
        if (id === terminalId && xtermRef.current) {
          xtermRef.current.write(data)
        }
      })

      socket.on('terminal:exit', ({ id }) => {
        if (id === terminalId) {
          setIsConnected(false)
          if (xtermRef.current) {
            xtermRef.current.writeln('\r\n\x1b[31mTerminal session ended\x1b[0m')
            xtermRef.current.write('$ ')
          }
        }
      })

      socket.on('terminal:error', ({ id, error }) => {
        if (id === terminalId && xtermRef.current) {
          xtermRef.current.writeln(`\r\n\x1b[31mError: ${error}\x1b[0m`)
          xtermRef.current.write('$ ')
        }
      })

      return () => {
        socket.emit('terminal:destroy', { id: terminalId })
        socket.off('terminal:created')
        socket.off('terminal:data')
        socket.off('terminal:exit')
        socket.off('terminal:error')
      }
    }
  }, [socket, terminalId, workspaceDir])

  const handleLocalInput = (data) => {
    const char = data.charCodeAt(0)
    
    if (char === 13) { // Enter key
      handleCommand()
    } else if (char === 127) { // Backspace
      if (currentCommand.length > 0) {
        setCurrentCommand(prev => prev.slice(0, -1))
        xtermRef.current.write('\b \b')
      }
    } else if (char === 27) { // Escape sequences (arrow keys)
      // Handle arrow keys for command history
      if (data === '\x1b[A') { // Up arrow
        navigateHistory(-1)
      } else if (data === '\x1b[B') { // Down arrow
        navigateHistory(1)
      }
    } else if (char >= 32 && char <= 126) { // Printable characters
      setCurrentCommand(prev => prev + data)
      xtermRef.current.write(data)
    }
  }

  const handleCommand = async () => {
    const command = currentCommand.trim()
    
    if (!command) {
      xtermRef.current.writeln('')
      xtermRef.current.write('$ ')
      return
    }

    // Add to history
    setCommandHistory(prev => [...prev, command])
    setHistoryIndex(-1)
    
    xtermRef.current.writeln('')

    try {
      // Check if it's a natural language command
      if (isNaturalLanguage(command)) {
        xtermRef.current.writeln(`\x1b[33mAI interpreting: "${command}"\x1b[0m`)
        const aiCommand = await convertToCommand(command)
        xtermRef.current.writeln(`\x1b[36mSuggested command: ${aiCommand}\x1b[0m`)
        
        // Execute the AI-suggested command
        const result = await onCommandRun(aiCommand, workspaceDir)
        displayCommandResult(result)
      } else {
        // Execute command directly
        const result = await onCommandRun(command, workspaceDir)
        displayCommandResult(result)
      }
    } catch (error) {
      xtermRef.current.writeln(`\x1b[31mError: ${error.message}\x1b[0m`)
    }

    setCurrentCommand('')
    xtermRef.current.write('$ ')
  }

  const displayCommandResult = (result) => {
    if (result.stdout) {
      xtermRef.current.writeln(result.stdout)
    }
    if (result.stderr) {
      xtermRef.current.writeln(`\x1b[31m${result.stderr}\x1b[0m`)
    }
    if (!result.success && !result.stderr) {
      xtermRef.current.writeln(`\x1b[31mCommand failed with exit code: ${result.exitCode}\x1b[0m`)
    }
  }

  const isNaturalLanguage = (command) => {
    const naturalIndicators = [
      'install', 'create', 'build', 'run', 'start', 'stop', 
      'list', 'show', 'make', 'generate', 'add', 'remove',
      'update', 'upgrade', 'check', 'test', 'deploy'
    ]
    
    const hasSpaces = command.includes(' ')
    const hasNaturalWords = naturalIndicators.some(word => 
      command.toLowerCase().includes(word)
    )
    const isNotCommand = !command.startsWith('./') && 
                        !command.startsWith('/') &&
                        !command.includes('&&') &&
                        !command.includes('||')
    
    return hasSpaces && hasNaturalWords && isNotCommand
  }

  const convertToCommand = async (naturalLanguage) => {
    try {
      const response = await fetch('https://js.puter.com/v2/ai/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          model: 'claude-sonnet-4',
          messages: [{
            role: 'user',
            content: `Convert this natural language request to a terminal command. Only respond with the command, no explanation:

Request: "${naturalLanguage}"

Context: Working in a development environment with Node.js, Python, Git available.`
          }]
        })
      })
      
      if (response.ok) {
        const data = await response.json()
        return data.choices?.[0]?.message?.content?.trim() || naturalLanguage
      }
    } catch (error) {
      console.error('AI command conversion failed:', error)
    }
    
    return naturalLanguage
  }

  const navigateHistory = (direction) => {
    if (commandHistory.length === 0) return

    let newIndex = historyIndex + direction
    
    if (newIndex < -1) newIndex = -1
    if (newIndex >= commandHistory.length) newIndex = commandHistory.length - 1

    setHistoryIndex(newIndex)

    // Clear current line
    xtermRef.current.write('\r$ ')
    xtermRef.current.write(' '.repeat(currentCommand.length))
    xtermRef.current.write('\r$ ')

    if (newIndex === -1) {
      setCurrentCommand('')
    } else {
      const command = commandHistory[commandHistory.length - 1 - newIndex]
      setCurrentCommand(command)
      xtermRef.current.write(command)
    }
  }

  const clearTerminal = () => {
    if (xtermRef.current) {
      xtermRef.current.clear()
      xtermRef.current.write('$ ')
    }
  }

  const runQuickCommand = async (command) => {
    xtermRef.current.writeln(`$ ${command}`)
    const result = await onCommandRun(command, workspaceDir)
    displayCommandResult(result)
    xtermRef.current.write('$ ')
  }

  return (
    <div className="terminal-container">
      <div className="terminal-header">
        <div className="terminal-title">
          <span>🖥️ Terminal</span>
          <span className={`connection-status ${isConnected ? 'connected' : 'disconnected'}`}>
            {isConnected ? '●' : '○'}
          </span>
        </div>
        
        <div className="terminal-actions">
          <button 
            className="terminal-action-btn"
            onClick={clearTerminal}
            title="Clear Terminal"
          >
            🗑️
          </button>
          
          <div className="quick-commands">
            <button 
              className="quick-cmd-btn"
              onClick={() => runQuickCommand('npm install')}
              title="npm install"
            >
              📦
            </button>
            <button 
              className="quick-cmd-btn"
              onClick={() => runQuickCommand('npm start')}
              title="npm start"
            >
              ▶️
            </button>
            <button 
              className="quick-cmd-btn"
              onClick={() => runQuickCommand('git status')}
              title="git status"
            >
              📋
            </button>
          </div>
          
          <button 
            className="terminal-action-btn close-btn"
            onClick={onClose}
            title="Close Terminal"
          >
            ✕
          </button>
        </div>
      </div>
      
      <div className="terminal-content">
        <div ref={terminalRef} className="xterm-container" />
      </div>
      
      <div className="terminal-footer">
        <div className="terminal-info">
          <span>Working Directory: {workspaceDir}</span>
          {commandHistory.length > 0 && (
            <span>Commands: {commandHistory.length}</span>
          )}
        </div>
        <div className="terminal-hints">
          💡 Try natural language: "install react", "run tests", "check git status"
        </div>
      </div>
    </div>
  )
}

export default Terminal