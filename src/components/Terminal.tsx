import React, { useEffect, useRef, useState } from 'react'
import { Terminal as XTerm } from 'xterm'
import { FitAddon } from 'xterm-addon-fit'
import { WebLinksAddon } from 'xterm-addon-web-links'
import { useTheme } from '../contexts/ThemeContext'
import { X, Square, RotateCcw } from 'lucide-react'
import 'xterm/css/xterm.css'

export default function Terminal() {
  const { theme } = useTheme()
  const terminalRef = useRef<HTMLDivElement>(null)
  const xtermRef = useRef<XTerm | null>(null)
  const wsRef = useRef<WebSocket | null>(null)
  const fitAddonRef = useRef<FitAddon | null>(null)
  const [isConnected, setIsConnected] = useState(false)

  useEffect(() => {
    if (!terminalRef.current) return

    // Create terminal instance
    const terminal = new XTerm({
      cursorBlink: true,
      fontSize: 14,
      fontFamily: 'Menlo, Monaco, "Courier New", monospace',
      theme: {
        background: theme === 'dark' ? '#1e1e1e' : '#ffffff',
        foreground: theme === 'dark' ? '#d4d4d4' : '#000000',
        cursor: theme === 'dark' ? '#ffffff' : '#000000',
        selection: theme === 'dark' ? '#264f78' : '#c0c0c0',
        black: theme === 'dark' ? '#000000' : '#000000',
        red: theme === 'dark' ? '#cd3131' : '#cd3131',
        green: theme === 'dark' ? '#0dbc79' : '#00bc00',
        yellow: theme === 'dark' ? '#e5e510' : '#949800',
        blue: theme === 'dark' ? '#2472c8' : '#0451a5',
        magenta: theme === 'dark' ? '#bc3fbc' : '#bc05bc',
        cyan: theme === 'dark' ? '#11a8cd' : '#0598bc',
        white: theme === 'dark' ? '#e5e5e5' : '#555555',
        brightBlack: theme === 'dark' ? '#666666' : '#666666',
        brightRed: theme === 'dark' ? '#f14c4c' : '#cd3131',
        brightGreen: theme === 'dark' ? '#23d18b' : '#14ce14',
        brightYellow: theme === 'dark' ? '#f5f543' : '#b5ba00',
        brightBlue: theme === 'dark' ? '#3b8eea' : '#0451a5',
        brightMagenta: theme === 'dark' ? '#d670d6' : '#bc05bc',
        brightCyan: theme === 'dark' ? '#29b8db' : '#0598bc',
        brightWhite: theme === 'dark' ? '#e5e5e5' : '#a5a5a5',
      },
    })

    // Add addons
    const fitAddon = new FitAddon()
    const webLinksAddon = new WebLinksAddon()
    
    terminal.loadAddon(fitAddon)
    terminal.loadAddon(webLinksAddon)
    
    // Open terminal
    terminal.open(terminalRef.current)
    
    // Store references
    xtermRef.current = terminal
    fitAddonRef.current = fitAddon
    
    // Fit terminal to container
    fitAddon.fit()
    
    // Connect to WebSocket
    connectWebSocket()
    
    // Handle resize
    const handleResize = () => {
      fitAddon.fit()
    }
    
    window.addEventListener('resize', handleResize)
    
    return () => {
      terminal.dispose()
      wsRef.current?.close()
      window.removeEventListener('resize', handleResize)
    }
  }, [theme])

  const connectWebSocket = () => {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    const ws = new WebSocket(`${protocol}//${window.location.host}/api/terminal`)
    
    wsRef.current = ws
    
    ws.onopen = () => {
      setIsConnected(true)
      if (xtermRef.current) {
        xtermRef.current.writeln('Terminal connected. Type commands below:')
        xtermRef.current.writeln('')
        
        // Handle terminal input
        xtermRef.current.onData((data) => {
          ws.send(data)
        })
      }
    }
    
    ws.onmessage = (event) => {
      if (xtermRef.current) {
        xtermRef.current.write(event.data)
      }
    }
    
    ws.onclose = () => {
      setIsConnected(false)
      if (xtermRef.current) {
        xtermRef.current.writeln('\r\nConnection lost. Click reconnect to restore connection.')
      }
    }
    
    ws.onerror = (error) => {
      console.error('Terminal WebSocket error:', error)
      setIsConnected(false)
    }
  }

  const clearTerminal = () => {
    if (xtermRef.current) {
      xtermRef.current.clear()
    }
  }

  const reconnect = () => {
    wsRef.current?.close()
    connectWebSocket()
  }

  const kill = () => {
    if (wsRef.current) {
      wsRef.current.send('\x03') // Send Ctrl+C
    }
  }

  useEffect(() => {
    // Fit terminal when container size changes
    const resizeObserver = new ResizeObserver(() => {
      if (fitAddonRef.current) {
        fitAddonRef.current.fit()
      }
    })
    
    if (terminalRef.current) {
      resizeObserver.observe(terminalRef.current)
    }
    
    return () => {
      resizeObserver.disconnect()
    }
  }, [])

  return (
    <div className="h-full flex flex-col bg-card">
      {/* Terminal Header */}
      <div className="flex items-center justify-between p-2 border-b border-border bg-muted/30">
        <div className="flex items-center space-x-2">
          <h3 className="font-medium text-sm">Terminal</h3>
          <div className={`w-2 h-2 rounded-full ${isConnected ? 'bg-green-500' : 'bg-red-500'}`} />
        </div>
        
        <div className="flex items-center space-x-1">
          <button
            onClick={clearTerminal}
            className="p-1.5 rounded hover:bg-muted text-muted-foreground hover:text-foreground"
            title="Clear Terminal"
          >
            <X className="h-4 w-4" />
          </button>
          
          <button
            onClick={kill}
            className="p-1.5 rounded hover:bg-muted text-muted-foreground hover:text-foreground"
            title="Kill Process (Ctrl+C)"
            disabled={!isConnected}
          >
            <Square className="h-4 w-4" />
          </button>
          
          <button
            onClick={reconnect}
            className="p-1.5 rounded hover:bg-muted text-muted-foreground hover:text-foreground"
            title="Reconnect"
          >
            <RotateCcw className="h-4 w-4" />
          </button>
        </div>
      </div>

      {/* Terminal Content */}
      <div 
        ref={terminalRef} 
        className="flex-1 p-2"
        style={{ minHeight: 0 }} // Important for proper scrolling
      />
    </div>
  )
}