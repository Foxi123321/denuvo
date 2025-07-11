import React from 'react'
import { useAuth } from '../contexts/AuthContext'
import { useTheme } from '../contexts/ThemeContext'
import { 
  Code, 
  Search, 
  GitBranch, 
  Bot, 
  Terminal, 
  Sun, 
  Moon, 
  User, 
  LogOut,
  Files
} from 'lucide-react'

interface HeaderProps {
  activePanel: 'files' | 'search' | 'git' | 'ai'
  setActivePanel: (panel: 'files' | 'search' | 'git' | 'ai') => void
  showTerminal: boolean
  setShowTerminal: (show: boolean) => void
}

export default function Header({ 
  activePanel, 
  setActivePanel, 
  showTerminal, 
  setShowTerminal 
}: HeaderProps) {
  const { user, logout } = useAuth()
  const { theme, toggleTheme } = useTheme()

  const navItems = [
    { id: 'files' as const, icon: Files, label: 'Explorer' },
    { id: 'search' as const, icon: Search, label: 'Search' },
    { id: 'git' as const, icon: GitBranch, label: 'Git' },
    { id: 'ai' as const, icon: Bot, label: 'AI Assistant' },
  ]

  return (
    <header className="h-12 bg-card border-b border-border flex items-center justify-between px-4">
      {/* Logo and Navigation */}
      <div className="flex items-center space-x-4">
        <div className="flex items-center space-x-2">
          <Code className="h-6 w-6 text-primary" />
          <span className="font-bold text-lg">Advanced IDE</span>
        </div>
        
        <nav className="flex items-center space-x-1">
          {navItems.map((item) => {
            const Icon = item.icon
            return (
              <button
                key={item.id}
                onClick={() => setActivePanel(item.id)}
                className={`flex items-center space-x-1 px-3 py-1.5 rounded-md text-sm font-medium transition-colors ${
                  activePanel === item.id
                    ? 'bg-primary text-primary-foreground'
                    : 'text-muted-foreground hover:text-foreground hover:bg-muted'
                }`}
              >
                <Icon className="h-4 w-4" />
                <span className="hidden sm:inline">{item.label}</span>
              </button>
            )
          })}
        </nav>
      </div>

      {/* Right Side Controls */}
      <div className="flex items-center space-x-2">
        {/* Terminal Toggle */}
        <button
          onClick={() => setShowTerminal(!showTerminal)}
          className={`p-2 rounded-md transition-colors ${
            showTerminal
              ? 'bg-primary text-primary-foreground'
              : 'text-muted-foreground hover:text-foreground hover:bg-muted'
          }`}
          title="Toggle Terminal"
        >
          <Terminal className="h-4 w-4" />
        </button>

        {/* Theme Toggle */}
        <button
          onClick={toggleTheme}
          className="p-2 rounded-md text-muted-foreground hover:text-foreground hover:bg-muted transition-colors"
          title={`Switch to ${theme === 'light' ? 'dark' : 'light'} mode`}
        >
          {theme === 'light' ? <Moon className="h-4 w-4" /> : <Sun className="h-4 w-4" />}
        </button>

        {/* User Menu */}
        <div className="flex items-center space-x-2">
          <div className="flex items-center space-x-1 text-sm">
            <User className="h-4 w-4" />
            <span className="hidden sm:inline">{user?.username}</span>
          </div>
          
          <button
            onClick={logout}
            className="p-2 rounded-md text-muted-foreground hover:text-foreground hover:bg-muted transition-colors"
            title="Logout"
          >
            <LogOut className="h-4 w-4" />
          </button>
        </div>
      </div>
    </header>
  )
}