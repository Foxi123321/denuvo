export interface FileItem {
  name: string
  path: string
  type: 'file' | 'directory'
  size?: number
  modified?: Date
  children?: FileItem[]
}

export interface FileContent {
  content: string
  language?: string
}

export interface GitStatus {
  branch: string
  staged: string[]
  unstaged: string[]
  untracked: string[]
}

export interface SearchResult {
  file: string
  line: number
  content: string
}

export interface AIMessage {
  id: string
  role: 'user' | 'assistant'
  content: string
  timestamp: Date
}

export interface Theme {
  name: string
  displayName: string
  type: 'light' | 'dark'
}

export interface EditorSettings {
  fontSize: number
  tabSize: number
  wordWrap: boolean
  minimap: boolean
  lineNumbers: boolean
  theme: string
}