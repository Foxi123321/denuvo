import React, { useState, useEffect } from 'react'
import axios from 'axios'
import { Search, File, FileText, X, Filter } from 'lucide-react'
import { FileItem, SearchResult } from '../types'

interface SearchPanelProps {
  onFileSelect: (file: FileItem) => void
}

export default function SearchPanel({ onFileSelect }: SearchPanelProps) {
  const [query, setQuery] = useState('')
  const [searchType, setSearchType] = useState<'files' | 'content'>('files')
  const [fileResults, setFileResults] = useState<any[]>([])
  const [contentResults, setContentResults] = useState<SearchResult[]>([])
  const [loading, setLoading] = useState(false)
  const [includePattern, setIncludePattern] = useState('')
  const [excludePattern, setExcludePattern] = useState('')
  const [showFilters, setShowFilters] = useState(false)

  useEffect(() => {
    if (query.trim()) {
      const timeoutId = setTimeout(() => {
        performSearch()
      }, 300)
      return () => clearTimeout(timeoutId)
    } else {
      setFileResults([])
      setContentResults([])
    }
  }, [query, searchType, includePattern, excludePattern])

  const performSearch = async () => {
    if (!query.trim()) return
    
    setLoading(true)
    try {
      if (searchType === 'files') {
        const response = await axios.get('/search/files', {
          params: { query }
        })
        setFileResults(response.data.results)
      } else {
        const response = await axios.get('/search/content', {
          params: { 
            query,
            ...(includePattern && { include: includePattern }),
            ...(excludePattern && { exclude: excludePattern })
          }
        })
        setContentResults(response.data.results)
      }
    } catch (error) {
      console.error('Search failed:', error)
    } finally {
      setLoading(false)
    }
  }

  const handleFileClick = (filePath: string) => {
    const file: FileItem = {
      name: filePath.split('/').pop() || '',
      path: filePath,
      type: 'file'
    }
    onFileSelect(file)
  }

  const highlightMatch = (text: string, query: string) => {
    if (!query) return text
    
    const regex = new RegExp(`(${query.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')})`, 'gi')
    return text.replace(regex, '<mark class="search-highlight">$1</mark>')
  }

  const clearSearch = () => {
    setQuery('')
    setFileResults([])
    setContentResults([])
  }

  return (
    <div className="h-full flex flex-col bg-card">
      {/* Header */}
      <div className="p-3 border-b border-border">
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center space-x-2">
            <Search className="h-5 w-5" />
            <h3 className="font-medium text-sm">Search</h3>
          </div>
          <button
            onClick={() => setShowFilters(!showFilters)}
            className="p-1 rounded hover:bg-muted"
            title="Search Filters"
          >
            <Filter className="h-4 w-4" />
          </button>
        </div>

        {/* Search Input */}
        <div className="relative mb-3">
          <input
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search files and content..."
            className="w-full pl-3 pr-8 py-2 border border-input rounded-md bg-background text-foreground placeholder-muted-foreground focus:outline-none focus:ring-2 focus:ring-ring focus:border-transparent text-sm"
          />
          {query && (
            <button
              onClick={clearSearch}
              className="absolute right-2 top-1/2 transform -translate-y-1/2 p-1 rounded hover:bg-muted"
            >
              <X className="h-3 w-3" />
            </button>
          )}
        </div>

        {/* Search Type Toggle */}
        <div className="flex space-x-1 mb-3">
          <button
            onClick={() => setSearchType('files')}
            className={`px-3 py-1 text-xs rounded-md transition-colors ${
              searchType === 'files'
                ? 'bg-primary text-primary-foreground'
                : 'bg-muted text-muted-foreground hover:text-foreground'
            }`}
          >
            Files
          </button>
          <button
            onClick={() => setSearchType('content')}
            className={`px-3 py-1 text-xs rounded-md transition-colors ${
              searchType === 'content'
                ? 'bg-primary text-primary-foreground'
                : 'bg-muted text-muted-foreground hover:text-foreground'
            }`}
          >
            Content
          </button>
        </div>

        {/* Filters */}
        {showFilters && searchType === 'content' && (
          <div className="space-y-2 pt-3 border-t border-border">
            <div>
              <label className="block text-xs font-medium text-muted-foreground mb-1">
                Include Pattern
              </label>
              <input
                type="text"
                value={includePattern}
                onChange={(e) => setIncludePattern(e.target.value)}
                placeholder="*.ts,*.js,*.tsx"
                className="w-full px-2 py-1 border border-input rounded text-xs bg-background"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-muted-foreground mb-1">
                Exclude Pattern
              </label>
              <input
                type="text"
                value={excludePattern}
                onChange={(e) => setExcludePattern(e.target.value)}
                placeholder="node_modules,*.min.js"
                className="w-full px-2 py-1 border border-input rounded text-xs bg-background"
              />
            </div>
          </div>
        )}
      </div>

      {/* Results */}
      <div className="flex-1 overflow-auto">
        {loading ? (
          <div className="flex items-center justify-center py-8">
            <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-primary" />
          </div>
        ) : (
          <div className="p-2">
            {/* File Results */}
            {searchType === 'files' && fileResults.length > 0 && (
              <div className="space-y-1">
                <div className="text-xs font-medium text-muted-foreground px-2 py-1">
                  Files ({fileResults.length})
                </div>
                {fileResults.map((result, index) => (
                  <div
                    key={index}
                    onClick={() => handleFileClick(result.path)}
                    className="flex items-center space-x-2 p-2 rounded hover:bg-muted cursor-pointer text-sm"
                  >
                    <File className="h-4 w-4 text-blue-500 flex-shrink-0" />
                    <div className="flex-1 min-w-0">
                      <div 
                        className="truncate font-medium"
                        dangerouslySetInnerHTML={{ 
                          __html: highlightMatch(result.name, query) 
                        }}
                      />
                      <div className="text-xs text-muted-foreground truncate">
                        {result.path}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}

            {/* Content Results */}
            {searchType === 'content' && contentResults.length > 0 && (
              <div className="space-y-1">
                <div className="text-xs font-medium text-muted-foreground px-2 py-1">
                  Content ({contentResults.length})
                </div>
                {contentResults.map((result, index) => (
                  <div
                    key={index}
                    onClick={() => handleFileClick(result.file)}
                    className="p-2 rounded hover:bg-muted cursor-pointer text-sm border-l-2 border-primary/20"
                  >
                    <div className="flex items-center space-x-2 mb-1">
                      <FileText className="h-4 w-4 text-green-500 flex-shrink-0" />
                      <span className="font-medium truncate">{result.file}</span>
                      <span className="text-xs text-muted-foreground">
                        :{result.line}
                      </span>
                    </div>
                    <div 
                      className="text-xs text-muted-foreground ml-6 font-mono"
                      dangerouslySetInnerHTML={{ 
                        __html: highlightMatch(result.content.trim(), query) 
                      }}
                    />
                  </div>
                ))}
              </div>
            )}

            {/* No Results */}
            {query && !loading && (
              (searchType === 'files' && fileResults.length === 0) ||
              (searchType === 'content' && contentResults.length === 0)
            ) && (
              <div className="flex items-center justify-center py-8 text-muted-foreground">
                <div className="text-center">
                  <Search className="h-8 w-8 mx-auto mb-2 opacity-50" />
                  <p className="text-sm">No results found</p>
                  <p className="text-xs mt-1">Try adjusting your search terms</p>
                </div>
              </div>
            )}

            {/* Empty State */}
            {!query && (
              <div className="flex items-center justify-center py-8 text-muted-foreground">
                <div className="text-center">
                  <Search className="h-8 w-8 mx-auto mb-2 opacity-50" />
                  <p className="text-sm">Search files and content</p>
                  <p className="text-xs mt-1">Enter a search term to get started</p>
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}