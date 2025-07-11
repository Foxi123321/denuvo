const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const cors = require('cors');
const fs = require('fs-extra');
const path = require('path');
const { execa } = require('execa');
const chokidar = require('chokidar');
const mime = require('mime-types');
const pty = require('node-pty');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: "http://localhost:3000",
    methods: ["GET", "POST"]
  }
});

// Middleware
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.static('public'));

// Store active terminals and file watchers
const terminals = new Map();
const fileWatchers = new Map();

// File API Routes
app.get('/api/files', async (req, res) => {
  try {
    const { dir = process.cwd() } = req.query;
    const files = await fs.readdir(dir);
    const fileList = [];

    for (const file of files) {
      const filePath = path.join(dir, file);
      const stats = await fs.stat(filePath);
      
      fileList.push({
        name: file,
        path: filePath,
        isDirectory: stats.isDirectory(),
        size: stats.size,
        modified: stats.mtime,
        type: mime.lookup(file) || 'unknown'
      });
    }

    res.json(fileList);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/file/content', async (req, res) => {
  try {
    const { path: filePath } = req.query;
    const content = await fs.readFile(filePath, 'utf8');
    res.json({ content });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/file/save', async (req, res) => {
  try {
    const { path: filePath, content } = req.body;
    
    // Ensure directory exists
    await fs.ensureDir(path.dirname(filePath));
    await fs.writeFile(filePath, content, 'utf8');
    
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/file/create', async (req, res) => {
  try {
    const { path: filePath, content = '', isDirectory = false } = req.body;
    
    if (isDirectory) {
      await fs.ensureDir(filePath);
    } else {
      await fs.ensureDir(path.dirname(filePath));
      await fs.writeFile(filePath, content, 'utf8');
    }
    
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/file/delete', async (req, res) => {
  try {
    const { path: filePath } = req.body;
    await fs.remove(filePath);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Command execution
app.post('/api/command/run', async (req, res) => {
  try {
    const { command, cwd = process.cwd() } = req.body;
    
    const result = await execa(command, {
      shell: true,
      cwd,
      timeout: 30000
    });
    
    res.json({
      success: true,
      stdout: result.stdout,
      stderr: result.stderr,
      exitCode: result.exitCode
    });
  } catch (error) {
    res.json({
      success: false,
      stdout: error.stdout || '',
      stderr: error.stderr || error.message,
      exitCode: error.exitCode || 1
    });
  }
});

// Project templates
app.post('/api/project/create', async (req, res) => {
  try {
    const { name, template, path: projectPath } = req.body;
    const fullPath = path.join(projectPath || process.cwd(), name);
    
    await fs.ensureDir(fullPath);
    
    const templates = {
      react: {
        'package.json': JSON.stringify({
          name,
          version: '1.0.0',
          private: true,
          dependencies: {
            'react': '^18.2.0',
            'react-dom': '^18.2.0',
            'react-scripts': '5.0.1'
          },
          scripts: {
            start: 'react-scripts start',
            build: 'react-scripts build',
            test: 'react-scripts test',
            eject: 'react-scripts eject'
          }
        }, null, 2),
        'src/App.js': `import React from 'react';

function App() {
  return (
    <div className="App">
      <h1>Welcome to ${name}!</h1>
      <p>Built with FreeAI IDE</p>
    </div>
  );
}

export default App;`,
        'src/index.js': `import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';

const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(<App />);`,
        'public/index.html': `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>${name}</title>
</head>
<body>
    <div id="root"></div>
</body>
</html>`
      },
      
      node: {
        'package.json': JSON.stringify({
          name,
          version: '1.0.0',
          main: 'index.js',
          scripts: {
            start: 'node index.js',
            dev: 'nodemon index.js'
          },
          dependencies: {
            express: '^4.18.2',
            cors: '^2.8.5'
          },
          devDependencies: {
            nodemon: '^3.0.1'
          }
        }, null, 2),
        'index.js': `const express = require('express');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

app.get('/', (req, res) => {
  res.json({ message: 'Welcome to ${name} API!' });
});

app.listen(PORT, () => {
  console.log(\`Server running on port \${PORT}\`);
});`,
        'README.md': `# ${name}

A Node.js API built with FreeAI IDE.

## Getting Started

\`\`\`bash
npm install
npm run dev
\`\`\`
`
      },
      
      python: {
        'main.py': `#!/usr/bin/env python3
"""
${name} - A Python application built with FreeAI IDE
"""

def main():
    print("Welcome to ${name}!")
    print("Built with FreeAI IDE")

if __name__ == "__main__":
    main()`,
    
        'requirements.txt': `# Add your Python dependencies here
# Example:
# requests>=2.25.0
# flask>=2.0.0`,
        
        'README.md': `# ${name}

A Python application built with FreeAI IDE.

## Getting Started

\`\`\`bash
pip install -r requirements.txt
python main.py
\`\`\`
`
      }
    };
    
    const templateFiles = templates[template];
    if (!templateFiles) {
      return res.status(400).json({ error: 'Invalid template' });
    }
    
    for (const [filePath, content] of Object.entries(templateFiles)) {
      const fullFilePath = path.join(fullPath, filePath);
      await fs.ensureDir(path.dirname(fullFilePath));
      await fs.writeFile(fullFilePath, content, 'utf8');
    }
    
    res.json({ success: true, path: fullPath });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Socket.io for real-time features
io.on('connection', (socket) => {
  console.log('Client connected:', socket.id);
  
  // Terminal handling
  socket.on('terminal:create', ({ id, cwd = process.cwd() }) => {
    try {
      const shell = process.platform === 'win32' ? 'powershell.exe' : 'bash';
      const terminal = pty.spawn(shell, [], {
        name: 'xterm-color',
        cols: 80,
        rows: 30,
        cwd,
        env: process.env
      });
      
      terminals.set(id, terminal);
      
      terminal.on('data', (data) => {
        socket.emit('terminal:data', { id, data });
      });
      
      terminal.on('exit', () => {
        terminals.delete(id);
        socket.emit('terminal:exit', { id });
      });
      
      socket.emit('terminal:created', { id });
    } catch (error) {
      socket.emit('terminal:error', { id, error: error.message });
    }
  });
  
  socket.on('terminal:input', ({ id, data }) => {
    const terminal = terminals.get(id);
    if (terminal) {
      terminal.write(data);
    }
  });
  
  socket.on('terminal:resize', ({ id, cols, rows }) => {
    const terminal = terminals.get(id);
    if (terminal) {
      terminal.resize(cols, rows);
    }
  });
  
  socket.on('terminal:destroy', ({ id }) => {
    const terminal = terminals.get(id);
    if (terminal) {
      terminal.kill();
      terminals.delete(id);
    }
  });
  
  // File watching
  socket.on('files:watch', ({ path: watchPath }) => {
    if (fileWatchers.has(watchPath)) {
      return;
    }
    
    const watcher = chokidar.watch(watchPath, {
      ignored: /(^|[\/\\])\../, // ignore dotfiles
      persistent: true
    });
    
    watcher
      .on('add', path => socket.emit('file:added', { path }))
      .on('change', path => socket.emit('file:changed', { path }))
      .on('unlink', path => socket.emit('file:deleted', { path }))
      .on('addDir', path => socket.emit('dir:added', { path }))
      .on('unlinkDir', path => socket.emit('dir:deleted', { path }));
    
    fileWatchers.set(watchPath, watcher);
  });
  
  socket.on('files:unwatch', ({ path: watchPath }) => {
    const watcher = fileWatchers.get(watchPath);
    if (watcher) {
      watcher.close();
      fileWatchers.delete(watchPath);
    }
  });
  
  socket.on('disconnect', () => {
    console.log('Client disconnected:', socket.id);
    
    // Clean up terminals for this socket
    for (const [id, terminal] of terminals.entries()) {
      terminal.kill();
      terminals.delete(id);
    }
    
    // Clean up file watchers
    for (const [path, watcher] of fileWatchers.entries()) {
      watcher.close();
      fileWatchers.delete(path);
    }
  });
});

const PORT = process.env.PORT || 3001;
server.listen(PORT, () => {
  console.log(`🚀 FreeAI IDE Backend running on port ${PORT}`);
  console.log(`📁 Working directory: ${process.cwd()}`);
  console.log(`💻 Platform: ${process.platform}`);
});