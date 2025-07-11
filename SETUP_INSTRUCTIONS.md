# 🚀 FreeAI IDE Setup Instructions

## Quick Start (Current Browser Version)

**For immediate use, just open `index.html` in your browser!** The AI authentication has been completely fixed.

1. Open `index.html` in any modern browser
2. Click "🔐 Sign in to Puter.com" when prompted
3. Sign in at puter.com (free account)
4. Come back and click "⚡ Test AI Connection"
5. Start coding with unlimited AI help!

---

## Professional Setup (React + Node.js)

For the full professional IDE experience with all the advanced features:

### Prerequisites
- Node.js 16+ installed
- Git (optional)

### Installation

```bash
# Install dependencies
npm install

# Start the development server
npm run dev
```

This will start:
- **Frontend (React)**: http://localhost:3000
- **Backend (Node.js)**: http://localhost:3001

### Features in Professional Version

#### 🎯 **Backend Features**
- **Real Terminal**: Actual shell access with xterm.js
- **File System**: Real file operations on your computer
- **Project Templates**: React, Node.js, Python project scaffolding
- **Command Execution**: Run npm, git, python commands
- **File Watching**: Auto-reload when files change

#### ⚛️ **Frontend Features**  
- **Monaco Editor**: Same editor as VS Code
- **Hot Reload**: Changes appear instantly
- **Professional UI**: Modern React components
- **Socket.io**: Real-time communication
- **Tailwind CSS**: Beautiful, responsive design

#### 🤖 **AI Features (Same as Browser Version)**
- **Unlimited AI**: Via puter.js authentication
- **Multiple Models**: Claude, GPT-4o, Llama 3.1
- **Code Generation**: Auto-create files from AI responses
- **Smart Completion**: Context-aware suggestions
- **Natural Language Terminal**: "install react" → `npm install react`

### Development Scripts

```bash
# Development (both frontend + backend)
npm run dev

# Frontend only
npm run client

# Backend only  
npm run server

# Build for production
npm run build

# Preview production build
npm run preview
```

### Project Structure

```
freeai-ide/
├── src/                     # React frontend
│   ├── components/
│   │   ├── Editor.jsx       # Monaco Editor
│   │   ├── Terminal.jsx     # xterm.js terminal
│   │   ├── Sidebar.jsx      # File explorer
│   │   ├── Chat.jsx         # AI chat
│   │   └── MenuBar.jsx      # Top menu
│   └── App.jsx              # Main app
├── backend/
│   └── server.js            # Express + Socket.io server
├── public/                  # Static assets
├── dist/                    # Built files (after npm run build)
└── package.json
```

### Optional: Desktop App (Tauri)

To build a native desktop app:

```bash
# Install Tauri CLI
npm install -g @tauri-apps/cli

# Run in desktop mode
npm run tauri:dev

# Build desktop app
npm run tauri:build
```

This creates a native desktop application for Windows, Mac, or Linux.

---

## 🎯 **Which Version Should You Use?**

### **Browser Version (Current)**
✅ **Use if you want:**
- Immediate setup (just open HTML file)
- Simple AI coding assistance  
- File management in browser
- No installation required

### **Professional Version (React + Node.js)**
✅ **Use if you want:**
- Real terminal access
- Actual file system operations
- Project scaffolding
- Professional development environment
- Desktop app capability

### **Recommendation**
- **Start with Browser Version** to test AI features
- **Upgrade to Professional** when you need real terminal/file access

Both versions have the same AI capabilities and authentication system! 🎉