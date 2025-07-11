# Advanced IDE

A modern, full-featured web-based IDE with authentication and all the features of Cursor, built with React, TypeScript, FastAPI, and Monaco Editor.

## ✨ Features

### 🔐 Authentication
- Secure JWT-based authentication
- User registration and login
- Protected routes and API endpoints

### 📁 File Management
- Full file explorer with tree view
- Create, edit, delete files and folders
- Real-time file watching
- Multiple file tabs

### 🖥️ Code Editor
- Monaco Editor (VS Code's editor engine)
- Syntax highlighting for 100+ languages
- IntelliSense and auto-completion
- Code formatting and linting
- Multiple themes (dark/light)
- Minimap and rulers
- Find and replace
- Keyboard shortcuts

### 🔍 Search & Navigation
- Global file search
- Content search with regex support
- File filtering and patterns
- Jump to line and symbol navigation

### 🤖 AI Assistant
- Integrated AI chat for code assistance
- Context-aware code suggestions
- Code explanation and debugging help
- Natural language to code conversion

### 📊 Git Integration
- Visual git status
- Stage and commit changes
- Branch management
- File diff viewing

### 💻 Integrated Terminal
- Full terminal access with WebSocket
- Multiple terminal instances
- Command history
- Customizable themes

### 🎨 UI/UX
- Modern, responsive design
- Dark/Light theme toggle
- Resizable panels
- Customizable layout
- Keyboard shortcuts

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- Node.js 16+
- Redis (for real-time features)
- Git

### Installation

1. **Clone the repository**
```bash
git clone <repository-url>
cd advanced-ide
```

2. **Run setup script**
```bash
chmod +x setup.sh
./setup.sh
```

3. **Start the IDE**
```bash
chmod +x start.sh
./start.sh
```

4. **Open in browser**
Navigate to http://localhost:3000

### Manual Setup

If you prefer manual setup:

**Backend:**
```bash
# Install Python dependencies
pip install -r requirements.txt

# Start Redis
redis-server

# Start backend
cd backend
python main.py
```

**Frontend:**
```bash
# Install Node dependencies
npm install

# Start development server
npm run dev
```

## 🛠️ Configuration

### Environment Variables

Copy `.env.example` to `.env` and configure:

```bash
cp .env.example .env
```

### AI Integration

To enable AI features, add your API keys to `.env`:
```
OPENAI_API_KEY=your-openai-api-key
# or
ANTHROPIC_API_KEY=your-anthropic-api-key
```

## 📖 Usage

### First Time Setup
1. Open http://localhost:3000
2. Create an account or sign in
3. Start coding!

### Keyboard Shortcuts
- `Ctrl/Cmd + S` - Save file
- `Ctrl/Cmd + /` - Toggle comment
- `Ctrl/Cmd + F` - Find in file
- `Ctrl/Cmd + Shift + F` - Global search
- `Ctrl/Cmd + Shift + P` - Command palette
- `Ctrl/Cmd + \`` - Toggle terminal

### File Operations
- Right-click in file explorer for context menu
- Drag and drop to move files
- Double-click to open files
- Use the + button to create new files/folders

### Git Workflow
1. Use the Git panel to see file changes
2. Select files to stage
3. Write commit message
4. Click Commit

## 🏗️ Architecture

### Frontend (React + TypeScript)
- **React 18** with hooks and context
- **TypeScript** for type safety
- **Tailwind CSS** for styling
- **Monaco Editor** for code editing
- **Vite** for fast development

### Backend (FastAPI + Python)
- **FastAPI** for high-performance API
- **JWT** authentication
- **WebSocket** for real-time features
- **SQLAlchemy** for database ORM
- **Redis** for caching and sessions

### Features Architecture
- **File System**: Direct file operations with security
- **Terminal**: WebSocket-based terminal emulation
- **Git**: GitPython for version control
- **AI**: Plugin architecture for different AI providers
- **Search**: Fast grep-based content search

## 🔧 Development

### Project Structure
```
├── backend/           # FastAPI backend
│   ├── main.py       # Main application
│   └── ...
├── src/              # React frontend
│   ├── components/   # React components
│   ├── contexts/     # React contexts
│   ├── types/        # TypeScript types
│   └── ...
├── package.json      # Frontend dependencies
├── requirements.txt  # Backend dependencies
└── README.md
```

### Adding New Features

**Backend endpoints:**
Add new routes in `backend/main.py`

**Frontend components:**
Add new components in `src/components/`

**Types:**
Add TypeScript interfaces in `src/types/`

### Building for Production

**Frontend:**
```bash
npm run build
```

**Backend:**
```bash
pip install gunicorn
gunicorn backend.main:app
```

## 🔒 Security

- JWT tokens for authentication
- CORS protection
- Input validation and sanitization
- File system access controls
- Environment variable protection

## 🚀 Deployment

### Docker (Recommended)

Create `Dockerfile`:
```dockerfile
FROM node:18 AS frontend
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
RUN npm run build

FROM python:3.9
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY backend/ ./backend/
COPY --from=frontend /app/dist ./static
EXPOSE 8000
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

### Cloud Platforms
- **Vercel/Netlify**: Frontend deployment
- **Railway/Heroku**: Full-stack deployment
- **AWS/GCP/Azure**: Production deployment

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

- Create an issue for bugs or feature requests
- Check existing issues for solutions
- Join our Discord community

## 🔮 Roadmap

- [ ] Plugin system for extensions
- [ ] Collaborative editing
- [ ] Docker integration
- [ ] More AI providers
- [ ] Mobile support
- [ ] Cloud file storage
- [ ] Advanced debugging tools

---

**Built with ❤️ for developers who want a powerful, modern IDE experience in the browser.**