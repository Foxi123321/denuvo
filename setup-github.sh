#!/bin/bash

echo "🚀 FreeAI IDE - GitHub Setup Script"
echo "=================================="

# Check if git is installed
if ! command -v git &> /dev/null; then
    echo "❌ Git is not installed. Please install Git first."
    exit 1
fi

echo "📁 Initializing Git repository..."
git init

echo "📝 Creating .gitignore..."
cat > .gitignore << EOF
# IDE files
.vscode/
.idea/

# OS files
.DS_Store
Thumbs.db

# Logs
*.log

# Temporary files
*.tmp
*.temp

# Node modules (if any)
node_modules/

# Build outputs
dist/
build/

# Environment files
.env
.env.local
EOF

echo "➕ Adding all files to Git..."
git add .

echo "💾 Creating initial commit..."
git commit -m "🎉 Initial commit - FreeAI IDE with unlimited AI assistance

Features:
- AI-powered code editor with multiple models (GPT-4o, Claude, Llama)
- Complete IDE experience in browser
- Project templates for React, Node.js, Python, Android
- Build system for web, desktop, and mobile apps
- Natural language terminal commands
- Unlimited free AI assistance via puter.js

Built with: HTML5, CSS3, JavaScript, CodeMirror, Puter.js"

echo ""
echo "✅ Git repository initialized successfully!"
echo ""
echo "🔗 Next steps:"
echo "1. Create a new repository on GitHub.com"
echo "2. Copy the repository URL"
echo "3. Run these commands:"
echo ""
echo "   git remote add origin https://github.com/YOUR_USERNAME/freeai-ide.git"
echo "   git branch -M main"
echo "   git push -u origin main"
echo ""
echo "4. Enable GitHub Pages in repository settings"
echo "5. Your IDE will be live at: https://YOUR_USERNAME.github.io/freeai-ide"
echo ""
echo "🎉 Happy coding with unlimited AI assistance!"