#!/bin/bash

echo "📦 Creating FreeAI IDE Release Package"
echo "====================================="

# Create a temporary directory for the release
mkdir -p freeai-ide-release

# Copy essential files
echo "📁 Copying files..."
cp index.html freeai-ide-release/
cp styles.css freeai-ide-release/
cp app.js freeai-ide-release/
cp demo.html freeai-ide-release/
cp README.md freeai-ide-release/
cp DEPLOY.md freeai-ide-release/
cp QUICK_SETUP.md freeai-ide-release/
cp package.json freeai-ide-release/

# Copy GitHub workflows
mkdir -p freeai-ide-release/.github/workflows/
cp .github/workflows/deploy.yml freeai-ide-release/.github/workflows/

# Create .gitignore
cat > freeai-ide-release/.gitignore << EOF
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

# Node modules
node_modules/

# Build outputs
dist/
build/

# Environment files
.env
.env.local
EOF

echo "✅ Release package created in 'freeai-ide-release/' directory"
echo ""
echo "📋 Files included:"
echo "   - index.html (Main IDE)"
echo "   - styles.css (Styling)"
echo "   - app.js (Functionality)" 
echo "   - demo.html (Demo page)"
echo "   - README.md (Documentation)"
echo "   - DEPLOY.md (Deployment guide)"
echo "   - QUICK_SETUP.md (Setup instructions)"
echo "   - package.json (Project config)"
echo "   - .github/workflows/deploy.yml (Auto-deployment)"
echo "   - .gitignore (Git ignore rules)"
echo ""
echo "🚀 Ready to upload to GitHub!"
echo ""
echo "Next steps:"
echo "1. Zip the 'freeai-ide-release' folder"
echo "2. Create new GitHub repository"
echo "3. Upload the files"
echo "4. Enable GitHub Pages"
echo "5. Your IDE will be live! 🎉"