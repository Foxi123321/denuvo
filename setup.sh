#!/bin/bash

echo "🚀 Setting up Advanced IDE..."

# Install Python dependencies
echo "📦 Installing Python dependencies..."
pip install -r requirements.txt

# Install Node.js dependencies  
echo "📦 Installing Node.js dependencies..."
npm install

# Add react-resizable (it's not in package.json but needed)
npm install react-resizable @types/react-resizable

# Create backend directory if it doesn't exist
mkdir -p backend

# Start Redis (needed for real-time features)
echo "🔴 Starting Redis..."
redis-server --daemonize yes

echo "✅ Setup complete!"
echo ""
echo "To start the IDE:"
echo "1. Start the backend: cd backend && python main.py"
echo "2. Start the frontend: npm run dev"
echo ""
echo "Then open http://localhost:3000 in your browser"