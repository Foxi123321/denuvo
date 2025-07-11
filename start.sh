#!/bin/bash

echo "🚀 Starting Advanced IDE..."

# Function to cleanup processes on exit
cleanup() {
    echo "🛑 Shutting down..."
    pkill -f "python.*main.py"
    pkill -f "npm.*dev"
    exit
}

# Set trap to cleanup on script exit
trap cleanup SIGINT SIGTERM

# Start backend in background
echo "🐍 Starting Python backend..."
cd backend && python main.py &
BACKEND_PID=$!

# Wait a moment for backend to start
sleep 3

# Start frontend in background
echo "⚛️ Starting React frontend..."
cd ..
npm run dev &
FRONTEND_PID=$!

echo "✅ IDE is starting up!"
echo "📝 Backend running on http://localhost:8000"
echo "🌐 Frontend running on http://localhost:3000"
echo ""
echo "Press Ctrl+C to stop both services"

# Wait for both processes
wait $BACKEND_PID $FRONTEND_PID