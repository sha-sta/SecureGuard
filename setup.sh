#!/bin/bash

# SecureGuard Setup Script
echo "🛡️  Setting up SecureGuard Email Scam Detection System"
echo "=================================================="

# Check if Python 3.8+ is installed
python_version=$(python3 --version 2>&1 | awk '{print $2}' | cut -d. -f1,2)
required_version="3.8"

if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is required but not installed"
    exit 1
fi

echo "✅ Python $python_version detected"

# Check if Node.js is installed for Chrome extension
if ! command -v node &> /dev/null; then
    echo "⚠️  Node.js not found - Chrome extension build will be skipped"
    node_available=false
else
    echo "✅ Node.js $(node --version) detected"
    node_available=true
fi

# Setup Python backend
echo ""
echo "📦 Setting up Python backend..."
cd backend

# Create virtual environment
if [ ! -d "venv" ]; then
    echo "Creating Python virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
source venv/bin/activate

# Install Python dependencies
echo "Installing Python dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

echo "✅ Python backend setup complete"

# Setup Chrome extension (if Node.js is available)
if [ "$node_available" = true ]; then
    echo ""
    echo "🔧 Setting up Chrome extension..."
    cd ../chrome-extension
    
    # Install Node.js dependencies
    if [ ! -d "node_modules" ]; then
        echo "Installing Node.js dependencies..."
        npm install
    fi
    
    # Build extension
    echo "Building Chrome extension..."
    npm run build
    
    echo "✅ Chrome extension setup complete"
    cd ..
else
    cd ..
fi

# Create environment file
echo ""
echo "⚙️  Creating configuration files..."

if [ ! -f "backend/.env" ]; then
    cp backend/env.example backend/.env
    echo "Created backend/.env - Please update with your API keys"
fi

# Set executable permissions
chmod +x backend/run_server.py
chmod +x setup.sh

echo ""
echo "🎉 Setup complete!"
echo ""
echo "Next steps:"
echo "1. Update backend/.env with your API keys (optional but recommended)"
echo "2. Start the backend server: cd backend && python run_server.py"
echo "3. Load the Chrome extension from chrome-extension/dist/"
echo ""
echo "API Keys (optional):"
echo "- VIRUSTOTAL_API_KEY: For malware detection"
echo "- GOOGLE_SAFE_BROWSING_API_KEY: For URL reputation"
echo "- GEMINI_API_KEY: For AI content analysis"
echo ""
echo "Documentation:"
echo "- Backend API: http://localhost:8000/docs (after starting server)"
echo "- Chrome Extension: Load unpacked from chrome-extension/dist/"
