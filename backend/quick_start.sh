#!/bin/bash

# ViruScan AI Quick Start Script
# This script automates the setup process

echo "🚀 ViruScan AI - Quick Start Setup"
echo "=================================="
echo ""

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo -e "${RED}❌ Docker is not installed${NC}"
    echo "Please install Docker first: https://docs.docker.com/get-docker/"
    exit 1
fi

# Check if Docker Compose is installed
if ! command -v docker-compose &> /dev/null; then
    echo -e "${RED}❌ Docker Compose is not installed${NC}"
    echo "Please install Docker Compose first"
    exit 1
fi

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}❌ Python 3 is not installed${NC}"
    echo "Please install Python 3.11 or later"
    exit 1
fi

echo -e "${GREEN}✓${NC} All prerequisites found"
echo ""

# Step 1: Start Database
echo "📦 Step 1: Starting PostgreSQL database..."
docker-compose up -d db

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓${NC} Database container started"
else
    echo -e "${RED}❌ Failed to start database${NC}"
    exit 1
fi

echo "⏳ Waiting for database to be ready (15 seconds)..."
sleep 15

# Step 2: Install Dependencies
echo ""
echo "📚 Step 2: Installing Python dependencies..."

# Check if venv exists
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

# Activate venv
source venv/bin/activate

# Install requirements
pip install -q -r requirements.txt

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓${NC} Dependencies installed"
else
    echo -e "${RED}❌ Failed to install dependencies${NC}"
    exit 1
fi

# Step 3: Setup Database
echo ""
echo "🗄️  Step 3: Setting up database..."

export FLASK_APP=app.py
export DATABASE_URL="postgresql://viruscan_user:viruscan_pass_2024@localhost:5432/viruscan_db"

# Initialize migrations if not exists
if [ ! -d "migrations" ]; then
    echo "Initializing database migrations..."
    flask db init
fi

# Create migration
echo "Creating migration..."
flask db migrate -m "Initial migration" 2>/dev/null || true

# Apply migration
echo "Applying migration..."
flask db upgrade

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓${NC} Database setup complete"
else
    echo -e "${RED}❌ Database setup failed${NC}"
    exit 1
fi

# Step 4: Create Admin User
echo ""
echo "👤 Step 4: Creating admin user..."
python create_admin.py

# Step 5: Start Backend
echo ""
echo "🎯 Step 5: Starting backend server..."
echo ""
echo -e "${YELLOW}Backend will start on http://127.0.0.1:8000${NC}"
echo ""
echo "=================================="
echo "🎉 Setup Complete!"
echo "=================================="
echo ""
echo "📝 Next steps:"
echo "1. Backend is starting now"
echo "2. Open index.html in your browser"
echo "3. Test regular user signup"
echo "4. Test admin login with:"
echo "   Email: admin@viruscan.com"
echo "   Password: admin123"
echo ""
echo "⚠️  Remember to change admin password!"
echo ""
echo "Press Ctrl+C to stop the server"
echo "=================================="
echo ""

# Start Flask app
python app.py