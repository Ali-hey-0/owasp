#!/bin/bash

# OWASP Security Lab - Startup Script
echo "�️ OWASP Security Lab - Docker Setup"
echo "===================================="

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "❌ Docker is not running. Please start Docker first."
    exit 1
fi

# Check if Docker Compose is available
if ! command -v docker-compose &> /dev/null; then
    echo "❌ Docker Compose is not installed. Please install Docker Compose first."
    exit 1
fi

echo "✅ Docker is running"
echo "✅ Docker Compose is available"

# Create .env file if it doesn't exist
if [ ! -f .env ]; then
    echo "� Creating .env file from template..."
    cp .env.example .env
    echo "✅ .env file created"
fi

# Generate SSL certificates if they don't exist
if [ ! -f ssl/cert.pem ] || [ ! -f ssl/key.pem ]; then
    echo "� Generating SSL certificates..."
    mkdir -p ssl
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout ssl/key.pem \
        -out ssl/cert.pem \
        -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost" 2>/dev/null
    echo "✅ SSL certificates generated"
fi

# Build and start services
echo "�️ Building Docker images..."
docker-compose build

echo "� Starting services..."
docker-compose up -d

# Wait for services to be ready
echo "⏳ Waiting for services to be ready..."
sleep 10

# Check service status
echo "� Service Status:"
docker-compose ps

echo ""
echo "� OWASP Security Lab is ready!"
echo ""
echo "� Access Points:"
echo "  - Main Application: http://localhost"
echo "  - PHP Applications: http://localhost:8080"
echo "  - Node.js API: http://localhost:5000"
echo "  - Python Server: http://localhost:8000"
echo "  - Database Admin: http://localhost:8081"
echo ""
echo "� Learning Resources:"
echo "  - Week 1: http://localhost/week1/"
echo "  - Week 2: http://localhost/week2/"
echo "  - Week 3: http://localhost/week3/"
echo "  - Week 4: http://localhost/week4/"
echo "  - Week 5: http://localhost/week5/"
echo ""
echo "�️ Management Commands:"
echo "  - View logs: docker-compose logs -f"
echo "  - Stop services: docker-compose down"
echo "  - Restart services: docker-compose restart"
echo "  - Check status: docker-compose ps"
echo ""
echo "⚠️ Remember: This lab is for educational purposes only!"
