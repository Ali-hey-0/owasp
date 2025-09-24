#!/bin/bash

# OWASP Security Lab - Startup Script
echo "Ìª°Ô∏è OWASP Security Lab - Docker Setup"
echo "===================================="

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "‚ùå Docker is not running. Please start Docker first."
    exit 1
fi

# Check if Docker Compose is available
if ! command -v docker-compose &> /dev/null; then
    echo "‚ùå Docker Compose is not installed. Please install Docker Compose first."
    exit 1
fi

echo "‚úÖ Docker is running"
echo "‚úÖ Docker Compose is available"

# Create .env file if it doesn't exist
if [ ! -f .env ]; then
    echo "Ì≥ù Creating .env file from template..."
    cp .env.example .env
    echo "‚úÖ .env file created"
fi

# Generate SSL certificates if they don't exist
if [ ! -f ssl/cert.pem ] || [ ! -f ssl/key.pem ]; then
    echo "Ì¥ê Generating SSL certificates..."
    mkdir -p ssl
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout ssl/key.pem \
        -out ssl/cert.pem \
        -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost" 2>/dev/null
    echo "‚úÖ SSL certificates generated"
fi

# Build and start services
echo "ÌøóÔ∏è Building Docker images..."
docker-compose build

echo "Ì∫Ä Starting services..."
docker-compose up -d

# Wait for services to be ready
echo "‚è≥ Waiting for services to be ready..."
sleep 10

# Check service status
echo "Ì≥ä Service Status:"
docker-compose ps

echo ""
echo "Ìæâ OWASP Security Lab is ready!"
echo ""
echo "Ì≥ö Access Points:"
echo "  - Main Application: http://localhost"
echo "  - PHP Applications: http://localhost:8080"
echo "  - Node.js API: http://localhost:5000"
echo "  - Python Server: http://localhost:8000"
echo "  - Database Admin: http://localhost:8081"
echo ""
echo "Ì≥ñ Learning Resources:"
echo "  - Week 1: http://localhost/week1/"
echo "  - Week 2: http://localhost/week2/"
echo "  - Week 3: http://localhost/week3/"
echo "  - Week 4: http://localhost/week4/"
echo "  - Week 5: http://localhost/week5/"
echo ""
echo "Ìª†Ô∏è Management Commands:"
echo "  - View logs: docker-compose logs -f"
echo "  - Stop services: docker-compose down"
echo "  - Restart services: docker-compose restart"
echo "  - Check status: docker-compose ps"
echo ""
echo "‚ö†Ô∏è Remember: This lab is for educational purposes only!"
