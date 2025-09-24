# OWASP Security Lab - Docker Management Makefile

.PHONY: help build up down restart logs shell clean dev prod

# Default target
help: ## Show this help message
@echo "OWASP Security Lab - Docker Management"
@echo "======================================"
@echo ""
@echo "Available commands:"
@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# Development commands
dev: ## Start development environment
@echo "Starting development environment..."
docker-compose up -d
@echo "Development environment started!"
@echo "Access the application at:"
@echo "  - Main site: http://localhost"
@echo "  - PHP apps: http://localhost:8080"
@echo "  - Node.js API: http://localhost:5000"
@echo "  - Python server: http://localhost:8000"
@echo "  - Database admin: http://localhost:8081"

# Production commands
prod: ## Start production environment
@echo "Starting production environment..."
docker-compose up -d
@echo "Production environment started!"

# Basic Docker commands
build: ## Build all Docker images
@echo "Building Docker images..."
docker-compose build

up: ## Start all services
@echo "Starting all services..."
docker-compose up -d

down: ## Stop all services
@echo "Stopping all services..."
docker-compose down

restart: ## Restart all services
@echo "Restarting all services..."
docker-compose restart

# Logging commands
logs: ## Show logs for all services
docker-compose logs -f

logs-php: ## Show PHP service logs
docker-compose logs -f php-apache

logs-nodejs: ## Show Node.js service logs
docker-compose logs -f nodejs

logs-python: ## Show Python service logs
docker-compose logs -f python

logs-mysql: ## Show MySQL service logs
docker-compose logs -f mysql

logs-nginx: ## Show Nginx service logs
docker-compose logs -f nginx

# Shell access commands
shell-php: ## Access PHP container shell
docker-compose exec php-apache bash

shell-nodejs: ## Access Node.js container shell
docker-compose exec nodejs sh

shell-python: ## Access Python container shell
docker-compose exec python bash

shell-mysql: ## Access MySQL container shell
docker-compose exec mysql mysql -u root -p

# Database commands
db-reset: ## Reset database (WARNING: This will delete all data)
@echo "WARNING: This will delete all database data!"
@read -p "Are you sure? (y/N): " confirm && [ "$$confirm" = "y" ]
docker-compose down -v
docker-compose up -d mysql
sleep 10
docker-compose up -d

db-backup: ## Backup database
@echo "Creating database backup..."
docker-compose exec mysql mysqldump -u root -p$$MYSQL_ROOT_PASSWORD owasp_lab > backup_$$(date +%Y%m%d_%H%M%S).sql
@echo "Database backup created!"

# Cleanup commands
clean: ## Remove all containers, networks, and volumes
@echo "Cleaning up Docker resources..."
docker-compose down -v --remove-orphans
docker system prune -f

clean-images: ## Remove all Docker images
@echo "Removing all Docker images..."
docker-compose down --rmi all

# SSL commands
ssl-generate: ## Generate self-signed SSL certificates
@echo "Generating self-signed SSL certificates..."
mkdir -p ssl
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
-keyout ssl/key.pem \
-out ssl/cert.pem \
-subj "/C=US/ST=State/L=City/O=Organization/CN=localhost"
@echo "SSL certificates generated in ssl/ directory"

# Status commands
status: ## Show status of all services
@echo "Service Status:"
@echo "==============="
docker-compose ps

# Update commands
update: ## Pull latest images and rebuild
@echo "Updating Docker images..."
docker-compose pull
docker-compose build --no-cache

# Quick start for beginners
quickstart: build dev ## Quick start for beginners (build and start dev environment)
@echo ""
@echo "Ìæâ OWASP Security Lab is ready!"
@echo ""
@echo "Ì≥ö Learning Resources:"
@echo "  - Week 1: http://localhost/week1/"
@echo "  - Week 2: http://localhost/week2/"
@echo "  - Week 3: http://localhost/week3/"
@echo "  - Week 4: http://localhost/week4/"
@echo "  - Week 5: http://localhost/week5/"
@echo ""
@echo "Ìª†Ô∏è  Tools & Services:"
@echo "  - Database Admin: http://localhost:8081"
@echo "  - API Endpoints: http://localhost/api/"
@echo "  - Python Scripts: http://localhost:8000/"
@echo ""
@echo "Ì≥ñ Documentation:"
@echo "  - README.md for detailed instructions"
@echo "  - Each week folder contains specific guides"
@echo ""
@echo "‚ö†Ô∏è  Remember: This is for educational purposes only!"
