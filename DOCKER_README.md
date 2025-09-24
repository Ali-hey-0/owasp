# Ì∞≥ OWASP Security Lab - Docker Setup

This document provides comprehensive instructions for running the OWASP Security Lab using Docker containers.

## Ì≥ã Prerequisites

- Docker Engine 20.10+
- Docker Compose 2.0+
- Git
- Make (optional, for using Makefile commands)

## Ì∫Ä Quick Start

### Option 1: Using Makefile (Recommended)

```bash
# Clone the repository
git clone https://github.com/Ali-hey-0/owasp.git
cd owasp

# Quick start (build and run everything)
make quickstart
```

### Option 2: Using Docker Compose Directly

```bash
# Clone the repository
git clone https://github.com/Ali-hey-0/owasp.git
cd owasp

# Build and start all services
docker-compose up -d

# Check status
docker-compose ps
```

## ÌøóÔ∏è Architecture Overview

The Docker setup includes the following services:

| Service | Port | Description |
|---------|------|-------------|
| **nginx** | 80, 443 | Reverse proxy and load balancer |
| **php-apache** | 8080 | PHP applications and HTML files |
| **nodejs** | 5000 | Node.js API server |
| **python** | 8000 | Python HTTP server |
| **mysql** | 3306 | MySQL database |
| **redis** | 6379 | Redis cache and session storage |
| **adminer** | 8081 | Database administration tool |

## Ì≥Å File Structure

```
owasp/
‚îú‚îÄ‚îÄ Dockerfile.php         # PHP/Apache container
‚îú‚îÄ‚îÄ Dockerfile.nodejs       # Node.js container
‚îú‚îÄ‚îÄ Dockerfile.python       # Python container
‚îú‚îÄ‚îÄ docker-compose.yml      # Main compose configuration
‚îú‚îÄ‚îÄ nginx.conf              # Nginx configuration
‚îú‚îÄ‚îÄ package.json            # Node.js dependencies
‚îú‚îÄ‚îÄ requirements.txt       # Python dependencies
‚îú‚îÄ‚îÄ .env.example           # Environment variables template
‚îú‚îÄ‚îÄ .dockerignore          # Docker ignore file
‚îú‚îÄ‚îÄ Makefile               # Management commands
‚îú‚îÄ‚îÄ database-init/         # Database initialization scripts
‚îÇ   ‚îî‚îÄ‚îÄ 01-init.sql       # Sample data and tables
‚îî‚îÄ‚îÄ ssl/                   # SSL certificates (generated)
```

## Ìª†Ô∏è Available Commands

### Using Makefile

```bash
# Show all available commands
make help

# Development
make dev              # Start development environment
make build            # Build all Docker images
make up               # Start all services
make down             # Stop all services
make restart          # Restart all services

# Logging
make logs             # Show all logs
make logs-php         # Show PHP logs
make logs-nodejs      # Show Node.js logs
make logs-python      # Show Python logs
make logs-mysql       # Show MySQL logs
make logs-nginx       # Show Nginx logs

# Shell Access
make shell-php        # Access PHP container
make shell-nodejs     # Access Node.js container
make shell-python     # Access Python container
make shell-mysql      # Access MySQL container

# Database Management
make db-backup        # Backup database
make db-reset         # Reset database (WARNING: deletes data)

# Maintenance
make clean            # Clean up Docker resources
make ssl-generate     # Generate SSL certificates
make status           # Show service status
make update           # Update images and rebuild
```

### Using Docker Compose Directly

```bash
# Basic operations
docker-compose up -d                    # Start services
docker-compose down                     # Stop services
docker-compose restart                  # Restart services
docker-compose ps                       # Show status
docker-compose logs -f                  # Show logs

# Build and rebuild
docker-compose build                    # Build images
docker-compose build --no-cache         # Rebuild without cache

# Individual services
docker-compose up -d php-apache         # Start only PHP service
docker-compose logs -f nodejs           # Show Node.js logs
docker-compose exec mysql bash          # Access MySQL container
```

## Ìºê Access Points

Once the services are running, you can access:

- **Main Application**: http://localhost
- **PHP Applications**: http://localhost:8080
- **Node.js API**: http://localhost:5000
- **Python Server**: http://localhost:8000
- **Database Admin**: http://localhost:8081

## Ì≥ö Learning Path Access

- **Week 1**: http://localhost/week1/
- **Week 2**: http://localhost/week2/
- **Week 3**: http://localhost/week3/
- **Week 4**: http://localhost/week4/
- **Week 5**: http://localhost/week5/

## Ì∑ÑÔ∏è Database Configuration

### Default Credentials

- **Host**: localhost:3306
- **Database**: owasp_lab
- **Username**: owasp_user
- **Password**: owasp_password
- **Root Password**: rootpassword

### Sample Data

The database is automatically initialized with sample data including:

- **Users**: admin, alice, bob, guest
- **Products**: Security books and courses
- **Orders**: Sample order data
- **Comments**: Test comments for XSS labs

### Database Management

Access the database through:

1. **Adminer**: http://localhost:8081
2. **Command Line**: `make shell-mysql`
3. **Direct Connection**: Use any MySQL client with the credentials above

## Ì¥ß Configuration

### Environment Variables

Copy `.env.example` to `.env` and modify as needed:

```bash
cp .env.example .env
```

Key variables:
- `MYSQL_ROOT_PASSWORD`: MySQL root password
- `MYSQL_DATABASE`: Database name
- `MYSQL_USER`: Database user
- `MYSQL_PASSWORD`: Database password
- `REDIS_PASSWORD`: Redis password
- `APP_ENV`: Application environment (development/production)

### SSL Configuration

Generate self-signed certificates for HTTPS:

```bash
make ssl-generate
```

This creates certificates in the `ssl/` directory.

## Ì∞õ Troubleshooting

### Common Issues

1. **Port Conflicts**
   ```bash
   # Check if ports are in use
   netstat -tulpn | grep :80
   netstat -tulpn | grep :3306
   
   # Stop conflicting services or change ports in docker-compose.yml
   ```

2. **Permission Issues**
   ```bash
   # Fix file permissions
   sudo chown -R $USER:$USER .
   chmod -R 755 .
   ```

3. **Database Connection Issues**
   ```bash
   # Check MySQL logs
   make logs-mysql
   
   # Restart MySQL service
   docker-compose restart mysql
   ```

4. **Container Build Failures**
   ```bash
   # Clean and rebuild
   make clean
   make build
   ```

### Logs and Debugging

```bash
# View all logs
make logs

# View specific service logs
make logs-php
make logs-nodejs
make logs-mysql

# Access container shell for debugging
make shell-php
make shell-nodejs
```

### Reset Everything

```bash
# Complete reset (WARNING: deletes all data)
make clean
make build
make dev
```

## Ì¥í Security Considerations

### Development Environment

- Default passwords are used for easy setup
- Debug mode is enabled
- All services are accessible from host

### Production Environment

For production deployment:

1. Change all default passwords
2. Use proper SSL certificates
3. Configure firewall rules
4. Enable proper logging
5. Use environment-specific configurations

```bash
# Production setup
cp .env.example .env
# Edit .env with production values
make prod
```

## Ì≥ä Monitoring and Maintenance

### Health Checks

```bash
# Check service status
make status

# Check individual service health
docker-compose ps
```

### Backup and Restore

```bash
# Backup database
make db-backup

# Restore from backup
docker-compose exec mysql mysql -u root -p owasp_lab < backup_file.sql
```

### Updates

```bash
# Update all images and rebuild
make update

# Update specific service
docker-compose pull mysql
docker-compose up -d mysql
```

## Ì¥ù Contributing

When contributing to the Docker setup:

1. Test your changes locally
2. Update documentation if needed
3. Ensure all services start correctly
4. Test the learning path functionality

## Ì≥û Support

If you encounter issues:

1. Check the logs: `make logs`
2. Verify service status: `make status`
3. Try a clean rebuild: `make clean && make build`
4. Check the GitHub issues page

## ‚ö†Ô∏è Educational Disclaimer

**IMPORTANT**: This lab is for educational purposes only. Use these techniques only on systems you own or have explicit permission to test.

---

**Happy Learning! Ìª°Ô∏è**
