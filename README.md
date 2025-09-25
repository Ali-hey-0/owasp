---

# 🛡️ OWASP Security Training & Penetration Testing Lab

[![Security Focus](https://img.shields.io/badge/Focus-Web%20Security-red?style=for-the-badge)](https://owasp.org/)
[![Learning Path](https://img.shields.io/badge/Learning-7%20Weeks-blue?style=for-the-badge)](https://github.com/Ali-hey-0/owasp#learning-path-recommendations)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![Author](https://img.shields.io/badge/Author-Ali%20Heydari-purple?style=for-the-badge)](https://github.com/Ali-hey-0)

> **A comprehensive 7-week security training program covering the OWASP Top 10, real-world exploitation, and defensive strategies.**

## 📋 Overview

This repository is a hands-on, week-by-week learning path for web application security and penetration testing. Each week covers a major area of the OWASP Top 10, with practical scripts, labs, and documentation. The project is ideal for students, professionals, and anyone seeking to master web security.

## Table of Contents

- [Project Overview](#project-overview)
- [Features](#features)
- [Screenshots](#screenshots)
- [Folder Structure](#folder-structure)
- [Quick Start](#quick-start)
- [Setup &amp; Usage](#setup--usage)
- [Module Breakdown](#module-breakdown)
- [Contributing](#contributing)
- [License](#license)
- [References &amp; Further Reading](#references--further-reading)

---

## Project Overview

This repository provides:

- Step-by-step labs for common web vulnerabilities
- Scripts and code samples in Python, PHP, Node.js
- Dockerized environment for safe testing
- Weekly modules for progressive learning
- Nginx reverse proxy for multi-language labs

---

## Features

- OWASP Top 10 coverage
- Realistic attack scenarios (SQLi, XSS, CSRF, SSRF, RCE, etc.)
- Protocols, status codes, and security concepts explained
- Docker Compose for multi-language lab setup
- Nginx reverse proxy configuration
- Database initialization scripts
- Multi-language support: Python, Node.js, PHP
- Ready-to-run scripts and sample exploits

---

## Screenshots

> _Add screenshots or diagrams here to showcase the UI, lab structure, or workflow._

<p align="center">
	<img src="images/lab-screenshot.png" alt="Lab Screenshot" width="600" />
</p>

---

## Folder Structure

```text
├── basic/                # Web protocols, status codes, URL characters
├── database-init/        # SQL scripts for DB setup
├── ssl/                  # SSL/TLS related files
├── week1/ - week7/       # Weekly security modules
│   ├── command_injection/
│   ├── RCE/
│   ├── recon/
│   ├── SQL_Injection/
│   ├── SSTI/
│   └── ...
├── Dockerfile.*          # Dockerfiles for Python, Node.js, PHP
├── docker-compose.yml    # Multi-container orchestration
├── nginx.conf            # Nginx reverse proxy config
├── requirements.txt      # Python dependencies
├── package.json          # Node.js dependencies
├── Makefile              # Common build/run commands
├── start.sh              # Startup script
├── README.md             # Project documentation
```

---

## Quick Start

```bash
# Clone the repository
git clone https://github.com/Ali-hey-0/owasp.git
cd owasp

# Build and run with Docker Compose
docker-compose up --build

# Access labs at
open http://localhost:8080
```

---

## Setup & Usage

### Prerequisites

- [Docker](https://www.docker.com/get-started)
- [Docker Compose](https://docs.docker.com/compose/)
- Bash shell (for scripts)
- Python 3.x, Node.js, PHP (if running labs manually)

### Running with Docker Compose

```bash
docker-compose up --build
```

- Access web labs via [http://localhost:8080](http://localhost:8080) (default)
- Nginx routes traffic to language-specific containers

### Manual Setup (Optional)

Install dependencies:

- Python: `pip install -r requirements.txt`
- Node.js: `npm install`
- PHP: Use built-in server or configure as needed

Run scripts in `week*/` folders as described in module docs.

### Using the Makefile

Common commands:

```bash
make build      # Build Docker images
make up         # Start containers
make down       # Stop containers
make clean      # Remove containers/images
```

---

## Module Breakdown

- **basic/**: HTTP protocols, status codes, URL encoding, fundamentals
- **database-init/**: SQL scripts for initializing databases
- **ssl/**: SSL/TLS configuration and certificates
- **week1/**: Command Injection, RCE, Recon, SQL Injection, SSTI
- **week2/**: API Security, CORS, XSS, CSRF, DOM/BOM, Same Origin Policy
- **week3/**: Bypassing Protection, Open Redirect, Security Misconfig, SSRF
- **week4/**: Crypto, JWT, IDOR, Insecure Design, Nuclei
- **week5/**: Deserialization, XXE
- **week6/**: Authentication, Session, OAuth, SSO, Cookie vs Token, HTTP, JSONP
- **week7/**: API, Mass Assignment, Cache, Smuggling
- **nginx.conf**: Reverse proxy setup for multi-language labs
- **Dockerfile.*:** Language-specific Dockerfiles
- **Makefile:** Automation for build/run/clean

---

## Contributing

Contributions are welcome! To contribute:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature-name`)
3. Commit your changes with clear messages
4. Submit a pull request with a detailed description
5. Follow code style and add documentation where needed

Please check open issues before starting new work. For major changes, open an issue to discuss your proposal.

---

## Support & Contact

- For questions or issues, open an [issue](https://github.com/Ali-hey-0/owasp/issues) on GitHub
- Contact the maintainer via [GitHub profile](https://github.com/Ali-hey-0)

---

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

---

## References & Further Reading

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)
- [Docker Documentation](https://docs.docker.com/)
- [Nginx Documentation](https://nginx.org/en/docs/)
- [Awesome Security](https://github.com/sbilly/awesome-security)

---

_Happy hacking and learning!_
