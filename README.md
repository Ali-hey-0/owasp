
# 🛡️ OWASP Security Training & Penetration Testing Lab

[![Security Focus](https://img.shields.io/badge/Focus-Web%20Security-red?style=for-the-badge)](https://owasp.org/)
[![Learning Path](https://img.shields.io/badge/Learning-3%20Weeks-blue?style=for-the-badge)](#)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![Author](https://img.shields.io/badge/Author-Ali%20Heydari-purple?style=for-the-badge)](https://github.com/Ali-hey-0)

> **A comprehensive 7-week security training program covering OWASP Top 10 vulnerabilities, exploitation techniques, and defensive strategies.**

## 📋 Overview

This repository contains a structured, week-by-week learning path for web application security testing and penetration testing. Each week focuses on different aspects of cybersecurity, from basic injection attacks to advanced bypass techniques and security misconfigurations.

## 📁 Repository Structure

```
owasp/
├── 📂 week1/           # Foundation: Injection Attacks & Reconnaissance
├── 📂 week2/           # Client-Side: XSS, CORS, API Security  
├── 📂 week3/           # Advanced: Bypassing & Misconfigurations
├── 📂 week4/           # Cryptography, IDOR, Insecure Design, Nuclei
├── 📂 week5/           # Deserialization Attacks & Multi-language Exploits
└── 📄 README.md        # This file
```


## 🚀 Week 1: Foundation Security Testing

**Focus**: Server-side injection vulnerabilities and reconnaissance techniques

### 🔧 [`week1/command_injection/`](./week1/command_injection/)

- **`general.md`** - Introduction to OS Command Injection
- **`Data_Exfiltration.md`** - Techniques for data extraction via command injection
- **`Detection_phase.md`** - Methods to identify command injection vulnerabilities
- **`Out-of-Band.md`** - Out-of-band command injection techniques
- **`Reverse_Shell.md`** - Establishing reverse shells through command injection

### 💥 [`week1/RCE/`](./week1/RCE/)

- **`rce.md`** - Remote Code Execution vulnerabilities and exploitation

### 🔍 [`week1/recon/`](./week1/recon/)

- **`recon.sh`** - Advanced reconnaissance automation script (NSA-grade framework)
- **`recon1.sh`** - Alternative reconnaissance script

### 🗃️ [`week1/SQL_Injection/`](./week1/SQL_Injection/)

- **`sql.md`** - SQL Injection fundamentals and techniques
- **`blind_injection.md`** - Blind SQL injection methodology
- **`sqlmap.md`** - Automated SQL injection testing with SQLMap
- **`sample.py`** & **`sample2.py`** - Practical Python exploitation scripts
- **`image/sql/`** - Visual documentation and screenshots

### 🔧 [`week1/SSTI/`](./week1/SSTI/)

- **`ssti.md`** - Server-Side Template Injection vulnerabilities
- **`ssti.py`** - SSTI exploitation scripts
- **`tplmap.md`** - Automated SSTI testing with Tplmap

---

## 🌐 Week 2: Client-Side Security & API Testing

**Focus**: Client-side vulnerabilities, CORS misconfigurations, and API security

### 🔐 [`week2/API-SEC/`](./week2/API-SEC/)

- **`Cookies.md`** - HTTP Cookies security analysis and exploitation
- **`cookies.php`** - Practical cookie manipulation examples
- **`DOM&BOM.md`** - Document Object Model and Browser Object Model security
- **`csp.md`** - Content Security Policy analysis and bypasses
- **`csp.php`** - CSP implementation examples
- **`same_origin_policy.md`** - Same Origin Policy and its implications
- **`exam.html`** - Interactive security testing exercises

### 🌍 [`week2/COSRS/`](./week2/COSRS/) *(CORS)*

- **`cors.md`** - Cross-Origin Resource Sharing fundamentals
- **`cors_misconfiguration.md`** - Common CORS misconfigurations
- **`cross_origin_http_request.md`** - Cross-origin HTTP request analysis
- **`implementation.md`** - CORS implementation best practices
- **`checker_function.md`** - CORS validation techniques
- **`vulnerable_cors.md`** - Vulnerable CORS configurations
- **`cors.html`** - Interactive CORS testing

### ⚡ [`week2/XSS/`](./week2/XSS/)

- **`XSS.md`** - Cross-Site Scripting vulnerabilities and payloads
- **`CSRF.md`** - Cross-Site Request Forgery attacks and defenses

---

## 🔥 Week 3: Advanced Techniques & Security Misconfigurations

**Focus**: Protection bypassing, redirects, misconfigurations, and SSRF

### 🛡️ [`week3/bypassing Protection/`](./week3/bypassing%20Protection/)

- **`bypassing_Protection.md`** - Comprehensive guide to bypassing security controls
- **`javascript_exam.html`** - JavaScript security testing challenges
- **`php_exam.php`** - PHP security assessment exercises

### 🔀 [`week3/open Redirect/`](./week3/open%20Redirect/)

- **`open_redirect.md`** - Open redirect vulnerabilities and exploitation
- **`redirect_by_javascript.html`** - Client-side redirect examples
- **`redirect_by_python.py`** - Server-side redirect implementations

### ⚙️ [`week3/security misconfig/`](./week3/security%20misconfig/)

- **`README.md`** - Security misconfiguration overview
- **`default_credential.md`** - Default credential vulnerabilities
- **`ffuf.md`** - Web fuzzing with ffuf tool
- **`force_browsing.md`** - Forced browsing techniques
- **`s3_bucket.md`** - AWS S3 bucket security testing
- **`verb_tamper.md`** - HTTP verb tampering attacks

### 🌐 [`week3/ssrf/`](./week3/ssrf/)

- **`ssrf.md`** - Server-Side Request Forgery vulnerabilities and exploitation

---

## 🧩 Week 4: Cryptography, IDOR, Insecure Design & Nuclei

**Focus**: Cryptographic vulnerabilities, JWT, Insecure Direct Object References (IDOR), insecure design patterns, and automated vulnerability scanning with Nuclei.

### 🔒 [`week4/crypto/`](./week4/crypto/)

- **`crypto.md`** - Cryptography basics and common flaws
- **`crypto.php`** - Practical cryptography examples in PHP
- **`jwt.md`** - JSON Web Token vulnerabilities and exploitation

### 🔑 [`week4/idor/`](./week4/idor/)

- **`idor.md`** - Insecure Direct Object Reference vulnerabilities
- **`safe.php`** - Secure coding practices for IDOR

### 🏗️ [`week4/insecure design/`](./week4/insecure%20design/)

- **`insecure.md`** - Insecure design patterns and business logic errors
- **`business_logic_error.md`** - Real-world business logic flaws
- **`upload.md`** - Insecure file upload vulnerabilities

### ⚡ [`week4/nuclei/`](./week4/nuclei/)

- **`explain.md`** - Automated vulnerability scanning with Nuclei

---

## 🧬 Week 5: Deserialization Attacks & Multi-language Exploits

**Focus**: Insecure deserialization vulnerabilities across PHP, Python, and Node.js, with hands-on exploitation and automation.

### 🧩 [`week5/deserialization/`](./week5/deserialization/)

- **`insecure_serialization.md`** - Insecure serialization and deserialization concepts
- **`serialaztion_deserialazion.md`** - Serialization/deserialization attack techniques
- **`php.md`** - PHP deserialization vulnerabilities and exploitation

#### Language-specific Exploits

- **`nodejs/`** - Node.js deserialization attack scripts
- **`php/`** - PHP deserialization attack scripts and examples
- **`python/`** - Python deserialization attack scripts

---

## 🛠️ Tools & Technologies Featured

| Category                     | Tools                                         |
| ---------------------------- | --------------------------------------------- |
| **Reconnaissance**     | Custom NSA-grade framework, subfinder, nuclei |
| **SQL Injection**      | SQLMap, custom Python scripts                 |
| **Web Fuzzing**        | ffuf, custom wordlists                        |
| **Template Injection** | Tplmap, custom payloads                       |
| **Proxy/Interception** | Manual testing, browser tools                 |

---

## 🚀 Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/Ali-hey-0/owasp.git
cd owasp
```

### 2. Start with Week 1

```bash
cd week1
# Read the fundamentals
cat command_injection/general.md
cat SQL_Injection/sql.md

# Try the reconnaissance script
chmod +x recon/recon.sh
./recon/recon.sh example.com
```

### 3. Progress Through Each Week

- Follow the structured learning path: Week 1 → Week 2 → Week 3
- Practice with the provided scripts and examples
- Study the markdown documentation for theory
- Use the HTML/PHP files for hands-on testing

---

## 📚 Learning Path Recommendations

### 🟢 Beginner Track

1. Start with `week1/command_injection/general.md`
2. Practice basic SQL injection with `week1/SQL_Injection/sql.md`
3. Learn reconnaissance with `week1/recon/recon.sh`

### 🟡 Intermediate Track

1. Dive into `week2/XSS/XSS.md` and `week2/COSRS/cors.md`
2. Understand API security with `week2/API-SEC/`
3. Practice with interactive HTML examples

### 🔴 Advanced Track

1. Master bypass techniques in `week3/bypassing Protection/`
2. Learn about security misconfigurations in `week3/security misconfig/`
3. Understand SSRF attacks with `week3/ssrf/`

---

## ⚠️ Educational Disclaimer

**⚠️ IMPORTANT**: This repository is for **educational purposes only**.

- Use these techniques only on systems you own or have explicit permission to test
- Always follow responsible disclosure practices
- Respect applicable laws and regulations
- This content is intended for security professionals, students, and researchers

---

## 🤝 Contributing

We welcome contributions! Please see our contribution guidelines:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

### Areas for Contribution

- Additional vulnerability examples
- New exploitation techniques
- Improved documentation
- Interactive labs and challenges
- Tool automation scripts

---

## 📖 References & Resources

### OWASP Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)

### Additional Learning

- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [SANS Reading Room](https://www.sans.org/reading-room/)

### Security Tools

- [SQLMap](http://sqlmap.org/) - Automatic SQL injection tool
- [ffuf](https://github.com/ffuf/ffuf) - Fast web fuzzer
- [Nuclei](https://github.com/projectdiscovery/nuclei) - Vulnerability scanner

---

## 📞 Contact & Support

- **Author**: Ali Heydari
- **Email**: aliheydari1381doc@gmail.com
- **Issues**: [GitHub Issues](https://github.com/Ali-hey-0/owasp/issues)

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- OWASP Foundation for their invaluable security resources
- Security research community for continuous knowledge sharing
- Contributors and users who help improve this educational resource

---

<div align="center">

**🛡️ Stay Secure, Keep Learning! 🚀**

[![Star this repository](https://img.shields.io/github/stars/Ali-hey-0/owasp?style=social)](https://github.com/Ali-hey-0/owasp)

</div>
