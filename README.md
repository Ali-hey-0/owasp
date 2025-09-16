# OWASP Security Training Repository

Welcome to the **OWASP Security Training Repository**! This project is designed to help you learn, practice, and understand common web application security vulnerabilities, including SQL Injection, Command Injection, and Remote Code Execution (RCE). Each section contains educational resources, code samples, and practical exercises to enhance your security skills.

---

## 📁 Folder Structure

```
├── README.md
├── recon.sh
├── command_injection/
│   ├── Data_Exfiltration.md
│   ├── Detection_phase.md
│   ├── general.md
│   ├── Out-of-Band.md
│   └── Reverse_Shell.md
├── RCE/
│   └── rce.md
├── SQL_Injection/
│   ├── blind_injection.md
│   ├── sample.py
│   ├── sample2.py
│   ├── sql.md
│   ├── sqlmap.md
│   └── image/
│       └── sql/
│           ├── 1758004775270.png
│           └── 1758005846422.png
```

---

## 🛡️ Sections Overview

### 1. Command Injection
- **Data_Exfiltration.md**: Techniques for extracting data via command injection.
- **Detection_phase.md**: Methods to detect command injection vulnerabilities.
- **general.md**: Introduction and general concepts of command injection.
- **Out-of-Band.md**: Out-of-band exploitation strategies.
- **Reverse_Shell.md**: How to obtain a reverse shell using command injection.

### 2. Remote Code Execution (RCE)
- **rce.md**: Explains RCE vulnerabilities, exploitation methods, and mitigation strategies.

### 3. SQL Injection
- **blind_injection.md**: Blind SQL injection techniques and detection.
- **sample.py & sample2.py**: Python scripts demonstrating SQL injection vulnerabilities and exploitation.
- **sql.md**: Overview of SQL injection, types, and prevention.
- **sqlmap.md**: Guide to using `sqlmap` for automated SQL injection testing.
- **image/sql/**: Visual aids and diagrams related to SQL injection.

### 4. Reconnaissance
- **recon.sh**: Shell script for basic reconnaissance tasks.

---

## 🚀 Getting Started

1. **Clone the repository:**
	```bash
	git clone https://github.com/Ali-hey-0/owasp.git
	```
2. **Explore each section:**
	- Read the markdown files for theory and practical examples.
	- Run the Python scripts in the `SQL_Injection` folder to practice exploitation.
	- Use the images for visual reference.
3. **Run Recon Script:**
	```bash
	bash recon.sh
	```

---

## 📝 Contributing

Contributions are welcome! Feel free to submit issues, suggestions, or pull requests to improve the content and examples.

---

## 📚 References
- [OWASP Official Website](https://owasp.org/)
- [OWASP Top Ten](https://owasp.org/www-project-top-ten/)
- [SQLMap Tool](http://sqlmap.org/)

---

## 📧 Contact
For questions or feedback, please open an issue or contact the repository owner.

---

## 🏆 License
This project is licensed under the MIT License.
