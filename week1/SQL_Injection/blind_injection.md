### **Types of Blind SQL Injection**

1. **Boolean-Based Blind SQL Injection**

   - The application returns different responses (e.g., "true" or "false") based on the injected condition.
   - Example:
     ```sql
     SELECT * FROM users WHERE id = 1 AND 1=1; -- Returns true (normal response)
     SELECT * FROM users WHERE id = 1 AND 1=2; -- Returns false (no data or error)
     ```
   - Attackers infer data by crafting conditions (e.g., "Is the first character of the admin's password 'A'?").

2. **Time-Based Blind SQL Injection**

   - The attacker injects a query that forces the database to pause (e.g., `SLEEP(5)`) if a condition is true.
   - Example (MySQL):
     ```sql
     SELECT * FROM users WHERE id = 1 AND IF(1=1, SLEEP(5), 0); -- Delays response if true
     ```
   - The delay confirms the condition's validity.

---

### **How Blind SQL Injection Works**

1. **Detection**

   - Test for boolean or time-based behavior by injecting simple conditions (e.g., `AND 1=1` vs. `AND 1=2`).
   - Observe differences in HTTP responses (status codes, content length, or time delays).

2. **Exploitation**

   - Extract data character-by-character using binary search or brute-force:
     ```sql
     AND SUBSTRING((SELECT password FROM users WHERE username='admin'), 1, 1) = 'a'
     ```
   - For time-based:
     ```sql
     AND IF(SUBSTRING((SELECT password FROM users LIMIT 1), 1, 1)='a', SLEEP(5), 0)
     ```

3. **Automation**

   - Tools like **sqlmap** automate blind SQLi by sending payloads and analyzing responses:
     ```bash
     sqlmap -u "http://example.com/page?id=1" --technique=B --dbs
     ```

---

### **Mitigation**

1. **Prepared Statements (Parameterized Queries)**

   - Use placeholders to separate SQL logic from data:
     ```python
     cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
     ```

2. **Input Validation**

   - Whitelist allowed characters (e.g., only digits for IDs).

3. **Web Application Firewalls (WAFs)**

   - Deploy WAFs to filter malicious payloads.

4. **Least Privilege**

   - Restrict database user permissions to limit damage.

---

### **Example Scenario**

- **Target**: A login form vulnerable to blind SQLi.
- **Attack**:

  ```sql
  username: admin' AND SUBSTRING(password, 1, 1)='a'--
  password: anything
  ```

  - If the login fails, the first character is not 'a'; if it succeeds, it is.

Would you like a deeper dive into exploitation techniques or tools?
