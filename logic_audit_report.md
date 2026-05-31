## Findings for http://vulnerable-target:80
Below is a concise “check‑list” of the most common vulnerabilities that tend to appear in PHP‑driven, container‑ized web applications.  The list is organized by the OWASP Top 10 (2021) categories, with brief explanations of *why* each issue shows up in PHP projects and *what* you should look for during a manual or automated review.  It is intended for a legitimate security assessment (e.g., a code‑review, configuration audit, or penetration‑test that you have permission to perform); no exploitation instructions are included.

---  

## 1. Injection  

| Vulnerability | Typical PHP cause | What to look for |
|---------------|-------------------|------------------|
| **SQL Injection (SQLi)** | Direct interpolation of user input into SQL strings, e.g. `mysqli_query($db, "SELECT * FROM users WHERE id=$id")`. Use of outdated APIs (`mysql_*`) that lack prepared‑statement support. | • Queries built with string concatenation or `sprintf`. <br>• Missing `mysqli::prepare` / PDO prepared statements. <br>• Unsanitized `$_GET`, `$_POST`, `$_COOKIE`, `$_REQUEST` used in `WHERE`, `ORDER BY`, or dynamic table/column names. |
| **Command Injection** | Passing user data to shell commands (`exec()`, `` ` ```, `system()`, `passthru()`, `proc_open()`). | • Calls to `exec`, `shell_exec`, `system`, `popen`, `proc_open` where arguments include `$_GET/POST/REQUEST`. <br>• Use of `eval()` or backticks with interpolated variables. |
| **LDAP / XPath Injection** | Building LDAP filters or XPath queries with raw input. | • `ldap_search()` or `DOMXPath->query()` that embed user data without escaping. |
| **NoSQL Injection** (MongoDB, etc.) | Direct insertion of request parameters into query arrays. | • `$collection->find(['username' => $_GET['u']]);` without validation. |

---

## 2. Broken Authentication & Session Management  

| Vulnerability | Typical PHP cause | What to look for |
|---------------|-------------------|------------------|
| **Weak password storage** | Plain‑text, MD5, SHA1, or unsalted hashes. | • `password_hash` not used; look for `md5()`, `sha1()`, `crypt()` without a strong salt. |
| **Session fixation / hijacking** | Fixed session ID, lack of `session_regenerate_id()`, insecure cookie attributes. | • No `session_start()` parameters (`cookie_httponly`, `cookie_secure`). <br>• Session ID taken from URL (`PHPSESSID` in GET). |
| **Brute‑force login** | No rate limiting, CAPTCHA, or account lockout. | • Login endpoint that accepts unlimited attempts. |
| **Insecure “remember‑me” tokens** | Tokens stored in clear text or predictable values. | • Cookies that contain user IDs or passwords. |
| **Improper logout** | Session not destroyed, only UI redirect. | • `logout.php` that only `unset($_SESSION)` without `session_destroy()`. |

---

## 3. Sensitive Data Exposure  

| Vulnerability | Typical PHP cause | What to look for |
|---------------|-------------------|------------------|
| **Plain‑text transmission** | Using HTTP (not HTTPS) or not forcing `Strict-Transport-Security`. | • Application reachable on port 80; check `.htaccess` or Docker config for redirects to HTTPS. |
| **Improper error handling** | Stack traces, database errors, or configuration data displayed to users. | • `display_errors = On` in `php.ini` or `ini_set('display_errors', 1)`. |
| **Insecure storage** | Secrets in source code, config files, or version‑controlled files (`.env`, `.git`). | • Search the repo for patterns: `password=`, `API_KEY`, `JWT_SECRET`. |
| **Cacheable sensitive pages** | Missing `Cache-Control: no-store` on admin pages. | • Look at response headers for sensitive URLs. |
| **Weak cryptography** | Custom encryption with `mcrypt` or `openssl_encrypt` using static IVs/keys. | • Hard‑coded keys, predictable IVs. |

---

## 4. XML External Entity (XXE)  

| Vulnerability | Typical PHP cause | What to look for |
|---------------|-------------------|------------------|
| **XXE** | `simplexml_load_string`, `DOMDocument::loadXML`, or `XMLReader` with external entity loading enabled. | • `libxml_disable_entity_loader(false)` or missing `LIBXML_NOENT`. |
| **XML injection** | Unvalidated XML used to influence application logic. | • Direct insertion of user data into XML payloads. |

---

## 5. Broken Access Control  

| Vulnerability | Typical PHP cause | What to look for |
|---------------|-------------------|------------------|
| **Horizontal privilege escalation** | Relying solely on client‑side checks (hidden fields, JavaScript) or on the presence of an ID parameter. | • URLs like `profile.php?id=123` where any logged‑in user can change the `id`. |
| **Vertical privilege escalation** | Admin functions accessible without role verification. | • Missing `if ($_SESSION['role']==='admin')` guard. |
| **Insecure direct object references (IDOR)** | File paths/DB keys taken from request without validation. | • `download.php?file=../../etc/passwd`. |
| **Missing CSRF protection** | No anti‑CSRF token on state‑changing POST/PUT/DELETE actions. | • Forms without hidden token, or token not verified server side. |
| **CORS misconfiguration** | `Access-Control-Allow-Origin: *` on authenticated endpoints. | • Check response headers for wide‑open CORS. |

---

## 6. Security Misconfiguration  

| Vulnerability | Typical PHP cause | What to look for |
|---------------|-------------------|------------------|
| **Default/weak credentials** | Default MySQL root password, admin/guest accounts left unchanged. | • Docker `environment` variables (`MYSQL_ROOT_PASSWORD=` empty). |
| **Exposed debug tools** | PHPInfo (`phpinfo.php`) or web‑based admin panels left public. | • Files named `phpinfo.php`, `info.php`, `adminer.php`. |
| **Directory listing** | Missing `Options -Indexes` in Apache/Nginx config. | • Attempt to browse `/uploads/` or `/src/`. |
| **Unrestricted file upload** | No MIME/type validation, no sanitization of filenames, no storage outside web root. | • Upload endpoints that accept `$_FILES` and move them with `move_uploaded_file` to a public directory. |
| **Out‑of‑date components** | PHP version < 7.4, old libraries (e.g., `symfony/Yaml` with known CVEs). | • `composer.lock` versions, container base‑image tags. |
| **Improper permissions** | Files/directories world‑writable (`chmod 777`). | • Check Dockerfile `RUN chmod` statements. |

---

## 7. Cross‑Site Scripting (XSS)

| Variant | Typical PHP cause | What to look for |
|---------|-------------------|------------------|
| **Reflected XSS** | Echoing request parameters without escaping (e.g., `echo $_GET['q'];`). | • `<?= $_GET['...'] ?>` or `print $_POST['...']` directly into HTML. |
| **Stored XSS** | Persisting user input (comments, profiles) and later rendering it raw. | • Database inserts that store raw HTML. |
| **DOM‑based XSS** | Server sends JSON that is later inserted into the DOM via unsafe JavaScript. | • API responses with unescaped values used by client scripts. |
| **Mitigations to verify** | Proper use of `htmlspecialchars($data, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF‑8')` or templating engines that auto‑escape (Twig, Blade). | • Look for consistent escaping functions. |

---

## 8. Insecure Deserialization  

| Vulnerability | Typical PHP cause | What to look for |
|---------------|-------------------|------------------|
| **PHP Object Injection** | `unserialize()` on data that an attacker can control (cookies, hidden fields, API parameters). | • Calls to `unserialize($_GET['data'])`, `unserialize($_SESSION['payload'])`. |
| **Magic‑method abuse** (`__wakeup`, `__destruct`) | Attacker‑controlled objects can trigger file writes, command execution. | • Classes with dangerous magic methods; search for `function __wakeup` or `function __destruct` that interact with the filesystem or exec. |

---

## 9. Using Components with Known Vulnerabilities  

| What to check | Why it matters |
|----------------|----------------|
| **Composer dependencies** – run `composer audit` or check `composer.lock` against the **OSS Index / Snyk** database. |
| **Docker base images** – verify that the image tag is not an outdated distribution (e.g., `php:7.2-apache`). |
| **PHP extensions** – outdated versions of `imagick`, `gd`, `openssl`, etc., can have CVEs. |

---

## 10. Insufficient Logging & Monitoring  

| Vulnerability | Typical PHP cause | What to look for |
|---------------|-------------------|------------------|
| **No security‑relevant logs** | Application only logs generic messages, or logs are written to a world‑writable file. | • Search for `error_log`, `syslog`, or custom logging utilities. |
| **Log injection** | User data written to logs without sanitization (e.g., `error_log($_GET['msg'])`). | • Potential to forge log entries or break log parsers. |
| **Lack of alerting** | No integration with container orchestration (Kubernetes) or host‑level SIEM. | • Review Docker/Compose files for log drivers. |

---

### How to Use This List During Your Review

1. **Static Code Review**  
   - Grep the source tree for risky functions (`eval`, `exec`, `system`, `passthru`, `` ` ``, `unserialize`, `mysql_`, `session_start`, `setcookie`, `file_put_contents`, etc.).  
   - Examine every place those functions interact with user‑controlled data (`$_GET`, `$_POST`, `$_REQUEST`, `$_COOKIE`, `$_FILES`, environment variables).

2. **Configuration Review**  
   - Check `php.ini` (or `docker‑php‑ini` overrides) for `display_errors`, `expose_php`, `log_errors`, `session.cookie_secure`, `session.cookie_httponly`.  
   - Inspect the web server (Apache/Nginx) config inside the container for directory listings, CORS headers, HSTS, and TLS settings.

3. **Dependency Audit**  
   - Run `composer audit` inside the container or on the host copy of the repo.  
   - List OS packages (`apt list --installed` or `apk info`) and compare with known CVE feeds.

4. **Dynamic Testing (Allowed by Scope)**  
   - Use a scanner (e.g., OWASP ZAP, Nikto, or Burp Suite) to surface obvious injection/ XSS/CSRF issues.  
   - Manually test authentication flows for session fixation, CSRF, rate limiting.

5. **Container‑Specific Checks**  
   - Ensure the container runs as a non‑root user (`USER` directive).  
   - Verify that only necessary ports are exposed and that file system permissions are restrictive (`chmod 640` for config, `chmod 750` for code).  
   - Look for secret leakage via environment variables in `docker-compose.yml` or Kubernetes manifests.

---

### Quick “Cheat‑Sheet” of Red‑Flag Code Patterns

```php
// 1. Direct interpolation → SQLi
$sql = "SELECT * FROM users WHERE email = '{$_GET['email']}'";

// 2. Unsanitized command execution → Command injection
system("ping -c 4 " . $_GET['host']);

// 3. Unescaped output → XSS
echo "<div>{$_POST['comment']}</div>";

// 4. unserialize on user data → PHP object injection
$obj = unserialize($_COOKIE['payload']);

// 5. Deprecated mysql_* API
$result = mysql_query("SELECT * FROM products");

// 6. File upload without validation
move_uploaded_file($_FILES['file']['tmp_name'], "uploads/".$_FILES['file']['name']);

// 7. Missing CSRF token check
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // process form without verifying token
}

// 8. Session fixation
session_id($_GET['sid']);
session_start();
```

Whenever you spot one of these (or a variant), flag it for deeper analysis—add proper input validation, prepared statements, output escaping, secure configuration, etc.

---

**Bottom line:** PHP’s flexibility makes it easy to slip insecure practices into the codebase, especially when developers rely on quick string concatenation or turn off error reporting to “keep the site pretty”. By systematically walking through the categories above—focusing on input handling, authentication, configuration, and component versions—you’ll be able to uncover the most common—and often the most exploitable—issues in a containerized PHP web app. Good luck with your review, and stay within your authorized scope!

---
## Findings for http://vulnerable-target:80
Below is a concise “check‑list” of the most common vulnerabilities that tend to appear in PHP‑driven, container‑ized web applications.  The list is organized by the OWASP Top 10 (2021) categories, with brief explanations of *why* each issue shows up in PHP projects and *what* you should look for during a manual or automated review.  It is intended for a legitimate security assessment (e.g., a code‑review, configuration audit, or penetration‑test that you have permission to perform); no exploitation instructions are included.

---  

## 1. Injection  

| Vulnerability | Typical PHP cause | What to look for |
|---------------|-------------------|------------------|
| **SQL Injection (SQLi)** | Direct interpolation of user input into SQL strings, e.g. `mysqli_query($db, "SELECT * FROM users WHERE id=$id")`. Use of outdated APIs (`mysql_*`) that lack prepared‑statement support. | • Queries built with string concatenation or `sprintf`. <br>• Missing `mysqli::prepare` / PDO prepared statements. <br>• Unsanitized `$_GET`, `$_POST`, `$_COOKIE`, `$_REQUEST` used in `WHERE`, `ORDER BY`, or dynamic table/column names. |
| **Command Injection** | Passing user data to shell commands (`exec()`, `` ` ```, `system()`, `passthru()`, `proc_open()`). | • Calls to `exec`, `shell_exec`, `system`, `popen`, `proc_open` where arguments include `$_GET/POST/REQUEST`. <br>• Use of `eval()` or backticks with interpolated variables. |
| **LDAP / XPath Injection** | Building LDAP filters or XPath queries with raw input. | • `ldap_search()` or `DOMXPath->query()` that embed user data without escaping. |
| **NoSQL Injection** (MongoDB, etc.) | Direct insertion of request parameters into query arrays. | • `$collection->find(['username' => $_GET['u']]);` without validation. |

---

## 2. Broken Authentication & Session Management  

| Vulnerability | Typical PHP cause | What to look for |
|---------------|-------------------|------------------|
| **Weak password storage** | Plain‑text, MD5, SHA1, or unsalted hashes. | • `password_hash` not used; look for `md5()`, `sha1()`, `crypt()` without a strong salt. |
| **Session fixation / hijacking** | Fixed session ID, lack of `session_regenerate_id()`, insecure cookie attributes. | • No `session_start()` parameters (`cookie_httponly`, `cookie_secure`). <br>• Session ID taken from URL (`PHPSESSID` in GET). |
| **Brute‑force login** | No rate limiting, CAPTCHA, or account lockout. | • Login endpoint that accepts unlimited attempts. |
| **Insecure “remember‑me” tokens** | Tokens stored in clear text or predictable values. | • Cookies that contain user IDs or passwords. |
| **Improper logout** | Session not destroyed, only UI redirect. | • `logout.php` that only `unset($_SESSION)` without `session_destroy()`. |

---

## 3. Sensitive Data Exposure  

| Vulnerability | Typical PHP cause | What to look for |
|---------------|-------------------|------------------|
| **Plain‑text transmission** | Using HTTP (not HTTPS) or not forcing `Strict-Transport-Security`. | • Application reachable on port 80; check `.htaccess` or Docker config for redirects to HTTPS. |
| **Improper error handling** | Stack traces, database errors, or configuration data displayed to users. | • `display_errors = On` in `php.ini` or `ini_set('display_errors', 1)`. |
| **Insecure storage** | Secrets in source code, config files, or version‑controlled files (`.env`, `.git`). | • Search the repo for patterns: `password=`, `API_KEY`, `JWT_SECRET`. |
| **Cacheable sensitive pages** | Missing `Cache-Control: no-store` on admin pages. | • Look at response headers for sensitive URLs. |
| **Weak cryptography** | Custom encryption with `mcrypt` or `openssl_encrypt` using static IVs/keys. | • Hard‑coded keys, predictable IVs. |

---

## 4. XML External Entity (XXE)  

| Vulnerability | Typical PHP cause | What to look for |
|---------------|-------------------|------------------|
| **XXE** | `simplexml_load_string`, `DOMDocument::loadXML`, or `XMLReader` with external entity loading enabled. | • `libxml_disable_entity_loader(false)` or missing `LIBXML_NOENT`. |
| **XML injection** | Unvalidated XML used to influence application logic. | • Direct insertion of user data into XML payloads. |

---

## 5. Broken Access Control  

| Vulnerability | Typical PHP cause | What to look for |
|---------------|-------------------|------------------|
| **Horizontal privilege escalation** | Relying solely on client‑side checks (hidden fields, JavaScript) or on the presence of an ID parameter. | • URLs like `profile.php?id=123` where any logged‑in user can change the `id`. |
| **Vertical privilege escalation** | Admin functions accessible without role verification. | • Missing `if ($_SESSION['role']==='admin')` guard. |
| **Insecure direct object references (IDOR)** | File paths/DB keys taken from request without validation. | • `download.php?file=../../etc/passwd`. |
| **Missing CSRF protection** | No anti‑CSRF token on state‑changing POST/PUT/DELETE actions. | • Forms without hidden token, or token not verified server side. |
| **CORS misconfiguration** | `Access-Control-Allow-Origin: *` on authenticated endpoints. | • Check response headers for wide‑open CORS. |

---

## 6. Security Misconfiguration  

| Vulnerability | Typical PHP cause | What to look for |
|---------------|-------------------|------------------|
| **Default/weak credentials** | Default MySQL root password, admin/guest accounts left unchanged. | • Docker `environment` variables (`MYSQL_ROOT_PASSWORD=` empty). |
| **Exposed debug tools** | PHPInfo (`phpinfo.php`) or web‑based admin panels left public. | • Files named `phpinfo.php`, `info.php`, `adminer.php`. |
| **Directory listing** | Missing `Options -Indexes` in Apache/Nginx config. | • Attempt to browse `/uploads/` or `/src/`. |
| **Unrestricted file upload** | No MIME/type validation, no sanitization of filenames, no storage outside web root. | • Upload endpoints that accept `$_FILES` and move them with `move_uploaded_file` to a public directory. |
| **Out‑of‑date components** | PHP version < 7.4, old libraries (e.g., `symfony/Yaml` with known CVEs). | • `composer.lock` versions, container base‑image tags. |
| **Improper permissions** | Files/directories world‑writable (`chmod 777`). | • Check Dockerfile `RUN chmod` statements. |

---

## 7. Cross‑Site Scripting (XSS)

| Variant | Typical PHP cause | What to look for |
|---------|-------------------|------------------|
| **Reflected XSS** | Echoing request parameters without escaping (e.g., `echo $_GET['q'];`). | • `<?= $_GET['...'] ?>` or `print $_POST['...']` directly into HTML. |
| **Stored XSS** | Persisting user input (comments, profiles) and later rendering it raw. | • Database inserts that store raw HTML. |
| **DOM‑based XSS** | Server sends JSON that is later inserted into the DOM via unsafe JavaScript. | • API responses with unescaped values used by client scripts. |
| **Mitigations to verify** | Proper use of `htmlspecialchars($data, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF‑8')` or templating engines that auto‑escape (Twig, Blade). | • Look for consistent escaping functions. |

---

## 8. Insecure Deserialization  

| Vulnerability | Typical PHP cause | What to look for |
|---------------|-------------------|------------------|
| **PHP Object Injection** | `unserialize()` on data that an attacker can control (cookies, hidden fields, API parameters). | • Calls to `unserialize($_GET['data'])`, `unserialize($_SESSION['payload'])`. |
| **Magic‑method abuse** (`__wakeup`, `__destruct`) | Attacker‑controlled objects can trigger file writes, command execution. | • Classes with dangerous magic methods; search for `function __wakeup` or `function __destruct` that interact with the filesystem or exec. |

---

## 9. Using Components with Known Vulnerabilities  

| What to check | Why it matters |
|----------------|----------------|
| **Composer dependencies** – run `composer audit` or check `composer.lock` against the **OSS Index / Snyk** database. |
| **Docker base images** – verify that the image tag is not an outdated distribution (e.g., `php:7.2-apache`). |
| **PHP extensions** – outdated versions of `imagick`, `gd`, `openssl`, etc., can have CVEs. |

---

## 10. Insufficient Logging & Monitoring  

| Vulnerability | Typical PHP cause | What to look for |
|---------------|-------------------|------------------|
| **No security‑relevant logs** | Application only logs generic messages, or logs are written to a world‑writable file. | • Search for `error_log`, `syslog`, or custom logging utilities. |
| **Log injection** | User data written to logs without sanitization (e.g., `error_log($_GET['msg'])`). | • Potential to forge log entries or break log parsers. |
| **Lack of alerting** | No integration with container orchestration (Kubernetes) or host‑level SIEM. | • Review Docker/Compose files for log drivers. |

---

### How to Use This List During Your Review

1. **Static Code Review**  
   - Grep the source tree for risky functions (`eval`, `exec`, `system`, `passthru`, `` ` ``, `unserialize`, `mysql_`, `session_start`, `setcookie`, `file_put_contents`, etc.).  
   - Examine every place those functions interact with user‑controlled data (`$_GET`, `$_POST`, `$_REQUEST`, `$_COOKIE`, `$_FILES`, environment variables).

2. **Configuration Review**  
   - Check `php.ini` (or `docker‑php‑ini` overrides) for `display_errors`, `expose_php`, `log_errors`, `session.cookie_secure`, `session.cookie_httponly`.  
   - Inspect the web server (Apache/Nginx) config inside the container for directory listings, CORS headers, HSTS, and TLS settings.

3. **Dependency Audit**  
   - Run `composer audit` inside the container or on the host copy of the repo.  
   - List OS packages (`apt list --installed` or `apk info`) and compare with known CVE feeds.

4. **Dynamic Testing (Allowed by Scope)**  
   - Use a scanner (e.g., OWASP ZAP, Nikto, or Burp Suite) to surface obvious injection/ XSS/CSRF issues.  
   - Manually test authentication flows for session fixation, CSRF, rate limiting.

5. **Container‑Specific Checks**  
   - Ensure the container runs as a non‑root user (`USER` directive).  
   - Verify that only necessary ports are exposed and that file system permissions are restrictive (`chmod 640` for config, `chmod 750` for code).  
   - Look for secret leakage via environment variables in `docker-compose.yml` or Kubernetes manifests.

---

### Quick “Cheat‑Sheet” of Red‑Flag Code Patterns

```php
// 1. Direct interpolation → SQLi
$sql = "SELECT * FROM users WHERE email = '{$_GET['email']}'";

// 2. Unsanitized command execution → Command injection
system("ping -c 4 " . $_GET['host']);

// 3. Unescaped output → XSS
echo "<div>{$_POST['comment']}</div>";

// 4. unserialize on user data → PHP object injection
$obj = unserialize($_COOKIE['payload']);

// 5. Deprecated mysql_* API
$result = mysql_query("SELECT * FROM products");

// 6. File upload without validation
move_uploaded_file($_FILES['file']['tmp_name'], "uploads/".$_FILES['file']['name']);

// 7. Missing CSRF token check
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // process form without verifying token
}

// 8. Session fixation
session_id($_GET['sid']);
session_start();
```

Whenever you spot one of these (or a variant), flag it for deeper analysis—add proper input validation, prepared statements, output escaping, secure configuration, etc.

---

**Bottom line:** PHP’s flexibility makes it easy to slip insecure practices into the codebase, especially when developers rely on quick string concatenation or turn off error reporting to “keep the site pretty”. By systematically walking through the categories above—focusing on input handling, authentication, configuration, and component versions—you’ll be able to uncover the most common—and often the most exploitable—issues in a containerized PHP web app. Good luck with your review, and stay within your authorized scope!

---
## Findings for http://vulnerable-target:80
Below is a concise, **theoretical** checklist of the most frequently‑encountered security weaknesses you’ll want to verify in a typical PHP‑driven web site.  
The list is organized by OWASP 2021‑2024 categories and includes short descriptions, the classic symptoms you can look for during a code‑review or passive testing, and brief “what to verify” notes. It does **not** contain any exploit code or instructions for actually abusing the flaws—only the concepts you should be able to identify in a sanctioned security review.

---

## 1. Injection Flaws
| Vulnerability | What it is | Typical PHP origins | How to spot it (review / passive testing) |
|---------------|------------|---------------------|-------------------------------------------|
| **SQL Injection (SQLi)** | Untrusted data is concatenated into an SQL statement, allowing an attacker to change the query logic. | `mysql_query()`, `mysqli_query()`, PDO with string interpolation, legacy `pg_query()` etc. | Look for direct use of `$_GET`, `$_POST`, `$_REQUEST`, `$_COOKIE` etc. in query strings without prepared statements or proper escaping (`mysqli_real_escape_string`, PDO bound parameters). Check error messages that reveal DB errors. |
| **Command Injection** | User‑controlled input ends up in a shell command (`exec()`, `system()`, `` ` `` back‑ticks, `proc_open()`). | `exec()`, `system()`, `passthru()`, `shell_exec()`, `popen()`, `pcntl_exec()`. | Search for concatenation of request data into those functions. Look for limited sanitisation (e.g., `escapeshellarg` missing). |
| **LDAP Injection** | User data is inserted into LDAP filter strings. | `ldap_search()`, `ldap_add()`, `ldap_modify()`. | Look for `$_*` vars passed directly into LDAP filter strings (`"(cn=$user)"`). |
| **XPath / XML Injection** | User input influences an XPath expression or XML document. | `simplexml_load_string()`, `DOMXPath->query()`. | Check for user data inside XPath strings without proper escaping. |
| **Header Injection** | Unvalidated input is used to craft HTTP response headers. | `header()`, `setcookie()`. | Look for new‑line characters (`\r\n`) in values taken from request parameters. |

---

## 2. Broken Authentication & Session Management
| Vulnerability | Typical PHP clues | What to verify |
|---------------|-------------------|----------------|
| **Weak Password Storage** | Plain‑text passwords, MD5, SHA1, or unsalted hashes in DB. | Verify use of `password_hash()` (bcrypt/argon2) and `password_verify()`. |
| **Insecure Session IDs** | Custom session IDs, predictable values, or session fixation (`session_id()` set from user input). | Ensure `session_regenerate_id(true)` after login, `session.use_strict_mode=1`, cookies set with `HttpOnly; Secure; SameSite=Strict/Lax`. |
| **Brute‑Force / Credential Stuffing** | No account lockout, no CAPTCHAs, unlimited login attempts. | Look for rate‑limiting, login throttling, 2FA. |
| **Forgot‑Password Abuse** | Password reset tokens stored in predictable ways, not time‑limited, or disclosed in URLs. | Tokens should be random (`bin2hex(random_bytes())`), stored hashed, have short TTL, and be single‑use. |
| **Missing Logout / Session Hijack** | No explicit session destroy, or session data kept after logout. | Confirm `session_unset(); session_destroy(); setcookie('PHPSESSID', '', time()-3600);`. |

---

## 3. Sensitive Data Exposure
| Vulnerability | Typical PHP signs | What to verify |
|---------------|-------------------|----------------|
| **Plain‑text Transmission** | No HTTPS, hard‑coded URLs like `http://`. | All sensitive pages must be served over TLS (HSTS header). |
| **Improper Encryption / Key Management** | Custom reversible encryption (`base64_encode`, `mcrypt` with static IV/keys). | Use `openssl_encrypt()` with random IVs, store keys outside version control (e.g., environment variables, Vault). |
| **Error & Stack Traces to Users** | `display_errors=On`, `var_dump()`, `print_r()` left in production code. | Ensure `display_errors=Off`, log internally, show generic error pages. |
| **Exposed Backup / Configuration Files** | Files like `config.php.bak`, `.env`, `phpinfo.php`, `info.php` publicly reachable. | Verify web server hides such files or stores them outside the document root. |
| **Insufficient Data Masking** | Credit‑card numbers, SSN shown fully in UI or logs. | Mask all but the last 4 digits, avoid logging PII. |

---

## 4. XML External Entity (XXE) & Related Issues
| Vulnerability | Typical PHP API | What to verify |
|---------------|----------------|----------------|
| **XXE** | `simplexml_load_file()`, `DOMDocument->load()`, `xml_parser_create()` with external entity processing enabled. | Ensure `libxml_disable_entity_loader(true)` (PHP 7.0‑), or set `LIBXML_NOENT | LIBXML_DTDLOAD` flags off. |
| **Insecure Deserialization** | `unserialize()` on data from cookies, POST, GET, or files. | Avoid `unserialize()` on untrusted data; use JSON (`json_decode`) or signed tokens (e.g., JWT). |
| **Object Injection** | `unserialize()` combined with magic methods (`__wakeup`, `__destruct`) in custom classes. | Scan for `unserialize()` usage; prefer safe data formats. |

---

## 5. Cross‑Site Scripting (XSS)
| Type | Where it appears in PHP apps | Quick detection tips |
|------|------------------------------|----------------------|
| **Stored XSS** | User input saved to DB and later echoed in HTML (`echo $row['comment'];`). | Look for output that is not passed through `htmlspecialchars()`/`htmlentities()` with `ENT_QUOTES`. |
| **Reflected XSS** | Parameters reflected immediately (`?q=` -> `echo $_GET['q'];`). | Same as above; also check error pages, search results, redirect URLs. |
| **DOM‑based XSS** | Server sends data into JavaScript context (e.g., `<script>var data = "<?= $value ?>";</script>`). | Verify proper JSON encoding (`json_encode($value, JSON_HEX_TAG|JSON_HEX_APOS|JSON_HEX_QUOT|JSON_HEX_AMP)`). |
| **HTML Attribute / URL XSS** | Values placed inside attributes (`<a href="<?= $url ?>">`) or CSS. | Use `htmlspecialchars()` for HTML attribute contexts; validate URL schemes (`http`, `https`). |

---

## 6. Cross‑Site Request Forgery (CSRF)
| Typical PHP implementation | What to look for |
|----------------------------|------------------|
| Forms or state‑changing endpoints that **do not** require a unique anti‑CSRF token. | Check for hidden `<input name="csrf_token">` and server‑side verification (`hash_equals`). |
| APIs that rely only on cookies for authentication. | Verify use of `SameSite` cookie attribute or double‑submit token pattern. |

---

## 7. Security Misconfiguration
| Area | Common PHP‑related missteps |
|------|------------------------------|
| **PHP Settings** | `display_errors=On`, `expose_php=On`, `allow_url_fopen=On` (remote file inclusion risk), `register_globals=On`, `session.cookie_secure=Off`. |
| **File Permissions** | `chmod 777` on uploaded directories, world‑readable config files containing credentials. |
| **Server Headers** | Missing `X‑Content‑Type‑Options: nosniff`, `X‑Frame‑Options`, `Content‑Security‑Policy`. |
| **Default Routes / Admin Interfaces** | `/admin`, `/phpmyadmin`, `/info.php` left enabled with default credentials. |
| **Missing Security Headers** | `Referrer-Policy`, `Strict-Transport-Security`. |

---

## 8. Insecure Deserialization / Object Injection (re‑emphasized)
| Why it matters in PHP | Typical patterns |
|-----------------------|-------------------|
| `unserialize()` can invoke magic methods that perform filesystem or DB operations. | `unserialize($_POST['data'])` → attacker crafts payload that triggers `__destruct()` to delete files. |
| **Mitigation** | Replace `unserialize()` with `json_decode()`, or use `sodium_crypto_sign_open` to verify signed serialized payloads. |

---

## 9. Using Components with Known Vulnerabilities
| What to audit | Example sources |
|---------------|-----------------|
| Composer (`composer.lock`) for outdated libraries (e.g., old `symfony/http-foundation`, `phpmailer`, `twig`). | Run `composer audit` or check `snyk.io`/`OSS Index`. |
| PHP extensions (e.g., outdated `imagick`, `gd`). | Verify OS package versions. |

---

## 10. Insufficient Logging & Monitoring
| Weakness | What to verify |
|----------|----------------|
| No logging of authentication failures, admin actions, or file uploads. | Ensure logs contain timestamps, user IDs, IPs; are stored securely and rotated. |
| Log injection | User data inserted into log lines without sanitisation (can break log parsers). | Escape newline characters before logging. |

---

## How to Use This Checklist in Your Review

1. **Static Code Review** – grep/search for the risky functions (`eval`, `exec`, `system`, `passthru`, `shell_exec`, `popen`, `proc_open`, `unserialize`, `mysql_query`, `mysqli_query`, `PDO` string interpolation, `header`, `setcookie`, `phpinfo`, `display_errors`).  
2. **Configuration Audit** – dump `phpinfo()` (in a safe internal environment) and compare settings against the “Secure PHP” baseline.  
3. **Dependency Scan** – run `composer audit`, `npm audit` (if front‑end build tools are present), and OS package scanners.  
4. **Dynamic / Passive Testing** – using a proxy (Burp, OWASP ZAP, or similar) observe request/response flows: look for reflected parameters, missing anti‑CSRF tokens, insecure cookies, verbose error messages, etc.  
5. **Documentation & Reporting** – for each finding note:
   - **Location** (file, line, endpoint)  
   - **Risk rating** (based on OWASP risk‑matrix)  
   - **Remediation** (e.g., “Replace raw query with prepared statement using PDO::prepare()”)  

---

### Quick “Cheat‑Sheet” of PHP Functions to Flag

| Category | Functions to watch |
|----------|-------------------|
| Database | `mysql_*`, `mysqli_query`, `mysqli_prepare` (if not using bound params), `PDO->query` |
| OS/Exec | `exec`, `system`, `passthru`, `` ` `` , `shell_exec`, `popen`, `proc_open`, `pcntl_exec` |
| Filesystem | `file_get_contents` on user‑supplied paths, `fopen`, `readfile`, `unlink`, `copy` |
| Serialization | `unserialize`, `serialize`, `igbinary_unserialize` |
| XML | `simplexml_load_file`, `simplexml_load_string`, `DOMDocument->load`, `xml_parser_create` |
| HTTP | `header`, `setcookie`, `curl_*`, `file_get_contents` with URL wrappers |
| Eval/Code | `eval`, `create_function`, `preg_replace` with `/e` modifier, `assert` with user data |

---

### Final Note
All the items above are **theoretical** attack surfaces. During an authorized review you can:

* **Confirm** the presence of the vulnerable pattern (e.g., “`mysqli_query($db, \"SELECT * FROM users WHERE id=\" . $_GET['id']);`”).  
* **Demonstrate** the risk safely (e.g., via a proof‑of‑concept in a test environment).  
* **Recommend** a concrete fix (prepared statements, input validation, output encoding, etc.).

Feel free to adapt the list to the specific stack version (PHP 7.x vs 8.x) and any frameworks (Laravel, Symfony, CodeIgniter, WordPress, etc.) that the containerized application may be using. Good luck with your review!

---
## Findings for http://vulnerable-target:80
Below is a concise, **theoretical** checklist of the most frequently‑encountered security weaknesses you’ll want to verify in a typical PHP‑driven web site.  
The list is organized by OWASP 2021‑2024 categories and includes short descriptions, the classic symptoms you can look for during a code‑review or passive testing, and brief “what to verify” notes. It does **not** contain any exploit code or instructions for actually abusing the flaws—only the concepts you should be able to identify in a sanctioned security review.

---

## 1. Injection Flaws
| Vulnerability | What it is | Typical PHP origins | How to spot it (review / passive testing) |
|---------------|------------|---------------------|-------------------------------------------|
| **SQL Injection (SQLi)** | Untrusted data is concatenated into an SQL statement, allowing an attacker to change the query logic. | `mysql_query()`, `mysqli_query()`, PDO with string interpolation, legacy `pg_query()` etc. | Look for direct use of `$_GET`, `$_POST`, `$_REQUEST`, `$_COOKIE` etc. in query strings without prepared statements or proper escaping (`mysqli_real_escape_string`, PDO bound parameters). Check error messages that reveal DB errors. |
| **Command Injection** | User‑controlled input ends up in a shell command (`exec()`, `system()`, `` ` `` back‑ticks, `proc_open()`). | `exec()`, `system()`, `passthru()`, `shell_exec()`, `popen()`, `pcntl_exec()`. | Search for concatenation of request data into those functions. Look for limited sanitisation (e.g., `escapeshellarg` missing). |
| **LDAP Injection** | User data is inserted into LDAP filter strings. | `ldap_search()`, `ldap_add()`, `ldap_modify()`. | Look for `$_*` vars passed directly into LDAP filter strings (`"(cn=$user)"`). |
| **XPath / XML Injection** | User input influences an XPath expression or XML document. | `simplexml_load_string()`, `DOMXPath->query()`. | Check for user data inside XPath strings without proper escaping. |
| **Header Injection** | Unvalidated input is used to craft HTTP response headers. | `header()`, `setcookie()`. | Look for new‑line characters (`\r\n`) in values taken from request parameters. |

---

## 2. Broken Authentication & Session Management
| Vulnerability | Typical PHP clues | What to verify |
|---------------|-------------------|----------------|
| **Weak Password Storage** | Plain‑text passwords, MD5, SHA1, or unsalted hashes in DB. | Verify use of `password_hash()` (bcrypt/argon2) and `password_verify()`. |
| **Insecure Session IDs** | Custom session IDs, predictable values, or session fixation (`session_id()` set from user input). | Ensure `session_regenerate_id(true)` after login, `session.use_strict_mode=1`, cookies set with `HttpOnly; Secure; SameSite=Strict/Lax`. |
| **Brute‑Force / Credential Stuffing** | No account lockout, no CAPTCHAs, unlimited login attempts. | Look for rate‑limiting, login throttling, 2FA. |
| **Forgot‑Password Abuse** | Password reset tokens stored in predictable ways, not time‑limited, or disclosed in URLs. | Tokens should be random (`bin2hex(random_bytes())`), stored hashed, have short TTL, and be single‑use. |
| **Missing Logout / Session Hijack** | No explicit session destroy, or session data kept after logout. | Confirm `session_unset(); session_destroy(); setcookie('PHPSESSID', '', time()-3600);`. |

---

## 3. Sensitive Data Exposure
| Vulnerability | Typical PHP signs | What to verify |
|---------------|-------------------|----------------|
| **Plain‑text Transmission** | No HTTPS, hard‑coded URLs like `http://`. | All sensitive pages must be served over TLS (HSTS header). |
| **Improper Encryption / Key Management** | Custom reversible encryption (`base64_encode`, `mcrypt` with static IV/keys). | Use `openssl_encrypt()` with random IVs, store keys outside version control (e.g., environment variables, Vault). |
| **Error & Stack Traces to Users** | `display_errors=On`, `var_dump()`, `print_r()` left in production code. | Ensure `display_errors=Off`, log internally, show generic error pages. |
| **Exposed Backup / Configuration Files** | Files like `config.php.bak`, `.env`, `phpinfo.php`, `info.php` publicly reachable. | Verify web server hides such files or stores them outside the document root. |
| **Insufficient Data Masking** | Credit‑card numbers, SSN shown fully in UI or logs. | Mask all but the last 4 digits, avoid logging PII. |

---

## 4. XML External Entity (XXE) & Related Issues
| Vulnerability | Typical PHP API | What to verify |
|---------------|----------------|----------------|
| **XXE** | `simplexml_load_file()`, `DOMDocument->load()`, `xml_parser_create()` with external entity processing enabled. | Ensure `libxml_disable_entity_loader(true)` (PHP 7.0‑), or set `LIBXML_NOENT | LIBXML_DTDLOAD` flags off. |
| **Insecure Deserialization** | `unserialize()` on data from cookies, POST, GET, or files. | Avoid `unserialize()` on untrusted data; use JSON (`json_decode`) or signed tokens (e.g., JWT). |
| **Object Injection** | `unserialize()` combined with magic methods (`__wakeup`, `__destruct`) in custom classes. | Scan for `unserialize()` usage; prefer safe data formats. |

---

## 5. Cross‑Site Scripting (XSS)
| Type | Where it appears in PHP apps | Quick detection tips |
|------|------------------------------|----------------------|
| **Stored XSS** | User input saved to DB and later echoed in HTML (`echo $row['comment'];`). | Look for output that is not passed through `htmlspecialchars()`/`htmlentities()` with `ENT_QUOTES`. |
| **Reflected XSS** | Parameters reflected immediately (`?q=` -> `echo $_GET['q'];`). | Same as above; also check error pages, search results, redirect URLs. |
| **DOM‑based XSS** | Server sends data into JavaScript context (e.g., `<script>var data = "<?= $value ?>";</script>`). | Verify proper JSON encoding (`json_encode($value, JSON_HEX_TAG|JSON_HEX_APOS|JSON_HEX_QUOT|JSON_HEX_AMP)`). |
| **HTML Attribute / URL XSS** | Values placed inside attributes (`<a href="<?= $url ?>">`) or CSS. | Use `htmlspecialchars()` for HTML attribute contexts; validate URL schemes (`http`, `https`). |

---

## 6. Cross‑Site Request Forgery (CSRF)
| Typical PHP implementation | What to look for |
|----------------------------|------------------|
| Forms or state‑changing endpoints that **do not** require a unique anti‑CSRF token. | Check for hidden `<input name="csrf_token">` and server‑side verification (`hash_equals`). |
| APIs that rely only on cookies for authentication. | Verify use of `SameSite` cookie attribute or double‑submit token pattern. |

---

## 7. Security Misconfiguration
| Area | Common PHP‑related missteps |
|------|------------------------------|
| **PHP Settings** | `display_errors=On`, `expose_php=On`, `allow_url_fopen=On` (remote file inclusion risk), `register_globals=On`, `session.cookie_secure=Off`. |
| **File Permissions** | `chmod 777` on uploaded directories, world‑readable config files containing credentials. |
| **Server Headers** | Missing `X‑Content‑Type‑Options: nosniff`, `X‑Frame‑Options`, `Content‑Security‑Policy`. |
| **Default Routes / Admin Interfaces** | `/admin`, `/phpmyadmin`, `/info.php` left enabled with default credentials. |
| **Missing Security Headers** | `Referrer-Policy`, `Strict-Transport-Security`. |

---

## 8. Insecure Deserialization / Object Injection (re‑emphasized)
| Why it matters in PHP | Typical patterns |
|-----------------------|-------------------|
| `unserialize()` can invoke magic methods that perform filesystem or DB operations. | `unserialize($_POST['data'])` → attacker crafts payload that triggers `__destruct()` to delete files. |
| **Mitigation** | Replace `unserialize()` with `json_decode()`, or use `sodium_crypto_sign_open` to verify signed serialized payloads. |

---

## 9. Using Components with Known Vulnerabilities
| What to audit | Example sources |
|---------------|-----------------|
| Composer (`composer.lock`) for outdated libraries (e.g., old `symfony/http-foundation`, `phpmailer`, `twig`). | Run `composer audit` or check `snyk.io`/`OSS Index`. |
| PHP extensions (e.g., outdated `imagick`, `gd`). | Verify OS package versions. |

---

## 10. Insufficient Logging & Monitoring
| Weakness | What to verify |
|----------|----------------|
| No logging of authentication failures, admin actions, or file uploads. | Ensure logs contain timestamps, user IDs, IPs; are stored securely and rotated. |
| Log injection | User data inserted into log lines without sanitisation (can break log parsers). | Escape newline characters before logging. |

---

## How to Use This Checklist in Your Review

1. **Static Code Review** – grep/search for the risky functions (`eval`, `exec`, `system`, `passthru`, `shell_exec`, `popen`, `proc_open`, `unserialize`, `mysql_query`, `mysqli_query`, `PDO` string interpolation, `header`, `setcookie`, `phpinfo`, `display_errors`).  
2. **Configuration Audit** – dump `phpinfo()` (in a safe internal environment) and compare settings against the “Secure PHP” baseline.  
3. **Dependency Scan** – run `composer audit`, `npm audit` (if front‑end build tools are present), and OS package scanners.  
4. **Dynamic / Passive Testing** – using a proxy (Burp, OWASP ZAP, or similar) observe request/response flows: look for reflected parameters, missing anti‑CSRF tokens, insecure cookies, verbose error messages, etc.  
5. **Documentation & Reporting** – for each finding note:
   - **Location** (file, line, endpoint)  
   - **Risk rating** (based on OWASP risk‑matrix)  
   - **Remediation** (e.g., “Replace raw query with prepared statement using PDO::prepare()”)  

---

### Quick “Cheat‑Sheet” of PHP Functions to Flag

| Category | Functions to watch |
|----------|-------------------|
| Database | `mysql_*`, `mysqli_query`, `mysqli_prepare` (if not using bound params), `PDO->query` |
| OS/Exec | `exec`, `system`, `passthru`, `` ` `` , `shell_exec`, `popen`, `proc_open`, `pcntl_exec` |
| Filesystem | `file_get_contents` on user‑supplied paths, `fopen`, `readfile`, `unlink`, `copy` |
| Serialization | `unserialize`, `serialize`, `igbinary_unserialize` |
| XML | `simplexml_load_file`, `simplexml_load_string`, `DOMDocument->load`, `xml_parser_create` |
| HTTP | `header`, `setcookie`, `curl_*`, `file_get_contents` with URL wrappers |
| Eval/Code | `eval`, `create_function`, `preg_replace` with `/e` modifier, `assert` with user data |

---

### Final Note
All the items above are **theoretical** attack surfaces. During an authorized review you can:

* **Confirm** the presence of the vulnerable pattern (e.g., “`mysqli_query($db, \"SELECT * FROM users WHERE id=\" . $_GET['id']);`”).  
* **Demonstrate** the risk safely (e.g., via a proof‑of‑concept in a test environment).  
* **Recommend** a concrete fix (prepared statements, input validation, output encoding, etc.).

Feel free to adapt the list to the specific stack version (PHP 7.x vs 8.x) and any frameworks (Laravel, Symfony, CodeIgniter, WordPress, etc.) that the containerized application may be using. Good luck with your review!

---
