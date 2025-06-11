### 1. **Hardcoded Credentials**

**Description:** Detect instances where passwords or credentials are hardcoded into the source code.

**Regex Patterns:**

- **Java Properties and Assignments:**
  ```regex
  (password|passwd|pwd|secret)\s*=\s*["'][^"']{4,}["']
  ```
- **XML Configuration:**
  ```regex
  <(password|secretKey)>[^<]{4,}</\1>
  ```
- **YAML/JSON Files:**
  ```regex
  ["']?(password|passwd|pwd|secret)["']?\s*:\s*["'][^"']{4,}["']
  ```

---

### 2. **Disabled Security Settings**

**Description:** Identify configurations where security is explicitly disabled.

**Regex Patterns:**

- **General Security Disabled:**
  ```regex
  security\.enabled\s*=\s*false
  ```
- **CSRF Protection Disabled:**
  ```regex
  (?i)csrfProtection\.enabled\s*=\s*false
  ```
- **CLI Authentication Disabled:**
  ```regex
  (?i)cli\.authentication\s*=\s*false
  ```

---

### 3. **Use of Unsecured Protocols**

**Description:** Find usages of HTTP instead of HTTPS, which can expose sensitive data.

**Regex Patterns:**

- **HTTP URLs:**
  ```regex
  http://[^\s'"]+
  ```
- **Non-SSL Connectors in XML:**
  ```regex
  <Connector\s+[^>]*protocol=["']HTTP/1\.1["'][^>]*>
  ```

---

### 4. **Anonymous Access Permissions**

**Description:** Detect configurations where anonymous users are granted access.

**Regex Patterns:**

- **Granting Permissions to Anonymous:**
  ```regex
  (?i)permissions\.grant\s*\(\s*['"]?anonymous['"]?
  ```
- **Anonymous User in XML:**
  ```regex
  <user\s+name=["']anonymous["'][^>]*>
  ```
- **Authorization Strategy Set to Allow Anonymous:**
  ```regex
  (?i)new\s+FullControlOnceLoggedInAuthorizationStrategy\s*\(\s*true\s*\)
  ```

---

### 5. **Weak Cipher Suites and SSL Protocols**

**Description:** Identify configurations that use weak SSL/TLS protocols or cipher suites.

**Regex Patterns:**

- **SSL Protocols:**
  ```regex
  (?i)sslProtocol\s*=\s*["'](SSLv2|SSLv3|TLSv1|TLSv1\.1)["']
  ```
- **Cipher Suites:**
  ```regex
  (?i)cipherSuites\s*=\s*["'][^"']*(NULL|EXPORT|RC4|MD5)[^"']*["']
  ```

---

### 6. **Insecure Bindings**

**Description:** Find instances where the application binds to all network interfaces or insecure IPs.

**Regex Patterns:**

- **Binding to All Interfaces:**
  ```regex
  (?i)bindAddress\s*=\s*["']0\.0\.0\.0["']
  ```
- **XML Connector Binding:**
  ```regex
  <Connector\s+[^>]*address=["']0\.0\.0\.0["'][^>]*>
  ```

---

### 7. **Dangerous Scripting and Script Approvals**

**Description:** Detect approvals of potentially dangerous scripts or methods.

**Regex Patterns:**

- **Script Approval Entries:**
  ```regex
  scriptApproval\.approveSignature\(['"][^'"]+['"]\)
  ```
- **Approval of Dangerous Methods:**
  ```regex
  (?i)approveSignature\(['"]method\s+java\.lang\.(Runtime|System)\.[^'"]+['"]\)
  ```

---

### 8. **Missing Input Validation**

**Description:** Identify code that handles user input without proper validation or sanitization.

**Regex Patterns:**

- **Reading Unvalidated Parameters:**
  ```regex
  getParameter\(\s*["'][^"']+["']\s*\)
  ```
- **Usage Without Sanitization:**
  ```regex
  [^/]\b(getParameter|getHeader|getQueryString)\b[^\n;]*[;\n]
  ```

---

### 9. **Deprecated or Vulnerable Plugins**

**Description:** Find references to deprecated or known vulnerable plugins.

**Regex Patterns:**

- **Plugins Listed in Plugins File:**
  ```regex
  ^[^\n#]+$
  ```
  *(Cross-reference the plugin names against a list of deprecated/vulnerable plugins.)*

---

### 10. **Weak Password Policies**

**Description:** Detect configurations where password policies are weak or disabled.

**Regex Patterns:**

- **Password Policy Set to None or Weak:**
  ```regex
  (?i)passwordPolicy\s*=\s*['"](none|weak)['"]
  ```
- **Minimum Password Length Too Low:**
  ```regex
  (?i)minimumPasswordLength\s*=\s*\d{1}
  ```

---

### 11. **Master Kill Switch for Security**

**Description:** Identify instances where the security realm is set to null, effectively disabling security.

**Regex Patterns:**

- **Security Realm Disabled:**
  ```regex
  (?i)securityRealm\s*=\s*null
  ```
- **Authorization Strategy Set to Allow All:**
  ```regex
  (?i)authorizationStrategy\s*=\s*new\s+LegacyAuthorizationStrategy\s*\(\s*\)
  ```

---

### 12. **Excessive Logging of Sensitive Information**

**Description:** Find logging statements that may output sensitive data.

**Regex Patterns:**

- **Logging Passwords or Secrets:**
  ```regex
  log\.(debug|info|warn|error)\s*\(.*(password|secret|credential).*?\)
  ```
- **System Output of Sensitive Data:**
  ```regex
  System\.(out|err)\.println\s*\(.*(password|secret|credential).*?\)
  ```

---

### 13. **Unrestricted File Uploads**

**Description:** Detect file upload handling code without proper validation.

**Regex Patterns:**

- **File Upload Handling:**
  ```regex
  request\.getPart\s*\(\s*["'][^"']+["']\s*\)
  ```
- **Saving Uploaded Files Without Checks:**
  ```regex
  file\.write\s*\(.*\)
  ```

---

### 14. **Insecure Deserialization**

**Description:** Identify code that deserializes objects without validation.

**Regex Patterns:**

- **Java Deserialization:**
  ```regex
  (ObjectInputStream|XMLDecoder)\s+.*=\s+new\s+\1\s*\(.*\)
  ```
- **Reading Serialized Objects:**
  ```regex
  readObject\s*\(\s*\)
  ```

---

### 15. **Use of Eval or Execute Methods**

**Description:** Find code that uses dynamic execution methods, which can lead to code injection.

**Regex Patterns:**

- **JavaScript Eval in Jenkinsfiles:**
  ```regex
  eval\s*\(\s*[^)]+\s*\)
  ```
- **Groovy Shell Execution:**
  ```regex
  (evaluate|execute)\s*\(\s*['"][^'"]+['"]\s*\)
  ```

---

### 16. **Overly Permissive File Permissions**

**Description:** Detect file operations that set permissions to globally writable or executable.

**Regex Patterns:**

- **Setting File Permissions:**
  ```regex
  setPermissions\s*\(\s*["']?0[0-7]{3,4}["']?\s*\)
  ```
- **Chmod to 777:**
  ```regex
  chmod\s+['"]?777['"]?
  ```

---

### 17. **Improper Exception Handling**

**Description:** Find empty catch blocks or generic exception catches that can hide security issues.

**Regex Patterns:**

- **Empty Catch Blocks:**
  ```regex
  catch\s*\(\s*[^\)]*\s*\)\s*\{\s*\}
  ```
- **Catching Generic Exceptions:**
  ```regex
  catch\s*\(\s*(Exception|Throwable)\s+[^\)]+\)
  ```

---

### 18. **Use of Outdated Encryption Algorithms**

**Description:** Identify code using weak or deprecated encryption algorithms.

**Regex Patterns:**

- **MD5 or SHA1 Usage:**
  ```regex
  MessageDigest\.getInstance\s*\(\s*["'](MD5|SHA1|SHA-1)["']\s*\)
  ```
- **RSA with Short Keys:**
  ```regex
  KeyPairGenerator\.getInstance\s*\(\s*["']RSA["']\s*\).*initialize\s*\(\s*(512|768|1024)\s*\)
  ```

---

### 19. **Unvalidated Redirects and Forwards**

**Description:** Detect redirects or forwards that use unvalidated user input.

**Regex Patterns:**

- **Redirects with User Input:**
  ```regex
  response\.sendRedirect\s*\(\s*request\.getParameter\s*\(
  ```
- **Forwards with User Input:**
  ```regex
  RequestDispatcher\s+.*=\s+request\.getRequestDispatcher\s*\(\s*request\.getParameter\s*\(
  ```

---

### 20. **Server-Side Request Forgery (SSRF)**

**Description:** Find code that makes HTTP requests based on user input without validation.

**Regex Patterns:**

- **HTTP Client Usage with User Input:**
  ```regex
  (HttpClient|HttpURLConnection)\s+.*=\s+.*\(\s*request\.getParameter\s*\(
  ```
- **URL Connections with User Input:**
  ```regex
  URL\s+url\s*=\s*new\s+URL\s*\(\s*request\.getParameter\s*\(
  ```