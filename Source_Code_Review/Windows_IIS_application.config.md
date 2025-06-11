In IIS, some configuration sections should **never** be set to `overrideModeDefault="Allow"` in the `applicationHost.config` file for security purposes. Allowing these sections to be overridden at lower levels (e.g., site-level `web.config`) can lead to misconfigurations, exposure of sensitive data, or unauthorized access to system-level settings.

Here’s a list of critical sections and why they should typically be locked down (`overrideModeDefault="Deny"`):

---

### **1. system.webServer/security/**

- **Subsections**:
    - `authentication` (e.g., `basicAuthentication`, `windowsAuthentication`)
    - `authorization`
    - `isapiFilters`
    - `requestFiltering`
- **Reason**:
    - These control authentication and authorization settings, which are critical for securing access to resources.
    - Allowing overrides could enable unauthorized access or bypass access controls.
    - Example Exploit: A `web.config` file overriding `authorization` settings could accidentally allow unrestricted access to sensitive files or directories.

---

### **2. system.webServer/handlers**

- **Reason**:
    - Controls how requests are mapped to handlers (e.g., CGI, FastCGI, ASP.NET).
    - Misconfigured handlers can lead to remote code execution or the exposure of sensitive file contents (e.g., serving `.config` files as plaintext).
    - Example Exploit: Allowing a custom handler could expose `.aspx` or `.php` source code.

---

### **3. system.webServer/modules**

- **Reason**:
    - Defines HTTP modules that execute at different pipeline stages.
    - Overriding could enable insecure or malicious modules at the application level.
    - Example Exploit: An attacker could add a custom module that logs sensitive request headers, including authentication tokens.

---

### **4. system.webServer/serverRuntime**

- **Reason**:
    - Controls server runtime settings, such as thread limits or request queuing.
    - Misconfigurations here could affect server stability or performance, and potentially create denial-of-service conditions.

---

### **5. system.webServer/httpProtocol**

- **Reason**:
    - Governs HTTP settings like headers and keep-alive.
    - Overriding this at lower levels might introduce security vulnerabilities like enabling weak HTTP headers or disabling protections such as X-Content-Type-Options.

---

### **6. system.webServer/asp**

- **Reason**:
    - Configures classic ASP behavior.
    - Allowing changes here could expose sensitive debugging information (e.g., enabling detailed error messages).
    - Example Exploit: Enabling `EnableParentPaths` in a lower-level configuration could allow directory traversal attacks.

---

### **7. system.webServer/tracing**

- **Reason**:
    - Enables request tracing for debugging.
    - Should not be overrideable because it may expose sensitive request data (e.g., cookies, headers, query parameters).

---

### **8. system.webServer/proxy**

- **Reason**:
    - Configures proxy settings for ARR (Application Request Routing).
    - Misconfigurations could lead to open proxy abuse or improper routing of sensitive traffic.

---

### **9. system.webServer/caching**

- **Reason**:
    - Governs output caching and kernel caching.
    - Allowing overrides could result in improper caching of sensitive responses (e.g., pages containing authentication tokens).

---

### **10. system.web/sessionState**

- **Reason**:
    - Governs session state configuration, such as cookie settings and storage.
    - Misconfigured session state could enable session fixation or hijacking attacks.

---

### **11. system.web/compilation**

- **Reason**:
    - Controls the compilation of ASP.NET code.
    - Overriding could enable debugging or expose sensitive compilation information.

---

### **12. system.web/customErrors**

- **Reason**:
    - Configures custom error handling.
    - Allowing overrides could expose sensitive server information in error messages.

---

### **13. system.web/httpRuntime**

- **Reason**:
    - Governs key runtime behaviors like request validation and maximum request size.
    - Overriding could disable protections like request validation, opening the door to injection attacks.

---

### **14. system.webServer/anonymousAuthentication**

- **Reason**:
    - Controls whether anonymous access is allowed.
    - Overriding this could inadvertently allow unrestricted access to sensitive resources.

---

### **Best Practices**

- Set `overrideModeDefault="Deny"` for all critical sections in `applicationHost.config` to prevent lower-level overrides.
- Monitor and audit all `web.config` files for unauthorized changes.
- Use proper access controls to restrict who can modify configuration files.

---

### Example Configuration for Security:

```xml
<section name="system.webServer/security/authentication" overrideModeDefault="Deny" />
<section name="system.webServer/security/authorization" overrideModeDefault="Deny" />
<section name="system.webServer/handlers" overrideModeDefault="Deny" />
<section name="system.webServer/modules" overrideModeDefault="Deny" />
<section name="system.webServer/serverRuntime" overrideModeDefault="Deny" />
<section name="system.webServer/httpProtocol" overrideModeDefault="Deny" />
<section name="system.web/sessionState" overrideModeDefault="Deny" />
<section name="system.web/httpRuntime" overrideModeDefault="Deny" />
<section name="system.webServer/tracing" overrideModeDefault="Deny" />
<section name="system.webServer/anonymousAuthentication" overrideModeDefault="Deny" />
```

---

Locking down these sections ensures that site-specific configuration files (`web.config`) cannot introduce critical vulnerabilities into the server configuration.