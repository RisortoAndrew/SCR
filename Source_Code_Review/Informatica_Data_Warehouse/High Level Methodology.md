### VS-Code Compatible Regex Patterns:
#### 1. SQL Queries (Possible SQL Injection Points)
   ```regex
   (SELECT|INSERT|UPDATE|DELETE)\s+.*(\+|\&\&|\|\|).*;?
   ```
   - **Explanation**: Matches SQL queries where concatenation (`+`, `&&`, `||`) might be used to dynamically add inputs.
   - **Use**: Detects areas where SQL queries are constructed dynamically, often leading to SQL injection risks.

#### 2. Input Validation and Sanitization Checks
   ```regex
   (input|request|param|value|query|data)\s*=\s*.*(getParameter|getQueryParam|getHeader|parse)
   ```
   - **Explanation**: Finds instances where input is retrieved, especially from user-controlled sources, without validation.
   - **Use**: Identify places where user input is obtained; review further for validation.

#### 3. Hard-Coded Secrets (Credentials, API Keys)
   ```regex
   (password|passwd|pwd|secret|token|key|private_key|api_key)\s*=\s*["'][^"']+["']
   ```
   - **Explanation**: Searches for variables commonly used to store sensitive data and flags any assignment to literals.
   - **Use**: Locate sensitive hard-coded values like credentials or tokens.

#### 4. Error and Debug Logging (Sensitive Information Exposure)
   ```regex
   (log|logger|print|console\.log)\s*\(.*(Exception|Error|trace|sql|stack|password|token).*\)
   ```
   - **Explanation**: Matches logging statements where sensitive data like SQL, tokens, or stack traces might be logged.
   - **Use**: Review these for potential information leaks, especially in production code.

#### 5. Authorization and Authentication Bypass Checks
   ```regex
   (isAuthenticated|isAuthorized|checkPermission|hasRole)\s*\(.*false.*\)
   ```
   - **Explanation**: Finds instances where authentication or authorization checks may be conditionally disabled.
   - **Use**: Helps identify places where authentication or access control might be skipped, deliberately or mistakenly.

#### 6. Data Export and Transformation (Sensitive Data Exposure)
   ```regex
   (export|write|file|send|save)\s*\(.*(csv|xls|json|xml|txt|dump).*;?
   ```
   - **Explanation**: Flags data export or file generation functions that could potentially expose data.
   - **Use**: Helps track data export paths and formats, which are prone to sensitive data leaks.

#### 7. Dynamic File or Path Creation (Directory Traversal Risk)
   ```regex
   (path|dir|file|folder)\s*=\s*(["'][^"']*["']|\w+\s*\+\s*\w+)
   ```
   - **Explanation**: Detects file path generation which may involve user input, leading to directory traversal.
   - **Use**: Ensure that file paths are properly sanitized to avoid unintended access.