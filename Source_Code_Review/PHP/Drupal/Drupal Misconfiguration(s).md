## 1. Hardcoded Secrets / Credentials

**Issue**  
Drupal sites commonly store configuration in `settings.php`, `settings.local.php`, or custom modules. Developers may unintentionally embed sensitive info—like database credentials, API keys, tokens, or private keys—directly within PHP, YAML, or JSON files.

**Sample Regex Patterns**

### 1A. PHP variables containing sensitive keywords

```
\$.*(pass|secret|token|api[_-]?key|credential|auth|private[_-]?key|db[_-]?pass)\s*=\s*['"]
```

- **Explanation**
    - Searches for PHP variables (e.g., `$my_db_pass`, `$apiKey`, `$secretToken`) assigned to a string.
    - Use `[Pp][Aa][Ss][Ss]` if you need case-insensitive searching.
    - You can enable case-insensitivity in VS Code’s search if you prefer.

#### Example Code Snippet That Matches

```php
<?php
$my_db_pass = 'SuperSecretPass123';
$apiKey = "abc123token";
```

**Security Impact**: An attacker who sees these secrets can log into databases or external services, potentially escalating to a full system compromise.

---

### 1B. YAML or JSON references to “secret” keywords

```
(pass|secret|token|api[_-]?key|credential|private[_-]?key|db[_-]?pass)["']?\s*:\s*["'][^"']+
```

- **Explanation**
    - Captures lines like `db_pass: "mypassword"` or `api_key: 'abcdef'`.
    - Matches typical key-value structures in YAML/JSON.

#### Example Code Snippet That Matches

```yaml
my_module:
  db_pass: "HardCodedP@ss!"
  api_key: "XYZ123Token"
```

**Security Impact**: Storing credentials in plain text or version-controlled YAML/JSON can expose them to anyone with repository read access.

---

## 2. Overly Broad Permissions / Access Controls

**Issue**  
In Drupal, permissions and access controls are often defined in `.permissions.yml` or `.routing.yml`. Overly broad settings like `'_permission': '.*'` or `'access: TRUE'` can expose admin-level privileges or sensitive routes to all users.

**Sample Regex Patterns**

### 2A. Catch-all permissions or “access callback => TRUE”

```
(_permission['"]?\s*:\s*['"]\\\.\\\*['"])|(access\s*:\s*TRUE)|(access\s*=>\s*TRUE)
```

- **Explanation**
    - Matches:
        - `'_permission': '.*'` (regex that grants all permissions)
        - `access: TRUE` or `access => TRUE` in routes or hook_menu definitions.

#### Example Code Snippet That Matches

```yaml
mymodule.route:
  path: '/admin/big-danger'
  defaults:
    _controller: '\Drupal\mymodule\Controller\SecretController::danger'
  requirements:
    _permission: '.*'
```

```php
function mymodule_menu() {
  $items['big-danger'] = [
    'title' => 'Secret Admin Access',
    'page callback' => 'mymodule_danger_callback',
    'access callback' => TRUE,
  ];
  return $items;
}
```

**Security Impact**: Any user (including anonymous) could access sensitive functionality, leading to privilege escalation or data leakage.

---

### 2B. Permissions specifying high-level roles carelessly

```
(permission|roles?)['"]?\s*:\s*\[\s*['"](administrator|admin|.*super.*)['"]
```

- **Explanation**
    - Flags lines like `roles: ['administrator']` or `permission: ['super admin']`, which might be used incorrectly or too broadly.

#### Example Code Snippet That Matches

```yaml
mymodule.permissions:
  roles: ['administrator']
```

**Security Impact**: Over-granting the `administrator` or similarly high-privileged roles can expose dangerous operations to undesired user groups.

---

## 3. Dangerous PHP Function Calls (Custom Modules/Themes)

**Issue**  
Custom Drupal modules or themes might inadvertently use dangerous PHP functions like `eval()`, `exec()`, `passthru()`, `shell_exec()`, or `popen()`.

**Sample Regex Patterns**

### 3A. Dangerous function usage

```
\b(eval|exec|passthru|shell_exec|popen|proc_open|system)\s*\(
```

- **Explanation**
    - Matches the call to dangerous PHP functions, ignoring whitespace between function name and parentheses.

#### Example Code Snippet That Matches

```php
<?php
$output = shell_exec('ls -al /var/www');
```

**Security Impact**: Attackers could inject system commands if these functions process user input unsafely, leading to remote code execution on the server.

---

## 4. Disabled CSRF Form Protections

**Issue**  
Drupal’s Form API includes built-in CSRF tokens. Developers may disable token validation, leaving forms vulnerable to Cross-Site Request Forgery.

**Sample Regex Patterns**

### 4A. Disabling form token / skipping validation

```
\$form_state->(disableTokenValidation|setNoToken|setValidationTrigger)\s*\(
```

- **Explanation**
    - Flags suspicious calls to skip or disable Drupal’s default CSRF protection in custom forms.

#### Example Code Snippet That Matches

```php
function mymodule_form($form, &$form_state) {
  $form_state->disableTokenValidation(TRUE);
  ...
}
```

**Security Impact**: An attacker can trick authenticated users into submitting malicious requests, potentially modifying site content or user data without authorization.

---

## 5. Insecure File Upload Configurations

**Issue**  
Drupal modules often handle file uploads. Misconfigurations allowing executable extensions, skipping file validation, or storing files in public directories can lead to code execution or data breaches.

**Sample Regex Patterns**

### 5A. Permissive file upload extensions

```
'file_extensions'\s*=>\s*['"]([^'"]*(php|phar|phtml|asp|exe|sh|cgi)[^'"]*)['"]
```

- **Explanation**
    - Matches a typical Drupal `$form['#upload_validators']` or `file_upload` definition that includes dangerous extensions.

#### Example Code Snippet That Matches

```php
$form['uploaded_file'] = [
  '#type' => 'managed_file',
  '#upload_location' => 'public://uploads/',
  '#upload_validators' => [
    'file_validate_extensions' => ['php phtml exe sh'],
  ],
];
```

**Security Impact**: Attackers could upload malicious executables or scripts, leading to remote code execution or pivoting to other systems.

---

### 5B. Skipping file validation altogether

```
(file_validate_extensions|file_validate_size)\s*=>\s*\(\s*\)
```

- **Explanation**
    - Detects an empty array or parentheses, meaning no validation rules are provided.

#### Example Code Snippet That Matches

```php
'#upload_validators' => [
  'file_validate_extensions' => (),
],
```

**Security Impact**: If no validation is done, any file type can be uploaded, including potentially harmful files.

---

## 6. Improper Cache / Page Caching Settings

**Issue**  
Drupal’s page caching or render caching can cause leakage of private or user-specific data if misconfigured.

**Sample Regex Patterns**

### 6A. Disabling cache control in modules

```
->setMaxAge\s*\(\s*0\s*\)|->setCacheMaxAge\s*\(\s*0\s*\)
```

- **Explanation**
    - Identifies code forcibly disabling caching or setting it to zero. This might be valid for some content, but it’s risky if it leads to ignoring user roles or access checks.

#### Example Code Snippet That Matches

```php
$response->setMaxAge(0);
$response->setCacheMaxAge(0);
```

**Security Impact**: If used incorrectly, can hamper performance or cause confusion about which data is private vs. public. In other contexts, incorrectly enabling or disabling caching might leak user data.

---

### 6B. Overly permissive or missing cache context

```
'#cache'\s*=>\s*\[\s*(['"]contexts['"]\s*=>\s*\[\])\s*\]
```

- **Explanation**
    - Flags empty or missing cache contexts, meaning the cache might not account for user roles, languages, or other important differences.

#### Example Code Snippet That Matches

```php
$build['#cache'] = [
  'contexts' => [],
];
```

**Security Impact**: Pages that should vary per-user may end up cached and shared publicly, causing sensitive data disclosure.

---

## 7. Insecure or Disabled Security Modules / Middleware

**Issue**  
Drupal ships with or supports security-related modules (e.g., Security Kit, Automated Logout). If they are disabled (or forcibly bypassed), you lose layers of protection.

**Sample Regex Patterns**

### 7A. Disabled security modules in `core.extension.yml`

```
security_kit:\s*0|automated_logout:\s*0|content_access:\s*0
```

- **Explanation**
    - Looks for known security modules set to `0` in `core.extension.yml`, indicating they are disabled.

#### Example Code Snippet That Matches

```yaml
module:
  security_kit: 0
  automated_logout: 0
```

**Security Impact**: Without these protective modules, the application may be exposed to XSS, CSRF, or session hijacking attacks.

---

### 7B. Force-disable in settings

```
['"]module_disable['"]\s*=>\s*\[\s*['"](security_kit|automated_logout|content_access)['"]
```

- **Explanation**
    - Custom code forcibly disabling modules in a site-wide configuration array.

#### Example Code Snippet That Matches

```php
$settings['module_disable'] = [
  'security_kit',
  'automated_logout',
];
```

**Security Impact**: Disabling security modules across the entire site can open significant attack vectors.

---

## 8. Insecure External Service Calls (HTTP/Unvalidated)

**Issue**  
Drupal modules or custom code might call external APIs or services over plain HTTP or handle responses insecurely.

**Sample Regex Patterns**

### 8A. Plain HTTP usage

```
(['"]http://[^'"]+['"])
```

- **Explanation**
    - Captures any string containing `http://`, which could indicate an insecure API endpoint or external resource.

#### Example Code Snippet That Matches

```php
$ch = curl_init("http://insecure-remote-service.com/api/endpoint");
```

**Security Impact**: Attackers can perform man-in-the-middle attacks, injecting or tampering with data in transit, compromising the site or user data.

---

### 8B. Skipping certificate/SSL checks in Guzzle or cURL

```
'verify'(\s*=>\s*false)|CURLOPT_SSL_VERIFYPEER\s*,\s*0
```

- **Explanation**
    - Identifies code explicitly disabling SSL verification in Guzzle (`'verify' => false`) or cURL (`CURLOPT_SSL_VERIFYPEER, 0`).

#### Example Code Snippet That Matches

```php
$client = new Client([
  'verify' => false,
]);
```

**Security Impact**: Leaves communication susceptible to spoofing or man-in-the-middle attacks, potentially leading to credential theft or malicious data injection.

---

## 9. Hardcoded Environment Paths / Executable Calls

**Issue**  
Custom or contributed Drupal code might rely on absolute paths to system commands (like `mysqldump`) or other environment-specific resources. If these are world-writable or incorrectly validated, attackers could escalate privileges.

**Sample Regex Patterns**

### 9A. Direct references to /bin, /usr/bin, or \Windows\System32

```
(["'])(/usr/bin/|/bin/|C:\\Windows\\System32\\)[^"']+\1
```

- **Explanation**
    - Captures strings with direct references to common OS directories.

#### Example Code Snippet That Matches

```php
$backup_command = "/usr/bin/mysqldump -u drupal --password=secret drupal_db > /tmp/backup.sql";
```

**Security Impact**: If an attacker can replace these binaries or manipulate arguments, they may escalate privileges or cause data corruption.

---

### 9B. Shell or Exec calls referencing dangerous system paths

```
(exec|shell_exec|system)\s*\(\s*["'].*(mysqldump|tar|cp|rm|wget|curl).*
```

- **Explanation**
    - Flags usage of external commands with potentially destructive or high-impact tools.

#### Example Code Snippet That Matches

```php
$output = exec("/usr/bin/tar -zcvf /tmp/site.tar.gz /var/www/drupal");
```

**Security Impact**: Attackers who control parameters could pivot to local privilege escalation or data destruction.

---

## 10. Logging Sensitive Data (e.g., PII) in Watchdog or Debug Statements

**Issue**  
Developers sometimes log sensitive user info (passwords, tokens, personal data) to the Drupal watchdog, custom logs, or debug outputs. This can lead to data exposure if logs are compromised.

**Sample Regex Patterns**

### 10A. Logging passwords or tokens to watchdog()

```
watchdog\s*\(\s*['"][^'"]*(pass|secret|token|api|credential|auth)['"]
```

- **Explanation**
    - Identifies calls to Drupal’s `watchdog()` function that include sensitive keywords in the log message.

#### Example Code Snippet That Matches

```php
watchdog('mymodule', 'User password reset token: ' . $token);
```

**Security Impact**: Password tokens or secret strings can appear in logs, which attackers or unauthorized staff can read, enabling privilege escalation or lateral moves.

---

### 10B. Drupal debug statements referencing sensitive data

```
(dpm|dsm|kint)\s*\(\s*\$?[A-Za-z0-9_]*(pass|secret|token|api|credential|auth)
```

- **Explanation**
    - Matches certain debug calls (e.g., `dpm()`, `dsm()`, or `kint()`) that include variables with sensitive keywords.

#### Example Code Snippet That Matches

```php
dpm($apiSecretToken, 'Debugging secret token');
```

**Security Impact**: If debug output is viewed on a production system, it can leak secrets to staff, logs, or attackers monitoring debug data.