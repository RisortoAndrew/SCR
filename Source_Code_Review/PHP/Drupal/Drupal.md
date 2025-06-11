## 1.1 Hardcoded passwords in PHP assignments

```regex
(\$[A-Za-z0-9_]*passw(or)?d\s*=\s*['"][^'"]+['"])|(\$[A-Za-z0-9_]*secret\s*=\s*['"][^'"]+['"])
```

**Explanation**

- Searches for variables in PHP files whose names contain “passwd,” “password,” or “secret” and that are assigned string literals.

**Example**

```php
$admin_password = 'SuperSecret123';
$mysecret = "AnotherSecretValue";
```

**Security Impact**  
Hardcoding passwords in version control can lead to credential leaks.

---

## 1.2 API keys or tokens in PHP code

```regex
(\$[A-Za-z0-9_]*key\s*=\s*['"][^'"]+['"])|(\$[A-Za-z0-9_]*(token|apikey)\s*=\s*['"][^'"]+['"])
```

**Explanation**

- Looks for variables named “key,” “token,” or “apikey,” assigned to a quoted string.

**Example**

```php
$google_api_key = "AIzaSyA-EXAMPLEKEY-1234";
$auth_token = 'eyJD...abcd1234';
```

**Security Impact**  
API keys can allow unauthorized access to third-party services or internal APIs.

---

## 1.3 Connection strings or database credentials in `settings.php`

```regex
['"]database['"]\s*=>\s*['"].+['"].+['"]username['"]\s*=>\s*['"].+['"].+['"]password['"]\s*=>\s*['"].+['"]
```

**Explanation**

- Matches typical `$databases` array entries in Drupal’s `settings.php` file that define `database`, `username`, and `password`.
- This **won’t catch** every variant, but it can highlight suspicious or older direct credentials.

**Example**

```php
$databases['default']['default'] = [
  'database' => 'drupal_db',
  'username' => 'drupal_user',
  'password' => 'drupal_pass123',
  'host' => 'localhost',
  'driver' => 'mysql',
];
```

**Security Impact**  
Exposing DB credentials in repos or insecure backups can compromise the entire Drupal site.

---

## 1.4 YAML-based secrets (e.g., in `.env.yml` or “services” config)

```regex
(password|secret|token|api_key|auth_key|private_key|credential):\s*['"]?[^'"\n]+['"]?
```

**Explanation**

- Searches for YAML key-value pairs where the key contains sensitive terms.
- Note that Drupal 9+ uses YAML for configuration, but production secrets usually go in `settings.php`. This pattern can still catch custom or third-party YAML-based secrets.

**Example**

```yaml
my_custom_module:
  secret: 'SomethingSensitive'
  token: abc123XYZ
```

**Security Impact**  
Leaked YAML config with secrets can give attackers direct access to privileged services.

---

# 2. Debug or Development Settings Left Enabled

When Drupal is running in production, certain developer or debug settings (e.g., verbose error display, debug modules like `devel`, or dev services) should be disabled.

## 2.1 Detection of `devel` module references

```regex
['"](devel|webprofiler)['"]\s*:\s*['"](\^?\d+(\.\d+)*|\*)['"]
```

**Explanation**

- This pattern looks for a typical composer.json entry referencing `devel` or `webprofiler` modules.
- Adjust to also search for these modules in `.info.yml` or `.module` references.

**Example**

```json
"require-dev": {
  "drupal/devel": "^4.1",
  "drupal/webprofiler": "^4.1"
}
```

**Security Impact**  
Leaving dev modules installed in production can expose debug info, performance data, or additional attack surfaces.

---

## 2.2 Error/Debug settings in `settings.php`

```regex
(\$config\['system.logging'\]\['error_level'\]\s*=\s*'verbose')|(\$settings\['php_storage_overrides'\])
```

**Explanation**

- Searches for known debug-level logging settings or advanced dev overrides in `settings.php`.
- `error_level = 'verbose'` indicates that full debug messages are displayed.

**Example**

```php
$config['system.logging']['error_level'] = 'verbose';
```

**Security Impact**  
Verbose errors can reveal sensitive paths, database schemas, or user info.

---

# 3. Misconfigured Trusted Host Settings

Drupal includes `$settings['trusted_host_patterns']` to protect against HTTP Host header attacks.

## 3.1 Missing or commented-out trusted host patterns

```regex
(\$settings\['trusted_host_patterns'\].*?#.*?$)|(\$settings\['trusted_host_patterns'\]\s*=\s*\[\s*\])
```

**Explanation**

- Searches for lines where `trusted_host_patterns` is either commented out or assigned an empty array, meaning it’s disabled.
- Use multiline regex if needed, or do separate checks for presence/absence.

**Example**

```php
// $settings['trusted_host_patterns'] = ['^www\.example\.com$'];
$settings['trusted_host_patterns'] = [];
```

**Security Impact**  
An empty or missing `trusted_host_patterns` can allow host header spoofing and potential injection or cache poisoning.

---

# 4. Missing or Insecure Security Headers

Often configured at the server or `.htaccess` level, but some may appear in custom Drupal modules or `settings.php`.

## 4.1 Searching for `header()` calls without secure directives

```regex
header\s*\(\s*['"]Content-Security-Policy:?
```

**Explanation**

- Finds references to setting the `Content-Security-Policy` header.
- Use negative lookups or additional logic if you want to find _missing_ CSP calls. Realistically, you might invert the search: “Find all `header(` calls, then manually check if CSP is present.”

**Example**

```php
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline';");
```

**Security Impact**  
Not setting CSP and other headers (X-Frame-Options, X-Content-Type-Options, etc.) can leave your site vulnerable to XSS or clickjacking.

---

# 5. Overly Permissive File Permissions or .htaccess Issues

Regex can only partially detect file-permission logic in code or .htaccess directives. You might also grep for suspicious numeric permissions or missing protective lines in `.htaccess`.

## 5.1 Searching for chmod calls with `777` or `755`

```regex
chmod\s*\([^,]+,\s*(0777|0755|0[0-7]{3})
```

**Explanation**

- Identifies PHP `chmod()` calls that set broad permissions.
- Real risk depends on context, but `0777` is especially dangerous in multi-tenant environments.

**Example**

```php
chmod($file_path, 0777);
```

**Security Impact**  
Excessively permissive rights can let other users on the server read/modify sensitive files.

---

## 5.2 Checking `.htaccess` references to “Deny from all”

```regex
(?i)^\s*deny\s+from\s+all
```

**Explanation**

- Case-insensitive search for lines that explicitly block access.
- In Drupal’s default `.htaccess`, we expect to see rules blocking direct access to certain files (e.g., `settings.php` backups). Searching for missing lines is trickier but you can search for the presence or correctness of these lines.

**Example**

```apache
<FilesMatch "(settings\.php|\.htaccess)">
  Deny from all
</FilesMatch>
```

**Security Impact**  
If `.htaccess` rules are removed or incomplete, private files or backups could be directly accessed via the browser.

---

# 6. Overly Generous User Roles & Permissions

Drupal permissions are typically declared in `.info.yml` or in code by hooking `hook_permission()`. Overly broad permissions often aren’t trivially found by regex, but you can still spot check known permissions.

## 6.1 Searching for suspicious permission definitions

```regex
'administer site configuration'|'administer users'|'administer content'
```

**Explanation**

- Highlights lines of code or YAML referencing high-level Drupal permissions that might be inadvertently granted to non-administrative roles.
- You’ll likely need to read your `my_module.permissions.yml` or `hook_permission()` definitions carefully.

**Example**

```yaml
my_module.admin:
  title: 'Administer My Module'
  description: 'Grants all privileges in My Module'
  restrict: TRUE
```

**Security Impact**  
Giving normal users “administer” powers can lead to privilege escalation or site defacement.

---

# 7. Failure to Use Drupal Form API / CSRF Protections

Custom forms that bypass the Drupal Form API or skip token checks can be vulnerable to CSRF.

## 7.1 Direct usage of `$_POST` or `$_GET` in modules

```regex
\$_(POST|GET)\s*\[
```

**Explanation**

- Searches for direct superglobal references in `.module`, `.php`, `.inc` files.
- Drupal best practice: use `$form`, `$form_state`, or the `Request` object.

**Example**

```php
$user_input = $_POST['user_data'];
```

**Security Impact**  
Skipping Drupal’s built-in sanitization and CSRF tokens can enable cross-site request forgery or injection attacks.

---

# 8. Insecure File Upload Handling

Allowing arbitrary file extensions or failing to sanitize uploaded filenames can lead to remote code execution or data exposure.

## 8.1 Searching for `move_uploaded_file` without extension checks

```regex
move_uploaded_file\s*\([^,]+,\s*\$?\w*\s*\.\s*['"]\.[^'"]+['"]
```

**Explanation**

- Finds code that directly uses `move_uploaded_file()` and appends the original extension without filtering.
- In Drupal, file handling typically uses the File/Stream APIs, but custom code might do this.

**Example**

```php
move_uploaded_file($_FILES['upload']['tmp_name'], $destination . '.' . $_FILES['upload']['name']);
```

**Security Impact**  
If `.php` files are allowed, an attacker could execute arbitrary code on the server.

---

# 9. Potential XSS via Unescaped Output

Drupal’s theming and rendering system encourages using `check_plain()`, `Html::escape()`, or Twig’s `|e` filter. Directly echoing user data can cause XSS.

## 9.1 Direct “echo” or “print” of variables in PHP/Drupal modules

```regex
(?<!\/\/)\s*(echo|print)\s*\$[A-Za-z0-9_]+
```

**Explanation**

- Searches for echo/print statements referencing variables. Skips lines commented with `//` in a crude manner, but might yield false positives.
- Then manually verify if the variable was sanitized first.

**Example**

```php
echo $user_comment;
print $input_value;
```

**Security Impact**  
Unescaped user input in HTML can enable XSS.

---

# 10. Direct SQL Queries (Possible SQL Injection)

Drupal has a Database API providing parameterized queries. Hand-crafted SQL strings with user input concatenation can be vulnerable.

## 10.1 Raw `db_query()` calls with string concatenation

```regex
db_query\s*\(\s*["'].*\.\$_(GET|POST)
```

**Explanation**

- Searches for `db_query("SELECT ...".$\_GET/...`.
- Not perfect, but a typical sign of unsafe string concatenation.

**Example**

```php
db_query("SELECT uid, name FROM {users} WHERE uid = " . $_GET['uid']);
```

**Security Impact**  
Allows attackers to inject SQL if the input isn’t sanitized.

---

# Additional Examples & Notes

Many other items (e.g., “Running unsupported versions of Drupal,” “Not applying security patches,” “No HSTS,” “Weak session configuration,” “Neglected logs or intrusion detection,” etc.) are **not reliably caught by regex**. For instance:

- **Unsupported Drupal versions**: Check your `composer.json` or Drupal core `CHANGELOG.txt` for the version string, or use `drush status`.
    
- **Lack of HSTS**: Typically a webserver config (`.htaccess`, `nginx.conf`) matter. You can search for the header line:
    
    ```regex
    header\s*\(\s*['"]Strict-Transport-Security
    ```
    
    but you must confirm it’s configured for production.
    
- **Weak or default credentials**: A regex can’t guess if your password is “admin123.” That requires manual review or automated password audits.
    
- **Missing security advisories**: This requires checking the [official Drupal Security Advisories](https://www.drupal.org/security) or using a Composer security scanner (`composer audit`)—not just searching code.