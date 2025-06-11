### 1A. Simple assignment of secret-like variables

```
(password|passwd|pwd|secret|token|api_key)\s*=\s*['"][^'"]+['"]
```

- **Explanation**
    
    - Looks for variable names containing common secret keywords.
        
    - Matches assignments to string literals.
        

#### Example Code Snippet That Matches

```python
db_password = "MySuperSecret123!"
api_key = 'ABCD-1234-EFGH-5678'
secret_token="s3cr3t"
```

**Security Impact**: Exposed credentials in source control allow attackers with read access to immediately compromise external systems.

---

### 1B. Direct indexing of config or environment dicts

```
(?:os\.environ|getenv|config)\s*\(\s*['"](PASSWORD|SECRET|TOKEN|API_KEY)['"]\s*\)
```

- **Explanation**
    
    - Captures calls to `os.environ(...)`, `getenv(...)`, or a generic `config(...)` helper retrieving secret names.
        
    - Both uppercase and lowercase keywords will match, depending on implementation.
        

#### Example Code Snippet That Matches

```python
import os
db_pass = os.environ("DB_PASSWORD")
token = getenv("SECRET_TOKEN")
config("API_KEY")
```

**Security Impact**: Hardcoded references betray the exact environment variables or config keys an attacker needs to hijack.

---

### 1C. Formatting secrets into strings (e.g., f-strings)

```
f?['"][^'"]*(password|secret|token|api_key)[^'"]*['"]\s*%?\s*["{]
```

- **Explanation**
    
    - Detects string literals (including f-strings) containing secret keywords.
        
    - Flags constructions like `f"…{password}…"` or `"%s %s"%(token, …)`.
        

#### Example Code Snippet That Matches

```python
print(f"Database password is {db_password}")
conn_str = "Server=...;Pwd=%s;" % api_key
```

**Security Impact**: Logging or printing secrets leaks them to stdout or logs, where they may be harvested.

---

## 2. Weak Authentication Mechanisms

**Issue**  
Using simplistic authentication schemes or hardcoded credentials undermines trust in identity checks:

- **HTTP Basic Auth** with static credentials.
    
- **Custom “token” schemes** with predictable formats.
    
- **Lack of rate limiting or account lockout**.
    

**Sample Regex Patterns**

### 2A. Use of HTTP Basic Auth in requests

```
requests\.(get|post|put|delete)\s*\([^,]+,\s*auth\s*=\s*\([^,]+,\s*[^)]+\)
```

- **Explanation**
    
    - Flags any `requests` call passing an `auth=(user, pass)` tuple.
        
    - Often indicates Basic Auth over potentially unencrypted channels.
        

#### Example Code Snippet That Matches

```python
import requests
r = requests.get("https://api.example.com/data", auth=("admin", "password123"))
```

**Security Impact**: Credentials travel in cleartext (even over HTTPS they’re Base64‑encoded) and can be replayed if intercepted.

---

### 2B. Hardcoded Authorization headers

```
Authorization\s*=\s*['"]Basic\s+[A-Za-z0-9+/=]+['"]
```

- **Explanation**
    
    - Matches assignment of a static “Basic …” header value.
        
    - Captures Base64‑encoded credentials embedded in code.
        

#### Example Code Snippet That Matches

```python
headers = {
    "Authorization": "Basic YWRtaW46cGFzc3dvcmQxMjM="
}
```

**Security Impact**: Embeds secrets client‑side; any compromise of the code reveals the entire auth scheme.

---

## 3. Missing Authentication Checks

**Issue**  
Endpoints or functions exposed without verifying user identity allow anonymous access:

- **Unprotected Flask/Django routes**.
    
- **Missing decorator-based guards** (e.g. `@login_required`).
    
- **Function-level checks omitted**.
    

**Sample Regex Patterns**

### 3A. Flask route definitions

```
@app\.route\([^)]*\)\s*def\s+\w+\s*\(
```

- **Explanation**
    
    - Finds any Flask `@app.route(...)`-decorated function.
        
    - Manual review needed to confirm presence of `@login_required`.
        

#### Example Code Snippet That Matches

```python
@app.route('/admin/dashboard')
def dashboard():
    return render_template('dashboard.html')
```

**Security Impact**: Endpoints without auth checks may be invoked by anyone, leading to data disclosure or privilege escalation.

---

### 3B. Django view definitions without login decorators

```
def\s+\w+\s*\(.*request.*\):\s*(?!.*@login_required)
```

- **Explanation**
    
    - Identifies view functions accepting `request` but not preceded by `@login_required`.
        
    - May produce false positives; use as a starting point.
        

#### Example Code Snippet That Matches

```python
def profile(request):
    # No @login_required decorator above
    return render(request, 'profile.html')
```

**Security Impact**: Publicly accessible pages leak personal or sensitive data when auth controls are absent.

---

## 4. Broken Access Control / Authorization Bypasses

**Issue**  
Logic flaws or oversights that let users perform actions beyond their privileges:

- **Role checks by string comparison** (brittle).
    
- **Hardcoded “admin” flags** granting unrestricted access.
    
- **Backdoor methods** that always return true.
    

**Sample Regex Patterns**

### 4A. Role comparison against plaintext

```
if\s+user\.(role|is_admin)\s*==\s*['"](admin|superuser|root)['"]
```

- **Explanation**
    
    - Finds code checking for specific role values in a brittle manner.
        
    - Hard to maintain and easy to bypass if values change.
        

#### Example Code Snippet That Matches

```python
if user.role == "admin":
    perform_sensitive_action()
```

**Security Impact**: Attackers who can manipulate `user.role` can escalate to admin functionality.

---

### 4B. Backdoor functions always returning true

```
def\s+\w*is_admin\w*\s*\(.*\)\s*:\s*return\s+True
```

- **Explanation**
    
    - Flags any `is_admin`-style function that unconditionally returns `True`.
        
    - Common “backdoor” left for debugging or tests.
        

#### Example Code Snippet That Matches

```python
def is_admin(user):
    return True  # Backdoor
```

**Security Impact**: Grants full privileges to all users, effectively disabling RBAC.

---

## 5. Insecure Session and Cookie Management

**Issue**  
Poorly configured cookies and session stores expose session tokens:

- **Missing Secure/HttpOnly flags**.
    
- **Storing session data client‑side without encryption**.
    
- **Using pickle or other unsafe serializers**.
    

**Sample Regex Patterns**

### 5A. Setting cookies without flags

```
response\.set_cookie\s*\([^,]+,[^)]*\)
```

- **Explanation**
    
    - Catches any `set_cookie(...)` call.
        
    - Must review for absence of `secure=True` and `httponly=True`.
        

#### Example Code Snippet That Matches

```python
resp = make_response(render_template(...))
resp.set_cookie('sessionid', session_token)
```

**Security Impact**: Cookies vulnerable to interception (no Secure) or client‑side access (no HttpOnly), leading to session hijacking.

---

### 5B. Disabling security flags in Flask config

```
app\.config\[['"]SESSION_COOKIE_SECURE['"]\]\s*=\s*False
```

- **Explanation**
    
    - Identifies explicit turning off of `SESSION_COOKIE_SECURE`.
        
    - Similar patterns apply to `SESSION_COOKIE_HTTPONLY`.
        

#### Example Code Snippet That Matches

```python
app.config['SESSION_COOKIE_SECURE'] = False
app.config["SESSION_COOKIE_HTTPONLY"] = False
```

**Security Impact**: Weakens protection of session cookies, making them accessible over HTTP or via JavaScript.

---

## 6. Insecure Cryptographic Functions and Hashing

**Issue**  
Use of outdated or broken cryptographic primitives undermines password storage and data integrity:

- **MD5 or SHA1** for password hashing.
    
- **Static salts** or none at all.
    
- **Symmetric encryption with weak algorithms**.
    

**Sample Regex Patterns**

### 6A. MD5 hashing

```
hashlib\.md5\s*\(
```

- **Explanation**
    
    - Flags any use of MD5 from Python’s `hashlib`.
        
    - MD5 is considered cryptographically broken.
        

#### Example Code Snippet That Matches

```python
hashed = hashlib.md5(password.encode()).hexdigest()
```

**Security Impact**: MD5-hashed passwords are vulnerable to collision attacks and rainbow‑table cracking.

---

### 6B. SHA1 hashing

```
hashlib\.sha1\s*\(
```

- **Explanation**
    
    - Finds usage of SHA‑1, which is also deprecated for security-sensitive use.
        

#### Example Code Snippet That Matches

```python
digest = hashlib.sha1(data).digest()
```

**Security Impact**: SHA‑1 is vulnerable to collision attacks; data integrity or password storage can be broken.

---

## 7. Insecure Token and JWT Handling

**Issue**  
Misconfigured token libraries allow forgery or replay:

- **Decoding JWTs without signature verification**.
    
- **Accepting `alg: none`** as a valid algorithm.
    
- **Storing tokens in insecure locations**.
    

**Sample Regex Patterns**

### 7A. Decoding without verification

```
jwt\.decode\s*\(\s*[^,]+,\s*None
```

- **Explanation**
    
    - Matches calls where the `key` parameter to `jwt.decode` is explicitly `None`.
        
    - Skips signature verification entirely.
        

#### Example Code Snippet That Matches

```python
payload = jwt.decode(token, None, algorithms=['HS256'])
```

**Security Impact**: Any token can be crafted by an attacker, granting arbitrary access.

---

### 7B. Explicit disabling of signature verification

```
options\s*=\s*\{[^}]*['"]verify_signature['"]\s*:\s*False[^}]*\}
```

- **Explanation**
    
    - Flags use of the `options={'verify_signature': False}` override.
        

#### Example Code Snippet That Matches

```python
data = jwt.decode(token, secret, algorithms=['HS256'], options={'verify_signature': False})
```

**Security Impact**: Signature checks are skipped, allowing token forgery and privilege escalation.

---

## 8. CSRF Protection Missing in Auth Endpoints

**Issue**  
Authentication forms without CSRF tokens let attackers perform login CSRF or state-changing requests:

- **Django views missing `@csrf_protect`**.
    
- **Flask forms without `Flask-WTF` CSRF tokens**.
    
- **APIs accepting POST without CSRF checks**.
    

**Sample Regex Patterns**

### 8A. Django view lacking CSRF decorator

```
@(?:login_required|api_view\([^)]*\))\s*\n(?!@csrf_protect)
```

- **Explanation**
    
    - Finds login or API views not immediately preceded by `@csrf_protect`.
        

#### Example Code Snippet That Matches

```python
@login_required
def change_password(request):
    # No @csrf_protect above
    ...
```

**Security Impact**: Attackers can trick authenticated users into changing passwords or session data.

---

### 8B. Flask route without CSRF integration

```
@app\.route\([^)]*methods=['"]POST['"][^)]*\)\s*def\s+\w+
```

- **Explanation**
    
    - Identifies POST routes in Flask; must manually verify use of CSRF tokens.
        

#### Example Code Snippet That Matches

```python
@app.route('/login', methods=['POST'])
def login():
    # No CSRF token handling
    ...
```

**Security Impact**: Login CSRF can cause users to authenticate under attacker‑controlled accounts or leak credentials.

---

## 9. Insecure Direct Object References (IDOR)

**Issue**  
Direct use of user-supplied identifiers without authorization checks allows data from other users:

- **File or record IDs** passed directly without verifying ownership.
    
- **URLs exposing sequential IDs** (e.g., `/user/123/profile`).
    
- **Missing checks in ORM queries**.
    

**Sample Regex Patterns**

### 9A. Querying by parameter without filter

```
Model\.objects\.get\(\s*id\s*=\s*request\.args\[['"]id['"]\]\s*\)
```

- **Explanation**
    
    - Matches Django ORM lookups using `request.args['id']` directly.
        

#### Example Code Snippet That Matches

```python
profile = UserProfile.objects.get(id=request.args['id'])
```

**Security Impact**: Users can iterate IDs to access other users’ profiles or data.

---

### 9B. File access via user‑controlled path

```
open\(\s*request\.(args|get|form)\[['"][^'"]+['"]\]\s*\)
```

- **Explanation**
    
    - Detects direct `open()` calls on input from query/form parameters.
        

#### Example Code Snippet That Matches

```python
path = request.args['filename']
f = open(path, 'rb')
```

**Security Impact**: Enables IDOR and path traversal to fetch arbitrary files on disk.

---

## 10. Path Traversal in Authorization Checks

**Issue**  
Poor sanitization of file or resource paths combined with weak auth checks:

- **Using `../` or absolute paths**.
    
- **Building filesystem paths from user input**.
    
- **Missing canonicalization**.
    

**Sample Regex Patterns**

### 10A. Detection of `..` in path construction

```
(os\.path\.join|path =).*(request\.(args|get|form)\[['"][^'"]+['"]\]).*['"]\.\.['"]
```

- **Explanation**
    
    - Catches string concatenation or `path.join` where `..` appears literally.
        

#### Example Code Snippet That Matches

```python
filename = request.args['file']
path = os.path.join('/var/data', '../' + filename)
```

**Security Impact**: Attackers can break out of intended directories to access sensitive files.

---

### 10B. Absolute path usage from user input

```
open\(\s*request\.(args|get|form)\[['"][^'"]+['"]\]\s*\)
```

- **Explanation**
    
    - Flags any direct `open()` of a parameter that could contain an absolute path.
        

#### Example Code Snippet That Matches

```python
with open(request.form['config_path']) as cfg:
    data = cfg.read()
```

**Security Impact**: Enables path traversal or unauthorized file read, bypassing any auth checks.

---

## 11. Insecure OAuth and Third‑Party Authentication Configurations

**Issue**  
Misconfigured OAuth flows expose tokens or allow redirect abuses:

- **Redirect URIs using wildcards**.
    
- **Token exchange without state parameter**.
    
- **Disabling SSL verification**.
    

**Sample Regex Patterns**

### 11A. OAuth redirect URI wildcards

```
redirect_uri\s*=\s*['"][^'"]*\*[^'"]*['"]
```

- **Explanation**
    
    - Detects wildcard (`*`) in `redirect_uri`.
        

#### Example Code Snippet That Matches

```python
oauth2_session = OAuth2Session(CLIENT_ID, redirect_uri='https://example.com/*')
```

**Security Impact**: Wildcard URIs let attackers craft malicious redirect targets in phishing flows.

---

### 11B. Disabling SSL verification in OAuth or requests

```
verify\s*=\s*False
```

- **Explanation**
    
    - Catches any `verify=False` in HTTP/OAuth calls.
        

#### Example Code Snippet That Matches

```python
token = oauth.fetch_token(TOKEN_URL, verify=False)
```

**Security Impact**: Leaves token exchange or API calls susceptible to Man‑in‑the‑Middle attacks.