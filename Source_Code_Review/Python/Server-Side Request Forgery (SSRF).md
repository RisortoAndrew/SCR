## 1. Dynamic URLs in `requests` helper methods

**Issue**  
`requests.get()`, `.post()`, etc. are called with user-influenced URLs.

- **Common misuse**: concatenation, f-strings, `.format()`, or a standalone variable.
    

**Sample Regex Patterns**

### 1A. Literal + variable concatenation

```regex
requests\.(get|post|put|delete|head|options)\(\s*["'`][^"'`]+["'`]\s*\+\s*\w+
```

- **Explanation**
    
    - Matches `"https://foo/" + user_input` passed to any `requests.*` helper.
        

#### Example Code Snippet That Matches

```python
requests.get("http://internal.local/resource?id=" + request.args["id"])
```

**Security Impact**: Attacker can pivot to internal hosts or cloud metadata services.

---

### 1B. `f`-string interpolation

```regex
requests\.(get|post|put|delete|head|options)\(\s*f["'`][^"'`]*\{[^}]+\}[^"'`]*["'`]
```

- **Explanation**
    
    - Captures `f"https://{host}/api"` style URLs.
        

#### Example

```python
requests.post(f"http://{tenant_domain}/callback")
```

**Security Impact**: Hostname is fully attacker controlled.

---

### 1C. `.format()` substitution

```regex
requests\.(get|post|put|delete|head|options)\(\s*["'`][^"'`]*\{[^}]+\}[^"'`]*["'`]\.format\(
```

- **Explanation**
    
    - Finds `"http://{host}/".format(host=var)`.
        

#### Example

```python
requests.delete("https://{region}.api.internal/v1".format(region=r))
```

**Security Impact**: Same as above—internal network reach-through.

---

### 1D. Variable-only URL

```regex
requests\.(get|post|put|delete|head|options)\(\s*\w+\s*\)
```

- **Explanation**
    
    - A single variable (no literal) is the first positional argument.
        

#### Example

```python
requests.get(target_url)     # target_url comes from JSON body
```

**Security Impact**: Full URL path is attacker supplied.

---

## 2. `requests.request()` with dynamic inputs

**Issue**  
The generic `requests.request()` API is more flexible but just as dangerous.

**Sample Regex Patterns**

### 2A. Literal method, variable URL

```regex
requests\.request\(\s*["'`][A-Z]+["'`]\s*,\s*\w+
```

- **Explanation**
    
    - Method string (`"GET"`) followed by URL variable.
        

#### Example

```python
requests.request("GET", user_supplied_url)
```

**Security Impact**: Same SSRF risk.

---

### 2B. Both method and URL dynamic

```regex
requests\.request\(\s*\w+\s*,\s*\w+
```

- **Explanation**
    
    - Even the HTTP verb can be attacker controlled.
        

#### Example

```python
requests.request(req_method, req_url)
```

**Security Impact**: Attack surface widens to odd verbs like `LINK`, `TRACE`.

---

### 2C. Keyword `url=` with variable

```regex
requests\.(get|post|put|delete|head|options)\(\s*[^)]*url\s*=\s*\w+
```

- **Explanation**
    
    - Catches `requests.get(url=untrusted)` even when other kwargs precede it.
        

---

## 3. `urllib.request.urlopen`

**Issue**  
Low-level helper often slips past code review.

**Sample Regex Patterns**

### 3A. Concatenated URL

```regex
urllib\.request\.urlopen\(\s*["'`][^"'`]+["'`]\s*\+\s*\w+
```

### 3B. `f`-string URL

```regex
urllib\.request\.urlopen\(\s*f["'`][^"'`]*\{[^}]+\}[^"'`]*["'`]
```

### 3C. `.format()` URL

```regex
urllib\.request\.urlopen\(\s*["'`][^"'`]*\{[^}]+\}[^"'`]*["'`]\.format\(
```

### 3D. Variable-only URL

```regex
urllib\.request\.urlopen\(\s*\w+\s*\)
```

_(Each pattern’s explanation mirrors §1; `urlopen` reaches arbitrary schemes such as `file://`, amplifying risk.)_

---

## 4. `urllib3` pooled client

**Sample Regex Patterns**

### 4A. Literal method, variable URL

```regex
urllib3\.PoolManager\(\)\.request\(\s*["'`][A-Z]+["'`]\s*,\s*\w+
```

### 4B. Both dynamic

```regex
urllib3\.PoolManager\(\)\.request\(\s*\w+\s*,\s*\w+
```

---

## 5. `httpx` client helpers

### 5A. Variable-only URL

```regex
httpx\.(get|post|put|delete|head|options)\(\s*\w+
```

### 5B. Literal + variable URL

```regex
httpx\.(get|post|put|delete|head|options)\(\s*["'`][^"'`]+["'`]\s*\+\s*\w+
```

### 5C. `AsyncClient` variable URL

```regex
httpx\.AsyncClient\(\)[\s\S]*?\.(get|post|put|delete|head|options)\(\s*\w+
```

---

## 6. `aiohttp` asynchronous requests

### 6A. ClientSession with variable URL

```regex
aiohttp\.ClientSession\(\)[\s\S]*?\.(get|post|put|delete|head|options)\(\s*\w+
```

### 6B. Context-manager pattern

```regex
with\s+aiohttp\.ClientSession\([^\)]*\)\s+as\s+\w+:[\s\S]*?\.\s*(get|post|put|delete|head|options)\(\s*\w+
```

---

## 7. `http.client` / `httplib` low-level connections

### 7A. HTTPConnection dynamic host

```regex
http\.client\.HTTPConnection\(\s*\w+
```

### 7B. HTTPSConnection dynamic host

```regex
http\.client\.HTTPSConnection\(\s*\w+
```

### 7C. Legacy `httplib.HTTPConnection`

```regex
httplib\.HTTPConnection\(\s*\w+
```

### 7D. Legacy `httplib.HTTPSConnection`

```regex
httplib\.HTTPSConnection\(\s*\w+
```

- **Issue**
    
    - Raw host strings let attackers target internal IPs or Unix sockets via “.sock” proxies.
        

---

## 8. Raw sockets & SSH transport

### 8A. `socket.connect()` with variable host

```regex
socket\.socket\([^)]*\)\.connect\(\s*\(\s*\w+\s*,\s*\w+
```

### 8B. `paramiko.Transport(<host>)`

```regex
paramiko\.Transport\(\s*\w+
```

---

## 9. Miscellaneous network-aware libraries

### 9A. `ftplib.FTP(<host>)`

```regex
ftplib\.FTP\(\s*\w+
```

### 9B. `xmlrpc.client.ServerProxy(<url>)`

```regex
xmlrpc\.client\.ServerProxy\(\s*\w+
```

### 9C. `boto3.client(..., endpoint_url=<var>)`

```regex
boto3\.client\([^,]+,\s*endpoint_url\s*=\s*\w+
```

### 9D. `requests.Session().get(<var>)`

```regex
requests\.Session\(\)[\s\S]*?\.(get|post|put|delete|head|options)\(\s*\w+
```

---

## 10. Command-line fetchers invoked via `subprocess` / `os`

### 10A. `subprocess.run("curl " + var …)`

```regex
subprocess\.run\(\s*["'`][^"'`]*curl[^"'`]*["'`]\s*\+\s*\w+
```

### 10B. `subprocess.run("wget " + var …)`

```regex
subprocess\.run\(\s*["'`][^"'`]*wget[^"'`]*["'`]\s*\+\s*\w+
```

### 10C. `os.system("curl " + var)`

```regex
os\.system\(\s*["'`][^"'`]*curl[^"'`]*["'`]\s*\+\s*\w+
```

### 10D. `os.popen("wget " + var)`

```regex
os\.popen\(\s*["'`][^"'`]*wget[^"'`]*["'`]\s*\+\s*\w+
```

### 10E. PowerShell `Invoke-WebRequest` via `subprocess`

```regex
subprocess\.[\w\.]*\(\s*["'`][^"'`]*Invoke-WebRequest[^"'`]*["'`]\s*\+\s*\w+
```

**Issue** (for all §10 patterns)  
Shelling out with curl/wget/PowerShell inherits every protocol their binaries support—opening gopher, ftp, file, dict, ldap, or smb SSRF vectors.