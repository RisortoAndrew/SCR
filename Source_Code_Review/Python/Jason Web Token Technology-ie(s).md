## 1. “None” or Other Insecure Algorithms Enabled

**Issue**  
Allowing `alg = 'none'` (or weak HMAC-based algorithms) lets an attacker bypass signature verification or swap a strong asymmetric alg (RS256) for a weak symmetric one (HS256).

### 1A. “none” included in an algorithms map/list

```regex
ALGORITHMS?\s*=\s*\{[^}]*['"]none['"][^}]*\}
```

_Finds a dict such as_ `ALGORITHMS = {'none': None, 'HS256': ...}`.

### 1B. Decoding _without_ verification

```regex
jwt\.decode\([^,]+,\s*[^,]*,\s*verify\s*=\s*False
```

or the newer options style

```regex
jwt\.decode\([^)]*options\s*=\s*\{[^}]*['"]verify_signature['"]\s*:\s*False
```

#### Example Hit

```python
data = jwt.decode(token, key='', verify=False)
```

**Security Impact** — Tokens are accepted even if unsigned or tampered with.

---

## 2. Hard-Coded Secrets / Private Keys

### 2A. Obvious “secret” variable assignment

```regex
(secret|private_key|jwt(_?secret|_?key)|signing_key)\s*=\s*["'][^"']{8,}["']
```

### 2B. PEM blocks embedded in source

```regex
-----BEGIN [A-Z ]*PRIVATE KEY-----(?:.|\n)*?-----END [A-Z ]*PRIVATE KEY-----
```

#### Example Hit

```python
JWT_SECRET = "super-secret-value-123"
```

**Security Impact** — Anyone with repo access can mint valid tokens or decrypt data.

---

## 3. Weak HMAC Algorithms for Public-Facing APIs

```regex
jwt\.(encode|decode)\([^)]*algorithm\s*=\s*['"]HS(256|384|512)['"]
```

_Flags both encoding and decoding with shared-secret algorithms when asymmetric (RS256 / ES256) is safer._

**Security Impact** — If the server’s symmetric key leaks, attackers can forge valid JWTs for every user.

---

## 4. Missing Claim Validation (exp, nbf, aud, iss)

### 4A. Explicitly disabling claim checks

```regex
jwt\.decode\([^)]*options\s*=\s*\{[^}]*['"]verify_(exp|nbf|aud|iss)['"]\s*:\s*False
```

### 4B. Decoding without an `audience=` parameter

```regex
jwt\.decode\([^)]*\)(?:(?!audience=).)*$
```

_(Uses a negative-look-ahead to catch lines that end without “audience=”)._

**Security Impact** — Replay, token swap and cross-audience attacks become trivial.

---

## 5. Accepting Unsigned / Unprotected JWS Payloads

```regex
jws\.(deserialize|verify|decode)\([^,]+,\s*None\s*\)
```

**Security Impact** — The JWS layer is effectively removed; malicious claims go unchecked.

---

## 6. Insecure JWKS Download or TLS Validation

### 6A. HTTP-only JWKS endpoint

```regex
requests\.get\(['"]http://[^"']+\.well-known/jwks[^"']*['"]
```

### 6B. Disabling certificate verification

```regex
requests\.(get|post)\([^)]*verify\s*=\s*False
```

#### Example Hit

```python
resp = requests.get("http://auth.example.com/.well-known/jwks.json")
```

**Security Impact** — MITM can swap public keys and forge tokens.

---

## 7. Broken or Infinite JWT Cache TTL

```regex
(t(tl|ime_to_live)|max_age|expiry|expires_in)\s*=\s*(0|-1|None)
```

or

```regex
timedelta\([^)]*days\s*=\s*(?:[3-9]\d\d|[1-9]\d{3,})  # 1 year+
```

**Security Impact** — Revoked keys / kid rollovers aren’t picked up; compromised keys stay valid.

---

## 8. Broad or Silent Exception Handling

### 8A. Swallowing all exceptions

```regex
except\s*:\s*pass
```

### 8B. Catch-all then ignore JWT errors

```regex
except\s+(jwt\.[A-Za-z]+Error|Exception)\s*:\s*(pass|return\s+None)
```

**Security Impact** — Failures in validation fall through silently, letting bad tokens through.

---

## 9. Duplicate or Shadowed Module Names

```regex
^(\s*)def\s+.*  # (use "Files to include" filter: api_jwt.py)
```

_Manually check for conflicting function definitions; Python will import the **first** match in `sys.path`, possibly the wrong (less secure) one._

**Security Impact** — A rogue duplicate overrides the secure implementation.

---

## 10. Over-Permissive `algorithms=` Parameter During Decode

```regex
jwt\.decode\([^)]*algorithms\s*=\s*\[[^\]]{30,}\]   # suspiciously long list
```

_Huge allow-lists often include obsolete algorithms the app never needs._

**Security Impact** — Increases the attack surface; downgrade attacks become easier.