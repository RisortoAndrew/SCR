## 1. Dangerous `eval()` on Untrusted Input

**Issue**  
`eval()` executes arbitrary Python—trivial RCE if fed attacker-supplied data.

**Sample Regex Pattern**

```
\b(eval)\s*\(\s*event\[
```

- **Explanation**
    
    - Looks for `eval(` followed by any reference to the Lambda `event` dict.
        

#### Example Code Snippet That Matches

```python
result = eval(event['expression'])
```

**Security Impact**: Full code-execution within the Lambda runtime.

---

## 2. Unchecked `exec()`

**Issue**  
`exec()` with dynamic strings enables runtime code injection.

**Regex**

```
\bexec\s*\(\s*[^)]*event\[
```

#### Example

```python
exec(event['code'])
```

**Security Impact**: Attacker can run arbitrary commands.

---

## 3. `subprocess.*` with `shell=True`

**Issue**  
Shell expansion magnifies command-injection risk.

**Regex**

```
subprocess\.(run|Popen|call|check_output)\s*\([^)]*shell\s*=\s*True
```

#### Example

```python
subprocess.run(f"zip {event['file']}", shell=True)
```

**Security Impact**: OS-level compromise inside Lambda container.

---

## 4. `os.system()` on Event Data

```
os\.system\s*\([^)]*event\[
```

**Impact**: Same as above—arbitrary shell execution.

---

## 5. Unsafe `yaml.load()`

**Issue**  
Using the default loader executes arbitrary Python objects.

**Regex**

```
yaml\.load\s*\(
```

#### Example

```python
config = yaml.load(event['body'])
```

**Security Impact**: Deserialization RCE.

---

## 6. Insecure Pickle Deserialization

```
pickle\.loads?\s*\(
```

**Impact**: Attackers craft malicious pickles to pop shells.

---

## 7. `jsonpickle.decode()`

```
jsonpickle\.decode\s*\(
```

**Impact**: Same deserialization danger as Pickle.

---

## 8. MD5 or SHA-1 for Security Controls

```
hashlib\.(md5|sha1)\s*\(
```

**Impact**: Weak hashes → easy collision/password cracking.

---

## 9. Cryptographically Weak Randomness

```
random\.(randint|random|randrange|choice)\s*\(
```

**Impact**: Session IDs or tokens guessable.

---

## 10. Unsafely Disabling SSL Verification

```
requests\.\w+\s*\([^)]*verify\s*=\s*False
```

**Impact**: MITM can modify data in transit.

---

## 11. HTTP (non-HTTPS) Requests

```
requests\.\w+\s*\(\s*['"]http://
```

**Impact**: Credentials or data sent in clear-text.

---

## 12. Suppressing InsecureRequestWarning

```
urllib3\.disable_warnings\s*\(
```

**Impact**: Hides SSL errors and lulls devs into ignoring them.

---

## 13. Boto3 S3 Uploads with `ACL='public-read'`

```
put_object\s*\([^)]*ACL\s*=\s*['"]public-read['"]
```

**Impact**: Exposes uploaded objects to anyone on the internet.

---

## 14. S3 Bucket Creation with Public ACL

```
create_bucket\s*\([^)]*ACL\s*=\s*['"]public-read['"]
```

**Impact**: Whole bucket is world-readable.

---

## 15. Unsigned S3 Requests

```
signature_version\s*=\s*UNSIGNED
```

**Impact**: Request authenticity not enforced; easy MITM.

---

## 16. Disabling Server-Side Encryption on Upload

```
put_object\s*\([^)]*(?<!ServerSideEncryption)\)
```

**Impact**: Objects land unencrypted at rest.

---

## 17. Publishing to SNS w/ `RawMessageDelivery` Enabled

```
sns\.publish\s*\([^)]*RawMessageDelivery\s*=\s*True
```

**Impact**: Downstream services see unwrapped, spoofable JSON.

---

## 18. Returning CORS “**”

```
Access-Control-Allow-Origin['"]?\s*:\s*['"]\*
```

**Impact**: Any website can call your API endpoints.

---

## 19. Path Traversal When Saving to `/tmp`

```
open\s*\(\s*event\[[^\]]+\]\s*,\s*['"]w
```

**Impact**: Attacker traverses outside intended directory (e.g., `../../etc/passwd`).

---

## 20. `open()` Writing Outside `/tmp`

```
open\s*\(\s*['"]\/(?!tmp\/)[^'"]+['"]\s*,\s*['"]w
```

**Impact**: Lambda filesystem is read-only except `/tmp`; write attempts elsewhere break or leak.

---

## 21. SSRF to AWS Metadata Service

```
http[s]?:\/\/169\.254\.169\.254
```

**Impact**: Steals temporary IAM credentials.

---

## 22. External Requests Built from Event Input

```
requests\.\w+\s*\([^)]*event\[
```

**Impact**: SSRF / open redirect if attacker controls URLs.

---

## 23. Dynamic Import from Event Data

```
__import__\s*\(\s*event\[
```

**Impact**: Loads arbitrary module → code execution.

---

## 24. Calling `boto3.client('sts').assume_role` with Unvalidated RoleArn

```
assume_role\s*\([^)]*RoleArn\s*=\s*event\[
```

**Impact**: Privesc to arbitrary AWS accounts.

---

## 25. Lambda `add_permission` Granting `Principal '*'`

```
add_permission\s*\([^)]*Principal['"]?\s*:\s*['"]\*['"]
```

**Impact**: Any AWS principal can invoke the function.

---

## 26. Lambda `add_permission` Granting `Action 'lambda:*'`

```
add_permission\s*\([^)]*Action['"]?\s*:\s*['"]lambda:\*['"]
```

**Impact**: Over-broad; attackers can update or delete code.

---

## 27. Overly Broad SQS Queue Policy in Code

```
"Principal"\s*:\s*"\*".*?"Action"\s*:\s*"\s*sqs:\*"
```

**Impact**: Anyone can read or write to the queue.

---

## 28. DynamoDB `scan()` Without Filters

```
dynamodb\.Table\([^)]*\)\.scan\s*\(
```

**Impact**: Reads whole table → data exfiltration + throttling.

---

## 29. SQL Queries Built with f-Strings and Event Data

```
f['"][^'"]*\{event\[[^}]+\]\}[^'"]*['"]\.execute
```

**Impact**: Classic SQL injection.

---

## 30. Subprocess Command Injection via f-String

```
f['"][^'"]*\{event\[[^}]+\]\}[^'"]*['"]\s*\)
```

_Used with `subprocess.*`, `os.system()`, etc._

---

## 31. Paramiko with `AutoAddPolicy()`

```
paramiko\.AutoAddPolicy\s*\(
```

**Impact**: Accepts any host key—MITM risk.

---

## 32. JWT Validation Disabled

```
jwt\.decode\s*\([^)]*verify[\w]*\s*=\s*False
```

**Impact**: Accepts forged tokens.

---

## 33. Hard-coded Allow Policy for API Gateway Authorizer

```
"Effect"\s*:\s*"Allow".*?"Resource"\s*:\s*"\*"
```

**Impact**: Authorizer returns wildcard; attacker gets full API access.

---

## 34. DES or ECB Mode in `Crypto`

```
DES3?\.new\s*\(|MODE_ECB
```

**Impact**: Weak symmetric crypto.

---

## 35. Using `base64.b64decode(...); exec(...)` Chain

```
base64\.b64decode[^\n]+exec
```

**Impact**: Obfuscated RCE.

---

## 36. Logging Sensitive Event Data at DEBUG Level

```
logging\.basicConfig\s*\([^)]*level\s*=\s*logging\.DEBUG
```

**Impact**: Secrets may spill into CloudWatch.

---

## 37. Global Mutable State (Thread Safety)

```
^\s*[A-Za-z_]\w*\s*=\s*\[\]|\{\}
```

_(array/dict declared at top-level)_

**Impact**: Cross-invocation data leakage.

---

## 38. Writing Large Files > 512 MB to `/tmp`

```
open\([^)]*['"]w[b]?['"]\)[^\n]*\.write\([^)]{512}
```

**Impact**: Exceeds Lambda `/tmp` limit → function crashes.

---

## 39. Unbounded `while True:` Without Timeout

```
while\s+True\s*:
```

**Impact**: Infinite loops—resource exhaustion & unexpected billing.

---

## 40. Disabling X-Ray Sampling (Hiding Traces)

```
xray_recorder\.configure\s*\([^)]*sampling\s*=\s*False
```

**Impact**: Obscures malicious flows from monitoring.

---

## 41. Catch-All `except:` Swallowing Errors

```
except\s*:
```

**Impact**: Bugs/security failures remain hidden.

---

## 42. Returning Raw Exception Messages to Caller

```
return\s+str\(e\)
```

**Impact**: Leaks stack traces and environment details.

---

## 43. Accepting Any JSON MIME Type (`*/*`) in API Gateway Response

```
"Content-Type"\s*:\s*"\*/\*"
```

**Impact**: XSS / content-sniffing issues.

---

## 44. Trusting `event['headers']['X-Forwarded-For']` Directly

```
event\['headers'\]\['X-Forwarded-For'\]
```

**Impact**: Spoofed IP can bypass IP allowlists.

---

## 45. Unscoped IAM Policy JSON in Code (`"Resource": "*"`)

```
"Resource"\s*:\s*"\*"
```

**Impact**: Lambda can touch any AWS resource—lateral movement.

---

## 46. `boto3.client('s3', endpoint_url=event[...)` (Custom Endpoints)

```
endpoint_url\s*=\s*event\[
```

**Impact**: SSRF via rogue endpoint.

---

## 47. Hard-coded Region Dependent Logic

```
region_name\s*=\s*['"]us-[a-z]+-\d['"]
```

**Impact**: Breaks in multi-region DR; may leak infra layout.

---

## 48. Writing Plaintext Secrets to CloudWatch

```
print\(\s*['"].*(password|secret|token).*
```

_(Logs secrets even if not hard-coded.)_

---

## 49. Returning 200 OK on Exception (Silent Fail)

```
return\s*\{\s*['"]statusCode['"]\s*:\s*200
```

**Impact**: Attackers get green light despite errors.

---

## 50. Loading Unpinned Third-Party Package in Lambda Layer

```
requirements\.txt|Pipfile
```

_(Search for lines without `==` version pin:)_

```
^\s*[A-Za-z0-9_\-]+$
```

**Impact**: Future upstream package compromise → supply-chain attack.