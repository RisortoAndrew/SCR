## 1. Hard‑coded AWS Secrets / Credentials

Developers often drop keys, tokens, or passwords into source files or YAML/JSON templates. The following regexes surface the most common patterns.

**1.1 Access‑key IDs (AKIA…)**

```regex
AKIA[0-9A-Z]{16}
```

_Explanation:_ Finds 20‑char AWS access‑key IDs in any text file.  
_Example:_

```js
const accessKey = "AKIAIOSFODNN7EXAMPLE";
```

_Security Impact:_ Combined with a secret key, attackers can sign AWS API calls.

---

**1.2 Secret‑access keys**

```regex
aws_secret_access_key\s*[:=]\s*["']?[A-Za-z0-9/+=]{40}["']?
```

_Explanation:_ Looks for 40‑character AWS secret keys assigned in code or env files.  
_Example:_

```bash
aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
```

_Security Impact:_ Full credential pair enables total account compromise.

---

**1.3 Keys in Lambda Environment variables**

```regex
"Variables"\s*:\s*\{[^\}]*"(AWS_(?:ACCESS|SECRET)_KEY(?:_ID)?)"\s*:\s*"[^"]+"
```

_Explanation:_ Matches plaintext AWS keys defined in a function’s `Environment.Variables`.  
_Example:_

```json
"Environment": {
  "Variables": {
    "AWS_SECRET_KEY": "abcd1234examplekey"
  }
}
```

_Security Impact:_ Anyone who can view function configuration can steal creds.

---

**1.4 SSM parameter paths hard‑coded**

```regex
\/[A-Za-z0-9_\-/]*?(password|secret|token|key)[A-Za-z0-9_\-/]*?
```

_Explanation:_ Detects plain SSM parameter names that expose secret intent.  
_Example:_

```yaml
Environment:
  Variables:
    DB_PASSWORD: "/prd/db/password"
```

_Security Impact:_ Reveals secret parameter name and may miss KMS encryption.

---

**1.5 Secrets in serverless.yml variables**

```regex
\$\{self:custom\.(password|secret|token|apikey)[^\}]*\}
```

_Explanation:_ Spots custom variables with sensitive keywords in _Serverless Framework_ files.  
_Example:_

```yaml
custom:
  secret: myTestToken123
```

_Security Impact:_ Secrets may leak via version control or CloudFormation events.

---

**1.6 Base64‑looking secrets in code**

```regex
["'][A-Za-z0-9+/]{32,}={0,2}["']
```

_Explanation:_ Catches long base64 blobs that might be keys or certs.  
_Example:_

```python
PRIVATE_KEY = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC..."
```

_Security Impact:_ Hard‑coded keys undermine encryption integrity.

---

**1.7 Cognito / JWT tokens in source**

```regex
eyJ[A-Za-z0-9\-_]{20,}\.[A-Za-z0-9\-_]{20,}\.[A-Za-z0-9\-_]{20,}
```

_Explanation:_ Finds bearer tokens accidentally checked in.  
_Example:_

```js
// Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

_Security Impact:_ Lets attackers impersonate users or micro‑services.

---

**1.8 Secrets committed in layer archives**

```regex
layers\/[^\/]+\/.*\.(env|txt|cfg)
```

_Explanation:_ Identifies text files bundled into Lambda Layers that may hold secrets.  
_Example:_

```
layers/common/.env
```

_Security Impact:_ Anyone with the layer ARN can download and read the file.

---

**1.9 Commented‑out credentials**

```regex
\/\/.*(access_key|secret|password|token|apikey)
```

_Explanation:_ Flags single‑line comments containing credential keywords.  
_Example:_

```js
// TODO remove before commit: secret = "hunter2"
```

_Security Impact:_ Git history never forgets.

---

**1.10 Hard‑coded RDS connection strings**

```regex
"(jdbc|mysql|postgresql):\/\/[^"]*:[0-9]{1,5}\/[^\s"]*?password=[^"&"]+"
```

_Explanation:_ Searches for RDS‑style URIs embedded in code.  
_Example:_

```java
String url="jdbc:mysql://example.rds.amazonaws.com:3306/db?user=admin&password=BadPass!";
```

_Security Impact:_ Direct database access from stolen string.

---

## 2. Over‑Permissive IAM Roles / Policies

Improper privileges let a Lambda pivot or mutate infrastructure.

**2.1 Action equals “*”**

```regex
"Action"\s*:\s*"\*"
```

_Explanation:_ Finds policies granting _every_ AWS API.  
_Example:_

```json
"Action": "*"
```

_Security Impact:_ Complete administrative access.

---

**2.2 Resource equals “*”**

```regex
"Resource"\s*:\s*"\*"
```

_Explanation:_ Detects policies that allow access to all resources, even if action list is scoped.  
_Example:_

```json
"Resource": "*"
```

_Security Impact:_ Function can touch every ARN in the account.

---

**2.3 Wildcard service prefix**

```regex
"Action"\s*:\s*"[a-z0-9]+:\*"
```

_Explanation:_ Catches patterns like `"s3:*"` or `"iam:*"`.  
_Example:_

```json
"Action": "iam:*"
```

_Security Impact:_ Enables privilege escalation (e.g., creating new admins).

---

**2.4 iam:PassRole without Condition**

```regex
"iam:PassRole"[^\}]*\}(?![^\{]*"Condition")
```

_Explanation:_ Looks for PassRole permissions lacking constraints.  
_Example:_

```json
"Action": "iam:PassRole",
"Resource": "*"
```

_Security Impact:_ Lambda can assume higher‑priv roles.

---

**2.5 Permission boundary missing**

```regex
"PermissionsBoundary"\s*:\s*"\s*"
```

_Explanation:_ Flags empty PermissionBoundary statements in role definitions.  
_Example:_

```json
"PermissionsBoundary": ""
```

_Security Impact:_ Nothing limits privilege creep.

---

**2.6 Trust policy Principal "*"**

```regex
"Principal"\s*:\s*"\*"
```

_Explanation:_ Any AWS principal can assume the role.  
_Example:_

```json
"Principal":"*"
```

_Security Impact:_ Cross‑account hijack.

---

**2.7 AssumeRole service not lambda.amazonaws.com**

```regex
"Principal"[ \t\r\n]*:[ \t\r\n]*\{[\s\S]*?"Service"[ \t\r\n]*:[ \t\r\n]*"(?!lambda\.amazonaws\.com)[^"]+"
```

_Explanation:_ Detects roles a Lambda _should_ use but that trust something else.  
_Example:_

```json
"Service": "ec2.amazonaws.com"
```

_Security Impact:_ Confused‑deputy attack surface.

---

**2.8 Inline policies with * in Terraform**

```regex
inline_policy\s*=\s*\{[^}]*"\*"
```

_Explanation:_ Wildcards in TF inline blocks.  
_Example:_

```hcl
inline_policy = {
  statements = [{
    actions   = ["sqs:*"]
    resources = ["*"]
  }]
}
```

_Security Impact:_ Same as 2.1–2.3.

---

**2.9 MaxSessionDuration > 12h**

```regex
"MaxSessionDuration"\s*:\s*(4[3-9]\d{2}|[5-9]\d{3})
```

_Explanation:_ Flags roles with sessions longer than 12 hours.  
_Example:_

```json
"MaxSessionDuration": 14400
```

_Security Impact:_ Longer stolen‑token lifetime.

---

**2.10 Policies with “iam:CreateUser”**

```regex
"iam:CreateUser"
```

_Explanation:_ Creating users from Lambda is rarely needed.  
_Example:_

```json
"Action": ["iam:CreateUser","iam:PutUserPolicy"]
```

_Security Impact:_ Function can mint new identities for attackers.

---

## 3. Plain‑Text Environment Variables

Environment variables sit in Lambda configuration; unencrypted values are visible to anyone with `lambda:GetFunctionConfiguration`.

**3.1 Sensitive keywords in env block**

```regex
"Variables"[^{]*\{[^}]*"(secret|password|token|apikey|key)"\s*:\s*"[^"]+"
```

_Explanation:_ Finds obvious secrets in JSON/YAML env sections.  
_Example:_

```json
"Variables": {
  "password": "P@ssw0rd!"
}
```

_Security Impact:_ Secrets exposed in console, CloudFormation events, and SAM logs.

---

**3.2 serverless.yml env secrets**

```regex
environment:\s*\n(\s{2,})?(secret|password|token|apikey):\s*.+$
```

_Explanation:_ Checks multiline YAML blocks.  
_Example:_

```yaml
environment:
  token: abcdef123456
```

_Security Impact:_ Same as above.

---

**3.3 Dockerfile ENV with creds**

```regex
ENV\s+(AWS|SECRET|TOKEN)[^=\n]*=
```

_Explanation:_ Finds build‑time ENV instructions in container image Lambdas.  
_Example:_

```docker
ENV AWS_SECRET_ACCESS_KEY=wJalrXU...
```

_Security Impact:_ Secrets live forever in image layers.

---

**3.4 console.log of process.env**

```regex
console\.log\([^)]*process\.env[^)]*
```

_Explanation:_ Node devs printing all env vars.  
_Example:_

```js
console.log(process.env);
```

_Security Impact:_ Dumps secrets to CloudWatch.

---

**3.5 Python print(os.environ)**

```regex
print\([^)]*os\.environ[^)]*
```

_Explanation:_ Similar for Python.  
_Example:_

```python
print(dict(os.environ))
```

_Security Impact:_ Same leak vector.

---

**3.6 No KMSKeyArn defined**

```regex
"KmsKeyArn"\s*:\s*"\s*"
```

_Explanation:_ Empty KMS field → default AWS‑managed key (encryption at rest only).  
_Example:_

```json
"KmsKeyArn": ""
```

_Security Impact:_ Secrets still visible in plaintext via API.

---

**3.7 WithDecryption: false**

```regex
WithDecryption"\s*:\s*false
```

_Explanation:_ IaC pulling SSM SecureStrings **without** decryption.  
_Example:_

```yaml
- aws ssm get-parameters --names /prd/db/password --with-decryption false
```

_Security Impact:_ Leaves plaintext secret in logs & env.

---

**3.8 export in bash script**

```regex
export\s+(DB_PASSWORD|API_KEY)=[^\n]+
```

_Explanation:_ Build/deploy scripts exporting secrets.  
_Example:_

```bash
export DB_PASSWORD='badpass'
```

_Security Impact:_ Shell history leak.

---

**3.9 Plaintext env in SAM template**

```regex
Environment:\s*\n\s*Variables:\s*\n\s*[A-Za-z0-9_]+\s*:\s*["'][^"']+["']
```

_Explanation:_ Generic match for SAM YAML.  
_Example:_see 3.1._ | _Same impact._

---

**3.10 Secrets in layer .env**

```regex
layers\/.+\/\.env
```

_Explanation:_ Bundled env file inside layer archive.  
_Security Impact:_ Anyone who can download layer bytes gets the secret.

---

## 4. Public Lambda Endpoints (Lambda URL & API Gateway)

Publicly invocable functions with no auth are low‑hanging fruit.

**4.1 Lambda URL AuthType NONE**

```regex
"AuthType"\s*:\s*"NONE"
```

_Explanation:_ Lambda function URL configuration without IAM/Cognito.  
_Example:_

```json
"AuthType":"NONE"
```

_Security Impact:_ Anyone on the internet can invoke the function directly.

---

**4.2 API Gateway authorizationType NONE**

```regex
"authorizationType"\s*:\s*"NONE"
```

_Explanation:_ REST API / Method with no authorizer.  
_Example:_

```json
"authorizationType":"NONE"
```

_Security Impact:_ Bypasses authentication; backend exposed.

---

**4.3 ANY method proxy**

```regex
"httpMethod"\s*:\s*"ANY"
```

_Explanation:_ Catch‑all method proxies everything to Lambda.  
_Example:_

```json
"httpMethod":"ANY"
```

_Security Impact:_ Hard to restrict; may leak internal ops endpoints.

---

**4.4 CloudFormation Permission Principal "*"**

```regex
AWS::Lambda::Permission[^{]*"Principal"\s*:\s*"\*"
```

_Explanation:_ Permission resource that lets anybody call `InvokeFunction`.  
_Example:_

```json
"Principal":"*"
```

_Security Impact:_ Unauthenticated invoke.

---

**4.5 serverless.yml url: true with no auth**

```regex
url:\s*true
```

_Explanation:_ Serverless Framework implicitly sets AuthType NONE.  
_Example:_

```yaml
functions:
  hello:
    url: true
```

_Security Impact:_ Same as 4.1.

---

**4.6 CORS “*”**

```regex
"Access-Control-Allow-Origin"\s*:\s*"\*"
```

_Explanation:_ API Gateway or Lambda URL response header.  
_Example:_

```json
"Access-Control-Allow-Origin":"*"
```

_Security Impact:_ Cross‑site token theft via malicious web pages.

---

**4.7 Unauthenticated WebSocket route**

```regex
"routeSelectionExpression"\s*:\s*"\$request.body.action"
```

_Explanation:_ WebSocket API without authorizer.  
_Example:_

```json
"routeSelectionExpression":"$request.body.action"
```

_Security Impact:_ Anyone can open persistent connection to Lambda.

---

**4.8 Public invoke URL in comments**

```regex
https:\/\/[a-z0-9\-]+\.lambda-url\.[^\.]+\.on\.aws
```

_Explanation:_ Hard‑coded or commented Lambda URL reveals endpoint.  
_Example:_

```
// https://abcxyz-123.lambda-url.us-east-1.on.aws/
```

_Security Impact:_ Attackers can enumerate & DOS.

---

**4.9 API key printed in logs**

```regex
console\.log\([^)]*x-api-key[^)]*
```

_Explanation:_ Devs logging API GW key headers.  
_Example:_

```js
console.log(event.headers["x-api-key"]);
```

_Security Impact:_ Key reuse by attackers.

---

**4.10 Missing authorizer in SAM route**

```regex
AuthType:\s*NONE
```

_Explanation:_ Another YAML variation.  
_Example:_see 4.1._ | _Same impact._

---

## 5. Outdated or Unsupported Runtimes

Running EOL runtimes leaves you without security fixes.

**5.1 nodejs10.x / 12.x**

```regex
"runtime"\s*:\s*"nodejs(10|12)\.x"
```

_Explanation:_ Node 10/12 are deprecated.  
_Example:_

```json
"runtime":"nodejs12.x"
```

_Security Impact:_ Known CVEs remain unpatched.

---

**5.2 python2.7 / python3.6**

```regex
"runtime"\s*:\s*"python(2\.7|3\.6)"
```

_Explanation:_ Legacy Python.  
_Example:_

```yaml
Runtime: python2.7
```

_Security Impact:_ CVEs, missing TLS1.3 support.

---

**5.3 dotnetcore2.1**

```regex
dotnetcore2\.1
```

_Explanation:_ .NET Core 2.1 reached EOL.  
_Example:_

```json
"runtime":"dotnetcore2.1"
```

_Security Impact:_ No MS security patches.

---

**5.4 java8 (not AL2)**

```regex
"runtime"\s*:\s*"java8"(\s*[^a]|$)
```

_Explanation:_ Non‑AL2 Java 8 no longer receives updates.  
_Example:_

```json
"runtime":"java8"
```

_Security Impact:_ Unpatched JVM.

---

**5.5 Ruby 2.5**

```regex
"ruby2\.5"
```

_Explanation:_ Ruby 2.5 EOL.  
_Example:_

```yaml
Runtime: ruby2.5
```

_Security Impact:_ CVEs.

---

**5.6 Deprecated custom runtime in Dockerfile**

```regex
FROM\s+amazonlinux:(1|2\.0\.[0-9])
```

_Explanation:_ Old Amazon Linux distros.  
_Example:_

```docker
FROM amazonlinux:1
```

_Security Impact:_ OS packages outdated.

---

**5.7 Layer compiled for old ABI**

```regex
CompatibleRuntimes:\s*-\s*(nodejs6\.[0-9]|python2\.7)
```

_Explanation:_ Layer only for obsolete runtimes.  
_Example:_

```yaml
CompatibleRuntimes:
  - nodejs6.10
```

_Security Impact:_ Breaks when runtime upgraded, blocking patching.

---

**5.8 TODO upgrade runtime comment**

```regex
#\s*TODO.*upgrade.*runtime
```

_Explanation:_ Lingering tech debt marker.  
_Security Impact:_ Indicates ignored upgrade.

---

**5.9 `--runtime` flag old**

```regex
--runtime\s+(python27|nodejs10\.x)
```

_Explanation:_ CLI deploy script with obsolete runtime.  
_Example:_

```bash
aws lambda create-function --runtime python27 ...
```

_Security Impact:_ Same as 5.1/5.2.

---

**5.10 No `Runtime` key in template**

```regex
(Handler|CodeUri)[\s\S]{0,200}(?!"Runtime")
```

_Explanation:_ Some IaC tools default to old‑version runtimes if `Runtime` omitted.  
_Security Impact:_ Unexpected outdated defaults.