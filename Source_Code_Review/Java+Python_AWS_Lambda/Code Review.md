## Authentication Vulnerabilities

### VS Code Regex Patterns

#### HTTP Basic Auth Detection

```regex
HttpBasicAuth|BasicAuth|basic_auth|\.auth\(.*Basic|Authorization.*Basic|authType.*basic
```

#### Hardcoded Credentials

```regex
auth(entication)?.*="[^"]{3,}"|password.*="[^"]{3,}"|secret.*="[^"]{3,}"
```

#### Insecure JWT Handling

```regex
\.verify\([^,]+\)|verify\(\s*token\s*\)|jwtVerifier|jwt\.decode\([^,]+\)
```

#### Sample Vulnerable Code (Java)

```java
// Hardcoded credentials in authentication
if (username.equals("admin") && password.equals("password123")) {
    return true;
}
```

#### Sample Vulnerable Code (Python)

```python
# Basic auth without TLS verification
auth = HTTPBasicAuth('admin', os.environ.get('PASSWORD', 'default'))
response = requests.get(api_url, auth=auth, verify=False)
```

## Secret Management Issues

### VS Code Regex Patterns

#### Hardcoded Secrets

```regex
(password|passwd|pwd|secret|key|token|credentials).*=.*['"][^'"]{4,}['"]
```

#### Environment Variable Secrets

```regex
os\.environ\.get\(['"].*PASSWORD|os\.environ\.get\(['"].*SECRET|os\.environ\.get\(['"].*KEY|process\.env\.[A-Z_]*KEY
```

#### AWS Credentials in Code

```regex
aws_access_key_id|aws_secret_access_key|AWSCredentials\(|AWSCredentialsProvider|AWSSessionCredentials
```

#### Sample Vulnerable Code (Java)

```java
private static final String DB_URL = "jdbc:mysql://prod-db.company.com:3306/users";
private static final String DB_USER = "dbadmin";
private static final String DB_PASSWORD = "SuperSecretP@ss1!";
```

#### Sample Vulnerable Code (Python)

```python
API_KEY = "sk_live_a1b2c3d4e5f6g7h8i9j0"
headers = {"Authorization": f"Bearer {API_KEY}"}
response = requests.post("https://api.service.com/v1/charge", headers=headers)
```

## Input Validation Problems

### VS Code Regex Patterns

#### Missing Input Validation

```regex
request\.getParameter\(.*\)|event\.(get|['"].*['"])|body\..*|req\.params\..*|req\.query\.
```

#### Direct Use of Request Data

```regex
String\s+\w+\s*=\s*request\.|Map\s+\w+\s*=\s*objectMapper\.readValue\(request\.|json\.loads\(event
```

#### Dangerous Query Parameter Use

```regex
\?.*=.*\{.*\}|\?.*=.*\$\{|\?.*=.*\$\(|\?.*=.*\+
```

#### Sample Vulnerable Code (Java)

```java
String userId = (String) input.get("userId");
String action = (String) input.get("action");
if (action.equals("getDetails")) { return getUserDetails(userId); }
```

#### Sample Vulnerable Code (Python)

```python
user_id = event.get('userId')
query_params = event.get('queryStringParameters', {})
page = int(query_params.get('page', 1))
```

## Injection Vulnerabilities

### VS Code Regex Patterns

#### SQL Injection

```regex
"SELECT.*\+|"UPDATE.*\+|"DELETE.*\+|"INSERT.*\+|executeQuery\(".*\+|execute\(".*\+|cursor\.execute\(.*%|db\.query\(.*\+
```

#### Command Injection

```regex
exec\(.*\)|os\.system\(.*\+|subprocess\.call\(".*\+|Runtime\.getRuntime\(\)\.exec\(".*\+|ProcessBuilder\(".*\+
```

#### NoSQL Injection

```regex
find\(\{.*\$where|find\(\{.*\$regex|db\.collection\.find\(.*\+|MongoCollection\.find\(.*\+
```

#### Log Injection

```regex
logger\.(info|debug|warn|error)\(.*\+|System\.out\.println\(.*\+|print\(.*\+|console\.log\(.*\+
```

#### Sample Vulnerable Code (Java)

```java
String sql = "SELECT * FROM users WHERE name LIKE '%" + name + "%'";
Statement stmt = conn.createStatement();
ResultSet rs = stmt.executeQuery(sql);
```

#### Sample Vulnerable Code (Python)

```python
query = "SELECT * FROM users WHERE username = '" + username + "'"
cursor.execute(query)
```

## Cross-Language Vulnerabilities

### VS Code Regex Patterns

#### Unsafe Serialization

```regex
ObjectMapper|fromJson\(|JSONObject|json\.loads|pickle\.loads|marshal\.loads
```

#### Cross-Language Data Passing

```regex
s3Client\.putObject\(|s3\.upload_fileobj\(|s3\.put_object\(|SqsClient\.sendMessage
```

#### Unsafe Deserialization

```regex
readValue\(.*json|ObjectMapper.*readValue|json\.loads\(.*S3|pickle\.load\(|readObject\(
```

#### Sample Vulnerable Code (Java)

```java
ObjectMapper mapper = new ObjectMapper();
UserData userData = mapper.readValue(jsonString, UserData.class);
return processUserData(userData);
```

#### Sample Vulnerable Code (Python)

```python
user_data = json.loads(response['Body'].read().decode('utf-8'))
process_user_data(user_data)  # No validation
```

## AWS Lambda-Specific Issues

### VS Code Regex Patterns

#### Overly Permissive IAM

```regex
"Effect":\s*"Allow",\s*"Action":\s*"\*"|"Effect":\s*"Allow",\s*"Action":\s*\[\s*"\*"|"Effect":\s*"Allow",\s*"Resource":\s*"\*"|FullAccess|AdministratorAccess
```

#### Lambda Environment Variables

```regex
process\.env\.|os\.environ|System\.getenv\(|environment:(?:\s*\n\s*-.*)+
```

#### Insufficient Error Handling

```regex
try\s*\{.*\}\s*catch\s*\(.*\)\s*\{\s*\}|except Exception as e:\s*pass|except:\s*pass
```

#### Sample Vulnerable Code (Java)

```yaml
# SAM/CloudFormation
Policies:
  - AmazonDynamoDBFullAccess  # Too permissive
  - AmazonS3FullAccess        # Too permissive
```

#### Sample Vulnerable Code (Python)

```python
dynamodb = boto3.resource(
    'dynamodb',
    aws_access_key_id=os.environ['AWS_KEY'],
    aws_secret_access_key=os.environ['AWS_SECRET']
)
```

## Container Security Issues

### VS Code Regex Patterns

#### Running as Root

```regex
USER\s+root|USER\s+0|USER\s+0:0
```

#### Insecure Base Images

```regex
FROM\s+(?!amazonlinux|alpine|distroless|scratch).+:latest|FROM\s+.+:(?![\d\.]+|stable)
```

#### Sensitive Environment Variables

```regex
ENV\s+.*PASSWORD|ENV\s+.*SECRET|ENV\s+.*KEY|ENV\s+.*TOKEN
```

#### Sample Vulnerable Dockerfile

```dockerfile
FROM amazonlinux:latest
RUN pip install -r requirements.txt
# No user specified - defaults to root
CMD ["python", "/app/lambda_function.py"]
```

## Logging Security Issues

### VS Code Regex Patterns

#### Sensitive Data in Logs

```regex
log\(.*password|log\(.*secret|log\(.*key|log\(.*token|print\(.*password|console\.log\(.*password
```

#### Stack Trace Exposure

```regex
printStackTrace\(|e\.printStackTrace\(\)|.error\(e\)|log.error\(.*exception|console\.error\(.*error
```

#### Excessive Error Details

```regex
\.withBody\(".*" \+ e|return\s+.*\{\s*.*:\s*.*\s*,\s*.*:\s*e\.
```

#### Sample Vulnerable Code (Java)

```java
context.getLogger().log("Processing payment with card: " + creditCard + ", CVV: " + cvv);
e.printStackTrace();
return Response.status(500).entity("Error: " + e.getMessage()).build();
```

#### Sample Vulnerable Code (Python)

```python
logger.info(f"User authenticated with password: {password}")
except Exception as e:
    return {"statusCode": 500, "body": str(e)}
```

## Advanced Java-Specific Issues

### VS Code Regex Patterns

#### Unsafe JAXB/XML Processing

```regex
DocumentBuilderFactory|SAXParserFactory|XMLInputFactory|createXMLReader\(|\.newInstance\(\)
```

#### Insecure Cookie Handling

```regex
Cookie\(|new\sCookie\(|\.addCookie\(|HttpCookie|CookieManager
```

#### Java Deserialization

```regex
ObjectInputStream|readObject\(|Serializable|readResolve\(|readExternal\(
```

#### Sample Vulnerable Code (Java)

```java
ObjectInputStream in = new ObjectInputStream(inputStream);
Object obj = in.readObject();  // Unsafe deserialization
return processObject(obj);
```

## Advanced Python-Specific Issues

### VS Code Regex Patterns

#### Dynamic Code Execution

```regex
eval\(|exec\(|globals\(\)\[|locals\(\)\[|compile\(|__import__\(
```

#### Insecure Temp Files

```regex
tempfile\.mktemp\(|os\.tempnam\(|tempfile\.TemporaryFile\(|open\(/tmp/
```

#### Pickle Usage

```regex
pickle\.load|pickle\.loads|cPickle\.load|dill\.load|joblib\.load
```

#### Sample Vulnerable Code (Python)

```python
# Code injection
user_input = event.get('expression')
result = eval(user_input)  # Dangerous!
return {'result': result}
```

## AWS Lambda Python-Java Interaction

### VS Code Regex Patterns

#### Java Process Execution from Python

```regex
subprocess\.(?:call|run|Popen)\(['"]java|os\.system\(['"]java|os\.popen\(['"]java
```

#### Python Execution from Java

```regex
ProcessBuilder\(['"]python|Runtime\.getRuntime\(\)\.exec\(['"]python|new\sProcess\(['"]python
```

#### Cross-Language File Access

```regex
open\(['"].*\.java|new\sFile\(['"].*\.py|FileReader\(['"].*\.py|FileInputStream\(['"].*\.py
```

#### Sample Vulnerable Java to Python

```java
ProcessBuilder pb = new ProcessBuilder("python", "/tmp/script.py", userInput);
Process p = pb.start();  // Executing Python with unsanitized user input
```

#### Sample Vulnerable Python to Java

```python
os.system(f"java -jar /tmp/processor.jar {user_data}")  # Command injection
```

## Combined Environment Issues

### VS Code Regex Patterns

#### Event Source Mapping Vulnerabilities

```regex
AllowS3Invocation|AllowAPIGatewayInvocation|S3Bucket\s+Trigger|S3TriggerPermission
```

#### Container File Mapping Issues

```regex
AddPathMapping|Lambda::LayerVersion|\.zip|Lambda::Function.*\w+.jar|layers:
```

#### Lambda Concurrent Execution

```regex
ConcurrentExecutions|ReservedConcurrentExecutions|ProvisionedConcurrencyConfig
```

#### Sample Vulnerable Template

```yaml
# CloudFormation/SAM template
Resources:
  MyFunction:
    Type: AWS::Serverless::Function
    Properties:
      CodeUri: ./function.zip  # No code signing
      Policies: AWSLambdaFullAccess  # Excessive permissions
```