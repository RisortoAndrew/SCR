## XSS (Cross-Site Scripting) Vulnerabilities

### 1. Direct innerHTML Usage

```
\.innerHTML\s*=\s*(?!['"`])
```

```javascript
// Vulnerable
element.innerHTML = userInput;
element.innerHTML = req.body.content;
```

### 2. Dangerous React Props

```
dangerouslySetInnerHTML\s*=\s*\{\{\s*__html:
```

```javascript
// Vulnerable
<div dangerouslySetInnerHTML={{__html: userInput}} />
```

### 3. React createElement with User Input

```
React\.createElement\s*\(\s*['"`]script['"`]
```

```javascript
// Vulnerable
React.createElement('script', {src: userInput});
```

### 4. Document.write Usage

```
document\.write\s*\(
```

```javascript
// Vulnerable
document.write('<script>' + userInput + '</script>');
```

### 5. Eval-like Functions

```
\b(?:eval|Function|setTimeout|setInterval)\s*\(\s*(?!['"`])
```

```javascript
// Vulnerable
eval(userInput);
new Function(userInput)();
```

## SQL Injection

### 6. String Concatenation in Queries

```
(?:query|execute)\s*\(\s*['"`][^'"`]*\+
```

```javascript
// Vulnerable
db.query('SELECT * FROM users WHERE id = ' + userId);
```

### 7. Template Literals in Queries

```
(?:query|execute)\s*\(\s*\`[^`]*\$\{
```

```javascript
// Vulnerable
db.query(`SELECT * FROM users WHERE name = '${userName}'`);
```

### 8. Sequelize Raw Queries

```
\.query\s*\(\s*['"`][^'"`]*\+|sequelize\.literal\s*\(
```

```javascript
// Vulnerable
sequelize.query('SELECT * FROM users WHERE id = ' + req.params.id);
```

## NoSQL Injection

### 9. MongoDB Query Injection

```
\$where\s*:\s*(?!['"`])
```

```javascript
// Vulnerable
db.collection.find({$where: userInput});
```

### 10. Mongoose Query with User Input

```
\.find\s*\(\s*req\.(?:body|params|query)
```

```javascript
// Vulnerable
User.find(req.body.query);
```

## Command Injection

### 11. Child Process with User Input

```
(?:exec|spawn|execSync|spawnSync)\s*\(\s*(?!['"`])
```

```javascript
// Vulnerable
exec(userInput);
child_process.exec('ls ' + userInput);
```

### 12. Shell Command Construction

```
['"`][^'"`]*\+.*(?:exec|spawn|system)
```

```javascript
// Vulnerable
exec('ping ' + userInput);
```

## Path Traversal

### 13. File System Operations with User Input

```
(?:readFile|writeFile|readdir|stat)\s*\(\s*(?:req\.(?:body|params|query)|.*\+)
```

```javascript
// Vulnerable
fs.readFile(req.params.filename);
fs.readFile('./uploads/' + fileName);
```

### 14. Express Static with User Input

```
express\.static\s*\(\s*(?!['"`])
```

```javascript
// Vulnerable
app.use(express.static(userPath));
```

### 15. Path Join with User Input

```
path\.join\s*\([^)]*req\.(?:body|params|query)
```

```javascript
// Vulnerable
path.join(__dirname, req.params.path);
```

## Authentication & Authorization

### 16. Weak JWT Secret

```
jwt\.sign\s*\([^)]*,\s*['"`](?:secret|123|test|key)['"`]
```

```javascript
// Vulnerable
jwt.sign(payload, 'secret');
```

### 17. Missing JWT Verification

```
jwt\.decode\s*\(
```

```javascript
// Vulnerable - decode doesn't verify signature
const decoded = jwt.decode(token);
```

### 18. Insecure Session Configuration

```
session\s*\(\s*\{[^}]*secure\s*:\s*false
```

```javascript
// Vulnerable
app.use(session({
  secure: false,
  httpOnly: false
}));
```

### 19. Missing CSRF Protection

```
app\.use\s*\(\s*csrf\s*\(\s*\)\s*\)
```

```javascript
// Check for missing CSRF - this regex finds proper usage
// Look for routes without CSRF protection
```

## Input Validation

### 20. Missing Input Validation

```
req\.(?:body|params|query)\.[a-zA-Z_$][a-zA-Z0-9_$]*(?!\s*\.\s*(?:trim|toLowerCase|validation))
```

```javascript
// Vulnerable
const userId = req.params.id; // No validation
```

### 21. Weak Regex Validation

```
\.match\s*\(\s*\/.*\^\?\|\$\?.*\/
```

```javascript
// Vulnerable - missing anchors
if (input.match(/[a-z]+/)) {
```

### 22. Type Coercion Issues

```
==\s*(?:true|false|null|undefined|0|1)
```

```javascript
// Vulnerable
if (userInput == 0) {
```

## React-Specific Security Issues

### 23. Unsafe React Refs

```
ref\s*=\s*\{[^}]*\.current\s*=
```

```javascript
// Vulnerable
<input ref={inputRef => window.globalInput = inputRef} />
```

### 24. Event Handler Injection

```
on[A-Z][a-zA-Z]*\s*=\s*\{[^}]*userInput
```

```javascript
// Vulnerable
<button onClick={eval(userInput)}>
```

### 25. Component Prop Injection

```
\.\.\.(?:req\.(?:body|params|query)|userInput)
```

```javascript
// Vulnerable
<Component {...req.body.props} />
```

### 26. React Router Vulnerabilities

```
<Route\s+path\s*=\s*\{[^}]*req\.
```

```javascript
// Vulnerable
<Route path={req.params.path} />
```

## Express.js Security Issues

### 27. Missing Security Headers

```
app\.use\s*\(\s*helmet\s*\(\s*\)\s*\)
```

```javascript
// Look for missing helmet usage
// This regex finds proper usage - absence indicates vulnerability
```

### 28. Insecure CORS Configuration

```
cors\s*\(\s*\{[^}]*origin\s*:\s*['"`]\*['"`]
```

```javascript
// Vulnerable
app.use(cors({origin: '*'}));
```

### 29. Express Trust Proxy Issues

```
app\.set\s*\(\s*['"`]trust proxy['"`]\s*,\s*true\s*\)
```

```javascript
// Potentially vulnerable
app.set('trust proxy', true);
```

### 30. Unvalidated Redirects

```
res\.redirect\s*\(\s*req\.(?:body|params|query)
```

```javascript
// Vulnerable
res.redirect(req.query.url);
```

## File Upload Vulnerabilities

### 31. Unrestricted File Upload

```
multer\s*\(\s*\{[^}]*(?!.*fileFilter)
```

```javascript
// Vulnerable - no file type validation
const upload = multer({dest: 'uploads/'});
```

### 32. File Type Validation Bypass

```
\.mimetype\s*===?\s*['"`][^'"`]*\/\*['"`]
```

```javascript
// Vulnerable
if (file.mimetype === 'image/*') {
```

### 33. Unsafe File Paths

```
\.originalname\s*\)
```

```javascript
// Vulnerable
fs.writeFile(file.originalname, data);
```

## API Security Issues

### 34. Missing Rate Limiting

```
app\.(?:get|post|put|delete)\s*\(\s*['"`][^'"`]*['"`]\s*,\s*(?!.*rateLimit)
```

```javascript
// Vulnerable - no rate limiting
app.post('/api/login', (req, res) => {
```

### 35. Verbose Error Messages

```
res\.(?:send|json)\s*\(\s*(?:err|error)
```

```javascript
// Vulnerable
res.send(err.stack);
```

### 36. Information Disclosure

```
res\.(?:send|json)\s*\(\s*process\.env
```

```javascript
// Vulnerable
res.json(process.env);
```

## Database Security

### 37. MongoDB Connection String Exposure

```
mongodb:\/\/[^'"`\s]*:[^'"`\s]*@
```

```javascript
// Vulnerable
const uri = "mongodb://user:pass@localhost/db";
```

### 38. Sequelize Logging Sensitive Data

```
logging\s*:\s*console\.log
```

```javascript
// Vulnerable
const sequelize = new Sequelize('db', 'user', 'pass', {
  logging: console.log
});
```

### 39. Unsafe Database Queries

```
\.raw\s*\(\s*['"`][^'"`]*\+
```

```javascript
// Vulnerable
knex.raw('SELECT * FROM users WHERE id = ' + userId);
```

## Environment & Configuration

### 40. Debug Mode in Production

```
debug\s*:\s*true
```

```javascript
// Vulnerable
app.set('debug', true);
```

### 41. Development Dependencies in Production

```
require\s*\(\s*['"`](?:nodemon|webpack-dev-server|mocha)['"`]\s*\)
```

```javascript
// Vulnerable
const nodemon = require('nodemon');
```

### 42. Insecure Protocol Usage

```
http:\/\/(?!localhost|127\.0\.0\.1)
```

```javascript
// Vulnerable
const apiUrl = 'http://api.example.com';
```

## Cryptography Issues

### 43. Weak Hash Algorithms

```
createHash\s*\(\s*['"`](?:md5|sha1)['"`]\s*\)
```

```javascript
// Vulnerable
crypto.createHash('md5').update(password);
```

### 44. Static Salt Usage

```
\.update\s*\(\s*['"`][^'"`]*['"`]\s*\)
```

```javascript
// Vulnerable
crypto.createHash('sha256').update('staticsalt' + password);
```

### 45. Insecure Random Generation

```
Math\.random\s*\(\s*\)
```

```javascript
// Vulnerable for security purposes
const sessionId = Math.random().toString();
```

## WebSocket Security

### 46. Unvalidated WebSocket Messages

```
\.on\s*\(\s*['"`]message['"`]\s*,\s*(?!.*JSON\.parse)
```

```javascript
// Vulnerable
ws.on('message', (data) => {
  eval(data);
});
```

### 47. Missing WebSocket Authentication

```
new\s+WebSocket\s*\(\s*['"`][^'"`]*['"`]\s*\)
```

```javascript
// Check for missing auth in WebSocket connections
const ws = new WebSocket('ws://localhost:3000');
```

## React Hook Security

### 48. Unsafe useEffect Dependencies

```
useEffect\s*\(\s*\(\s*\)\s*=>\s*\{[^}]*eval
```

```javascript
// Vulnerable
useEffect(() => {
  eval(userInput);
}, []);
```

### 49. State Injection via Props

```
useState\s*\(\s*props\.[a-zA-Z_$]
```

```javascript
// Vulnerable
const [state, setState] = useState(props.userInput);
```

## Server-Side Request Forgery (SSRF)

### 50. HTTP Requests with User Input

```
(?:axios|fetch|request|http\.get)\s*\(\s*(?!['"`])
```

```javascript
// Vulnerable
axios.get(req.body.url);
```

### 51. URL Construction with User Input

```
new\s+URL\s*\(\s*(?!['"`])
```

```javascript
// Vulnerable
const url = new URL(userInput);
```

## Regular Expression Denial of Service (ReDoS)

### 52. Vulnerable Regex Patterns

```
new\s+RegExp\s*\(\s*(?!['"`])
```

```javascript
// Vulnerable
const regex = new RegExp(userInput);
```

### 53. Catastrophic Backtracking

```
\/.*\(\.\*\+.*\)\+.*\/
```

```javascript
// Vulnerable
const regex = /(.*+)+/;
```

## npm/Package Security

### 54. Unsafe Package Imports

```
require\s*\(\s*req\.(?:body|params|query)
```

```javascript
// Vulnerable
const module = require(req.body.moduleName);
```

### 55. Dynamic Import with User Input

```
import\s*\(\s*(?!['"`])
```

```javascript
// Vulnerable
import(userInput);
```

## Memory & Resource Issues

### 56. Potential Memory Leaks

```
setInterval\s*\([^)]*\)\s*(?!.*clearInterval)
```

```javascript
// Vulnerable
setInterval(() => {
  // No cleanup
}, 1000);
```

### 57. Unbounded Array Growth

```
\.push\s*\(\s*req\.(?:body|params|query)
```

```javascript
// Vulnerable
globalArray.push(req.body.data);
```

## React Native Specific

### 58. WebView JavaScript Injection

```
<WebView[^>]*source=\{\{[^}]*uri:\s*(?!['"`])
```

```javascript
// Vulnerable
<WebView source={{uri: userInput}} />
```

### 59. AsyncStorage Sensitive Data

```
AsyncStorage\.setItem\s*\(\s*['"`][^'"`]*(?:password|token|key)['"`]
```

```javascript
// Vulnerable
AsyncStorage.setItem('userPassword', password);
```

## GraphQL Security

### 60. GraphQL Query Complexity

```
buildSchema\s*\(\s*(?!.*maxDepth)
```

```javascript
// Vulnerable - no query complexity limits
const schema = buildSchema(schemaString);
```

### 61. GraphQL Injection

```
graphql\s*\(\s*[^,]*,\s*(?!['"`])
```

```javascript
// Vulnerable
graphql(schema, userQuery);
```

## Additional React/Node.js Specific Patterns

### 62. React Context Injection

```
\.Provider\s*value\s*=\s*\{[^}]*req\.(?:body|params|query)
```

```javascript
// Vulnerable
<AuthContext.Provider value={req.body.user}>
```

### 63. Next.js getServerSideProps Injection

```
getServerSideProps[^{]*\{[^}]*req\.(?:body|params|query)
```

```javascript
// Vulnerable
export async function getServerSideProps({req}) {
  return {props: req.body};
}
```

### 64. Express Middleware Bypass

```
app\.use\s*\(\s*['"`][^'"`]*['"`]\s*,\s*(?!.*auth)
```

```javascript
// Vulnerable - route without auth middleware
app.use('/api/admin', adminRoutes);
```

### 65. React setState with User Input

```
setState\s*\(\s*(?:req\.(?:body|params|query)|.*userInput)
```

```javascript
// Vulnerable
this.setState(req.body.state);
```

### 66. Node.js Process Exit

```
process\.exit\s*\(\s*(?!0\s*\))
```

```javascript
// Vulnerable - potential DoS
process.exit(req.body.code);
```

### 67. JWT Token in URL

```
token\s*=\s*['"`][^'"`]*['"`]\s*\+
```

```javascript
// Vulnerable
const url = `/api/data?token=${jwtToken}`;
```

### 68. React Component Names from User Input

```
<\s*\{[^}]*req\.(?:body|params|query)
```

```javascript
// Vulnerable
const ComponentName = req.body.component;
return <{ComponentName} />;
```

### 69. Node.js require.resolve with User Input

```
require\.resolve\s*\(\s*(?!['"`])
```

```javascript
// Vulnerable
const modulePath = require.resolve(userInput);
```

### 70. React useMemo with User Input

```
useMemo\s*\(\s*\(\s*\)\s*=>\s*[^,]*req\.(?:body|params|query)
```

```javascript
// Vulnerable
const memoized = useMemo(() => eval(userInput), []);
```
