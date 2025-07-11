# React Node.js Security Regex Cheat Sheet for VS Code

## XSS (Cross-Site Scripting) Vulnerabilities

### 1. Direct innerHTML Usage

**Regex:** `\.innerHTML\s*=\s*(?!['"`])`

```javascript
// Vulnerable
element.innerHTML = userInput;
element.innerHTML = req.body.content;
```

### 2. Dangerous React Props

**Regex:** `dangerouslySetInnerHTML\s*=\s*\{\{\s*__html:`

```javascript
// Vulnerable
<div dangerouslySetInnerHTML={{__html: userInput}} />
```

### 3. React createElement with User Input

**Regex:** `React\.createElement\s*\(\s*['"`]script['"`]`

```javascript
// Vulnerable
React.createElement('script', {src: userInput});
```

### 4. Document.write Usage

**Regex:** `document\.write\s*\(`

```javascript
// Vulnerable
document.write('<script>' + userInput + '</script>');
```

### 5. Eval-like Functions

**Regex:** `\b(?:eval|Function|setTimeout|setInterval)\s*\(\s*(?!['"`])`

```javascript
// Vulnerable
eval(userInput);
new Function(userInput)();
```

## SQL Injection

### 6. String Concatenation in Queries

**Regex:** `(?:query|execute)\s*\(\s*['"`][^'"`]*\+`

```javascript
// Vulnerable
db.query('SELECT * FROM users WHERE id = ' + userId);
```

### 7. Template Literals in Queries

**Regex:** `(?:query|execute)\s*\(\s*\`[^`]*\$\{`

```javascript
// Vulnerable
db.query(`SELECT * FROM users WHERE name = '${userName}'`);
```

### 8. Sequelize Raw Queries

**Regex:** `\.query\s*\(\s*['"`][^'"`]*\+|sequelize\.literal\s*\(`

```javascript
// Vulnerable
sequelize.query('SELECT * FROM users WHERE id = ' + req.params.id);
```

## NoSQL Injection

### 9. MongoDB Query Injection

**Regex:** `\$where\s*:\s*(?!['"`])`

```javascript
// Vulnerable
db.collection.find({$where: userInput});
```

### 10. Mongoose Query with User Input

**Regex:** `\.find\s*\(\s*req\.(?:body|params|query)`

```javascript
// Vulnerable
User.find(req.body.query);
```

## Command Injection

### 11. Child Process with User Input

**Regex:** `(?:exec|spawn|execSync|spawnSync)\s*\(\s*(?!['"`])`

```javascript
// Vulnerable
exec(userInput);
child_process.exec('ls ' + userInput);
```

### 12. Shell Command Construction

**Regex:** `['"`][^'"`]*\+.*(?:exec|spawn|system)`

```javascript
// Vulnerable
exec('ping ' + userInput);
```

## Path Traversal

### 13. File System Operations with User Input

**Regex:** `(?:readFile|writeFile|readdir|stat)\s*\(\s*(?:req\.(?:body|params|query)|.*\+)`

```javascript
// Vulnerable
fs.readFile(req.params.filename);
fs.readFile('./uploads/' + fileName);
```

### 14. Express Static with User Input

**Regex:** `express\.static\s*\(\s*(?!['"`])`

```javascript
// Vulnerable
app.use(express.static(userPath));
```

### 15. Path Join with User Input

**Regex:** `path\.join\s*\([^)]*req\.(?:body|params|query)`

```javascript
// Vulnerable
path.join(__dirname, req.params.path);
```

## Authentication & Authorization

### 16. Weak JWT Secret

**Regex:** `jwt\.sign\s*\([^)]*,\s*['"`](?:secret|123|test|key)['"`]`

```javascript
// Vulnerable
jwt.sign(payload, 'secret');
```

### 17. Missing JWT Verification

**Regex:** `jwt\.decode\s*\(`

```javascript
// Vulnerable - decode doesn't verify signature
const decoded = jwt.decode(token);
```

### 18. Insecure Session Configuration

**Regex:** `session\s*\(\s*\{[^}]*secure\s*:\s*false`

```javascript
// Vulnerable
app.use(session({
  secure: false,
  httpOnly: false
}));
```

### 19. Missing CSRF Protection

**Regex:** `app\.use\s*\(\s*csrf\s*\(\s*\)\s*\)`

```javascript
// Check for missing CSRF - this regex finds proper usage
// Look for routes without CSRF protection
```

## Input Validation

### 20. Missing Input Validation

**Regex:** `req\.(?:body|params|query)\.[a-zA-Z_$][a-zA-Z0-9_$]*(?!\s*\.\s*(?:trim|toLowerCase|validation))`

```javascript
// Vulnerable
const userId = req.params.id; // No validation
```

### 21. Weak Regex Validation

**Regex:** `\.match\s*\(\s*\/.*\^\?\|\$\?.*\/`

```javascript
// Vulnerable - missing anchors
if (input.match(/[a-z]+/)) {
```

### 22. Type Coercion Issues

**Regex:** `==\s*(?:true|false|null|undefined|0|1)`

```javascript
// Vulnerable
if (userInput == 0) {
```

## React-Specific Security Issues

### 23. Unsafe React Refs

**Regex:** `ref\s*=\s*\{[^}]*\.current\s*=`

```javascript
// Vulnerable
<input ref={inputRef => window.globalInput = inputRef} />
```

### 24. Event Handler Injection

**Regex:** `on[A-Z][a-zA-Z]*\s*=\s*\{[^}]*userInput`

```javascript
// Vulnerable
<button onClick={eval(userInput)}>
```

### 25. Component Prop Injection

**Regex:** `\.\.\.(?:req\.(?:body|params|query)|userInput)`

```javascript
// Vulnerable
<Component {...req.body.props} />
```

### 26. React Router Vulnerabilities

**Regex:** `<Route\s+path\s*=\s*\{[^}]*req\.`

```javascript
// Vulnerable
<Route path={req.params.path} />
```

## Express.js Security Issues

### 27. Missing Security Headers

**Regex:** `app\.use\s*\(\s*helmet\s*\(\s*\)\s*\)`

```javascript
// Look for missing helmet usage
// This regex finds proper usage - absence indicates vulnerability
```

### 28. Insecure CORS Configuration

**Regex:** `cors\s*\(\s*\{[^}]*origin\s*:\s*['"`]*['"`]`

```javascript
// Vulnerable
app.use(cors({origin: '*'}));
```

### 29. Express Trust Proxy Issues

**Regex:** `app\.set\s*\(\s*['"`]trust proxy['"`]\s*,\s*true\s*\)`

```javascript
// Potentially vulnerable
app.set('trust proxy', true);
```

### 30. Unvalidated Redirects

**Regex:** `res\.redirect\s*\(\s*req\.(?:body|params|query)`

```javascript
// Vulnerable
res.redirect(req.query.url);
```

## File Upload Vulnerabilities

### 31. Unrestricted File Upload

**Regex:** `multer\s*\(\s*\{[^}]*(?!.*fileFilter)`

```javascript
// Vulnerable - no file type validation
const upload = multer({dest: 'uploads/'});
```

### 32. File Type Validation Bypass

**Regex:** `\.mimetype\s*===?\s*['"`][^'"`]*\/\*['"`]`

```javascript
// Vulnerable
if (file.mimetype === 'image/*') {
```

### 33. Unsafe File Paths

**Regex:** `\.originalname\s*\)`

```javascript
// Vulnerable
fs.writeFile(file.originalname, data);
```

## API Security Issues

### 34. Missing Rate Limiting

**Regex:** `app\.(?:get|post|put|delete)\s*\(\s*['"`][^'"`]*['"`]\s*,\s*(?!.*rateLimit)`

```javascript
// Vulnerable - no rate limiting
app.post('/api/login', (req, res) => {
```

### 35. Verbose Error Messages

**Regex:** `res\.(?:send|json)\s*\(\s*(?:err|error)`

```javascript
// Vulnerable
res.send(err.stack);
```

### 36. Information Disclosure

**Regex:** `res\.(?:send|json)\s*\(\s*process\.env`

```javascript
// Vulnerable
res.json(process.env);
```

## Database Security

### 37. MongoDB Connection String Exposure

**Regex:** `mongodb:\/\/[^'"`\s]*:[^'"`\s]*@`

```javascript
// Vulnerable
const uri = "mongodb://user:pass@localhost/db";
```

### 38. Sequelize Logging Sensitive Data

**Regex:** `logging\s*:\s*console\.log`

```javascript
// Vulnerable
const sequelize = new Sequelize('db', 'user', 'pass', {
  logging: console.log
});
```

### 39. Unsafe Database Queries

**Regex:** `\.raw\s*\(\s*['"`][^'"`]*\+`

```javascript
// Vulnerable
knex.raw('SELECT * FROM users WHERE id = ' + userId);
```

## Environment & Configuration

### 40. Debug Mode in Production

**Regex:** `debug\s*:\s*true`

```javascript
// Vulnerable
app.set('debug', true);
```

### 41. Development Dependencies in Production

**Regex:** `require\s*\(\s*['"`](?:nodemon|webpack-dev-server|mocha)['"`]\s*\)`

```javascript
// Vulnerable
const nodemon = require('nodemon');
```

### 42. Insecure Protocol Usage

**Regex:** `http:\/\/(?!localhost|127\.0\.0\.1)`

```javascript
// Vulnerable
const apiUrl = 'http://api.example.com';
```

## Cryptography Issues

### 43. Weak Hash Algorithms

**Regex:** `createHash\s*\(\s*['"`](?:md5|sha1)['"`]\s*\)`

```javascript
// Vulnerable
crypto.createHash('md5').update(password);
```

### 44. Static Salt Usage

**Regex:** `\.update\s*\(\s*['"`][^'"`]*['"`]\s*)`

```javascript
// Vulnerable
crypto.createHash('sha256').update('staticsalt' + password);
```

### 45. Insecure Random Generation

**Regex:** `Math\.random\s*\(\s*\)`

```javascript
// Vulnerable for security purposes
const sessionId = Math.random().toString();
```

## WebSocket Security

### 46. Unvalidated WebSocket Messages

**Regex:** `\.on\s*\(\s*['"`]message['"`]\s*,\s*(?!.*JSON\.parse)`

```javascript
// Vulnerable
ws.on('message', (data) => {
  eval(data);
});
```

### 47. Missing WebSocket Authentication

**Regex:** `new\s+WebSocket\s*\(\s*['"`][^'"`]*['"`]\s*)`

```javascript
// Check for missing auth in WebSocket connections
const ws = new WebSocket('ws://localhost:3000');
```

## React Hook Security

### 48. Unsafe useEffect Dependencies

**Regex:** `useEffect\s*\(\s*\(\s*\)\s*=>\s*\{[^}]*eval`

```javascript
// Vulnerable
useEffect(() => {
  eval(userInput);
}, []);
```

### 49. State Injection via Props

**Regex:** `useState\s*\(\s*props\.[a-zA-Z_$]`

```javascript
// Vulnerable
const [state, setState] = useState(props.userInput);
```

## Server-Side Request Forgery (SSRF)

### 50. HTTP Requests with User Input

**Regex:** `(?:axios|fetch|request|http\.get)\s*\(\s*(?!['"`])`

```javascript
// Vulnerable
axios.get(req.body.url);
```

### 51. URL Construction with User Input

**Regex:** `new\s+URL\s*\(\s*(?!['"`])`

```javascript
// Vulnerable
const url = new URL(userInput);
```

## Regular Expression Denial of Service (ReDoS)

### 52. Vulnerable Regex Patterns

**Regex:** `new\s+RegExp\s*\(\s*(?!['"`])`

```javascript
// Vulnerable
const regex = new RegExp(userInput);
```

### 53. Catastrophic Backtracking

**Regex:** `\/.*\(\.\*\+.*\)\+.*\/`

```javascript
// Vulnerable
const regex = /(.*+)+/;
```

## npm/Package Security

### 54. Unsafe Package Imports

**Regex:** `require\s*\(\s*req\.(?:body|params|query)`

```javascript
// Vulnerable
const module = require(req.body.moduleName);
```

### 55. Dynamic Import with User Input

**Regex:** `import\s*\(\s*(?!['"`])`

```javascript
// Vulnerable
import(userInput);
```

## Memory & Resource Issues

### 56. Potential Memory Leaks

**Regex:** `setInterval\s*\([^)]*\)\s*(?!.*clearInterval)`

```javascript
// Vulnerable
setInterval(() => {
  // No cleanup
}, 1000);
```

### 57. Unbounded Array Growth

**Regex:** `\.push\s*\(\s*req\.(?:body|params|query)`

```javascript
// Vulnerable
globalArray.push(req.body.data);
```

## React Native Specific

### 58. WebView JavaScript Injection

**Regex:** `<WebView[^>]*source=\{\{[^}]*uri:\s*(?!['"`])`

```javascript
// Vulnerable
<WebView source={{uri: userInput}} />
```

### 59. AsyncStorage Sensitive Data

**Regex:** `AsyncStorage\.setItem\s*\(\s*['"`][^'"`]*(?:password|token|key)['"`]`

```javascript
// Vulnerable
AsyncStorage.setItem('userPassword', password);
```

## GraphQL Security

### 60. GraphQL Query Complexity

**Regex:** `buildSchema\s*\(\s*(?!.*maxDepth)`

```javascript
// Vulnerable - no query complexity limits
const schema = buildSchema(schemaString);
```

### 61. GraphQL Injection

**Regex:** `graphql\s*\(\s*[^,]*,\s*(?!['"`])`

```javascript
// Vulnerable
graphql(schema, userQuery);
```

## Usage Instructions

1. **Search in VS Code**: Use Ctrl+Shift+F (Cmd+Shift+F on Mac) to open global search
2. **Enable Regex**: Click the regex button (.*) in the search box
3. **Case Sensitivity**: Consider enabling case-sensitive search for better accuracy
4. **File Type Filtering**: Use the files to include field with patterns like `*.js,*.jsx,*.ts,*.tsx`
5. **Exclude Patterns**: Use files to exclude field with `node_modules,build,dist`

## False Positive Mitigation

- Review each match manually
- Consider context and surrounding code
- Check for existing security measures
- Verify if user input is properly sanitized
- Look for validation frameworks being used
- Check for security middleware implementations

## Additional Security Checks

- Review package.json for vulnerable dependencies
- Check for .env files in version control
- Validate HTTPS usage in production
- Review cookie security settings
- Check for proper error handling
- Validate logging practices
- Review access control implementations