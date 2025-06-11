1. **Insecure Use of bypassSecurityTrustHtml**  
    **Description:** Calling Angular’s bypassSecurityTrustHtml on untrusted HTML can lead to bypassing built-in sanitization.  
    **Regex:**
    
    ```
    bypassSecurityTrustHtml\s*\(
    ```
    
    **Vulnerable Code Example:**
    
    ```js
    this.sanitizer.bypassSecurityTrustHtml(userProvidedHtml);
    ```
    
2. **Insecure Use of bypassSecurityTrustStyle**  
    **Description:** Using bypassSecurityTrustStyle on untrusted CSS bypasses sanitization.  
    **Regex:**
    
    ```
    bypassSecurityTrustStyle\s*\(
    ```
    
    **Vulnerable Code Example:**
    
    ```js
    this.sanitizer.bypassSecurityTrustStyle(userProvidedStyle);
    ```
    
3. **Insecure Use of bypassSecurityTrustScript**  
    **Description:** Bypassing Angular’s script sanitization can allow arbitrary script execution.  
    **Regex:**
    
    ```
    bypassSecurityTrustScript\s*\(
    ```
    
    **Vulnerable Code Example:**
    
    ```js
    this.sanitizer.bypassSecurityTrustScript(userProvidedScript);
    ```
    
4. **Insecure Use of bypassSecurityTrustUrl**  
    **Description:** Allowing unvalidated URL strings to bypass security may lead to redirection attacks.  
    **Regex:**
    
    ```
    bypassSecurityTrustUrl\s*\(
    ```
    
    **Vulnerable Code Example:**
    
    ```js
    this.sanitizer.bypassSecurityTrustUrl(userUrl);
    ```
    
5. **Insecure Use of bypassSecurityTrustResourceUrl**  
    **Description:** Bypassing the security check on resource URLs may load unsafe external resources.  
    **Regex:**
    
    ```
    bypassSecurityTrustResourceUrl\s*\(
    ```
    
    **Vulnerable Code Example:**
    
    ```js
    this.sanitizer.bypassSecurityTrustResourceUrl(userResourceUrl);
    ```
    
6. **Un‑sanitized Data Binding to [innerHTML]**  
    **Description:** Binding data directly into innerHTML without proper sanitization can lead to XSS.  
    **Regex:**
    
    ```
    \[innerHTML\]\s*=\s*[^'"]+
    ```
    
    **Vulnerable Code Example:**
    
    ```html
    <div [innerHTML]="userInput"></div>
    ```
    
7. **Direct DOM Manipulation with nativeElement.innerHTML**  
    **Description:** Directly setting innerHTML on a DOM element bypasses Angular sanitization.  
    **Regex:**
    
    ```
    nativeElement\.innerHTML\s*=
    ```
    
    **Vulnerable Code Example:**
    
    ```js
    this.elementRef.nativeElement.innerHTML = unsafeHtml;
    ```
    
8. **Unsafe Use of eval**  
    **Description:** Using eval on user–supplied data can allow execution of malicious code.  
    **Regex:**
    
    ```
    eval\s*\(
    ```
    
    **Vulnerable Code Example:**
    
    ```js
    let result = eval(userInput);
    ```
    
9. **Dangerous Use of the Function Constructor**  
    **Description:** Instantiating functions from strings can be just as risky as eval.  
    **Regex:**
    
    ```
    new\s+Function\s*\(
    ```
    
    **Vulnerable Code Example:**
    
    ```js
    let func = new Function('return ' + userInput);
    ```
    
10. **Dynamic Component Creation Without Sanitization**  
    **Description:** Creating components dynamically without validating content can expose unsafe behavior.  
    **Regex:**
    
    ```
    ComponentFactoryResolver\s*\(
    ```
    
    **Vulnerable Code Example:**
    
    ```js
    this.resolver.resolveComponentFactory(untrustedComponent);
    ```
    
11. **Direct DOM Manipulation Using document.write**  
    **Description:** Using document.write with unsanitized content may allow HTML injection.  
    **Regex:**
    
    ```
    document\.write\s*\(
    ```
    
    **Vulnerable Code Example:**
    
    ```js
    document.write(userContent);
    ```
    
12. **Untrusted URL in [src] Binding**  
    **Description:** Binding unvalidated URLs to the src attribute can allow loading insecure content.  
    **Regex:**
    
    ```
    \[src\]\s*=\s*[^'"]+
    ```
    
    **Vulnerable Code Example:**
    
    ```html
    <img [src]="userProvidedUrl" />
    ```
    
13. **Untrusted URL in [href] Binding**  
    **Description:** Binding URLs directly in href without checks may lead to malicious redirections.  
    **Regex:**
    
    ```
    \[href\]\s*=\s*[^'"]+
    ```
    
    **Vulnerable Code Example:**
    
    ```html
    <a [href]="redirectUrl">Click Here</a>
    ```
    
14. **Angular Template Injection via Function Call**  
    **Description:** Invoking functions directly in template interpolations can lead to injection issues.  
    **Regex:**
    
    ```
    \{\{\s*getUserData\(\)\s*\}\}
    ```
    
    **Vulnerable Code Example:**
    
    ```html
    <div>{{ getUserData() }}</div>
    ```
    
15. **Exposed API Key in Environment Files**  
    **Description:** Hardcoding API keys or secrets in environment files exposes sensitive information.  
    **Regex:**
    
    ```
    apiKey\s*:\s*["'][^"']+["']
    ```
    
    **Vulnerable Code Example:**
    
    ```js
    export const environment = { apiKey: "ABC123SECRET" };
    ```
    
16. **Hard‑Coded Secrets in Component Code**  
    **Description:** Storing credentials directly within your Angular code can be easily compromised.  
    **Regex:**
    
    ```
    const\s+secret\s*=\s*["'][^"']+["']
    ```
    
    **Vulnerable Code Example:**
    
    ```js
    const secret = "hardcoded_secret";
    ```
    
17. **Misconfigured Angular Router Wildcard Route**  
    **Description:** A catch–all route (**) without proper restrictions might expose unintended endpoints.  
    **Regex:**
    
    ```
    \{\s*[^}]*path\s*:\s*["']\*\*["']
    ```
    
    **Vulnerable Code Example:**
    
    ```js
    { path: '**', component: ErrorComponent }
    ```
    
18. **Unprotected Cross–Site Requests via HttpClient**  
    **Description:** Making HTTP requests over insecure protocols can leave the app vulnerable to MITM attacks.  
    **Regex:**
    
    ```
    httpClient\.get\s*\(\s*["'][hH][tT][tT][pP]:\/\/
    ```
    
    **Vulnerable Code Example:**
    
    ```js
    this.httpClient.get('http://unsecure-api.com/data');
    ```
    
19. **Insecure JSONP Usage**  
    **Description:** Using JSONP with HTTP URLs can open the door to cross–site scripting.  
    **Regex:**
    
    ```
    httpClient\.jsonp\s*\(\s*["'][hH][tT][tT][pP]:\/\/
    ```
    
    **Vulnerable Code Example:**
    
    ```js
    this.httpClient.jsonp('http://insecure-jsonp.com', 'callback');
    ```
    
20. **Missing Input Sanitization in Angular Forms**  
    **Description:** Not validating or sanitizing form inputs may allow malicious payloads to be processed.  
    **Regex:**
    
    ```
    <input\s+[^>]*(ngModel|formControl)\s*=\s*["'][^"']+["']
    ```
    
    **Vulnerable Code Example:**
    
    ```html
    <input [(ngModel)]="userInput">
    ```
    
21. **Unsafe Use of bypassSecurityTrustUrl (Again)**  
    **Description:** Reusing bypassSecurityTrustUrl carelessly for dynamic URLs can permit redirection attacks.  
    **Regex:**
    
    ```
    bypassSecurityTrustUrl\s*\(
    ```
    
    **Vulnerable Code Example:**
    
    ```js
    this.sanitizer.bypassSecurityTrustUrl(userUrl);
    ```
    
22. **Improper Use of bypassSecurityTrustResourceUrl (Revisited)**  
    **Description:** Bypassing resource URL checks without validation can expose your app to external threats.  
    **Regex:**
    
    ```
    bypassSecurityTrustResourceUrl\s*\(
    ```
    
    **Vulnerable Code Example:**
    
    ```js
    this.sanitizer.bypassSecurityTrustResourceUrl(untrustedResource);
    ```
    
23. **Unsanitized User Input Through Custom Pipe**  
    **Description:** Creating a pipe that outputs unfiltered content may let unsafe HTML pass through.  
    **Regex:**
    
    ```
    \{\{\s*userInput\s*\|\s*raw\s*\}\}
    ```
    
    **Vulnerable Code Example:**
    
    ```html
    <div>{{ userInput | raw }}</div>
    ```
    
24. **Insecure Use of window.location Assignment**  
    **Description:** Directly assigning user input to window.location can cause malicious redirects.  
    **Regex:**
    
    ```
    window\.location\s*=
    ```
    
    **Vulnerable Code Example:**
    
    ```js
    window.location = userRedirect;
    ```
    
25. **Router Navigation with Dynamic URL**  
    **Description:** Navigating directly using a dynamic, unsanitized URL may allow unexpected behavior.  
    **Regex:**
    
    ```
    this\.router\.navigate\s*\(\s*\[\s*userUrl\s*\]
    ```
    
    **Vulnerable Code Example:**
    
    ```js
    this.router.navigate([userUrl]);
    ```
    
26. **Unrestricted Access to Sensitive Service Methods**  
    **Description:** Publicly exposing methods that return sensitive data can lead to unauthorized access.  
    **Regex:**
    
    ```
    public\s+getSensitiveData\s*\(
    ```
    
    **Vulnerable Code Example:**
    
    ```js
    public getSensitiveData() { return this.sensitiveData; }
    ```
    
27. **Exposure of Internal Variables in Template**  
    **Description:** Displaying internal or private data directly in templates may leak sensitive information.  
    **Regex:**
    
    ```
    \{\{\s*privateData\s*\}\}
    ```
    
    **Vulnerable Code Example:**
    
    ```html
    <div>{{ privateData }}</div>
    ```
    
28. **Insecure Use of localStorage for Sensitive Data**  
    **Description:** Storing sensitive tokens in localStorage exposes them to cross–site scripting attacks.  
    **Regex:**
    
    ```
    localStorage\.setItem\s*\(\s*["']token["']
    ```
    
    **Vulnerable Code Example:**
    
    ```js
    localStorage.setItem('token', userToken);
    ```
    
29. **Insecure Use of sessionStorage for Sensitive Data**  
    **Description:** Storing sensitive information in sessionStorage without proper safeguards is risky.  
    **Regex:**
    
    ```
    sessionStorage\.setItem\s*\(\s*["']session["']
    ```
    
    **Vulnerable Code Example:**
    
    ```js
    sessionStorage.setItem('session', sessionData);
    ```
    
30. **Misconfigured Angular CLI Build (Source Maps Enabled in Production)**  
    **Description:** Including source maps in production builds may expose internal application logic.  
    **Regex:**
    
    ```
    "sourceMap"\s*:\s*true
    ```
    
    **Vulnerable Code Example:**
    
    ```json
    {
      "build": {
        "options": {
          "sourceMap": true
        }
      }
    }
    ```
    
31. **Dangerous Use of eval in Template Expressions**  
    **Description:** Using eval in a template (or called indirectly) can lead to code–injection vulnerabilities.  
    **Regex:**
    
    ```
    \{\{\s*eval\s*\(
    ```
    
    **Vulnerable Code Example:**
    
    ```html
    <div>{{ eval(userCode) }}</div>
    ```
    
32. **Overly Verbose Error Logging Revealing Sensitive Information**  
    **Description:** Printing detailed errors that include sensitive information may aid attackers.  
    **Regex:**
    
    ```
    console\.log\s*\(.*errorMessage.*
    ```
    
    **Vulnerable Code Example:**
    
    ```js
    console.log("Error: " + errorMessage);
    ```
    
33. **Non‑HTTPS External Script in index.html**  
    **Description:** Loading external scripts via HTTP in your HTML exposes the site to MITM attacks.  
    **Regex:**
    
    ```
    <script\s+src\s*=\s*["'][hH][tT][tT][pP]:\/\/
    ```
    
    **Vulnerable Code Example:**
    
    ```html
    <script src="http://external.com/script.js"></script>
    ```
    
34. **Non‑HTTPS External CSS in index.html**  
    **Description:** Including stylesheets over HTTP can open up vectors for content injection.  
    **Regex:**
    
    ```
    <link\s+rel=["']stylesheet["']\s+href\s*=\s*["'][hH][tT][tT][pP]:\/\/
    ```
    
    **Vulnerable Code Example:**
    
    ```html
    <link rel="stylesheet" href="http://external.com/style.css">
    ```
    
35. **Hard‑Coded Credentials in Angular Service**  
    **Description:** Embedding usernames or passwords within the code can lead to easy credential compromise.  
    **Regex:**
    
    ```
    password\s*:\s*["'][^"']+["']
    ```
    
    **Vulnerable Code Example:**
    
    ```js
    const credentials = { username: 'admin', password: 'admin123' };
    ```
    
36. **Unsecured WebSocket Connections**  
    **Description:** Opening WebSocket connections over non‑secure protocols (ws://) can expose communication channels.  
    **Regex:**
    
    ```
    new\s+WebSocket\s*\(\s*["'][wW][sS]:\/\/
    ```
    
    **Vulnerable Code Example:**
    
    ```js
    const socket = new WebSocket('ws://insecure-websocket.com');
    ```
    
37. **Unsafe Use of JSON.parse on Untrusted Data**  
    **Description:** Parsing untrusted JSON can lead to unexpected behavior if the input is manipulated.  
    **Regex:**
    
    ```
    JSON\.parse\s*\(
    ```
    
    **Vulnerable Code Example:**
    
    ```js
    const data = JSON.parse(userInput);
    ```
    
38. **Insecure Use of document.cookie for Sensitive Data**  
    **Description:** Writing sensitive data to document.cookie without flags exposes it to potential theft.  
    **Regex:**
    
    ```
    document\.cookie\s*=
    ```
    
    **Vulnerable Code Example:**
    
    ```js
    document.cookie = "sessionId=" + userSession;
    ```
    
39. **Direct DOM Manipulation Using innerText**  
    **Description:** Manually setting innerText with untrusted data may bypass Angular’s binding protections.  
    **Regex:**
    
    ```
    nativeElement\.innerText\s*=
    ```
    
    **Vulnerable Code Example:**
    
    ```js
    this.elementRef.nativeElement.innerText = unescapedInput;
    ```
    
40. **Component Exposing Debug Information via console.debug**  
    **Description:** Leaving verbose debug logging in production can reveal internal state or sensitive data.  
    **Regex:**
    
    ```
    console\.debug\s*\(
    ```
    
    **Vulnerable Code Example:**
    
    ```js
    console.debug("User data:", data);
    ```
    
41. **Unrestricted Template Reference Variables Revealing Internals**  
    **Description:** Template variables meant for debugging might inadvertently expose sensitive data in the UI.  
    **Regex:**
    
    ```
    \#debug
    ```
    
    **Vulnerable Code Example:**
    
    ```html
    <div #debug>{{ secret }}</div>
    ```
    
42. **Dynamic Module Imports Without Sanitization**  
    **Description:** Importing modules based on user input without verification could load unintended code.  
    **Regex:**
    
    ```
    import\(\s*['"][^'"]+['"]\s*\)
    ```
    
    **Vulnerable Code Example:**
    
    ```js
    import(userModule).then(m => m.default);
    ```
    
43. **Insecure Dependency Injection Exposing Internal Services**  
    **Description:** Injecting internal services into public components without access control can leak functionality.  
    **Regex:**
    
    ```
    constructor\s*\([^)]*private\s+[^:]+\s*:\s*.*Service
    ```
    
    **Vulnerable Code Example:**
    
    ```js
    constructor(private internalService: InternalService) { }
    ```
    
44. **Unauthenticated Access to Sensitive Routes**  
    **Description:** Defining routes for sensitive components without route guards may expose them to unauthorized users.  
    **Regex:**
    
    ```
    path\s*:\s*["']secure["']
    ```
    
    **Vulnerable Code Example:**
    
    ```js
    { path: 'secure', component: SecureComponent }
    ```
    
45. **Excessively Permissive CORS Configuration in Proxies**  
    **Description:** A proxy setting that allows all origins (["*"]) can expose your APIs to abuse.  
    **Regex:**
    
    ```
    "allowedOrigins"\s*:\s*\[\s*["']\*["']\s*\]
    ```
    
    **Vulnerable Code Example:**
    
    ```json
    { "allowedOrigins": ["*"] }
    ```
    
46. **Unvalidated File Upload Handling**  
    **Description:** Using a file input without restricting file type/size can allow malicious files to be processed.  
    **Regex:**
    
    ```
    <input\s+type=["']file["']
    ```
    
    **Vulnerable Code Example:**
    
    ```html
    <input type="file" (change)="onFileChange($event)">
    ```
    
47. **Insecure Use of document.execCommand for Clipboard Operations**  
    **Description:** Relying on clipboard commands with unsanitized input may lead to information leakage.  
    **Regex:**
    
    ```
    document\.execCommand\s*\(\s*["']copy["']\s*\)
    ```
    
    **Vulnerable Code Example:**
    
    ```js
    document.execCommand('copy');
    ```
    
48. **setTimeout Invoked with User Input**  
    **Description:** Passing unsanitized user input as a function to setTimeout can result in delayed code–injection.  
    **Regex:**
    
    ```
    setTimeout\s*\(\s*userInput
    ```
    
    **Vulnerable Code Example:**
    
    ```js
    setTimeout(userInput, 1000);
    ```
    
49. **Inadequate Sanitization in Custom Pipes**  
    **Description:** Creating a custom pipe that returns unmodified input fails to remove malicious content.  
    **Regex:**
    
    ```
    transform\s*\(\s*value\s*:\s*any\s*\)
    ```
    
    **Vulnerable Code Example:**
    
    ```js
    transform(value: any): any {
      return value; // no sanitization performed
    }
    ```
    
50. **Misconfigured Internationalization Debug Attributes**  
    **Description:** Leaving debug attributes (such as i18n-debug) in production templates can expose sensitive keys.  
    **Regex:**
    
    ```
    i18n\-debug\s*
    ```
    
    **Vulnerable Code Example:**
    
    ```html
    <div i18n-debug>{{ 'DEBUG_KEY' }}</div>
    ```
    