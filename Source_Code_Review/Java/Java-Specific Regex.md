### **1. SQL Injection**

**Description**: Occurs when untrusted input is concatenated into SQL queries without proper sanitization.

**What to Search For**:

- **Usage of `Statement` instead of `PreparedStatement`**:
  ```regex
  \bStatement\b\s+\w+\s*=
  ```
- **Concatenated SQL queries**:
  ```regex
  \bexecute(Query|Update)\b\s*\(.*["'].*\+.*["'].*\)
  ```
  
  ```regex
  ["']\s*\+\s*\w+\s*\+\s*["']
  ```

**Example**:
```java
String query = "SELECT * FROM users WHERE id = " + userId;
Statement stmt = connection.createStatement();
ResultSet rs = stmt.executeQuery(query);
```

---

### **2. Cross-Site Scripting (XSS)**

**Description**: Occurs when unvalidated user input is rendered in the browser, potentially allowing script injection.

**What to Search For**:

- **Direct output to HTTP response**:
  ```regex
  response\.getWriter\(\)\.write\(
  ```
- **Model attributes with user input**:
  ```regex
  model\.addAttribute\(\s*["'].*["']\s*,\s*\w+\s*\)
  ```

**Example**:
```java
String comment = request.getParameter("comment");
response.getWriter().write(comment);
```

---

### **3. Insecure Deserialization**

**Description**: Deserializing untrusted data can lead to arbitrary code execution.

**What to Search For**:

- **ObjectInputStream usage**:
  ```regex
  new\s+ObjectInputStream\s*\(
  ```
- **readObject calls**:
  ```regex
  \breadObject\b\s*\(
  ```

**Example**:
```java
ObjectInputStream ois = new ObjectInputStream(inputStream);
Object obj = ois.readObject();
```

---

### **4. Command Injection**

**Description**: Occurs when user input is used in system commands without proper validation.

**What to Search For**:

- **Runtime execution with user input**:
  ```regex
  Runtime\.getRuntime\(\)\.exec\s*\(.*\+.*\)
  ```
- **ProcessBuilder with user input**:
  ```regex
  new\s+ProcessBuilder\s*\(.*\+.*\)
  ```

**Example**:
```java
String command = "/usr/bin/find " + userInput;
Runtime.getRuntime().exec(command);
```

---

### **5. Path Traversal**

**Description**: Using unvalidated input to construct file paths can allow attackers to access unauthorized files.

**What to Search For**:

- **File operations with user input**:
  ```regex
  new\s+File(InputStream|OutputStream)?\s*\(.*\+.*\)
  ```
- **Resource loading with user input**:
  ```regex
  getResource(AsStream)?\s*\(.*\+.*\)
  ```

**Example**:
```java
String filePath = baseDir + request.getParameter("fileName");
File file = new File(filePath);
```

---

### **6. Authentication and Authorization Issues**

**Description**: Missing or improper access control can expose sensitive functionalities to unauthorized users.

**What to Search For**:

- **Controller methods without security annotations**:
  ```regex
  @RequestMapping\s*\(.*\)\s*public\s+\w+\s+\w+\s*\(
  ```
- **Methods missing `@PreAuthorize`, `@Secured`, or similar annotations**:
  ```regex
  public\s+\w+\s+\w+\s*\(.*\)\s*\{
  ```

**Example**:
```java
@RequestMapping("/admin")
public String adminPanel() {
    // Sensitive admin functionality
}
```

---

### **7. Insecure Direct Object References (IDOR)**

**Description**: Occurs when an application provides direct access to objects based on user input without proper authorization checks.

**What to Search For**:

- **Direct access to entities using user input**:
  ```regex
  findById\s*\(\s*request\.getParameter\(
  ```
- **Repositories accessed with user input**:
  ```regex
  \w+Repository\.\w+\s*\(.*request\.getParameter\(
  ```

**Example**:
```java
int accountId = Integer.parseInt(request.getParameter("accountId"));
Account account = accountRepository.findById(accountId);
```

---

### **8. Unvalidated Redirects and Forwards**

**Description**: Redirecting users to URLs based on unvalidated input can lead to phishing and malicious redirects.

**What to Search For**:

- **Redirects with user input**:
  ```regex
  response\.sendRedirect\s*\(.*\+.*\)
  ```
- **Forwards with user input**:
  ```regex
  request\.getRequestDispatcher\s*\(.*\+.*\)
  ```

**Example**:
```java
String url = request.getParameter("url");
response.sendRedirect(url);
```

---

### **9. Logging Sensitive Information**

**Description**: Logging sensitive data like passwords or credit card numbers can lead to information disclosure.

**What to Search For**:

- **Logging statements with sensitive data**:
  ```regex
  log\.\w+\s*\(.*(password|pwd|secret|token|ssn).*\)
  ```
- **System output of sensitive data**:
  ```regex
  System\.out\.println\s*\(.*(password|pwd|secret|token|ssn).*\)
  ```

**Example**:
```java
log.debug("User password: " + password);
```

---

### **10. Use of Weak Cryptography**

**Description**: Using outdated or weak cryptographic algorithms can compromise data security.

**What to Search For**:

- **MD5 or SHA1 usage**:
  ```regex
  MessageDigest\.getInstance\s*\(\s*["'](MD5|SHA1)["']\s*\)
  ```
- **Insecure random number generation**:
  ```regex
  new\s+Random\s*\(
  ```

**Example**:
```java
MessageDigest md = MessageDigest.getInstance("MD5");
```

---

### **11. Hardcoded Credentials**

**Description**: Storing credentials in code can lead to unauthorized access if the code is compromised.

**What to Search For**:

- **Hardcoded usernames and passwords**:
  ```regex
  (username|user|password|passwd|pwd)\s*=\s*["'][^"']+["']
  ```
- **API keys and tokens**:
  ```regex
  (apiKey|token|secret)\s*=\s*["'][^"']+["']
  ```

**Example**:
```java
String password = "P@ssw0rd!";
```

---

### **12. Misconfiguration and Debug Information**

**Description**: Leaving debug configurations or stack traces in production code can expose sensitive information.

**What to Search For**:

- **Debug flags set to true**:
  ```regex
  (debug|enableDebug)\s*=\s*true
  ```
- **Printing stack traces**:
  ```regex
  catch\s*\(.*\)\s*\{\s*e\.printStackTrace\s*\(
  ```

**Example**:
```java
catch (Exception e) {
    e.printStackTrace();
}
```

---

### **13. Insecure Use of Reflection**

**Description**: Using reflection with untrusted input can lead to code execution vulnerabilities.

**What to Search For**:

- **Reflection methods with user input**:
  ```regex
  Class\.forName\s*\(.*\+.*\)
  ```
  ```regex
  \.getMethod\s*\(.*\+.*\)
  ```

**Example**:
```java
String className = request.getParameter("class");
Class<?> cls = Class.forName(className);
```

---

### **14. Inadequate Input Validation**

**Description**: Failing to validate input can lead to various injection attacks.

**What to Search For**:

- **Methods that accept input without validation**:
  ```regex
  request\.getParameter\s*\(\s*["'].*["']\s*\)
  ```
- **Absence of validation methods**:
  - Search for parameter retrieval without accompanying validation methods like `Integer.parseInt()`, `StringUtils.isNumeric()`, etc.

**Example**:
```java
String age = request.getParameter("age");
// No validation performed
```

---

### **15. Outdated Dependencies**

**Description**: Using outdated libraries can introduce known vulnerabilities.

**What to Search For**:

- **Dependency declarations**:
  - For Maven (`pom.xml`):
    ```regex
    <dependency>[\s\S]*?<groupId>.*?</groupId>[\s\S]*?<artifactId>.*?</artifactId>[\s\S]*?<version>(.*?)</version>[\s\S]*?</dependency>
    ```
  - For Gradle (`build.gradle`):
    ```regex
    (compile|implementation|api)\s+['"].*?:.*?:.*?['"]
    ```