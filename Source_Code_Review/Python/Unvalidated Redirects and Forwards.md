## **1. Introduction to Unvalidated Redirects and Forwards**

**Unvalidated Redirects and Forwards** are vulnerabilities that occur when an application redirects or forwards users to other URLs based on user input without validation. Attackers exploit these to:

- **Phishing Attacks**: Redirecting users to malicious websites.
- **Unauthorized Access**: Accessing restricted internal pages.
- **Cross-Site Scripting (XSS)**: Leveraging redirects to inject XSS payloads.

---

<a name="vulnerable-patterns"></a>
## **2. Common Vulnerable Patterns in Python**

Typical vulnerable patterns that lead to unvalidated redirects or forwards in Python applications include:

- **Using User Input in Redirects Without Validation**: Using request parameters or user-provided input directly in URL redirects.
- **Insecure Use of `redirect()` with User Input**: Flask’s `redirect()` is often used with URLs derived from user input without checks.
- **Open Redirects**: Allowing redirection to external URLs without validation.
- **Dynamic URL Construction**: Concatenating strings or using format functions with user input to build URLs.

---

<a name="regex-patterns"></a>
## **3. Regex Patterns for Detection**

Below are regex patterns tailored for Python to identify unvalidated redirects and forwards. Use these patterns in VS Code’s global search to perform manual inspections.

### **3.1. Usage of `redirect()` with Potential User Input**

**Pattern**:

```regex
redirect\s*\(\s*(.*request\.\w+\(.*\)|\w+\s*.*)
```

**Explanation**:
- Detects the use of `redirect()` with arguments that may include user-provided input.

### **3.2. Fetching Query Parameters for Redirect URLs**

**Pattern**:

```regex
request\.args\.get\s*\(\s*["'](redirect|url|path|next|destination)["']\s*\)
```

**Explanation**:
- Identifies cases where parameters that control redirects (`redirect`, `url`, `path`, etc.) are fetched from user input.

### **3.3. String Concatenation in Redirects or URL Construction**

**Pattern**:

```regex
("|\+)\s*\+\s*(\w+|request\.\w+\(.*\))\s*\+\s*("|\+)
```

**Explanation**:
- Captures URL or path constructions where user input is concatenated directly, making the code potentially vulnerable.

### **3.4. Dynamic URL Building with `f-strings` or `.format()`**

**Pattern for `f-strings`**:

```regex
f"[^"]*\{request\.\w+\([^)]*\)\}[^"]*"
```

**Pattern for `.format()`**:

```regex
\.format\s*\(\s*.*request\.\w+\(.*\).*\)
```

**Explanation**:
- Detects URL building with f-strings or `format()` where `request` parameters may be inserted dynamically.

---

<a name="examples"></a>
## **4. Detailed Examples and Explanations**

### **4.1. Vulnerable Code Example: Using `redirect()` with User Input**

```python
from flask import request, redirect

@app.route('/login')
def login():
    next_page = request.args.get('next')
    return redirect(next_page)
```

**Why It's Vulnerable**:
- The `next` parameter is user-supplied and not validated, allowing attackers to redirect users to external sites.

**Regex Match Explanation**:
- The regex identifies `redirect(next_page)` where `next_page` comes from `request.args.get()`.

---

### **4.2. Vulnerable Code Example: String Concatenation for Dynamic URLs**

```python
destination = "https://example.com/" + request.args.get("page")
return redirect(destination)
```

**Why It's Vulnerable**:
- The `page` parameter is added directly to the base URL without validation. Attackers could control the redirect path.

**Regex Match Explanation**:
- The regex captures `redirect(destination)` with `destination` containing `request.args.get("page")` concatenation.

---

### **4.3. Vulnerable Code Example: Using `.format()` in Redirects**

```python
next_page = request.args.get('next')
return redirect("https://example.com/{}".format(next_page))
```

**Why It's Vulnerable**:
- The URL is dynamically formatted with user input, making it susceptible to redirect to untrusted destinations.

**Regex Match Explanation**:
- The `.format()` pattern captures `next_page` sourced from `request.args.get()` used directly in the redirect.

---

<a name="interpreting-findings"></a>
## **5. Interpreting and Validating Findings**

- **Verify User Input**: Check if input in redirects is sourced from user-controlled parameters like `request.args.get()`.
- **Validation Logic**: Look for any validation or sanitization of the user input before use in redirects.
- **Check for Allowed Destinations**: Validate against a whitelist of permissible URLs.
- **Evaluate Context**: Determine whether redirection is intended to external websites or within the application.

**Example**:
- If `next_page` is validated to only include paths within the app, the risk is reduced. Without validation, the vulnerability persists.

---

<a name="prevention"></a>
## **6. Best Practices for Prevention**

### **6.1. Avoid Direct User Input in Redirects**

- **Avoid using parameters directly**:
  
  ```python
  next_page = request.args.get("next")
  # Do not use next_page directly in redirect
  ```

### **6.2. Implement Whitelisting of Allowed URLs**

- **Define Allowed Destinations**: Create a list of allowed internal paths and validate against it.

  ```python
  allowed_urls = ["/dashboard", "/profile", "/home"]
  next_page = request.args.get("next")
  if next_page in allowed_urls:
      return redirect(next_page)
  return redirect("/error")
  ```

### **6.3. Use Relative Paths for Internal Navigation**

- **Avoid Full URLs**: Use relative paths within the application to ensure the redirect is internal.

  ```python
  return redirect(url_for("home"))
  ```

### **6.4. Validate and Sanitize User Input**

- **Input Validation**: Enforce strict format expectations for parameters controlling redirects.

  ```python
  next_page = request.args.get("next")
  if is_valid_path(next_page):
      return redirect(next_page)
  ```

  ```python
  def is_valid_path(path):
      # Define valid patterns for internal paths
      return path in ["/home", "/profile"]
  ```

### **6.5. Use Flask’s `url_for()` for Internal Links**

- **Use `url_for()`**: Generate internal paths instead of concatenating strings.

  ```python
  return redirect(url_for("dashboard"))
  ```