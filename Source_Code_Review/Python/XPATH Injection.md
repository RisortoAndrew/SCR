## **1. Introduction to XPATH Injection**

**XPATH Injection** is a security vulnerability that occurs when an application constructs XPATH queries based on user input without proper validation or sanitization. This allows attackers to manipulate the query, potentially gaining unauthorized access to XML data.

In Python applications, XPATH injection can occur when handling XML data, particularly when user inputs are directly integrated into XPATH expressions. Detecting these vulnerabilities is crucial for securing sensitive data and ensuring application integrity.

---

<a name="vulnerable-patterns"></a>
## **2. Common Vulnerable Patterns in Python**

Vulnerable patterns that could lead to XPATH Injection include:

- **Direct Concatenation of User Input into XPATH Expressions**: Constructing XPATH queries by concatenating strings.
- **Lack of Parameterized Queries**: Failing to use secure libraries or parameterized methods to construct XPATH expressions.
- **Improper Input Sanitization**: Allowing unsanitized input in XPATH queries.
- **Custom Parsing Logic**: Implementing custom logic without proper input handling.

---

<a name="regex-patterns"></a>
## **3. Regex Patterns for Detection**

Below are VS Code-compatible regex patterns for identifying potential XPATH injection vulnerabilities in Python code.

### **3.1. Direct Concatenation of User Input into XPATH Expressions**

**Pattern**:

```regex
(["'].*\s*\+\s*user_input\s*\+\s*.*["'])
```

**Explanation**:

- Matches any line where an XPATH expression includes `+ user_input +`, indicating concatenation with potentially unvalidated input.
- Focuses on vulnerable patterns where variables are concatenated into an XPATH expression directly.

### **3.2. XPATH Queries Without Proper Input Validation**

**Pattern**:

```regex
\.find\(\s*["'].*\s*\+\s*\w+\s*\+\s*.*["']
```

**Explanation**:

- Captures instances of `.find()` that include concatenated input, which may indicate an insecure XPATH query.
- Highlights cases where concatenation might be used in XPATH expressions, leading to injection risks.

### **3.3. Unsanitized Input in XPATH Query**

**Pattern**:

```regex
\.xpath\(["'].*\s*\+\s*\w+\s*\+\s*.*["']
```

**Explanation**:

- Detects `xpath()` calls where user-controlled input is directly concatenated, highlighting potential injection points.
- This pattern identifies cases where user input may be injected into an XPATH query without sanitization.

### **3.4. Custom XML Parsing with User Input**

**Pattern**:

```regex
ET\.ElementTree\(.*user_input.*
```

**Explanation**:

- Finds uses of the `ElementTree` library where user input is directly passed, which may require careful validation.
- Emphasizes reviewing custom XML parsing and tree-building logic.

---

<a name="examples"></a>
## **4. Detailed Examples and Explanations**

### **4.1. Vulnerable Code Example: Direct Concatenation in XPATH Expression**

```python
user_id = request.get("user_id")
query = "/users/user[id='" + user_id + "']/name"
result = xml_tree.xpath(query)
```

**Why It's Vulnerable**:

- The `user_id` variable is concatenated directly into the XPATH query without validation.
- This allows an attacker to manipulate the query by injecting malicious XPATH syntax.

**Regex Match Explanation**:

- The regex matches the `+ user_input +` pattern, indicating potential concatenation in XPATH expressions.

### **4.2. Vulnerable Code Example: Unsanitized Input in XPATH Query**

```python
username = input("Enter username: ")
result = xml_tree.xpath("//user[name='" + username + "']")
```

**Why It's Vulnerable**:

- The `username` input is directly added to the XPATH expression without validation.
- Malicious input in `username` could allow an attacker to access unauthorized nodes.

**Regex Match Explanation**:

- The regex detects concatenation within the `xpath()` function, where unvalidated input is added to the XPATH query.

### **4.3. Vulnerable Code Example: Custom XML Parsing**

```python
from xml.etree import ElementTree as ET

data = request.get("data")
tree = ET.ElementTree(ET.fromstring(data))
```

**Why It's Vulnerable**:

- The `data` variable is directly passed to `fromstring()` without validation.
- An attacker could supply malformed XML data, leading to injection or parsing issues.

**Regex Match Explanation**:

- The regex matches usage of `ElementTree` with user-provided input, flagging potential areas for XPATH injection.

---

<a name="interpreting-findings"></a>
## **5. Interpreting and Validating Findings**

- **Analyze Context**: Not all matches indicate vulnerabilities. Check if proper validation or sanitization is applied.
- **Trace Input Flow**: Follow how user inputs are passed to ensure they are validated before being used in XPATH expressions.
- **Review Data Sources**: Examine data sources and ensure that they do not accept untrusted input without checks.

**Example**:

- Code may appear vulnerable but could have input validation elsewhere in the code that mitigates the risk.
- Input directly in `ET.ElementTree()` may be validated or escaped before reaching that point.

---

<a name="prevention"></a>
## **6. Best Practices for Prevention**

### **6.1. Avoid Direct Concatenation of User Input**

- **Use Libraries**: Use libraries that support parameterized XPATH queries, reducing injection risk.
- **Sanitize Input**: Escape or sanitize user inputs to prevent malicious XPATH expressions.

**Example**:

```python
from lxml import etree

safe_username = escape(user_input)  # Use a function to escape input
result = xml_tree.xpath(f"//user[name='{safe_username}']")
```

### **6.2. Validate and Sanitize Inputs**

- **Whitelist Patterns**: Allow only known-safe characters in user inputs to limit injection potential.
- **Use Validation Libraries**: Employ libraries that handle XML and XPATH safely.

**Example**:

```python
import re

def validate_input(input):
    if re.match("^[a-zA-Z0-9_]+$", input):
        return input
    raise ValueError("Invalid input")

username = validate_input(user_input)
result = xml_tree.xpath(f"//user[name='{username}']")
```

---