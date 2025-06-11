### Deep Dive on XPath Injection

**XPath Injection** occurs when an application constructs an XPath query dynamically using unsanitized user input. Similar to SQL Injection, if user input is not properly sanitized, attackers can inject malicious XPath expressions into the query. This can allow unauthorized data access, disclosure of sensitive information, or even manipulation of the query to bypass authentication.

#### How XPath Injection Works

XPath queries are often used in applications to retrieve or manipulate XML data. For instance, an application might use XPath to find a user by username and password in an XML document:

```xml
<users>
    <user>
        <username>admin</username>
        <password>password123</password>
    </user>
</users>
```

Given this XML data, an application might construct an XPath query like this:

```python
# Potentially vulnerable Python code
query = f"//user[username='{username}' and password='{password}']"
result = xml_root.xpath(query)
```

In this example, if `username` and `password` come directly from user input without sanitization, an attacker could inject XPath expressions to alter the query. For example, using a username input of `"admin' or '1'='1"`, the query becomes:

```xpath
//user[username='admin' or '1'='1' and password='']
```

This would always return a match, bypassing authentication.

### Example Vulnerable and Fixed Code

#### Vulnerable Example

Here’s a vulnerable Python example:

```python
username = input("Enter username: ")
password = input("Enter password: ")

query = f"//user[username='{username}' and password='{password}']"
result = xml_root.xpath(query)
```

- **Problem:** The query directly embeds user inputs into the XPath expression without sanitization.
- **Risk:** An attacker could inject additional conditions or operators to manipulate the XPath query.

#### Fixed, Non-Vulnerable Example

A safer approach uses parameterized XPath expressions or explicitly escapes inputs. Unfortunately, XPath libraries don’t always support parameterized queries natively, so escaping or encoding input is often the best approach.

```python
import lxml.etree as ET
import re

def sanitize_input(user_input):
    # Basic input sanitization for XPath
    return re.sub(r"['\"\\]", "", user_input)

username = sanitize_input(input("Enter username: "))
password = sanitize_input(input("Enter password: "))

query = f"//user[username='{username}' and password='{password}']"
result = xml_root.xpath(query)
```

- **Solution:** We remove any characters that could alter the XPath structure, like single quotes (`'`), double quotes (`"`), and backslashes (`\`).
- **Result:** The query remains safe because it cannot be easily manipulated by injecting special XPath characters.

### Regex to Find Potential XPath Injection in Code

To locate potential XPath injection vulnerabilities across a codebase, you can search for code patterns where dynamic queries are built using unsanitized user input.

Here’s a **VS Code compatible regex** pattern to identify potentially vulnerable code snippets:

```regex
(?:xpath\(|selectNodes\(|evaluate\()[^;]*["']\s*\+\s*\w+\s*\+\s*["']
```

### Explanation of the Regex

- `(?:xpath\(|selectNodes\(|evaluate\()`: Matches common XPath evaluation methods across different programming languages (like Python’s `xpath()` or JavaScript’s `selectNodes()`).
- `[^;]*`: Matches any content between the method call and the next statement terminator (`;`), indicating the portion of the dynamic query.
- `["']\s*\+\s*\w+\s*\+\s*["']`: Matches string concatenation, where user input variables are likely embedded between `+` symbols in the XPath query.

#### Using the Regex in VS Code

1. **Open the Search Panel**: Use `Ctrl+Shift+F` (Windows/Linux) or `Cmd+Shift+F` (Mac).
2. **Enable Regex**: Click the `.*` icon in the search bar to activate regex mode.
3. **Paste the Regex**: Copy and paste the regex pattern into the search bar to scan your codebase.
4. **Review Matches**: Look for suspicious patterns where XPath expressions use direct concatenation with variables, as these are likely vulnerable to injection.

### Example Matches

This regex would catch code snippets like:

```python
query = "//user[name='" + username + "' and password='" + password + "']"
```