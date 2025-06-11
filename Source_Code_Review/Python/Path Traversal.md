**Path Traversal**, or **Directory Traversal**, is a critical vulnerability where user-controlled input is used to traverse directories inappropriately. It can allow attackers to access sensitive files by manipulating file paths with sequences like `../`, potentially breaching sensitive directories.

In **Python**, this vulnerability arises when unvalidated user inputs are used to construct file paths. Regular code review and security measures are essential to prevent attackers from gaining unauthorized access to sensitive files.

---

<a name="vulnerable-patterns"></a>
## **2. Common Vulnerable Patterns in Python**

Vulnerable patterns in Python that can lead to Path Traversal vulnerabilities include:

- **Constructing Paths from User Input**: Using inputs directly to create file paths.
- **File Reading/Writing with Dynamic Paths**: Allowing users to define file paths for reading or writing.
- **Lack of Path Normalization**: Failing to use `os.path.realpath()` or `os.path.normpath()` on paths to verify they are within a restricted directory.
- **Unrestricted Use of Dangerous File Functions**: Using `open()`, `os.path.join()`, `os.path.isfile()`, `os.listdir()` and similar functions with unvalidated input.

---

<a name="regex-patterns"></a>
## **3. Regex Patterns for Detection**

Below are regex patterns designed to identify potential **Path Traversal** vulnerabilities in **Python** code, compatible with **VS Code**.

### **3.1. Detection of Path Construction with User Input**

**Pattern**:

```regex
(?:open|os\.path\.join|os\.listdir|shutil\.(?:copy|move)|os\.remove|os\.rename|os\.scandir|os\.walk)\s*\(\s*([^\)]+)\s*\)
```

**Explanation**:

- Identifies functions that deal with file and directory operations.
- Captures the arguments passed to these functions, which may include user input.

---

### **3.2. Reading Environment Variables or System Paths**

**Pattern**:

```regex
(os\.environ|getenv|get\('.*?'\))\s*\(\s*([^\)]+)\s*\)
```

**Explanation**:

- Detects cases where environment variables or system paths are used, which could potentially be influenced by user-controlled inputs.

---

### **3.3. Path Manipulation with `..` Sequences**

**Pattern**:

```regex
(["']\.\.\/|\.\.\\["'])
```

**Explanation**:

- Detects direct path manipulation using `../` sequences in strings, commonly used in Path Traversal attacks.

---

### **3.4. Concatenation of User Input for Paths**

**Pattern**:

```regex
\+\s*([a-zA-Z_]\w*\.(get|post|args)\[.*?\]|\w*input\(\))
```

**Explanation**:

- Finds string concatenation or formatting with functions that may contain user input, commonly used to construct file paths.

---

### **3.5. Use of `os.path.abspath` and `os.path.realpath` with User Input**

**Pattern**:

```regex
(os\.path\.abspath|os\.path\.realpath)\s*\(\s*([^\)]+)\s*\)
```

**Explanation**:

- Matches the use of `abspath()` and `realpath()` functions, where unvalidated paths may bypass security checks.

---

### **3.6. File Reading and Writing**

**Pattern**:

```regex
(?:open|read|write)\s*\(\s*([^\)]+)\s*\)
```

**Explanation**:

- Matches common file manipulation functions that may expose the system if user input is not properly validated.

---

<a name="examples"></a>
## **4. Detailed Examples and Explanations**

### **4.1. Vulnerable Code Example: Using `os.path.join` with User Input**

```python
filename = request.args.get('file')
file_path = os.path.join('/var/www/uploads', filename)
with open(file_path, 'r') as file:
    content = file.read()
```

**Why It’s Vulnerable**:

- User input `filename` is concatenated directly, allowing attackers to escape the intended directory by using `../`.

**Regex Match Explanation**:

- The pattern finds `os.path.join(...)` where one of the arguments is unvalidated user input.

---

### **4.2. Vulnerable Code Example: Using `shutil.copy` with User-Supplied Path**

```python
src_path = request.form['source']
dst_path = "/var/www/uploads/"
shutil.copy(src_path, dst_path)
```

**Why It’s Vulnerable**:

- `src_path` is controlled by the user, potentially leading to unauthorized file access.

**Regex Match Explanation**:

- The regex pattern detects `shutil.copy(...)` with unvalidated source paths.

---

### **4.3. Vulnerable Code Example: Reading System Paths with `os.environ`**

```python
config_path = os.environ.get('CONFIG_PATH')
with open(config_path, 'r') as config_file:
    config_data = config_file.read()
```

**Why It’s Vulnerable**:

- The environment variable `CONFIG_PATH` could be set by an attacker to a sensitive file.

**Regex Match Explanation**:

- Matches `os.environ.get(...)` calls that lack validation.

---

### **4.4. Vulnerable Code Example: Unsafe Path Construction Using Concatenation**

```python
filename = request.args.get('filename')
full_path = '/etc/' + filename
with open(full_path, 'r') as file:
    data = file.read()
```

**Why It’s Vulnerable**:

- `filename` is concatenated directly, allowing Path Traversal if `filename` contains `../`.

**Regex Match Explanation**:

- Finds concatenation with potential user input, `request.args.get()`.

---

### **4.5. Vulnerable Code Example: Improper Use of `os.path.abspath`**

```python
filename = request.args.get('file')
file_path = os.path.abspath('/uploads/' + filename)
with open(file_path, 'r') as file:
    data = file.read()
```

**Why It’s Vulnerable**:

- `os.path.abspath` doesn’t prevent traversal attacks if path validation isn’t enforced.

**Regex Match Explanation**:

- Detects `os.path.abspath` calls involving user-controlled data.

---

<a name="interpreting-findings"></a>
## **5. Interpreting and Validating Findings**

- **Source Validation**: Check if user-controlled variables are directly involved in path construction.
- **Path Normalization**: Ensure paths are normalized and checked for traversal sequences like `../`.
- **File Access Permissions**: Ensure the application operates under minimal privileges.
- **Function Purpose**: Identify if the function (e.g., `open`, `copy`) could compromise sensitive files if misused.

---

<a name="prevention"></a>
## **6. Best Practices for Prevention**

### **6.1. Validate and Sanitize User Inputs**

```python
from werkzeug.utils import secure_filename
filename = secure_filename(request.args.get("filename"))
```

- **Explanation**: `secure_filename()` removes dangerous path sequences like `../`.

### **6.2. Use Path Normalization and Canonicalization**

```python
base_path = '/var/www/uploads/'
file_path = os.path.realpath(os.path.join(base_path, filename))

if not file_path.startswith(base_path):
    raise ValueError("Invalid path")
```

- **Explanation**: Ensures the final path is within the restricted directory.