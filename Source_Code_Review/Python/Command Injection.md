**Command Injection** in Python is a critical security vulnerability that arises when applications pass untrusted, user-supplied input directly to system commands or shell operations. This can enable attackers to execute arbitrary commands on the host OS, leading to unauthorized access, data exfiltration, or complete system compromise.

Python applications are particularly vulnerable if they use methods like `os.system()`, `subprocess` functions, or similar without input validation and sanitization. Understanding and preventing these vulnerabilities is key to secure Python development.

---

<a name="vulnerable-patterns"></a>
## **2. Common Vulnerable Patterns in Python**

Python applications exhibit command injection vulnerabilities in scenarios such as:

- **Using `os.system()` with Untrusted Input**: Passing user input directly to `os.system()` commands.
- **Using `subprocess` with Shell=True**: Allowing user-controlled data in `subprocess` calls with `shell=True`.
- **Executing Dynamic Code with `eval()` or `exec()`**: Using user input in functions like `eval()` or `exec()` for command or code execution.
- **Using `popen` or `call` for Direct Command Execution**: Running shell commands directly with `popen()`, `call()`, `run()`, etc., using user input without sanitization.
- **Improper Input Validation and Sanitization**: Failing to validate or sanitize user input before it reaches any form of command execution.

---

<a name="regex-patterns"></a>
## **3. Regex Patterns for Detection**

Below are regex patterns for detecting potential command injection points in Python. These patterns are designed for VS Code’s global search functionality.

### **3.1. Usage of `os.system()` with User Input**

**Pattern**:

```regex
os\.system\s*\(\s*([^\)]+)\s*\)
```

**Explanation**:

- Identifies calls to `os.system()` with any arguments.
- Highlights user input passed to system commands.

### **3.2. Usage of `subprocess` with `shell=True`**

**Pattern**:

```regex
subprocess\.(call|run|Popen|check_output)\s*\(\s*([^\)]+),\s*shell\s*=\s*True
```

**Explanation**:

- Detects any `subprocess` function that enables `shell=True`, allowing command injection through user input.
- Focuses on potentially dangerous calls in `subprocess`.

### **3.3. Concatenation of Command Strings with User Input**

**Pattern**:

```regex
("|\+)\s*\+\s*(request\.args\.get|request\.form\.get|request\.cookies\.get|sys\.argv\[\d+\]|input\(|[^\s\+;]+)\s*\+\s*("|\+)
```

**Explanation**:

- Identifies instances where user-controlled data is concatenated with command strings.
- Useful for detecting dynamic command construction based on untrusted input.

### **3.4. Using `eval()` or `exec()` with User Input**

**Pattern**:

```regex
(eval|exec)\s*\(\s*([^\)]+)\s*\)
```

**Explanation**:

- Finds cases where `eval()` or `exec()` is used, both of which can lead to arbitrary code execution if user input is present.
- Matches the arguments passed to these potentially dangerous functions.

### **3.5. Direct Execution with `popen` or `call`**

**Pattern**:

```regex
subprocess\.(Popen|call|run|check_call|check_output)\s*\(\s*([^\)]+)\s*\)
```

**Explanation**:

- Detects subprocess command execution functions that may use unsanitized user input.
- Matches the function names and parameters used.

---

<a name="examples"></a>
## **4. Detailed Examples and Explanations**

### **4.1. Vulnerable Code Example: Using `os.system()` with User Input**

```python
command = request.args.get("cmd")
os.system(command)
```

**Why It’s Vulnerable**:

- Executes any command the user inputs, leading to arbitrary command execution.
- No validation on `command`, allowing injection.

**Regex Match Explanation**:

- The regex identifies `os.system(command)`, highlighting the command as user-supplied.

### **4.2. Vulnerable Code Example: `subprocess.run()` with `shell=True`**

```python
user_input = request.args.get("input")
subprocess.run("grep " + user_input, shell=True)
```

**Why It’s Vulnerable**:

- The `shell=True` option allows for command injection via `user_input`.
- An attacker can manipulate the shell command to execute additional commands.

**Regex Match Explanation**:

- This regex detects `subprocess.run(..., shell=True)` and highlights where injection may occur.

### **4.3. Vulnerable Code Example: Concatenation in Command Strings**

```python
filename = request.args.get("file")
cmd = "cat " + filename
os.system(cmd)
```

**Why It’s Vulnerable**:

- Concatenation of user input `filename` with `cmd` opens the door to injection.
- Allows for command manipulation by including special shell characters.

**Regex Match Explanation**:

- Detects the concatenation in `cmd` involving `filename`.

### **4.4. Vulnerable Code Example: Using `eval()` with User Input**

```python
code = request.args.get("code")
eval(code)
```

**Why It’s Vulnerable**:

- Allows execution of any code provided by the user.
- `eval()` should not be used with any user-controlled input.

**Regex Match Explanation**:

- The regex detects `eval(code)` to capture dangerous uses of `eval()`.

### **4.5. Vulnerable Code Example: `subprocess.Popen` with User Input**

```python
script = request.args.get("script")
subprocess.Popen(["/bin/bash", script])
```

**Why It’s Vulnerable**:

- Directly runs a user-supplied script, which could contain any malicious code.
- Requires careful validation on `script`.

**Regex Match Explanation**:

- This pattern identifies `subprocess.Popen` with parameters, highlighting possible user input injection.

---

<a name="interpreting-findings"></a>
## **5. Interpreting and Validating Findings**

- **Trace User Input**: Identify the origin of any data reaching system commands, such as `request.args.get()` or `input()`.
- **Analyze Command Construction**: Review any string concatenations or command constructions that involve user input.
- **Verify Method Calls**: Ensure that functions like `os.system()` and `subprocess` functions with `shell=True` don’t handle untrusted data.
- **Consider Execution Context**: Commands running with elevated privileges pose higher risks if vulnerable.

---

<a name="prevention"></a>
## **6. Best Practices for Prevention**

### **6.1. Avoid Using Commands with User Input**

- **Recommendation**: Avoid `os.system()` or `subprocess` with `shell=True` where user input is involved.
- **Alternative**: Use Python libraries for file operations or other functionality.

### **6.2. Validate and Whitelist Input**

- **Recommendation**: Whitelist inputs to only accept specific values or patterns.
- **Example**:

```python
allowed_commands = ["ls", "pwd", "whoami"]
cmd = request.args.get("cmd")
if cmd in allowed_commands:
    subprocess.run([cmd])
else:
    raise ValueError("Invalid command")
```

### **6.3. Use Argument Arrays Instead of Strings**

- **Avoid Shell Interpretation**: Pass commands as an array, which prevents shell injection.
  
```python
filename = request.args.get("filename")
subprocess.run(["cat", filename])
```

### **6.4. Escape or Sanitize User Input**

- **Sanitize Input**: Escape or remove special characters to prevent injection.

```python
import shlex
filename = request.args.get("filename")
sanitized_filename = shlex.quote(filename)
subprocess.run(["cat", sanitized_filename])
```