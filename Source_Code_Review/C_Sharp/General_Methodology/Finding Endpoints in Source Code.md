### **Step 1: Locate Controllers**

Controllers in C# are typically decorated with the `[Controller]` or `[ApiController]` attribute.

#### **Regex Pattern:**

```regex
\[ApiController\]|\[Controller\]
```

- Matches `[ApiController]` or `[Controller]` attributes.

#### **Process:**

1. Search all `.cs` files for this pattern to identify controller classes.
2. Note the namespaces and the inheritance of classes (e.g., `: ControllerBase`), which also indicate controllers.

---

### **Step 2: Identify Route Mappings**

C# uses attributes like `[Route]`, `[HttpGet]`, `[HttpPost]`, `[HttpPut]`, `[HttpDelete]`, and `[HttpPatch]` to define endpoints.

#### **Regex Pattern for Route Attributes:**

```regex
\[(Route|Http(Get|Post|Put|Delete|Patch))\s*\(\s*("([^"]*)"|path\s*=\s*"([^"]*)")\s*\)\]
```

- Matches attributes such as `[Route("/api/path")]`, `[HttpGet("path")]`, and `[HttpPost]`.

#### **Explanation:**

- `\[`: Matches the opening bracket of the attribute.
- `(Route|Http(Get|Post|Put|Delete|Patch))`: Matches `Route` or specific HTTP method attributes.
- `\s*\(\s*`: Matches the opening parenthesis and optional whitespace.
- `("([^"]*)"|path\s*=\s*"([^"]*)")`: Captures the path string.

#### **Process:**

1. Search within controllers identified in Step 1 using this regex.
2. Note the route definitions for methods and classes.

---

### **Step 3: Extract Full Endpoint Paths**

Routes in ASP.NET Core can be defined at both the **class level** and **method level**.

#### **Regex for Class-level Route:**

```regex
\[Route\("([^"]*)"\)\]
```

- Captures `[Route("base-path")]` annotations.

#### **Process:**

1. Combine class-level `[Route]` attributes with method-level routes to construct full endpoint paths.
2. For example, a class with `[Route("api")]` and a method with `[HttpGet("users")]` forms the full route `api/users`.

---

### **Step 4: Extract Method Signatures**

To understand the handling logic for endpoints, extract method signatures.

#### **Regex Pattern for Method Signatures:**

```regex
(public|protected|private|internal)\s+(\w+\s+)?\w+\s+\w+\s*\([^)]*\)\s*(throws\s+\w+(\s*,\s*\w+)*)?\s*\{?
```

- Captures method signatures, including visibility modifiers, return types, and method parameters.

#### **Explanation:**

- `(public|protected|private|internal)`: Matches access modifiers.
- `(\w+\s+)?`: Optionally captures the return type.
- `\w+\s*\([^)]*\)`: Captures the method name and parameters.

---

### **Step 5: Handle Route Parameters**

Routes can include path parameters such as `/api/users/{id}`.

#### **Regex Pattern for Path Parameters:**

```regex
\{[^}]+\}
```

- Matches variable segments within routes.

#### **Process:**

1. Look for matches within route annotations.
2. Note parameter names for use in endpoint documentation.

---

### **Step 6: Validate Security Configurations**

Endpoints may have security-related attributes like `[Authorize]` or `[AllowAnonymous]`.

#### **Regex Pattern for Security Attributes:**

```regex
\[(Authorize|AllowAnonymous|Authorize\(.*?\))\]
```

- Matches `[Authorize]`, `[AllowAnonymous]`, or `[Authorize("Policy")]`.

#### **Process:**

1. Search controllers and methods for these attributes.
2. Note policies or roles applied to endpoints.

---

### **Step 7: Explore Application Settings**

In ASP.NET Core, settings like a global route prefix or API conventions can be defined in `Startup.cs` or `Program.cs`.

#### **Regex Pattern for `UseEndpoints`:**

```regex
app\.UseEndpoints\s*\(\s*endpoints\s*=>\s*\{[^}]*\}\s*\);
```

- Matches endpoint definitions in the middleware configuration.

#### **Regex Pattern for Global Route Prefix:**

```regex
options\.RoutePrefix\s*=\s*"([^"]*)";
```

- Captures global prefixes for all routes.

#### **Process:**

1. Inspect `Startup.cs`, `Program.cs`, or `appsettings.json` for route-related configurations.
2. Note any middleware or filters that modify routing behavior.

---

### **Step 8: Analyze Dynamic Routes**

Routes can also be constructed dynamically using string concatenation or variables.

#### **Regex Pattern for String Concatenation in Routes:**

```regex
(string\s+\w+\s*=\s*"[^"]*"\s*\+\s*\w+)|\[Route\(".*\{.*\}.*"\)\]
```

- Captures concatenated strings or dynamic segments.

#### **Process:**

1. Manually review methods with dynamic route construction.
2. Trace variable values to understand the complete route.

---

### **Step 9: Automated Workflow**

1. **Locate controllers**: Use the `[ApiController]` and `[Controller]` regex patterns.
2. **Identify routes**: Search for `[Route]` and HTTP method attributes within controllers.
3. **Combine paths**: Merge class-level and method-level routes for full endpoint paths.
4. **Validate security**: Check for `[Authorize]` or `[AllowAnonymous]` annotations.
5. **Review configuration files**: Identify global prefixes or custom middleware.
6. **Trace dynamic routes**: Analyze string concatenations and runtime variables.

---

### **Sample Implementation Using Regex in PowerShell**

You can use a script to automate endpoint discovery:

```powershell
Get-ChildItem -Recurse -Filter "*.cs" | ForEach-Object {
    $content = Get-Content $_.FullName
    $controllers = $content -match "\[ApiController\]|\[Controller\]"
    $routes = $content -match "\[(Route|Http(Get|Post|Put|Delete|Patch))\s*\(.*\)\]"
    $security = $content -match "\[(Authorize|AllowAnonymous|Authorize\(.*?\))\]"
    if ($controllers -or $routes -or $security) {
        Write-Output "File: $($_.FullName)"
        Write-Output "Controllers: $controllers"
        Write-Output "Routes: $routes"
        Write-Output "Security: $security"
    }
}
```

This will:

- Identify controllers and their attributes.
- Extract routes and security annotations.