## **Step 1: Identify Route Parameters**

In ASP.NET Core, route parameters are defined within route templates in attributes like `[HttpGet("{id}")]` or `[Route("api/users/{userId}")]`.

### **1.1 Find Route Templates with Parameters**

**Regex Pattern:**

```regex
\[.*?(Route|Http(Get|Post|Put|Delete|Patch)).*?\("(.*?\{.*?\}.*?)"\)
```

- **Explanation**:
    - `\[`: Matches the opening square bracket of an attribute.
    - `.*?`: Non-greedy match of any characters.
    - `(Route|Http(Get|Post|Put|Delete|Patch))`: Matches `Route`, `HttpGet`, `HttpPost`, etc.
    - `.*?`: Non-greedy match of any characters.
    - `\("`: Matches `("`.
    - `(.*?\{.*?\}.*?)`: Captures strings containing `{}` which denote route parameters.
    - `"\)`: Matches `")`.

**Usage**:

- This regex will find all route attributes that contain route parameters.

### **1.2 Extract Route Parameter Names**

**Regex Pattern:**

```regex
\{(\w+)\}
```

- **Explanation**:
    - `\{`: Matches the `{` character.
    - `(\w+)`: Captures one or more word characters (the parameter name).
    - `\}`: Matches the `}` character.

**Usage**:

- Use this regex on the route templates extracted in Step 1.1 to find all route parameter names.

---

## **Step 2: Identify Query Parameters**

Query parameters can be bound implicitly by naming method parameters appropriately or explicitly using the `[FromQuery]` attribute.

### **2.1 Find Method Parameters with `[FromQuery]` Attribute**

**Regex Pattern:**

```regex
\[FromQuery\]\s*(?:\w+\s+)?(\w+)
```

- **Explanation**:
    - `\[FromQuery\]`: Matches the `[FromQuery]` attribute.
    - `\s*`: Matches optional whitespace.
    - `(?:\w+\s+)?`: Non-capturing group that optionally matches the data type.
    - `(\w+)`: Captures the parameter name.

**Usage**:

- This regex finds method parameters explicitly marked with `[FromQuery]`.

### **2.2 Find Implicit Query Parameters**

**Regex Pattern:**

```regex
public\s+\w+\s+\w+\s*\(([^)]*)\)
```

- **Explanation**:
    - `public\s+\w+\s+\w+`: Matches the method signature starting with `public`, return type, and method name.
    - `\s*\(`: Matches the opening parenthesis of the parameter list.
    - `([^)]*)`: Captures all characters until the closing parenthesis (the parameter list).

**Follow-Up**:

- Once you have the parameter list, parse each parameter that is not marked with `[FromBody]`, `[FromRoute]`, or `[FromForm]`, as they are likely to be query parameters.

**Refined Regex to Exclude Specific Attributes**:

```regex
(\[From(Body|Route|Form)\]\s*\w+\s+\w+)
```

- **Usage**:
    
    - Remove parameters matched by this regex from the parameter list obtained earlier.

---

## **Step 3: Identify Body Parameters**

Body parameters are typically bound using `[FromBody]` or `[FromForm]` attributes.

### **3.1 Find Parameters with `[FromBody]` or `[FromForm]` Attribute**

**Regex Pattern:**

```regex
\[(FromBody|FromForm)\]\s*(\w+\s+)?(\w+)
```

- **Explanation**:
    - `\[(FromBody|FromForm)\]`: Matches `[FromBody]` or `[FromForm]`.
    - `\s*`: Matches optional whitespace.
    - `(\w+\s+)?`: Optionally captures the data type.
    - `(\w+)`: Captures the parameter name.

**Usage**:

- This regex finds method parameters that receive data from the request body.

---

## **Step 4: Identify User-Controllable Inputs**

User-controllable inputs are parameters that originate from external sources and can be manipulated by users.

### **4.1 Find Direct Usage of User Inputs**

#### **4.1.1 SQL Queries**

**Regex Pattern:**

```regex
(SqlCommand|ExecuteSqlCommand|FromSqlRaw)\s*\(.*?(\w+).*?\)
```

- **Explanation**:
    - `(SqlCommand|ExecuteSqlCommand|FromSqlRaw)`: Matches methods used to execute SQL commands.
    - `\s*\(`: Matches the opening parenthesis.
    - `.*?(\w+)`: Captures the first word (which could be a user input) inside the method call.
    - `.*?\)`: Matches until the closing parenthesis.

**Usage**:

- This regex identifies potential SQL injection points where user inputs are used directly in SQL queries.

#### **4.1.2 File Access**

**Regex Pattern:**

```regex
new\s+File(Stream|Info)?\s*\(.*?(\w+).*?\)
```

- **Explanation**:
    - `new\s+File(Stream|Info)?`: Matches creation of `File`, `FileStream`, or `FileInfo` objects.
    - `\s*\(.*?(\w+)`: Captures the parameter inside the constructor call.
    - `.*?\)`: Matches until the closing parenthesis.

**Usage**:

- Identifies instances where user inputs may influence file operations.

#### **4.1.3 Process Execution**

**Regex Pattern:**

```regex
Process\.Start\s*\(.*?(\w+).*?\)
```

- **Explanation**:
    - `Process\.Start`: Matches the `Process.Start` method.
    - `\s*\(`: Matches the opening parenthesis.
    - `.*?(\w+)`: Captures the parameter inside the method call.
    - `.*?\)`: Matches until the closing parenthesis.

**Usage**:

- Detects potential command injection points.

### **4.2 Find Inputs from `HttpContext` or `Request` Objects**

**Regex Pattern:**

```regex
(HttpContext\.Request|Request)\.(Query|Form|Headers|Body|Path|Cookies)\[?["']?(\w+)["']?\]?
```

- **Explanation**:
    - `(HttpContext\.Request|Request)`: Matches `HttpContext.Request` or `Request`.
    - `\.`: Matches the dot operator.
    - `(Query|Form|Headers|Body|Path|Cookies)`: Matches common request properties.
    - `\[?["']?(\w+)["']?\]?`: Optionally matches an indexer with a key.

**Usage**:

- Identifies where user inputs are accessed directly from the `Request` object.

---

## **Step 5: Analyze Model Binding and View Data**

### **5.1 Find Model Properties in View Models**

**Regex Pattern:**

```regex
public\s+(\w+)\s+(\w+)\s*\{.*?\}
```

- **Explanation**:
    - `public\s+(\w+)\s+(\w+)`: Captures public properties with their data types and names.
    - `\s*\{.*?\}`: Matches the property body.

**Usage**:

- Lists all properties in models used for data binding, which could be user-controllable inputs.

### **5.2 Identify Data Annotations for Validation**

**Regex Pattern:**

```regex
\[(Required|StringLength|Range|RegularExpression|EmailAddress|Phone|Url)(\(.*?\))?\]
```

- **Explanation**:
    - `\[(Required|StringLength|Range|RegularExpression|EmailAddress|Phone|Url)`: Matches common data annotation attributes.
    - `(\(.*?\))?`: Optionally captures attribute parameters.
    - `\]`: Matches the closing bracket.

**Usage**:

- Finds properties that have validation attributes applied.

---

## **Step 6: Analyze JSON/XML Serialization**

### **6.1 Find JSON Deserialization**

**Regex Pattern:**

```regex
(JsonConvert\.DeserializeObject|System\.Text\.Json\.JsonSerializer\.Deserialize)\s*<.*?>\s*\(.*?(\w+).*?\)
```

- **Explanation**:
    - `(JsonConvert\.DeserializeObject|System\.Text\.Json\.JsonSerializer\.Deserialize)`: Matches deserialization methods.
    - `\s*<.*?>\s*`: Matches the generic type parameter.
    - `\(.*?(\w+)`: Captures the parameter inside the method call.
    - `.*?\)`: Matches until the closing parenthesis.

**Usage**:

- Identifies where JSON data is deserialized, potentially from user input.

---

## **Step 7: Combine and Cross-Reference Findings**

- **Trace Parameters**: Map the extracted parameters to their usage in the codebase.
- **Identify Vulnerabilities**: Look for patterns where user inputs are used in sensitive operations without proper validation or sanitization.

---

## **Summary of Regex Patterns**

### **Comprehensive List**

|Purpose|Regex Pattern|
|---|---|
|**Route Templates with Parameters**|`[.*?(Route|
|**Extract Route Parameter Names**|`\{(\w+)\}`|
|**Parameters with `[FromQuery]`**|`\[FromQuery\]\s*(?:\w+\s+)?(\w+)`|
|**Implicit Query Parameters**|`public\s+\w+\s+\w+\s*\(([^)]*)\)`|
|**Exclude `[FromBody]`, `[FromRoute]`**|`([From(Body|
|**Parameters with `[FromBody]`**|`[(FromBody|
|**SQL Query Execution**|`(SqlCommand|
|**File Access Operations**|`new\s+File(Stream|
|**Process Execution**|`Process\.Start\s*\(.*?(\w+).*?\)`|
|**Direct Request Inputs**|`(HttpContext.Request|
|**Model Properties**|`public\s+(\w+)\s+(\w+)\s*\{.*?\}`|
|**Data Annotations**|`[(Required|
|**JSON Deserialization**|`(JsonConvert.DeserializeObject|

---

## **Using the Methodology**

1. **Run the Regex Patterns**: Use the provided regex patterns in VS Code to search your codebase.
    - Press `Ctrl+Shift+F` to open the search panel.
    - Ensure the "Use Regular Expression" option is enabled (icon with `(.*)`).
2. **Analyze the Results**:
    - Review each match to understand how parameters are defined and used.
    - Pay attention to parameters that come from external sources.
3. **Trace Parameter Usage**:
    - Follow the data flow of each parameter to see how it's utilized in the code.
    - Look for any dangerous uses, such as direct inclusion in SQL queries or file paths.
4. **Assess Validation Mechanisms**:
    - Check if proper validation is applied to user inputs.
    - Ensure that data annotations or manual validations are in place.

---

## **Tips for Effective Analysis**

- **Incremental Searches**: Test regex patterns on small sections before applying them to the entire codebase.
- **Customize Patterns**: Adjust regex patterns if your codebase uses custom attributes or patterns.
- **Documentation**: Keep notes on findings to track potential security issues or areas that need refactoring.
- **Collaboration**: Share findings with your team to address any identified issues collaboratively.

---

## **Example Application**

**Given the following controller method:**

```csharp
[HttpPost("users/{userId}/orders")]
public IActionResult CreateOrder(int userId, [FromBody] Order order)
{
    var query = $"INSERT INTO Orders (UserId, ProductId) VALUES ({userId}, {order.ProductId})";
    // Execute query...
    return Ok();
}
```

**Analysis Using Regex Patterns:**

1. **Identify Route Parameters**:
    
    - Match `[HttpPost("users/{userId}/orders")]`.
    - Extract route parameter `{userId}`.
2. **Identify Body Parameters**:
    
    - Find `[FromBody] Order order`.
3. **Find SQL Queries with User Inputs**:
    
    - Match `var query = $"INSERT INTO Orders (UserId, ProductId) VALUES ({userId}, {order.ProductId})";`.
    - Recognize that `userId` and `order.ProductId` are used directly in the SQL query, indicating a potential SQL injection risk.
4. **Assess Validation**:
    
    - Check if `Order` model has data annotations for validation.
    - Ensure that `order.ProductId` is validated before use.