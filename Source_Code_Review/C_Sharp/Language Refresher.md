# C# Refresher Cheat Sheet for Source Code Review

This cheat sheet is designed to help you reacquaint yourself with C# applications, focusing on the language features, common patterns, and potential security pitfalls relevant to penetration testing and manual source code review.

---

## Table of Contents

1. **Introduction to C#**
2. **Structure of a C# Application**
3. **Data Types**
4. **Variables and Constants**
5. **Operators**
6. **Control Flow Statements**
7. **Arrays and Collections**
8. **Methods and Parameters**
9. **Exception Handling**
10. **Object-Oriented Programming**
    - Classes and Objects
    - Inheritance
    - Polymorphism
    - Interfaces
    - Abstract Classes
11. **Delegates and Events**
12. **Generics**
13. **LINQ (Language Integrated Query)**
14. **Asynchronous Programming**
15. **Common .NET Libraries**
16. **Security Considerations**
    - Input Validation
    - SQL Injection
    - Cross-Site Scripting (XSS)
    - Authentication and Authorization
    - Cryptography
    - Secure Coding Practices
17. **Best Practices for Code Review**

---

## 1. Introduction to C#

- **C#** is a modern, object-oriented programming language developed by Microsoft as part of the .NET framework.
- **Common Language Runtime (CLR):** Executes C# code and provides services like memory management, type safety, and exception handling.
- **Assemblies:** Compiled code in the form of DLLs or EXEs.

---

## 2. Structure of a C# Application

```csharp
using System; // Namespace declaration

namespace MyApp // Namespace
{
    class Program // Class
    {
        static void Main(string[] args) // Main method - entry point
        {
            // Code execution starts here
        }
    }
}
```

- **Namespaces** organize code and prevent naming conflicts.
- **Classes** are the building blocks containing methods and properties.
- **Methods** perform actions; the `Main` method is the entry point.

---

## 3. Data Types

### Value Types

- **Integral Types:**
    - `byte`, `sbyte`
    - `short`, `ushort`
    - `int`, `uint`
    - `long`, `ulong`
- **Floating-Point Types:**
    - `float`
    - `double`
    - `decimal` (high-precision)
- **Other Types:**
    - `char`
    - `bool`
    - `enum`
    - `struct`

### Reference Types

- **String:** `string`
- **Object:** `object`
- **Arrays:** `int[]`, `string[]`
- **Classes and Interfaces**

### Nullable Types

- Add `?` to value types to allow `null` values: `int?`, `bool?`

---

## 4. Variables and Constants

### Variables

```csharp
int age = 30;
string name = "Alice";
```

### Constants

```csharp
const double Pi = 3.14159;
```

- **Read-only Fields:**

```csharp
readonly int maxSize = 100;
```

---

## 5. Operators

### Arithmetic Operators

- `+`, `-`, `*`, `/`, `%`

### Comparison Operators

- `==`, `!=`, `>`, `<`, `>=`, `<=`

### Logical Operators

- `&&` (AND), `||` (OR), `!` (NOT)

### Assignment Operators

- `=`, `+=`, `-=`, `*=`, `/=`, `%=`

### Other Operators

- **Null-Coalescing:** `??`
- **Null-Conditional:** `?.`
- **Ternary Operator:** `condition ? first_expression : second_expression`

---

## 6. Control Flow Statements

### Conditional Statements

- **if-else:**

```csharp
if (condition)
{
    // Code
}
else if (anotherCondition)
{
    // Code
}
else
{
    // Code
}
```

- **switch:**

```csharp
switch (variable)
{
    case value1:
        // Code
        break;
    case value2:
        // Code
        break;
    default:
        // Code
        break;
}
```

### Loops

- **for Loop:**

```csharp
for (int i = 0; i < length; i++)
{
    // Code
}
```

- **foreach Loop:**

```csharp
foreach (var item in collection)
{
    // Code
}
```

- **while Loop:**

```csharp
while (condition)
{
    // Code
}
```

- **do-while Loop:**

```csharp
do
{
    // Code
} while (condition);
```

### Jump Statements

- `break`, `continue`, `return`, `goto`

---

## 7. Arrays and Collections

### Arrays

```csharp
int[] numbers = new int[5];
int[] initializedArray = { 1, 2, 3, 4, 5 };
```

### Lists

```csharp
List<int> numberList = new List<int>();
numberList.Add(1);
```

### Dictionaries

```csharp
Dictionary<string, int> ages = new Dictionary<string, int>();
ages.Add("Alice", 30);
```

### Other Collections

- `Queue<T>`
- `Stack<T>`
- `HashSet<T>`

---

## 8. Methods and Parameters

### Method Declaration

```csharp
public int Add(int a, int b)
{
    return a + b;
}
```

### Parameter Modifiers

- **ref:** Passes argument by reference.

```csharp
void Modify(ref int x) { x = x + 10; }
```

- **out:** Outputs data through parameters.

```csharp
void GetValues(out int x, out int y) { x = 1; y = 2; }
```

- **params:** Takes variable number of arguments.

```csharp
void PrintNumbers(params int[] numbers) { /*...*/ }
```

---

## 9. Exception Handling

```csharp
try
{
    // Code that may throw an exception
}
catch (ExceptionType ex)
{
    // Handle exception
}
finally
{
    // Code that runs regardless of exception
}
```

- **Custom Exceptions:** Inherit from `Exception` class.

```csharp
public class CustomException : Exception { /*...*/ }
```

---

## 10. Object-Oriented Programming

### Classes and Objects

- **Class Definition:**

```csharp
public class Person
{
    // Fields
    private string name;

    // Properties
    public string Name
    {
        get { return name; }
        set { name = value; }
    }

    // Constructor
    public Person(string name)
    {
        this.name = name;
    }

    // Methods
    public void Greet()
    {
        Console.WriteLine("Hello, " + name);
    }
}
```

- **Object Instantiation:**

```csharp
Person person = new Person("Alice");
person.Greet();
```

### Inheritance

- **Base Class:**

```csharp
public class Animal
{
    public void Eat() { /*...*/ }
}
```

- **Derived Class:**

```csharp
public class Dog : Animal
{
    public void Bark() { /*...*/ }
}
```

### Polymorphism

- **Method Overriding:**

```csharp
public class Animal
{
    public virtual void Speak() { Console.WriteLine("Animal speaks"); }
}

public class Dog : Animal
{
    public override void Speak() { Console.WriteLine("Dog barks"); }
}
```

### Interfaces

- **Interface Definition:**

```csharp
public interface IMovable
{
    void Move();
}
```

- **Implementing Interface:**

```csharp
public class Car : IMovable
{
    public void Move() { /*...*/ }
}
```

### Abstract Classes

- **Abstract Class:**

```csharp
public abstract class Shape
{
    public abstract double GetArea();
}
```

- **Concrete Implementation:**

```csharp
public class Circle : Shape
{
    public override double GetArea() { /*...*/ }
}
```

---

## 11. Delegates and Events

### Delegates

- **Delegate Declaration:**

```csharp
public delegate void Notify(string message);
```

- **Usage:**

```csharp
Notify notifyDelegate = ShowMessage;
notifyDelegate("Hello World");

void ShowMessage(string msg) { Console.WriteLine(msg); }
```

### Events

- **Event Declaration:**

```csharp
public event Notify OnNotify;
```

- **Event Invocation:**

```csharp
OnNotify?.Invoke("Event occurred");
```

---

## 12. Generics

- **Generic Class:**

```csharp
public class GenericList<T>
{
    private T[] items;
    // Implementation
}
```

- **Generic Method:**

```csharp
public void Swap<T>(ref T a, ref T b)
{
    T temp = a;
    a = b;
    b = temp;
}
```

---

## 13. LINQ (Language Integrated Query)

### Query Syntax

```csharp
var result = from item in collection
             where item.Property == value
             select item;
```

### Method Syntax

```csharp
var result = collection.Where(item => item.Property == value)
                       .Select(item => item);
```

### Common LINQ Methods

- `Where()`
- `Select()`
- `OrderBy()`, `OrderByDescending()`
- `GroupBy()`
- `Join()`
- `First()`, `FirstOrDefault()`
- `Any()`, `All()`

---

## 14. Asynchronous Programming

### Async and Await

```csharp
public async Task<string> GetDataAsync()
{
    string data = await FetchDataFromServer();
    return data;
}
```

- **Asynchronous Methods** return `Task` or `Task<T>`.

### Handling Exceptions

- Use `try-catch` within async methods.

---

## 15. Common .NET Libraries

- **System.IO:** File handling.
- **System.Net:** Networking.
- **System.Threading:** Multithreading.
- **System.Data:** Database operations.
- **Newtonsoft.Json or System.Text.Json:** JSON serialization/deserialization.

---

## 16. Security Considerations

### Input Validation

- **Sanitize All Inputs:**

```csharp
string sanitizedInput = HttpUtility.HtmlEncode(userInput);
```

- **Use Validation Libraries:**
    
    - Regular expressions
    - Data annotations in models

### SQL Injection

- **Avoid Concatenated Queries:**

```csharp
// Vulnerable
string query = "SELECT * FROM Users WHERE Name = '" + userInput + "'";
```

- **Use Parameterized Queries:**

```csharp
using (SqlCommand cmd = new SqlCommand("SELECT * FROM Users WHERE Name = @name", conn))
{
    cmd.Parameters.AddWithValue("@name", userInput);
    // Execute query
}
```

### Cross-Site Scripting (XSS)

- **Encode Output:**

```csharp
Response.Write(HttpUtility.HtmlEncode(userInput));
```

### Authentication and Authorization

- **Use Built-in Authentication Mechanisms:**
    
    - ASP.NET Identity
    - OAuth
- **Role-Based Access Control (RBAC):**
    

```csharp
[Authorize(Roles = "Admin")]
public IActionResult AdminOnly()
{
    // Code
}
```

### Cryptography

- **Hashing Passwords:**

```csharp
using (SHA256 sha256Hash = SHA256.Create())
{
    byte[] bytes = sha256Hash.ComputeHash(Encoding.UTF8.GetBytes(rawData));
    // Convert to string
}
```

- **Avoid Weak Algorithms:** Use strong algorithms like SHA256, SHA384, SHA512.

### Secure Coding Practices

- **Error Handling:**
    
    - Do not expose stack traces or sensitive information.
    - Use custom error pages.
- **Secure Configuration:**
    
    - Store connection strings and sensitive data securely.
    - Use configuration files like `appsettings.json` with secrets stored securely.
- **Session Management:**
    
    - Use HTTPS to protect cookies.
    - Set cookie flags: `Secure`, `HttpOnly`, `SameSite`.

---

## 17. Best Practices for Code Review

### General Tips

- **Understand the Architecture:** Familiarize yourself with the application's layers and components.
- **Trace Data Flow:** Identify where user input is accepted, processed, and stored.
- **Identify Entry Points:** Look for web forms, APIs, file uploads, etc.

### Common Vulnerabilities

- **Injection Flaws:** SQL, LDAP, OS command injections.
- **Cross-Site Scripting (XSS):** Reflective, stored, DOM-based.
- **Broken Authentication and Session Management**
- **Insecure Direct Object References**
- **Security Misconfiguration**
- **Sensitive Data Exposure**
- **Cross-Site Request Forgery (CSRF)**
- **Using Components with Known Vulnerabilities**

### Automated Tools

- **Static Code Analysis:** Use tools like SonarQube, Fortify, or Visual Studio Code Analysis.
- **Dependency Checking:** Identify vulnerable packages with tools like OWASP Dependency-Check.

### Checklist

- **Input Validation:** Are all inputs validated and sanitized?
- **Output Encoding:** Is data output to the user encoded properly?
- **Error Handling:** Are exceptions properly caught and handled?
- **Authentication:** Is authentication implemented securely?
- **Authorization:** Are access controls enforced?
- **Cryptography:** Are cryptographic practices up-to-date and strong algorithms used?
- **Logging and Monitoring:** Are security-relevant events logged?
- **Session Management:** Are sessions handled securely?

---

## Conclusion

This cheat sheet provides a comprehensive overview of C# and highlights areas critical for source code review in a security context. Use it as a starting point to dive deeper into specific areas during your code reviews.

---

**References**

- [Microsoft C# Documentation](https://docs.microsoft.com/en-us/dotnet/csharp/)
- [OWASP Secure Coding Practices](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/)
- [C# Programming Guide](https://docs.microsoft.com/en-us/dotnet/csharp/programming-guide/)