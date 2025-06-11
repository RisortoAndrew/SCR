Below is a **PHP-focused** methodology for discovering endpoints in source code, along with **individual regex patterns** (each placed in its own code block) that do **not** use lookbehind or negative lookahead. These patterns are designed to be _compatible with Visual Studio Code_, which does not support certain advanced lookaround features.

---

## **Step 1: Identify the Framework or Routing Approach**

1. Check `composer.json` or directory structure to see if it’s **Laravel**, **Symfony**, **CodeIgniter**, **Slim**, or a **custom** solution.
2. This will guide where to search for route files and controller files.

---

## **Step 2: Locate Routes**

Depending on the framework, the following regex patterns can help you find defined routes.

### **2.1: Laravel Routes**

Look in files like `routes/web.php`, `routes/api.php`, etc.

```regex
Route\s*::\s*(get|post|put|delete|patch|options)\s*\(\s*['"]([^'"]+)['"]\s*,\s*(\[?[A-Za-z0-9_:\\]+::class\s*,\s*['"][A-Za-z0-9_]+['"]\]?|['"][A-Za-z0-9_@]+['"])\)
```

- **Explanation**:
    - `Route\s*::\s*(get|post|...)`: Matches the typical Laravel route methods.
    - `['"]([^'"]+)['"]`: Captures the route path (e.g., `/users/{id}`).
    - Then captures the controller/method, like `[UserController::class, 'show']` or `'UserController@show'`.

---

### **2.2: Symfony Routes**

Symfony may store routes in:

- **Attributes** (PHP 8+)
- **Old Annotations** (docblocks)
- **YAML** or **PHP config** files

#### **a) Attributes (PHP 8+)**

```regex
#\[Route\s*\(\s*['"]([^'"]+)['"].*\)\]
```

- **Explanation**: Looks for `#[Route('/path', ...)]` lines. Captures the `('/path')` portion.

#### **b) Old Annotations (docblock)**

```regex
@Route\s*\(\s*['"]([^'"]+)['"].*\)
```

- **Explanation**: Matches `@Route("/path", ...)` within a docblock.

#### **c) YAML Route Definitions**

```regex
^[^#]*[A-Za-z0-9_]+:\s*\n\s*path:\s*['"]([^'"]+)['"]
```

- **Explanation**:
    - Looks for lines that aren’t commented out (`^[^#]*`) and match a route name.
    - On the next line, captures `path: '/something'`.

_(Note: For multiline YAML patterns, enable “Use Regular Expressions” and “Match multiline” in VS Code, or adapt accordingly.)_

---

### **2.3: CodeIgniter Routes**

For CodeIgniter 4, routes often reside in `app/Config/Routes.php`; for CI3, in `application/config/routes.php`.

```regex
\$routes->(get|post|put|delete|patch)\(\s*['"]([^'"]+)['"]\s*,\s*['"]?([A-Za-z0-9_\\:]+)['"]?\)
```

- **Explanation**:
    - `$routes->get('users', 'UserController::index');`
    - Captures the HTTP method, the URL path, and the controller/method reference.

---

### **2.4: Slim Framework**

Often in a routes file that loads a `Slim\App` instance:

```regex
\$app->(get|post|put|delete|patch|options)\(\s*['"]([^'"]+)['"]\s*,\s*([A-Za-z0-9_:\\]+)::class\s*\.\s*['"]:([A-Za-z0-9_]+)['"]\)
```

- **Explanation**:
    - `$app->get('/users', \App\Controllers\UserController::class . ':index');`
    - Captures the method, route path, controller class, and method name.

---

### **2.5: Custom or Raw PHP**

Look for places handling `$_SERVER['REQUEST_URI']`, or references in `.htaccess`, or custom `switch` statements in `index.php`.

```regex
\$_(GET|POST|REQUEST)\s*\[\s*['"]([^'"]+)['"]\s*\]
```

- **Explanation**: Finds usage of superglobal arrays for route parameters, e.g., `$_GET['page']`.

Also, keep an eye out for `header('Location: ...')` or `redirect(...)` calls that might define or mask endpoints.

---

## **Step 3: Identify Controller Classes or Functions**

Once you find a route reference like `SomeController@method`, locate the actual controller and method:

```regex
class\s+([A-Za-z_][A-Za-z0-9_]*)
```

```regex
public\s+function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\([^)]*\)
```

- **Explanation**:
    - The first captures PHP class definitions.
    - The second finds public method signatures (which often handle requests).

---

## **Step 4: Combine Paths (Group Prefixes, etc.)**

Frameworks like **Laravel** or **Symfony** might group or prefix routes:

- **Laravel** `Route::group(['prefix' => 'admin'], function() {...});`
- **Symfony** `#[Route('/admin')]` at the class level with another `#[Route('/users')]` at the method level → combined to `/admin/users`.

No specific regex is needed here; just watch for **prefix** or **group** definitions and manually merge them with method-level paths.

---

## **Step 5: Check for Dynamic or Variable Paths**

All frameworks support placeholders like `{id}`, `{slug}`, etc.

```regex
\{[a-zA-Z_][a-zA-Z0-9_]*\}
```

- **Explanation**: Captures parameterized route segments.

Also, dynamic route building could involve string concatenation:

```regex
Route\s*::.*\(\s*(["'].*\.\s*\$[A-Za-z_]\w*\s*\.\s*.*["'])\s*,\s*.*\)
```

- **Explanation**: Searches for a `Route::` definition where the path uses concatenation (e.g. `$baseUrl . '/users'`).

---

## **Step 6: Security & Middleware**

### **6.1: Laravel Middleware**

```regex
Route::(get|post|group)\(\s*.*?\[\s*'middleware'\s*=>\s*\[['"]([^'"]+)['"]\]
```

- **Explanation**: Finds lines like:
    
    ```php
    Route::group(['middleware' => ['auth']], function() {
        // ...
    });
    ```
    

### **6.2: Symfony Security**

Using attributes or annotations like `#[IsGranted]`, `@Security`, or `@IsGranted`.

```regex
\#\[IsGranted\s*\(\s*['"]([^'"]+)['"].*\)\]
```

```regex
@Security\s*\(\s*"([^"]+)"\s*\)
```

- **Explanation**: Captures lines like:
    
    ```php
    #[IsGranted('ROLE_ADMIN')]
    ```
    
    or
    
    ```php
    /**
     * @Security("is_granted('ROLE_ADMIN')")
     */
    ```
    

---

## **Step 7: Review Configuration**

- **Laravel**: `.env` might define `APP_URL` or `APP_ENV`.
- **Symfony**: `config/packages/*.yaml` or environment files.
- **CodeIgniter**: `env`, `app/Config/App.php`.
- **Slim/Custom**: custom variables or environment-based definitions.

_(No universal pattern, but searching for keywords like `context_path`, `APP_URL`, or environment references can reveal global prefixes.)_

---

## **Putting It All Together**

1. **Scan for routes** using the framework-specific regex (Steps 2.1–2.5).
2. **Map** each route to its controller or function (Step 3).
3. **Combine** path segments with group/prefix definitions (Step 4).
4. **Identify** dynamic parameters (Step 5).
5. **Check** for middleware/security layers or attributes (Step 6).
6. **Review** config files for additional routing or environment-based changes (Step 7).

The end result is a comprehensive list of **HTTP method → route path → controller method → security**. From there, you can thoroughly assess each endpoint’s functionality, parameters, and access controls.