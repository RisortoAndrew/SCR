## 1 String concatenation (`+`) inside `cursor.execute`

**Issue** – Untrusted data glued to literals via `+`.

### 1A Literal + variable

```regex
cursor\.execute\(\s*["'`][^"'`]+["'`]\s*\+\s*\w+
```

### 1B Literal + `str(var)`

```regex
cursor\.execute\(\s*["'`][^"'`]+["'`]\s*\+\s*str\(\w+\)
```

**Example**

```python
cursor.execute("SELECT * FROM users WHERE id = " + request.args["id"])
```

**Security Impact** – Attacker injects `OR 1=1 --` to dump data.

---

## 2 Old-style `%` formatting

**Issue** – `printf` substitution dumps raw text into SQL.

### 2A `%s` placeholder

```regex
cursor\.execute\(\s*["'`][^"'`]*%s[^"'`]*["'`]\s*%\s*\w+
```

### 2B Mapping placeholder `%(<key>)s`

```regex
cursor\.execute\(\s*["'`][^"'`]*%\(\w+\)[sd]["'`]\s*%\s*\w+
```

---

## 3 `.format()` / `.format_map()` substitution

**Issue** – `format` inserts variables directly.

### 3A `.format()`

```regex
cursor\.execute\(\s*["'`][^"'`]*\{[^}]+\}[^"'`]*["'`]\.format\(
```

### 3B `.format_map()`

```regex
cursor\.execute\(\s*["'`][^"'`]*\{[^}]+\}[^"'`]*["'`]\.format_map\(
```

---

## 4 `f`-strings (and `fr` raw-f-strings)

**Issue** – Inline interpolation.

### 4A Basic `f"…{var}…"`

```regex
cursor\.execute\(\s*f["'`][^"'`]*\{[^}]+\}[^"'`]*["'`]
```

### 4B `fr"…{var}…"` (raw+f)

```regex
cursor\.execute\(\s*fr?["'`][^"'`]*\{[^}]+\}[^"'`]*["'`]
```

---

## 5 Query variable built with `+=`

**Issue** – Multi-line string growth.

### 5A Incremental build then execute

```regex
query\s*=\s*["'`][^"'`]+[\s\S]*?query\s*\+=\s*\w+[\s\S]*?cursor\.execute\(\s*query
```

---

## 6 `''.join()` construction

**Issue** – Fragments joined then executed.

### 6A List join pattern

```regex
["'`]\.join\(\s*\[[^\]]*["'`][^"'`]*["'`][^\]]*\+\s*\w+
```

### 6B Generator join pattern

```regex
["'`]\.join\(\s*\(\w+\s*for\s*\w+\s*in\s*\w+
```

---

## 7 `string.Template` substitution

**Issue** – `$placeholder` filled unsafely.

### 7A `.substitute()`

```regex
string\.Template\(\s*["'`][^"'`]*\$[a-zA-Z_]\w*[^"'`]*["'`]\)\.substitute\(
```

### 7B `.safe_substitute()`

```regex
string\.Template\(\s*["'`][^"'`]*\$[a-zA-Z_]\w*[^"'`]*["'`]\)\.safe_substitute\(
```

---

## 8 `.replace()` patch-in

**Issue** – Placeholder token swapped for user data.

### 8A Single replace

```regex
cursor\.execute\(\s*["'`][^"'`]*["'`]\.replace\(\s*["'`][^"'`]+["'`]\s*,\s*\w+\s*\)
```

### 8B Chained replaces

```regex
cursor\.execute\(\s*["'`][^"'`]*["'`](?:\.replace\([^)]+\)){2,}
```

---

## 9 SQLAlchemy `text()` with runtime interpolation

**Issue** – Bypasses bind params.

### 9A `text(f"…{var}…")`

```regex
sqlalchemy\.text\(\s*f["'`][^"'`]*\{[^}]+\}[^"'`]*["'`]\)
```

### 9B `text("…{var}…".format())`

```regex
sqlalchemy\.text\(\s*["'`][^"'`]*\{[^}]+\}[^"'`]*["'`]\.format\(
```

---

## 10 Pandas `read_sql*()` helpers

**Issue** – Raw SQL passed to pandas.

### 10A F-string

```regex
read_sql(?:_query|_table)?\(\s*f["'`][^"'`]*\{[^}]+\}[^"'`]*["'`]
```

### 10B `%` formatting

```regex
read_sql(?:_query|_table)?\(\s*["'`][^"'`]*%s[^"'`]*["'`]\s*%\s*\w+
```

---

## 11 Django ORM raw helpers

**Issue** – Skips query builder safety.

### 11A `.raw()` with interpolation

```regex
\w+\.objects\.raw\(\s*f?["'`][^"'`]*\{[^}]+\}[^"'`]*["'`]\)
```

### 11B `.extra(where=[… + var …])`

```regex
\.extra\(\s*[^)]*where\s*=\s*\[[^\]]*\+\s*\w+
```

---

## 12 Peewee raw SQL

**Issue** – Peewee’s raw escape hatch.

### 12A `Model.raw()`

```regex
\w+\.raw\(\s*f?["'`][^"'`]*\{[^}]+\}[^"'`]*["'`]
```

### 12B `SQL("…{var}…")`

```regex
SQL\(\s*f?["'`][^"'`]*\{[^}]+\}[^"'`]*["'`]
```

---

## 13 `sqlite3.executescript`

**Issue** – Executes multiple statements unsafely.

### 13A Literal + variable

```regex
cursor\.executescript\(\s*["'`][^"'`]+["'`]\s*\+\s*\w+
```

### 13B F-string

```regex
cursor\.executescript\(\s*f["'`][^"'`]*\{[^}]+\}[^"'`]*["'`]
```

---

## 14 Dynamic `ORDER BY` / `LIMIT`

**Issue** – User controls structural clause.

### 14A `ORDER BY` concatenation

```regex
cursor\.execute\(\s*["'`][^"'`]*ORDER\s+BY[^"'`]*["'`]\s*\+\s*\w+
```

### 14B `LIMIT` concatenation

```regex
cursor\.execute\(\s*["'`][^"'`]*LIMIT[^"'`]*["'`]\s*\+\s*\w+
```

---

## 15 Dynamic `IN (…)` or `VALUES (…)` via `join`

**Issue** – List elements injected verbatim.

### 15A `IN (…)` list join

```regex
cursor\.execute\(\s*["'`][^"'`]*IN\s*\(\s*["'`]\s*\+\s*["'`]\.join\(
```

### 15B `VALUES (…)` join

```regex
cursor\.execute\(\s*["'`][^"'`]*VALUES\s*\(\s*["'`]\s*\+\s*["'`]\.join\(
```

---

## 16 Dynamic identifiers (table / column names)

**Issue** – Structure of query forged from input.

### 16A Table name via `f`-string

```regex
cursor\.execute\(\s*f["'`][^"'`]*FROM\s+\{[^}]+\}[^"'`]*["'`]
```

### 16B Column list via `f`-string

```regex
cursor\.execute\(\s*f["'`]\s*SELECT\s+\{[^}]+\}\s+FROM[^"'`]*["'`]
```

---

## 17 Dynamic stored-procedure / function call

**Issue** – Procedure name or args crafted unsafely.

### 17A `callproc()` with `f"…{var}…"`

```regex
cursor\.callproc\(\s*f["'`][^"'`]*\{[^}]+\}[^"'`]*["'`]
```