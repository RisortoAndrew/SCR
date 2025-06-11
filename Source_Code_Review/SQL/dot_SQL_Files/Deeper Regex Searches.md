## 1. Hard-coded Credentials in SQL Scripts

**Issue**  
Developers sometimes drop plaintext passwords, API keys, or access tokens directly into `.sql` files (e.g., test data inserts, connection commands).

**Sample Regex Patterns**

### 1A. Key-value style assignments

```
(password|pwd|secret|token|apikey|auth[_\-]?key)\s*=\s*['"][^'"]+['"]
```

- **Explanation**
    
    - Captures common secret keywords followed by `=` and any quoted value.
        

#### Example Code Snippet That Matches

```sql
-- Initial bootstrap
SET password = 'SuperSecret!123';
```

**Security Impact**: Anyone with repository read access can steal credentials and log straight into production databases.

---

## 2. Privileged User Creation

**Issue**  
Creating users with excessive privileges—or without safe password policies—opens direct lateral-movement paths.

**Sample Regex Pattern**

```
create\s+user\b[^\n]+identified\s+by\s+['"][^'"]+['"]
```

- **Explanation**
    
    - Finds `CREATE USER … IDENTIFIED BY 'password'` clauses.
        

#### Example

```sql
CREATE USER admin IDENTIFIED BY 'Pa$$w0rd';
```

**Security Impact**: Weak or default passwords + high privileges = instant compromise.

---

## 3. GRANT ALL PRIVILEGES on _._

**Issue**  
Scripts that grant blanket permissions ignore least-privilege principles.

**Regex**

```
grant\s+all\s+privileges\s+on\s+\*\.\*\s+to\b
```

#### Example

```sql
GRANT ALL PRIVILEGES ON *.* TO 'app'@'%';
```

**Security Impact**: A hijacked app account can read/alter every table in every schema.

---

## 4. DROP DATABASE / DROP TABLE Statements

**Issue**  
Destructive DDL in deployment scripts can be weaponized or executed accidentally.

**Regex**

```
drop\s+(database|table)\s+\b
```

#### Example

```sql
DROP TABLE users_backup;
```

**Security Impact**: Permanent data loss or ransom leverage.

---

## 5. TRUNCATE TABLE Without Safeguards

**Regex**

```
truncate\s+table\s+\b
```

**Impact**: Removes all rows instantly—often irreversible without backups.

---

## 6. ALTER USER TO SUPERUSER (PostgreSQL)

```
alter\s+user\b[^\n]+superuser
```

**Impact**: Escalates any compromised account to DBA.

---

## 7. `EXEC xp_cmdshell` (SQL Server)

```
exec\s+xp_cmdshell\b
```

**Impact**: Runs OS commands with SQL Server service-account rights → full host takeover.

---

## 8. Unencrypted Connection Flags (e.g., `sslmode=disable`)

```
sslmode\s*=\s*['"]?disable['"]?
```

**Impact**: MITM can sniff credentials and data in transit.

---

## 9. Dynamic SQL Concatenation (= Injection Risk)

```
('|"|`)\s*\+\s*\w+\s*\+\s*('|"|`)
```

**Impact**: Unsanitised variables concatenated into queries invite SQL injection.

---

## 10. `EXECUTE IMMEDIATE` with Variables (Oracle / PL/pgSQL)

```
execute\s+immediate\s+[^;\n]*\|\|[^;\n]*
```

**Impact**: If variables aren’t validated, attackers inject arbitrary SQL.

---

## 11. `LOAD DATA INFILE … LOCAL`

```
load\s+data\s+infile[^\n]*local
```

**Impact**: Reads arbitrary client-side files—exfiltrating tokens or SSH keys.

---

## 12. Forcing `USE master` or `USE mysql` (Prod Scripts)

```
use\s+(master|mysql|postgres|system)\b
```

**Impact**: Queries run in high-value system schemas where accident = disaster.

---

## 13. Disabling FK Checks (`SET FOREIGN_KEY_CHECKS=0`)

```
set\s+foreign_key_checks\s*=\s*0
```

**Impact**: Allows orphaned rows → integrity violations → stealth tampering.

---

## 14. `SET SQL_SAFE_UPDATES=0`

```
set\s+sql_safe_updates\s*=\s*0
```

**Impact**: Enables UPDATE/DELETE without keys—easy to nuke prod data.

---

## 15. Bulk Imports Into World-Readable Paths

```
into\s+outfile\s+['"]\/(var|tmp|www)[^'"]*['"]
```

**Impact**: Dumps tables where web servers or other users can read them.

---

## 16. `LOCK TABLES … WRITE` Left Behind

```
lock\s+tables\s+[^\n]+write
```

**Impact**: If script crashes, tables stay locked → app outage / DoS.

---

## 17. `SELECT … INTO OUTFILE`

```
into\s+outfile\s+['"][^'"]+['"]
```

**Impact**: Can exfiltrate data to attacker-controlled locations.

---

## 18. Hard-Coded Hostnames / IPs

```
(host|server|address)\s*=\s*['"]\d{1,3}(\.\d{1,3}){3}['"]
```

**Impact**: Environment-specific endpoints hinder secrets rotation and may leak topology.

---

## 19. `BACKUP DATABASE` to Public Folders

```
backup\s+database\b[^\n]+to\b[^\n]+disk\s*=\s*['"]\/(var|tmp|public)[^'"]+
```

**Impact**: Creates dump files world-readable or web-accessible.

---

## 20. `sp_addlogin` with Weak Passwords (SQL Server)

```
sp_addlogin\s+@loginame\s*=\s*['"][^'"]+['"][^\n]*@passwd\s*=\s*['"](?![A-Za-z0-9!@#\$%\^&\*]{12,})[^'"]+['"]
```

**Impact**: Adds logins shorter than 12 characters—easily brute-forced.

---

## 21. UPDATE Without WHERE Clause

```
update\s+[^\n]+set\s+[^\n]+;\s*$
```

**Impact**: Mass overwrite—all rows affected.

---

## 22. DELETE Without WHERE Clause

```
delete\s+from\s+[^\n]+;\s*$
```

**Impact**: Mass deletion—permanent data loss.

---

## 23. Cascading Deletes (`ON DELETE CASCADE`) on Sensitive Tables

```
on\s+delete\s+cascade
```

**Impact**: A single compromised FK row erases related records everywhere.

---

## 24. Role Escalation via `CREATE ROLE … SUPERUSER` (Postgres)

```
create\s+role\b[^\n]+superuser
```

**Impact**: New role inherits full cluster control.

---

## 25. Turning Off Logging

```
set\s+global\s+general_log\s*=\s*0
```

**Impact**: Attackers cover tracks by disabling audit trail.

---

## 26. `DROP TRIGGER` Statements

```
drop\s+trigger\b
```

**Impact**: Deletes security or auditing hooks.

---

## 27. Sensitive Comments (Secrets / Topology)

```
--\s*(todo|password|secret|key|token|internal)\b[^\n]*
```

**Impact**: Comments leak credentials, hostnames, or pentest bypass notes.

---

## 28. Inserting PII Unmasked (SSN, Credit-Card)

```
['"]\d{3}-\d{2}-\d{4}['"]|['"]\d{4}-\d{4}-\d{4}-\d{4}['"]
```

**Impact**: Violates privacy regs (GDPR, PCI-DSS).

---

## 29. Plaintext Symmetric Keys in Inserts

```
insert\s+into\s+\w*key\w*\s*\([^)]*\)\s*values\s*\([^)]*['"][A-Za-z0-9\/\+=]{32,}['"][^)]*\)
```

**Impact**: Hard-coded encryption keys allow data decryption outside DB.

---

## 30. Weak Hash Functions (`MD5`, `SHA1`)

```
(md5|sha1)\s*\(
```

**Impact**: Outdated hashing means password cracking is trivial.

---

## 31. Deprecated Crypto (`DES_ENCRYPT`, `OLD_PASSWORD`)

```
des_encrypt|old_password
```

**Impact**: Known-broken algorithms ↔ easy brute force.

---

## 32. Time-Delay Functions (`SLEEP`, `WAITFOR DELAY`)

```
sleep\s*\(|waitfor\s+delay
```

**Impact**: Can turn SQL injection into DoS by pausing threads.

---

## 33. Registry Access (`xp_regread`, `xp_regwrite`)

```
xp_reg(read|write)
```

**Impact**: Reads/writes Windows registry → host persistence.

---

## 34. Cross-Database Chaining (SQL Server)

```
sp_configure\s+['"]cross db ownership chaining['"]\s*,\s*1
```

**Impact**: Users jump across DBs bypassing isolation.

---

## 35. Public Schema Abuse (Postgres)

```
grant\s+.*on\s+schema\s+public\s+to\s+public
```

**Impact**: Anyone can create malicious functions or tables.

---

## 36. `ALTER SYSTEM` Setting Weak Params (Postgres)

```
alter\s+system\s+set\s+password_encryption\s*=\s*'?md5'?
```

**Impact**: Forces cluster-wide downgrade to insecure hash.

---

## 37. `GRANT EXECUTE ON xp_cmdshell`

```
grant\s+execute\s+on\s+xp_cmdshell
```

**Impact**: Non-DBAs can now run OS commands.

---

## 38. Hard-coded Replication Credentials

```
replication_user\s*=\s*['"][^'"]+['"]
```

**Impact**: Stealable creds let attackers stream WAL/binlogs.

---

## 39. Granting SELECT on Sensitive Tables to App Accounts

```
grant\s+select\s+on\s+(customer|user|credit|card|ssn)_\w*\s+to
```

**Impact**: Breach of least-privilege; data exposure if app is popped.

---

## 40. Disabling Audit Triggers (`ALTER TABLE … DISABLE TRIGGER ALL`)

```
alter\s+table\b[^\n]+disable\s+trigger\s+all
```

**Impact**: Eliminates change-tracking.

---

## 41. Unlogged Tables (Postgres)

```
create\s+unlogged\s+table
```

**Impact**: Data disappears on crash; good for temp but sometimes accidental.

---

## 42. `COPY … TO PROGRAM` (Postgres >= 9.3)

```
copy\s+\([^\)]+\)\s+to\s+program\s+['"][^'"]+['"]
```

**Impact**: Executes shell commands → RCE.

---

## 43. Temp Files in `/tmp` via `COPY … TO '/tmp/…'`

```
copy\s+[^\n]+\s+to\s+['"]\/tmp\/[^'"]+['"]
```

**Impact**: Dropped plain-text data readable by other users.

---

## 44. `SET IDENTITY_INSERT … ON` Outside Controlled Context

```
set\s+identity_insert\s+[^\n]+\s+on
```

**Impact**: Allows forging primary keys, breaking referential integrity.

---

## 45. Enabling Unsafe Trace Flags (`DBCC TRACEON`)

```
dbcc\s+traceon\s*\(\s*\d{3,}\s*\)
```

**Impact**: May reveal sensitive data or disable protections.

---

## 46. World-Readable Backup Paths in `mysqldump --result-file=`

```
mysqldump\b[^\n]*--result-file\s*=\s*\/(var|tmp|public)[^\s]+
```

**Impact**: Anyone with server access grabs entire dump.

---

## 47. Reusing Static Salts (`INSERT INTO salts … 'abcdef'`)

```
insert\s+into\s+\w*salt\w*\s+[^\n]*['"][A-Fa-f0-9]{6,8}['"]
```

**Impact**: Identical salts defeat rainbow-table mitigation.

---

## 48. Hard-coded AWS IAM Tokens in SQL Files

```
AKIA[0-9A-Z]{16}
```

**Impact**: Valid keys grant programmatic AWS access.

---

## 49. Stored Proc Building Query Strings (`@sql = @sql + …`)

```
@\w+\s*=\s*@\w+\s*\+\s*
```

**Impact**: Classic SQLi inside stored procedures.

---

## 50. External Language Calls (`LANGUAGE plpythonu|plv8`) Without Sandboxing

```
language\s+(plpythonu|plv8|plruby|plperlu)
```

**Impact**: Untrusted languages execute arbitrary OS code.