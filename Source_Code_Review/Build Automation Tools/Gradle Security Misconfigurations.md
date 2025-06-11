1. **HTTP Repository URL in buildscript repositories**  
    _Description_: The use of insecure HTTP URLs in buildscript repositories.  
    **Regex:**
    
    ```
    repositories\s*\{[^}]*url\s*\(\s*["'][hH][tT][tT][pP]:\/\/
    ```
    
    **Vulnerable Code Example:**
    
    ```groovy
    buildscript {
        repositories {
            maven {
                url 'http://insecure.repo.com/maven2'
            }
        }
    }
    ```
    
2. **HTTP Repository URL in project repositories**  
    _Description_: Insecure HTTP URLs used directly in repository definitions.  
    **Regex:**
    
    ```
    url\s*\(\s*["'][hH][tT][tT][pP]:\/\/
    ```
    
    **Vulnerable Code Example:**
    
    ```groovy
    repositories {
        maven {
            url 'http://example.repo.com/maven'
        }
    }
    ```
    
3. **HTTP Plugin Repository in pluginManagement**  
    _Description_: Use of HTTP in pluginManagement repositories.  
    **Regex:**
    
    ```
    pluginManagement\s*\{[^}]*url\s*\(\s*["'][hH][tT][tT][pP]:\/\/
    ```
    
    **Vulnerable Code Example:**
    
    ```groovy
    pluginManagement {
        repositories {
            maven {
                url 'http://plugins.insecure-repo.com'
            }
        }
    }
    ```
    
4. **Dynamic Dependency Version (Plus Operator)**  
    _Description_: Using a dynamic version (with a “+”) may pull in unverified versions.  
    **Regex:**
    
    ```
    ['"]\s*\d+(?:\.\d+){1,2}\+\s*['"]
    ```
    
    **Vulnerable Code Example:**
    
    ```groovy
    dependencies {
        implementation 'org.example:library:1.2+'
    }
    ```
    
5. **Usage of “latest.release” for Dependency Versions**  
    _Description_: Relying on “latest.release” can introduce unpredictable dependency versions.  
    **Regex:**
    
    ```
    ['"]\s*latest\.release\s*['"]
    ```
    
    **Vulnerable Code Example:**
    
    ```groovy
    dependencies {
        implementation 'org.example:library:latest.release'
    }
    ```
    
6. **Usage of “latest.integration” for Dependency Versions**  
    _Description_: Using “latest.integration” can lead to unvetted dependency upgrades.  
    **Regex:**
    
    ```
    ['"]\s*latest\.integration\s*['"]
    ```
    
    **Vulnerable Code Example:**
    
    ```groovy
    dependencies {
        implementation 'org.example:library:latest.integration'
    }
    ```
    
7. **Open-Ended Version Range (e.g. “[1.0,)”)**  
    _Description_: An open-ended version range can result in unintended dependency upgrades.  
    **Regex:**
    
    ```
    ['"]\s*\[.*?,\s*\)\s*['"]
    ```
    
    **Vulnerable Code Example:**
    
    ```groovy
    dependencies {
        implementation 'org.example:library:[1.0,)'
    }
    ```
    
8. **Flat Directory Repository Usage (flatDir)**  
    _Description_: Using a flat directory repository may allow loading of arbitrary JARs.  
    **Regex:**
    
    ```
    flatDir\s*\(\s*\[
    ```
    
    **Vulnerable Code Example:**
    
    ```groovy
    repositories {
        flatDir {
            dirs 'libs'
        }
    }
    ```
    
9. **Apply from External URL (HTTP) for Script Plugins**  
    _Description_: Pulling an external script over HTTP can be intercepted or modified.  
    **Regex:**
    
    ```
    apply\s+from\s*:\s*["'][hH][tT][tT][pP]:\/\/
    ```
    
    **Vulnerable Code Example:**
    
    ```groovy
    apply from: 'http://example.com/insecure-script.gradle'
    ```
    
10. **Explicit Enabling of Insecure Protocols**  
    _Description_: An explicit flag to allow insecure protocols may be enabling vulnerabilities.  
    **Regex:**
    
    ```
    allowInsecureProtocol\s*=\s*true
    ```
    
    **Vulnerable Code Example:**
    
    ```groovy
    repositories {
        maven {
            url 'https://secure.repo.com'
            allowInsecureProtocol = true
        }
    }
    ```
    
11. **Missing Checksum Verification in Gradle Wrapper**  
    _Description_: The absence of a distribution checksum check weakens the integrity of the wrapper.  
    **Regex:**
    
    ```
    [#/]*\s*distributionSha256Sum\s*=
    ```
    
    **Vulnerable Code Example:**
    
    ```properties
    # distributionSha256Sum=abc123def456...
    distributionUrl=https\://services.gradle.org/distributions/gradle-6.7-all.zip
    ```
    
12. **Hardcoded Repository Credentials**  
    _Description_: Hardcoding credentials exposes sensitive information.  
    **Regex:**
    
    ```
    credentials\s*\{[^}]*username\s*:\s*["'][^"']+["'][^}]*password\s*:\s*["'][^"']+["']
    ```
    
    **Vulnerable Code Example:**
    
    ```groovy
    repositories {
        maven {
            url 'https://secured.repo.com'
            credentials {
                username 'admin'
                password 'pass123'
            }
        }
    }
    ```
    
13. **Insecure Maven Repository Configuration**  
    _Description_: Defining a Maven repository using HTTP instead of HTTPS.  
    **Regex:**
    
    ```
    maven\s*\{[^}]*url\s*:\s*["'][hH][tT][tT][pP]:\/\/
    ```
    
    **Vulnerable Code Example:**
    
    ```groovy
    repositories {
        maven {
            url 'http://insecure.mavenrepo.com'
        }
    }
    ```
    
14. **Transitive Dependency Enabled Explicitly**  
    _Description_: Explicitly enabling transitive dependencies without control can inadvertently pull in vulnerable code.  
    **Regex:**
    
    ```
    transitive\s*=\s*true
    ```
    
    **Vulnerable Code Example:**
    
    ```groovy
    configurations.all {
        transitive = true
    }
    ```
    
15. **Use of eval() in Build Scripts**  
    _Description_: Using eval() to execute dynamic code can lead to arbitrary code execution.  
    **Regex:**
    
    ```
    \beval\s*\(
    ```
    
    **Vulnerable Code Example:**
    
    ```groovy
    def result = eval("1+1")
    ```
    
16. **Hardcoded Absolute File Paths (Windows style)**  
    _Description_: Hardcoded Windows file paths may inadvertently expose system structure.  
    **Regex:**
    
    ```
    ["'][A-Za-z]:\\
    ```
    
    **Vulnerable Code Example:**
    
    ```groovy
    def libPath = "C:\\Users\\example\\libs"
    ```
    
17. **Hardcoded Absolute File Paths (Unix style)**  
    _Description_: Absolute Unix file paths in code can reveal sensitive system details.  
    **Regex:**
    
    ```
    ["']\/[^"']+["']
    ```
    
    **Vulnerable Code Example:**
    
    ```groovy
    def configPath = '/etc/gradle/config'
    ```
    
18. **Direct Use of System Environment Variables**  
    _Description_: Directly pulling environment variables might bypass proper validations.  
    **Regex:**
    
    ```
    System\.getEnv\s*\(
    ```
    
    **Vulnerable Code Example:**
    
    ```groovy
    def dbPassword = System.getEnv("DB_PASS")
    ```
    
19. **Logging Sensitive Data (e.g. passwords, secrets) via println()**  
    _Description_: Logging sensitive data using println() can lead to accidental exposure.  
    **Regex:**
    
    ```
    println\s*\(.*(password|secret)
    ```
    
    **Vulnerable Code Example:**
    
    ```groovy
    println "User password: " + user.password
    ```
    
20. **Hardcoded Secrets in Key-Value Style**  
    _Description_: Hardcoded secrets in configuration maps represent a risk if checked into VCS.  
    **Regex:**
    
    ```
    ['"](?:password|secret|token)['"]\s*:\s*["'][^"']+["']
    ```
    
    **Vulnerable Code Example:**
    
    ```groovy
    ext {
        credentials = [username: 'user', password: 'secretPass']
    }
    ```
    
21. **Deprecated API Usage (Internal Gradle APIs)**  
    _Description_: Usage of Gradle internal APIs that are deprecated may bypass security fixes.  
    **Regex:**
    
    ```
    org\.gradle\.api\.internal
    ```
    
    **Vulnerable Code Example:**
    
    ```groovy
    import org.gradle.api.internal.artifacts.dependencies.DefaultExternalModuleDependency
    dependencies {
        implementation new DefaultExternalModuleDependency("org.example", "lib", "1.0")
    }
    ```
    
22. **Usage of Legacy Java Plugin Names**  
    _Description_: Applying legacy plugin names that might not be maintained or secure.  
    **Regex:**
    
    ```
    apply\s+plugin:\s*["']?java-old["']?
    ```
    
    **Vulnerable Code Example:**
    
    ```groovy
    apply plugin: 'java-old'
    ```
    
23. **Misconfigured Signing Configurations**  
    _Description_: Signing configurations that are incomplete or insecurely defined.  
    **Regex:**
    
    ```
    signing\s*\{
    ```
    
    **Vulnerable Code Example:**
    
    ```groovy
    signing {
        // Missing key and certificate configuration details
    }
    ```
    
24. **Improper Dependency Exclusions**  
    _Description_: Incorrect dependency exclusions may lead to unintentionally including vulnerable transitive dependencies.  
    **Regex:**
    
    ```
    exclude\s*\(\s*['"][^'"]+['"]\s*\)
    ```
    
    **Vulnerable Code Example:**
    
    ```groovy
    dependencies {
        implementation('org.example:library:1.0') {
            exclude 'org.unwanted'
        }
    }
    ```
    
25. **Wildcards in Dependency Group Names**  
    _Description_: Wildcards in group declarations might inadvertently match and pull unwanted artifacts.  
    **Regex:**
    
    ```
    group\s*:\s*["'][^"']*\*[^"']*["']
    ```
    
    **Vulnerable Code Example:**
    
    ```groovy
    dependencies {
        implementation 'org.*:library:1.0'
    }
    ```
    
26. **Skipping Tests in Build Configurations**  
    _Description_: Disabling tests may hide vulnerabilities during the build process.  
    **Regex:**
    
    ```
    test\s*\{[^}]*skipTests\s*=\s*true
    ```
    
    **Vulnerable Code Example:**
    
    ```groovy
    test {
        skipTests = true
    }
    ```
    
27. **Remote Build Script Inclusion from Insecure URLs**  
    _Description_: Including external scripts over HTTP can lead to execution of compromised code.  
    **Regex:**
    
    ```
    buildscript\s*\{[^}]*apply\s+from\s*:\s*["'][hH][tT][tT][pP]:\/\/
    ```
    
    **Vulnerable Code Example:**
    
    ```groovy
    buildscript {
        apply from: 'http://example.com/insecure-buildscript.gradle'
    }
    ```
    
28. **Unchecked Execution of Shell Commands**  
    _Description_: Tasks that execute shell commands without proper input sanitization may be abused.  
    **Regex:**
    
    ```
    task\s+\w+\s*\{[^}]*doLast\s*\{[^}]*Runtime\.getRuntime\(\)\.exec\s*\(
    ```
    
    **Vulnerable Code Example:**
    
    ```groovy
    task runShell {
        doLast {
            Runtime.getRuntime().exec("rm -rf /")
        }
    }
    ```
    
29. **Exposed Remote Build Cache URLs**  
    _Description_: Using remote build cache URLs over HTTP that are not secured.  
    **Regex:**
    
    ```
    buildCache\s*\{[^}]*remote\s*\{[^}]*url\s*:\s*["'][hH][tT][tT][pP]:\/\/
    ```
    
    **Vulnerable Code Example:**
    
    ```groovy
    buildCache {
        remote {
            url 'http://cache.insecure.com'
        }
    }
    ```
    
30. **Insecure Debug Mode Enabled**  
    _Description_: Enabling debug mode in a production build can expose sensitive build details.  
    **Regex:**
    
    ```
    debug\s*:\s*true
    ```
    
    **Vulnerable Code Example:**
    
    ```groovy
    buildTypes {
        release {
            debug = true
        }
    }
    ```
    
31. **Misconfigured or Unlabeled “Private” Repositories**  
    _Description_: Repositories labeled as “private” without proper access restrictions.  
    **Regex:**
    
    ```
    repositories\s*\{[^}]*(private)
    ```
    
    **Vulnerable Code Example:**
    
    ```groovy
    repositories {
        maven {
            name 'private'
            url 'http://internal.repo.com'
        }
    }
    ```
    
32. **Excessive Use of External Script Plugins**  
    _Description_: Multiple insecure external script inclusions increase risk.  
    **Regex:**
    
    ```
    apply\s+from\s*:\s*["'][hH][tT][tT][pP]:\/\/.+\.gradle
    ```
    
    **Vulnerable Code Example:**
    
    ```groovy
    apply from: 'http://example.com/script1.gradle'
    apply from: 'http://example.com/script2.gradle'
    ```
    
33. **Insecure Dependency Resolution Strategy**  
    _Description_: Disabling conflict resolution checks may lead to insecure dependency versions being used.  
    **Regex:**
    
    ```
    resolutionStrategy\s*\{[^}]*failOnVersionConflict\s*=\s*false
    ```
    
    **Vulnerable Code Example:**
    
    ```groovy
    configurations.all {
        resolutionStrategy {
            failOnVersionConflict = false
        }
    }
    ```
    
34. **Non-Canonical Dependency Coordinates**  
    _Description_: Using improperly formatted dependency coordinates can introduce ambiguities.  
    **Regex:**
    
    ```
    (compile|implementation)\s+['"][^:'"]+:[^:'"]+:[^:'"]+['"]
    ```
    
    **Vulnerable Code Example:**
    
    ```groovy
    dependencies {
        implementation "org.example:library:1.0"
    }
    ```
    
35. **Unspecified Gradle Wrapper SHA Checksum**  
    _Description_: Missing a specified SHA256 checksum for the Gradle wrapper distribution may let tampered distributions slip by.  
    **Regex:**
    
    ```
    distributionSha256Sum\s*=
    ```
    
    **Vulnerable Code Example:**
    
    ```properties
    distributionUrl=https\://services.gradle.org/distributions/gradle-6.7-all.zip
    # distributionSha256Sum is missing or commented out.
    ```
    
36. **Exposed Custom Task with Shell Execution**  
    _Description_: Custom tasks that directly call shell commands.  
    **Regex:**
    
    ```
    task\s+\w+\s*\{[^}]*exec\s*\(
    ```
    
    **Vulnerable Code Example:**
    
    ```groovy
    task runCommand {
        exec {
            commandLine 'sh', '-c', 'ls -la'
        }
    }
    ```
    
37. **Usage of Insecure TLS/SSL Options**  
    _Description_: Explicitly disabling TLS/SSL verification.  
    **Regex:**
    
    ```
    insecureTLS\s*=\s*true
    ```
    
    **Vulnerable Code Example:**
    
    ```groovy
    httpClient {
        insecureTLS = true
    }
    ```
    
38. **Disabled SSL Verification in HTTP Requests**  
    _Description_: Disabling SSL certificate verification in tasks or plugins.  
    **Regex:**
    
    ```
    sslVerification\s*=\s*false
    ```
    
    **Vulnerable Code Example:**
    
    ```groovy
    task fetchData {
        doLast {
            // Pseudo-code for an HTTP client disabling verification
            httpClient.sslVerification = false
            httpClient.get('https://secure.example.com')
        }
    }
    ```
    
39. **Improper Use of System Properties in JVM Args**  
    _Description_: Passing system properties, potentially sensitive, in JVM arguments without safeguards.  
    **Regex:**
    
    ```
    org\.gradle\.jvmargs\s*=
    ```
    
    **Vulnerable Code Example:**
    
    ```groovy
    gradle.startParameter.jvmArgs = ['-DapiKey=12345']
    ```
    
40. **Misconfigured Publishing Repository (HTTP)**  
    _Description_: Defining a publishing repository using an insecure HTTP URL.  
    **Regex:**
    
    ```
    publishing\s*\{[^}]*repository\s*\{[^}]*url\s*:\s*["'][hH][tT][tT][pP]:
    ```
    
    **Vulnerable Code Example:**
    
    ```groovy
    publishing {
        repositories {
            maven {
                url 'http://insecure.publish.repo.com'
            }
        }
    }
    ```
    
41. **Enabling Verbose Logging in Production Builds**  
    _Description_: Using command-line flags (e.g. “--debug”) in production may leak sensitive information.  
    **Regex:**
    
    ```
    --debug
    ```
    
    **Vulnerable Code Example:**
    
    ```bash
    ./gradlew build --debug
    ```
    
42. **Insecure Custom Gradle Script Inclusion**  
    _Description_: Re-including external scripts from HTTP sources in multiple places.  
    **Regex:**
    
    ```
    apply\s+from\s*:\s*["'][hH][tT][tT][pP]:\/\/.*\.gradle
    ```
    
    **Vulnerable Code Example:**
    
    ```groovy
    apply from: 'http://example.com/unsafe-script.gradle'
    ```
    
43. **Improper Dependency Locking Configuration**  
    _Description_: Failing to correctly configure dependency locking may allow unintended updates.  
    **Regex:**
    
    ```
    dependencyLock\s*\{
    ```
    
    **Vulnerable Code Example:**
    
    ```groovy
    dependencyLock {
        // Lock configuration is missing further detail.
    }
    ```
    
44. **Using Outdated Gradle Wrapper Versions**  
    _Description_: An outdated Gradle version might lack recent security fixes.  
    **Regex:**
    
    ```
    distributionUrl\s*=\s*.*gradle-[0-9\.]+-all\.zip
    ```
    
    **Vulnerable Code Example:**
    
    ```properties
    distributionUrl=https\://services.gradle.org/distributions/gradle-4.10.3-all.zip
    ```
    
45. **Unchecked Inclusion of External Artifacts**  
    _Description_: Declaring dependencies without strict controls on coordinates.  
    **Regex:**
    
    ```
    (compile|implementation|runtimeOnly)\s+['"][^:'"]+:[^:'"]+:[^:'"]+['"]
    ```
    
    **Vulnerable Code Example:**
    
    ```groovy
    dependencies {
        implementation 'com.example:unverified-lib:2.1.0'
    }
    ```
    
46. **Overly Broad Wildcards in File-Based Dependencies**  
    _Description_: Wildcards in file-based dependency declarations can accidentally include unsafe files.  
    **Regex:**
    
    ```
    fileTree\s*\(\s*dir\s*:\s*["'][^"']+["'][^)]*\*
    ```
    
    **Vulnerable Code Example:**
    
    ```groovy
    dependencies {
        implementation fileTree(dir: 'libs', include: ['*.jar'])
    }
    ```
    
47. **Exposed Unsecured Local Repository Paths**  
    _Description_: Hardcoding local repository paths that expose internal directory structures.  
    **Regex:**
    
    ```
    maven\s*\{[^}]*url\s*:\s*["']file:\/\/
    ```
    
    **Vulnerable Code Example:**
    
    ```groovy
    repositories {
        maven {
            url 'file:///home/user/internal_repo'
        }
    }
    ```
    
48. **Gradle Task Misconfigurations Allowing Arbitrary Code Execution**  
    _Description_: Custom tasks with overly permissive code execution logic.  
    **Regex:**
    
    ```
    task\s+\w+\s*\{[^}]*(Runtime\.getRuntime|exec)\s*\(
    ```
    
    **Vulnerable Code Example:**
    
    ```groovy
    task dangerousTask {
        doLast {
            Runtime.getRuntime().exec("rm -rf /")
        }
    }
    ```
    
49. **Disabled Dependency Verification Options**  
    _Description_: Disabling verification checks during dependency resolution increases risk.  
    **Regex:**
    
    ```
    dependencyVerification\s*\{\s*verify\s*=\s*false
    ```
    
    **Vulnerable Code Example:**
    
    ```groovy
    dependencyVerification {
        verify = false
    }
    ```
    
50. **Using External Build Logic Without Local Caching**  
    _Description_: Constantly pulling remote build scripts (via “apply from”) without caching can allow remote tampering.  
    **Regex:**
    
    ```
    apply\s+from\s*:\s*["'][hH][tT][tT][pP]:\/\/.*\.gradle
    ```
    
    **Vulnerable Code Example:**
    
    ```groovy
    apply from: 'http://example.com/remote-build.gradle'
    ```