1. **CSRF Protection Disabled**  
    **Description:** Disabling CSRF protection (via csrf().disable()) can expose endpoints to cross‑site request forgery attacks.  
    **Regex:**
    
    ```
    csrf\s*\(\s*\)\s*\.\s*[dD][iI][sS][aA][bB][lL][eE]\s*\(
    ```
    
    **Vulnerable Code Example:**
    
    ```java
    http.csrf().disable();
    ```
    
2. **Permit All Requests Without Authentication**  
    **Description:** Allowing unrestricted access using permitAll() in security configuration can expose sensitive endpoints.  
    **Regex:**
    
    ```
    antMatchers\s*\(\s*".*"\s*\)\s*\.\s*permitAll\s*\(
    ```
    
    **Vulnerable Code Example:**
    
    ```java
    http.authorizeRequests()
        .antMatchers("/**").permitAll();
    ```
    
3. **Overly Permissive URL Patterns**  
    **Description:** Using broad URL patterns (e.g., "/**") without proper role checks increases exposure risk.  
    **Regex:**
    
    ```
    antMatchers\s*\(\s*"\s*\/\*\*"\s*\)
    ```
    
    **Vulnerable Code Example:**
    
    ```java
    http.authorizeRequests()
        .antMatchers("/**").hasRole("USER");
    ```
    
4. **Ignoring CORS Configuration**  
    **Description:** Failing to restrict CORS settings can allow unauthorized cross‑origin requests.  
    **Regex:**
    
    ```
    cors\s*\(\s*\)\s*\.\s*configurationSource\s*\(
    ```
    
    **Vulnerable Code Example:**
    
    ```java
    http.cors().configurationSource(request -> new CorsConfiguration().applyPermitDefaultValues());
    ```
    
5. **HTTP Basic Authentication Enabled in Production**  
    **Description:** Using HTTP Basic authentication without TLS in production exposes credentials.  
    **Regex:**
    
    ```
    http\s*\.\s*httpBasic\s*\(
    ```
    
    **Vulnerable Code Example:**
    
    ```java
    http.httpBasic();
    ```
    
6. **No Password Encoder Configured**  
    **Description:** Storing passwords without a proper encoder (e.g., using plain text) is highly insecure.  
    **Regex:**
    
    ```
    passwordEncoder\s*\(
    ```
    
    **Vulnerable Code Example:**
    
    ```java
    @Bean
    public PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }
    ```
    
7. **Hard‑Coded Credentials in Configuration**  
    **Description:** Embedding usernames or passwords directly in code may lead to compromise.  
    **Regex:**
    
    ```
    username\s*:\s*".+"
    ```
    
    **Vulnerable Code Example:**
    
    ```java
    auth.inMemoryAuthentication()
        .withUser("admin").password("{noop}admin123").roles("ADMIN");
    ```
    
8. **Exposed Actuator Endpoints Without Authentication**  
    **Description:** Leaving sensitive actuator endpoints public can expose internal application details.  
    **Regex:**
    
    ```
    management\.endpoints\.web\.exposure\.include\s*=\s*".+"
    ```
    
    **Vulnerable Code Example:**
    
    ```yaml
    management:
      endpoints:
        web:
          exposure:
            include: "*"
    ```
    
9. **Disabling Security Headers**  
    **Description:** Turning off security headers (frameOptions, XSS protection, etc.) may leave the app vulnerable.  
    **Regex:**
    
    ```
    headers\s*\(\s*\)\s*\.\s*frameOptions\s*\(\s*\)\s*\.\s*[dD][iI][sS][aA][bB][lL][eE]
    ```
    
    **Vulnerable Code Example:**
    
    ```java
    http.headers().frameOptions().disable();
    ```
    
10. **HTTP Instead of HTTPS Enforcement**  
    **Description:** Not enforcing HTTPS on endpoints may expose sensitive data during transit.  
    **Regex:**
    
    ```
    requiresChannel\s*\(\s*\)\s*\.\s*anyRequest\s*\(\s*\)\s*\.\s*requiresSecure\s*\(
    ```
    
    **Vulnerable Code Example:**
    
    ```java
    http.requiresChannel()
        .anyRequest().requiresSecure();
    ```
    
11. **Misconfigured Logout Endpoint**  
    **Description:** Incorrect logout configurations (e.g., not invalidating sessions) can enable session fixation.  
    **Regex:**
    
    ```
    logout\s*\(\s*\)\s*\.\s*invalidateHttpSession\s*\(\s*false\s*\)
    ```
    
    **Vulnerable Code Example:**
    
    ```java
    http.logout().invalidateHttpSession(false);
    ```
    
12. **Unprotected Static Resources**  
    **Description:** Failing to restrict access to static content might allow attackers to leverage vulnerable scripts.  
    **Regex:**
    
    ```
    webSecurity\.ignoring\s*\(\s*"\s*\/static\/.*"\s*\)
    ```
    
    **Vulnerable Code Example:**
    
    ```java
    web.ignoring().antMatchers("/static/**");
    ```
    
13. **No Session Fixation Protection**  
    **Description:** Not configuring session fixation protection risks session hijacking attacks.  
    **Regex:**
    
    ```
    sessionManagement\s*\(\s*\)\s*\.\s*sessionFixation\s*\(\s*SessionFixationPolicy\.none\s*\)
    ```
    
    **Vulnerable Code Example:**
    
    ```java
    http.sessionManagement().sessionFixation().none();
    ```
    
14. **Allowing Unsafe HTTP Methods**  
    **Description:** Permitting HTTP methods like PUT or DELETE without proper control may allow unauthorized modifications.  
    **Regex:**
    
    ```
    antMatchers\s*\(\s*".*"\s*\)\s*\.\s*access\s*\(\s*".*(PUT|DELETE).*"
    ```
    
    **Vulnerable Code Example:**
    
    ```java
    http.authorizeRequests()
        .antMatchers(HttpMethod.DELETE, "/api/**").permitAll();
    ```
    
15. **Endpoints with CSRF Disabled**  
    **Description:** Disabling CSRF on selective endpoints can lead to CSRF vulnerabilities if not thoroughly secured.  
    **Regex:**
    
    ```
    csrf\s*\(\s*\)\s*\.\s*ignoringAntMatchers\s*\(\s*".+"
    ```
    
    **Vulnerable Code Example:**
    
    ```java
    http.csrf().ignoringAntMatchers("/api/**");
    ```
    
16. **Null or Insecure Authentication Manager**  
    **Description:** Overriding the default AuthenticationManager with a null or insecure one undermines security.  
    **Regex:**
    
    ```
    authenticationManager\s*\(\s*\)\s*=\s*null
    ```
    
    **Vulnerable Code Example:**
    
    ```java
    @Bean
    public AuthenticationManager authenticationManager() {
        return null;
    }
    ```
    
17. **Misconfigured Remember-Me Services**  
    **Description:** Weak or improperly configured remember-me functionality can allow session hijacking.  
    **Regex:**
    
    ```
    rememberMe\s*\(\s*\)\s*\.\s*key\s*\(\s*".+"
    ```
    
    **Vulnerable Code Example:**
    
    ```java
    http.rememberMe().key("weakKey");
    ```
    
18. **Insecure Cookie Settings**  
    **Description:** Cookies set without secure or HttpOnly flags are vulnerable to interception and XSS.  
    **Regex:**
    
    ```
    .*CookieSerializer.*setCookiePath\s*\(\s*".*"
    ```
    
    **Vulnerable Code Example:**
    
    ```java
    Cookie cookie = new Cookie("JSESSIONID", sessionId);
    cookie.setSecure(false);
    cookie.setHttpOnly(false);
    ```
    
19. **Reliance on Default Security Configuration**  
    **Description:** Relying on Spring Security’s defaults without explicit configuration may lead to unexpected exposures.  
    **Regex:**
    
    ```
    @EnableWebSecurity\s*public\s+class\s+\w+\s+\{\s*\}
    ```
    
    **Vulnerable Code Example:**
    
    ```java
    @EnableWebSecurity
    public class SecurityConfig extends WebSecurityConfigurerAdapter {
    }
    ```
    
20. **Logging of Sensitive Credentials**  
    **Description:** Logging authentication details can lead to exposure of sensitive information in logs.  
    **Regex:**
    
    ```
    logger\.info\s*\(.+password.+\)
    ```
    
    **Vulnerable Code Example:**
    
    ```java
    logger.info("User logged in with password: " + password);
    ```
    
21. **Disabled Password Policies**  
    **Description:** Failure to enforce strong password policies leaves the system vulnerable to brute-force attacks.  
    **Regex:**
    
    ```
    passwordPolicy\s*\(
    ```
    
    **Vulnerable Code Example:**
    
    ```java
    // No strong password policy enforced in the authentication provider configuration.
    ```
    
22. **Insecure Password Storage (Plain Text)**  
    **Description:** Storing user passwords in plain text or reversible encryption format exposes sensitive data if breached.  
    **Regex:**
    
    ```
    \{noop\}
    ```
    
    **Vulnerable Code Example:**
    
    ```java
    auth.inMemoryAuthentication()
        .withUser("user").password("{noop}password").roles("USER");
    ```
    
23. **Exposed H2 Console in Production**  
    **Description:** Leaving the H2 database console accessible in production can expose the database to external threats.  
    **Regex:**
    
    ```
    .*/h2-console/.*
    ```
    
    **Vulnerable Code Example:**
    
    ```java
    // H2 console enabled in application.properties for production use.
    spring.h2.console.enabled=true
    ```
    
24. **Unsanitized Parameter Injection**  
    **Description:** Failing to validate request parameters can lead to injection attacks, especially in custom filters.  
    **Regex:**
    
    ```
    request\.getParameter\s*\(\s*".+"
    ```
    
    **Vulnerable Code Example:**
    
    ```java
    String param = request.getParameter("input");
    // Use param directly in queries without sanitization
    ```
    
25. **Disabled Method-Level Security**  
    **Description:** Not enabling method-level security (e.g., @PreAuthorize) leaves service methods unprotected.  
    **Regex:**
    
    ```
    @EnableGlobalMethodSecurity\s*\(
    ```
    
    **Vulnerable Code Example:**
    
    ```java
    // Missing @EnableGlobalMethodSecurity(prePostEnabled = true)
    public class SomeService { ... }
    ```
    
26. **Misconfigured AntMatchers Patterns**  
    **Description:** Using flawed antMatchers patterns can lead to unintended access permissions.  
    **Regex:**
    
    ```
    antMatchers\s*\(\s*".*\\*\\*.*"
    ```
    
    **Vulnerable Code Example:**
    
    ```java
    http.authorizeRequests()
        .antMatchers("/api/**/admin/**").hasRole("ADMIN");
    ```
    
27. **Exposing Security Exception Details**  
    **Description:** Returning detailed security exception messages to the client can leak sensitive information.  
    **Regex:**
    
    ```
    exceptionHandling\s*\(\s*\)\s*\.\s*accessDeniedHandler\s*\(
    ```
    
    **Vulnerable Code Example:**
    
    ```java
    http.exceptionHandling()
        .accessDeniedHandler((req, res, ex) -> res.getWriter().write(ex.getMessage()));
    ```
    
28. **Disabled Logout Success Handler**  
    **Description:** Not configuring a proper logout success handler may allow session information to persist.  
    **Regex:**
    
    ```
    logout\s*\(\s*\)\s*\.\s*logoutSuccessHandler\s*\(\s*null\s*\)
    ```
    
    **Vulnerable Code Example:**
    
    ```java
    http.logout().logoutSuccessHandler(null);
    ```
    
29. **Overriding Security Config with Global Config**  
    **Description:** A global configuration that overrides finer-grain security can inadvertently open exposures.  
    **Regex:**
    
    ```
    WebSecurityConfigurerAdapter\s+.*override\s+void\s+configure
    ```
    
    **Vulnerable Code Example:**
    
    ```java
    @Configuration
    public class GlobalSecurityConfig extends WebSecurityConfigurerAdapter {
        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http.authorizeRequests().anyRequest().permitAll();
        }
    }
    ```
    
30. **Permitting HTTP OPTIONS Requests**  
    **Description:** Allowing HTTP OPTIONS requests without proper controls can be exploited for reconnaissance.  
    **Regex:**
    
    ```
    antMatchers\s*\(\s*HttpMethod\.OPTIONS\s*,\s*".+"
    ```
    
    **Vulnerable Code Example:**
    
    ```java
    http.authorizeRequests()
        .antMatchers(HttpMethod.OPTIONS, "/**").permitAll();
    ```
    
31. **Disabling X-Content-Type-Options Header**  
    **Description:** Omitting the X-Content-Type-Options header can allow MIME type sniffing attacks.  
    **Regex:**
    
    ```
    headers\s*\(\s*\)\s*\.\s*contentTypeOptions\s*\(\s*\)\s*\.\s*[dD][iI][sS][aA][bB][lL][eE]\s*\(
    ```
    
    **Vulnerable Code Example:**
    
    ```java
    http.headers().contentTypeOptions().disable();
    ```
    
32. **Disabling X-Frame-Options Header**  
    **Description:** Turning off the X-Frame-Options header may allow the app to be embedded in iframes for clickjacking.  
    **Regex:**
    
    ```
    headers\s*\(\s*\)\s*\.\s*frameOptions\s*\(\s*\)\s*\.\s*[dD][iI][sS][aA][bB][lL][eE]\s*\(
    ```
    
    **Vulnerable Code Example:**
    
    ```java
    http.headers().frameOptions().disable();
    ```
    
33. **Allowing Open Redirects in Security Config**  
    **Description:** Permitting dynamic redirection URLs without validation can lead to open redirect vulnerabilities.  
    **Regex:**
    
    ```
    .*\bredirect\b\s*\+\s*request\.getParameter\s*\(
    ```
    
    **Vulnerable Code Example:**
    
    ```java
    String target = request.getParameter("redirect");
    response.sendRedirect("/login?redirect=" + target);
    ```
    
34. **Insecure HTTP Protocol Use**  
    **Description:** Accepting HTTP (without HTTPS enforcement) in security-sensitive endpoints puts data at risk.  
    **Regex:**
    
    ```
    "http:\/\/
    ```
    
    **Vulnerable Code Example:**
    
    ```java
    // Using HTTP in a callback URL configuration
    String callbackUrl = "http://example.com/callback";
    ```
    
35. **Exposing Built‑in Admin Endpoints Unprotected**  
    **Description:** Leaving Spring Security admin endpoints open without authentication increases risk.  
    **Regex:**
    
    ```
    antMatchers\s*\(\s*"/admin/.*"
    ```
    
    **Vulnerable Code Example:**
    
    ```java
    http.authorizeRequests()
        .antMatchers("/admin/**").permitAll();
    ```
    
36. **Misconfigured OAuth2 Client Registration**  
    **Description:** Incorrect settings in OAuth2 client configuration may expose tokens or data improperly.  
    **Regex:**
    
    ```
    clientId\s*=\s*".+"
    ```
    
    **Vulnerable Code Example:**
    
    ```java
    spring.security.oauth2.client.registration.myclient.client-id=weakClientId
    ```
    
37. **Inadequate Authentication Event Logging**  
    **Description:** Not logging authentication events (or logging too verbosely) can either mask attacks or leak sensitive info.  
    **Regex:**
    
    ```
    .*\blog\b.*(failedAuthentication|successfulAuthentication)
    ```
    
    **Vulnerable Code Example:**
    
    ```java
    // Missing proper logging of authentication events
    ```
    
38. **No Multi‑Factor Authentication (MFA) Enforcement**  
    **Description:** Relying solely on single‑factor authentication increases risk if credentials are compromised.  
    **Regex:**
    
    ```
    mfa\s*\(
    ```
    
    **Vulnerable Code Example:**
    
    ```java
    // No MFA configured in security settings
    ```
    
39. **Misconfigured Token Store for OAuth2/JWT**  
    **Description:** Using an insecure token store (in‑memory or default settings) can expose token data.  
    **Regex:**
    
    ```
    tokenStore\s*\(
    ```
    
    **Vulnerable Code Example:**
    
    ```java
    @Bean
    public TokenStore tokenStore() {
        return new InMemoryTokenStore();
    }
    ```
    
40. **Weak JWT Signing Algorithm**  
    **Description:** Employing weak or no signing algorithms for JWT tokens compromises token integrity.  
    **Regex:**
    
    ```
    JwtAccessTokenConverter\s+converter\s*=\s*new\s+JwtAccessTokenConverter\s*\(
    ```
    
    **Vulnerable Code Example:**
    
    ```java
    JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
    converter.setSigningKey("weakSigningKey");
    ```
    
41. **Missing Role-Based Access Control on Endpoints**  
    **Description:** Failing to specify required roles on sensitive endpoints can lead to unauthorized access.  
    **Regex:**
    
    ```
    .*\bhasRole\s*\(\s*".+"
    ```
    
    **Vulnerable Code Example:**
    
    ```java
    http.authorizeRequests()
        .antMatchers("/sensitive/**").permitAll();
    ```
    
42. **Poor Session Management Practices**  
    **Description:** Not configuring session timeouts and concurrency limits can expose the application to session hijacking.  
    **Regex:**
    
    ```
    sessionManagement\s*\(\s*\)\s*\.\s*maximumSessions\s*\(
    ```
    
    **Vulnerable Code Example:**
    
    ```java
    http.sessionManagement().maximumSessions(1000);
    ```
    
43. **Plain Text in LDAP Configuration**  
    **Description:** Storing LDAP credentials in plain text in configurations makes them easily exploitable.  
    **Regex:**
    
    ```
    ldap\.url\s*=\s*".+"
    ```
    
    **Vulnerable Code Example:**
    
    ```java
    spring.ldap.urls=ldap://localhost:8389
    spring.ldap.username=cn=admin,dc=example,dc=com
    spring.ldap.password=plaintextpassword
    ```
    
44. **Exposing Detailed Error Messages**  
    **Description:** Detailed error messages, especially during authentication failures, can reveal security details.  
    **Regex:**
    
    ```
    exceptionTranslation\s*\(\s*\)\s*\.\s*accessDeniedPage\s*\(
    ```
    
    **Vulnerable Code Example:**
    
    ```java
    http.exceptionHandling().accessDeniedPage("/errorDetailed");
    ```
    
45. **Insecure File Permissions on Property Files**  
    **Description:** Property files containing security configurations should have strict OS-level permissions.  
    **Regex:**
    
    ```
    application\.properties
    ```
    
    **Vulnerable Code Example:**
    
    ```properties
    # application.properties with sensitive data exposed to all users on the server.
    ```
    
46. **Lack of Secure Random for Token Generation**  
    **Description:** Using weak random number generators for tokens or keys undermines security.  
    **Regex:**
    
    ```
    new\s+Random\s*\(
    ```
    
    **Vulnerable Code Example:**
    
    ```java
    String token = Integer.toString(new Random().nextInt());
    ```
    
47. **Failure to Validate the Authentication Principal**  
    **Description:** Not verifying the structure or attributes of the authentication principal may allow impersonation.  
    **Regex:**
    
    ```
    authentication\.getPrincipal\s*\(
    ```
    
    **Vulnerable Code Example:**
    
    ```java
    Object principal = authentication.getPrincipal();
    // No validation of the principal type or values
    ```
    
48. **Insecure XML Configuration Parsing**  
    **Description:** Parsing external XML without secure processing settings can lead to XXE attacks.  
    **Regex:**
    
    ```
    DocumentBuilderFactory\.newInstance\s*\(
    ```
    
    **Vulnerable Code Example:**
    
    ```java
    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    // Missing secure processing features configuration
    ```
    
49. **Overriding the Default Security Context**  
    **Description:** Manually overriding the security context in an insecure way can bypass authentication.  
    **Regex:**
    
    ```
    SecurityContextHolder\.setContext\s*\(
    ```
    
    **Vulnerable Code Example:**
    
    ```java
    SecurityContextHolder.setContext(new SecurityContextImpl());
    // May inadvertently clear or weaken the current security context
    ```
    
50. **Misconfigured Role Hierarchy**  
    **Description:** An improperly defined role hierarchy can grant users more privileges than intended.  
    **Regex:**
    
    ```
    roleHierarchy\s*\(\s*\)\s*\.\s*setHierarchy\s*\(\s*".+"
    ```
    
    **Vulnerable Code Example:**
    
    ```java
    @Bean
    public RoleHierarchy roleHierarchy() {
        RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
        roleHierarchy.setHierarchy("ROLE_ADMIN > ROLE_USER");
        return roleHierarchy;
    }
    ```
    
