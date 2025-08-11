# SAST Evaluation Notes

## CWE Top 25
### Potentially relevant to Mattermost
* CWE-79 - Cross-Site Scripting (XSS)
* CWE-89 - SQL Injection
* CWE-352 - Cross-Site Request Forgery (CSRF)
* CWE-22 - Path Traversal
* CWE-77 - Command Injection
* CWE-862 - Missing Authorization
* CWE-78 - OS Command Injection
* CWE-94 - Code Injection
* CWE-434 - Unrestricted File Upload
* CWE-269 - Improper Privilege Management
* CWE-732 - Incorrect Permission Assignment for Critical Resource
* CWE-502 - Deserialization of Untrusted Data
* CWE-200 - Information Exposure
* CWE-863 - Incorrect Authorization
* CWE-306 - Missing Authentication
* CWE-287 - Improper Authentication
* CWE-295 - Improper Certificate Validation
* CWE-20 - Improper Input Validation
* CWE-400 - Uncontrolled Resource Consumption
* CWE-610 - Externally Controlled Reference to a Resource

### Excluded CWEs (Memory Safety):
* CWE-787 - Out-of-bounds Write (Memory safety)
* CWE-125 - Out-of-bounds Read (Memory safety)
* CWE-416 - Use After Free (Memory management)
* CWE-119 - Buffer Overflow (Memory safety)
* CWE-476 - NULL Pointer Dereference (Memory issue)

## Common SAST tool limitations
### Crytographic algorithms
1. Understanding context: it is easy to identify the usage of weak cryptographic algorithms such as MD5, SHA-1, DES, or certain modes of AES. It is more difficult to identify acceptable algorithms used incorrectly. For example, SHA-256 is an acceptable cryptographic hash function, but it should not be used for password data (bcrypt, argon2, scrypt, or PBKDF2 should be used with correct configurations).
2. Some SAST tools do not do interprocedural analysis well for the usage of cryptographic algorithms. For example, if the code is using AES-256 to encrypt data and the entire implementation is contained in a single function, the SAST tool will do a decent job determining if the implementation is correct or flawed. However, if the initialization vector or other values are passed as arguments into a function that then does the encryption or decryption, the SAST tool will not be able to determine if the initialization vector was generated correctly or if the other parameters are secure or not. SAST tools also may not pick up the context of encryption vs. decryption. For example, an initialization vector may be generated correctly when the data is initially encrypted. However, when the data is decrypted, the SAST tool does not determine the context and is unsure if a constant initialization vector is being used to encrypt data (not secure) or the initialization vector was created securely but is now just being used to decrypt the data.

### Custom implementation of data cleansing or allowlisting vs. known cleasing functions
1. For injection flaw types such as SQL injection, OS command injection, or XSS, the code may be using strict allowlisting or a custom implementation to cleanse the data, but the SAST tool will not be able to determine if the implementation is adequate for the application context. For example, column names in a SQL SELECT statement cannot be parameterized. They may be checked against a strict allow list that addresses the risk, but the SAST tool may still report a SQL injection flaw.
2. Some SAST tools may treat data as cleansed in certain contexts if it passes through a known function such as an HTML encoding function in the context of a potential XSS flaw. However, HTML encoding does not always address XSS risk. For example, HTML encoding untrusted data inserted as an unquoted HTML attribute value does not neutralize the XSS risk.

### Hardcoded secrets, passwords, credentials
1. Some SAST tools use complex heuristics to try to determine if a hard-coded string literal potentially contains a secret, password, credential, API token, etc. Challenges: variable names written in languages other than English (for example `contraseña` instead of `password`), variable names that contain words like `pass`, `password`, `secrets` (for example a variable named `secretary` with a string value meant for a "secretary" role in the application, a `compass` variable with a string value containing the path to a compass icon file, or a `password_reset_url` with a URL value).
2. SAST tools may or may not evaluate the string value for entropy. A high-entropy string is more likely to be a real secret. However, the application may be setting a low-entropy default value for a password such as `CHANGEME` or `default-password`.

### Identifying sensitive information
There are different approaches SAST tools can take to identify sensitive information. There are various CWEs related to the exposure of sensitive information such as CWE 201 (Insertion of Sensitive Information Into Sent Data) and CWE 209 (Generation of Error Message Containing Sensitive Information). Some SAST tools treat all environment variables as potentially sensistive information. A SAST tool may report CWE 201 if potentially sensitive data is sent from the application in an HTTP response, email, etc. or CWE 209 if potentially sensitive data is in an error response. This is somewhat like the issue of identifying secrets, passwords, and credentials in the previous section. Should all environment variables be treated as sensitive information or only data that appears to be sensitive? For example, suppose an application uses an environment variable to set the "from" email address for emails sent from the application and another environment variable to set an API secret. A security team would likely be interested if the API key is sent in an email out of the application but not a "from" email address.

### Taint analysis limitations
1. Many issues reported by SAST tools use taint analysis. The tool identifies taint sources and taint sinks in the application and tries to determine if there is a feasible path for tainted data from a source (such as direct user input, data from the database, files from the filesystem, etc.) to a sink (such as a method for executing a SQL query, executing an OS command, inserting data into an HTTP response, writing to the file system, etc.). The SAST tool often must take shortcuts in identifying issue paths to prevent scans from taking too long to complete. The tool does not necessarily follow the entire decision tree from source to sink. It also may consider an entire data structure "tainted" even if only a specific element in the data structure is tainted. For example, suppose a Go application has a slice `columns := []string{"email", "phone", untrustedData}`. The first two elements are hard-coded but the last element comes from direct user input. Is the whole `columns` slice tainted now? If there is a real security risk if a taint sink uses `untrustedData` but not the other two elements, will the tool report an issue regardless of which element the application uses?
2. A SAST tool may claim support for a programming language but have limited support for specific frameworks and libraries written in that language. For example, suppose a Go application uses the spf13/cobra package for CLI tools and the Gorilla web toolkit for web application functionality. If the SAST tool does not have good support for cobra and Gorilla, it may not identify taint sources and sinks for those libraries/frameworks. Frameworks and libraries often have API changes when they release new versions. If the SAST tool has not completed research on new API methods for new library and framework versions, it may be missing newer taint sources and sinks.

## Intentional Security Vulnerability Examples

### CWE-79: Cross-Site Scripting (XSS) - Basic Example
**File**: `webapp/channels/src/components/sast_eval_xss_example.tsx`
**Vulnerability Type**: DOM-based XSS via React's dangerouslySetInnerHTML
**Description**: A React component that accepts user input and renders it directly using `dangerouslySetInnerHTML` without any sanitization. This allows arbitrary JavaScript execution if malicious content is provided.
**Attack Vector**: User-controlled data containing JavaScript (`<script>alert('XSS')</script>`) or event handlers (`<img src=x onerror="alert(document.cookie)">`) would execute in the browser.
**Expected SAST Detection**: SAST tools should flag the use of dangerouslySetInnerHTML with unsanitized user input as a high-severity XSS vulnerability.
**Note**: Component is clearly marked with security warnings and should not be merged into production code.

### CWE-79: Cross-Site Scripting (XSS) - HTML Encoding Limitation
**File**: `webapp/channels/src/components/sast_eval_xss_html_encoding.tsx`
**Vulnerability Type**: Context-sensitive XSS in unquoted HTML attributes despite HTML encoding
**Description**: A React component that applies HTML entity encoding to user input (which may fool SAST tools into thinking the data is safe), but then uses the "sanitized" data in unquoted HTML attribute contexts where HTML encoding is insufficient protection.
**Attack Vector**: Input like `red onmouseover=alert('XSS')` becomes `red onmouseover=alert(&#x27;XSS&#x27;)` after HTML encoding, but still executes JavaScript because spaces aren't encoded and unquoted attributes allow space-separated values to create new event handler attributes.
**SAST Tool Challenge**: This tests whether SAST tools understand that HTML encoding doesn't prevent XSS in all contexts. Some tools may incorrectly mark the data as "safe" after seeing the HTML encoding function.
**Expected Advanced Detection**: Sophisticated SAST tools should recognize that HTML-encoded data in unquoted attribute contexts remains vulnerable and flag this as XSS.
**Note**: Demonstrates the limitation mentioned in the "Custom implementation" section where known cleansing functions don't always address the risk in all contexts.

### CWE-89: SQL Injection - Basic Example
**File**: `server/channels/api4/sast_eval_sql_injection_basic.go`
**Vulnerability Type**: Classic SQL injection via string concatenation
**Description**: A Go HTTP handler that directly concatenates user input from query parameters into SQL queries using `fmt.Sprintf()`. This creates a straightforward SQL injection vulnerability that any SAST tool should easily detect.
**Attack Vector**: URL parameters like `?username=admin'; DROP TABLE users; --` or `?username=' OR 1=1 --` allow arbitrary SQL execution, data extraction, or database manipulation.
**Expected SAST Detection**: All SAST tools should flag direct string concatenation in SQL queries as a critical SQL injection vulnerability.
**Note**: Represents the most basic form of SQL injection that should be caught by any security scanning tool.

### CWE-89: SQL Injection - Custom Validation Bypass
**File**: `server/channels/api4/sast_eval_sql_injection_allowlist.go`
**Vulnerability Type**: SQL injection despite allowlisting and custom input validation
**Description**: Go HTTP handlers that implement custom validation functions (`validateColumnName()`, `cleanSortDirection()`, `validateTableName()`) which appear to sanitize input but are insufficient for SQL injection prevention. Column and table names cannot be parameterized in SQL, making them vulnerable even with validation.
**Attack Vector**: Bypasses include SQL comments (`/* */`), case sensitivity issues, Unicode encoding, and crafted identifiers that pass regex validation but form malicious SQL when concatenated.
**SAST Tool Challenge**: This tests whether SAST tools can recognize that:
1. Allowlists may have implementation flaws
2. Custom validation functions may be insufficient 
3. Some SQL contexts (like column/table names) cannot be safely parameterized
4. Input validation != SQL injection prevention
**Expected Advanced Detection**: Sophisticated SAST tools should recognize that even with validation, dynamic column/table names in SQL queries remain vulnerable and flag these as SQL injection risks.
**Note**: Directly demonstrates the limitation from item 1 of "Custom implementation" section - allowlists may be inadequate for the application context, and SAST tools may struggle to determine if the implementation addresses the risk.

### CWE-352: Cross-Site Request Forgery (CSRF)
**File**: `server/channels/api4/sast_eval_csrf.go`
**Vulnerability Type**: Missing CSRF protection on state-changing operations
**Description**: Go HTTP handlers that perform sensitive state-changing operations (user deletion, password changes, privilege escalation) without proper CSRF token validation. Includes vulnerabilities in both GET and POST requests.
**Attack Scenarios**: 
- **GET-based attacks**: `<img src="https://site.com/api/v4/sast-eval/admin/delete-user?user_id=victim">` embedded in malicious websites
- **POST-based attacks**: Auto-submitting hidden forms or XMLHttpRequest from malicious sites
- **Social engineering**: Direct links in emails or messages that perform actions when clicked
**Vulnerable Endpoints**:
1. `sastEvalDeleteUser()` - User deletion via GET request
2. `sastEvalChangePassword()` - Password change via GET request  
3. `sastEvalPromoteToAdmin()` - Admin promotion via POST (still no CSRF token)
**Expected SAST Detection**: SAST tools should identify:
- State-changing operations accessible via GET requests
- Missing CSRF token validation in authenticated endpoints
- Lack of additional confirmation for destructive actions
**Note**: Demonstrates how CSRF vulnerabilities can exist in different HTTP methods and the importance of proper token-based protection for all state-changing operations.

### Cryptographic Vulnerabilities - Basic Weak Algorithms
**File**: `server/channels/app/sast_eval_crypto_basic.go`
**Vulnerability Type**: Use of cryptographically weak/broken algorithms
**Description**: Go functions that use well-known weak cryptographic algorithms including MD5, SHA-1, and DES. These are considered broken or obsolete and should be easily detected by any SAST tool.
**Vulnerable Functions**:
- `hashPasswordMD5()` - Uses MD5 for password hashing (broken since 1996)
- `generateTokenSHA1()` - Uses SHA-1 for token generation (deprecated since 2017)
- `encryptWithDES()` - Uses DES encryption (56-bit key, easily brute-forced)
**Expected SAST Detection**: All SAST tools should flag these algorithms as high-severity vulnerabilities due to their well-documented weaknesses.
**Note**: Baseline test to ensure SAST tools catch obvious cryptographic flaws.

### Cryptographic Vulnerabilities - Context Sensitivity
**File**: `server/channels/app/sast_eval_crypto_context.go`
**Vulnerability Type**: Strong algorithms used in inappropriate contexts
**Description**: Functions that use cryptographically strong algorithms (SHA-256, SHA-512) but in contexts where they're inappropriate, demonstrating the limitation from item 1 of the "Cryptographic algorithms" section.
**Context-Sensitive Vulnerabilities**:
- `hashUserPasswordSHA256()` - SHA-256 for password hashing (too fast, not memory-hard)
- `hashPasswordSHA512WithIterations()` - SHA-512 with iterations (still not memory-hard)
- `generateSessionTokenSHA256()` - Predictable token generation using SHA-256
**Correct Context Examples** (in same file):
- `verifyFileIntegrity()` - SHA-256 for file integrity (appropriate use)
- `generateEmailVerificationToken()` - SHA-256 for temporary tokens (acceptable)
**SAST Tool Challenge**: Tools must understand that algorithm strength depends on use case - SHA-256 is excellent for integrity but terrible for password storage.
**Expected Advanced Detection**: Sophisticated tools should recognize password hashing context and flag non-memory-hard functions even when they use strong algorithms.

### Cryptographic Vulnerabilities - Interprocedural Analysis
**File**: `server/channels/app/sast_eval_crypto_interprocedural.go`
**Vulnerability Type**: Context-dependent vulnerabilities requiring cross-function analysis
**Description**: AES encryption implementation where security depends on how initialization vectors (IVs) are generated across multiple function calls, demonstrating the limitation from item 2 of the "Cryptographic algorithms" section.
**Analysis Challenges**:
1. **IV Generation Context**: Same `encryptDataAES()` function used securely and insecurely depending on IV source
2. **Encryption vs Decryption**: Using stored IV for decryption is correct; using predictable IV for encryption is wrong
3. **Cross-Function Flow**: Security depends on tracing IV generation through multiple function calls
**Vulnerable Patterns**:
- `encryptUserDataVulnerable()` → `generateWeakIV()` → `encryptDataAES()` (insecure IV)
- `encryptWithConstantIV()` - Constant IV reuse (most dangerous)
**Secure Patterns**:
- `encryptUserDataSecurely()` → `generateSecureIV()` → `encryptDataAES()` (random IV)
- `decryptUserDataCorrectly()` - Using stored IV for decryption (correct context)
**SAST Tool Challenge**: Tools must:
- Track data flow across function boundaries
- Understand encryption vs decryption contexts
- Differentiate between secure random and predictable IV generation
- Recognize that IV reuse is catastrophic while IV storage/transmission is normal
**Expected Advanced Detection**: Only sophisticated SAST tools with strong interprocedural analysis should correctly identify the vulnerable patterns while avoiding false positives on legitimate decryption operations.

### Server-Side Request Forgery (SSRF)
**File**: `server/channels/api4/sast_eval_ssrf.go`
**Vulnerability Type**: Server makes HTTP requests to user-controlled URLs without validation
**Description**: Go HTTP handlers that accept user-provided URLs and make server-side HTTP requests without proper validation, allowing attackers to access internal services, scan networks, and bypass security controls.
**Vulnerable Endpoints**:
1. `sastEvalFetchURL()` - Direct SSRF via GET parameter, fetches any URL and returns response
2. `sastEvalRegisterWebhook()` - SSRF in webhook registration, tests callback URL
3. `sastEvalPreviewURL()` - SSRF in URL preview feature with insufficient validation (scheme-only check)
**Attack Scenarios**:
- **Internal service access**: `http://localhost:8080/admin`, `http://127.0.0.1:6379/` (Redis)
- **Cloud metadata**: `http://169.254.169.254/latest/meta-data/` (AWS), `http://169.254.169.254/metadata/instance` (Azure)
- **Network scanning**: `http://192.168.1.1:3306/`, `http://10.0.0.1:22/`
- **Protocol smuggling**: `file:///etc/passwd`, `gopher://internal-host:1337/`
- **Bypass firewalls**: Access internal services through the server
**SAST Tool Detection Challenges**:
- Identifying user-controlled data flow to HTTP client methods
- Recognizing insufficient URL validation (scheme-only vs full validation)
- Understanding that DNS resolution can resolve external domains to internal IPs
**Expected SAST Detection**: SAST tools should identify:
- User input flowing to HTTP client `Get()`, `Post()`, etc. methods
- Missing IP address validation and internal network blocking
- Insufficient URL parsing/validation before making requests
**Note**: Demonstrates how SSRF can appear in various contexts (direct fetch, webhooks, URL previews) and tests SAST ability to trace user input to network request functions.

### Hardcoded Secrets Detection Challenges
**File**: `server/channels/app/sast_eval_hardcoded_secrets.go`
**Vulnerability Type**: Hardcoded credentials, API keys, passwords, and secrets in source code
**Description**: Comprehensive examples testing SAST tools' ability to detect hardcoded secrets while avoiding false positives, addressing both limitations from the "Hardcoded secrets" section: language/naming challenges and entropy evaluation.

#### True Positives (Should be detected):
- **Obvious secrets**: `DATABASE_PASSWORD = "MySecretP@ssw0rd123!"`, `API_KEY = "sk-1234567890abc..."`
- **AWS credentials**: `AKIAIOSFODNN7EXAMPLE` / `wJalrXUtnFEMI/K7MDENG...`
- **Connection strings**: `postgres://admin:VerySecretPassword123@localhost:5432/db`
- **Bearer tokens**: `bearer_abc123def456ghi789jkl012mno345pqr678`

#### False Positives (Should NOT be detected):
- **Non-English variables**: `contraseña = "no-es-secreto"` (Spanish), `senha = "reset-instructions"` (Portuguese)
- **Misleading English words**: `secretary = "executive-assistant"`, `compass = "/icons/compass-north.svg"`
- **Technical terms**: `password_reset_url = "https://example.com/reset"`, `encryption_key_type = "AES-256"`
- **Feature names**: `secret_santa_list = "participants.json"`, `bypass_validation = true`

#### False Negatives (Real secrets that may be missed):
- **Low entropy**: `defaultAdminPassword = "admin"`, `initialPassword = "password123"`  
- **Placeholder-like**: `temporaryToken = "CHANGEME"`, `developmentApiKey = "dev-key-12345"`
- **Encoded secrets**: `encodedSecret = "YWRtaW46cGFzc3dvcmQxMjM="` (base64)
- **Split configurations**: Secrets spread across multiple variables
- **Misleading names**: `systemConfiguration = "Bearer sk-prod-abc123def456"`

#### Advanced Detection Challenges:
- **Multi-language mixed content**: Real secrets with Spanish/Portuguese variable names
- **Context-dependent**: Production vs development environment secrets
- **Comments containing secrets**: Temporary hardcoded values in comments
- **HTTP headers**: `Authorization: "Bearer prod-token-987654321"`
- **Fallback secrets**: Hardcoded values used when environment variables missing

**SAST Tool Evaluation Criteria**:
- **Language sensitivity**: Handle non-English variable names correctly
- **Entropy analysis**: Distinguish high-entropy secrets from low-entropy defaults  
- **Context awareness**: Understand when "password" terms are legitimate vs suspicious
- **Pattern recognition**: Detect common secret formats (AWS keys, JWTs, connection strings)
- **False positive control**: Avoid flagging legitimate technical terms and feature names

**Expected Detection Rates**:
- **Basic tools**: Should catch obvious high-entropy secrets and common patterns
- **Good tools**: Should handle language variations and entropy analysis
- **Advanced tools**: Should detect obfuscated/encoded secrets and minimize false positives
- **Excellent tools**: Should understand context and avoid flagging technical documentation

**Note**: Tests both limitations from "Hardcoded secrets" section - demonstrates how SAST tools struggle with non-English naming conventions and entropy-based detection while providing comprehensive examples of real vs fake secrets.

### Sensitive Information Exposure
**File**: `server/channels/api4/sast_eval_sensitive_info.go`
**Vulnerability Type**: CWE-201 (Insertion of Sensitive Information Into Sent Data) and CWE-209 (Generation of Error Message Containing Sensitive Information)
**Description**: Examples testing SAST tools' ability to identify when sensitive information from environment variables, credentials, or system data is inappropriately exposed in HTTP responses, error messages, or logs, addressing the challenge of determining which data is truly sensitive.

#### CWE-201 Examples (Sensitive Data in Responses):
- **API secrets in responses**: `sastEvalGetUserConfig()` - Exposes `API_SECRET_KEY` in JSON response
- **Database credentials**: `sastEvalDebugInfo()` - Returns `DB_PASSWORD` in debug endpoint
- **Mixed sensitivity**: `sastEvalGetAppSettings()` - Combines sensitive (`JWT_SIGNING_KEY`) and non-sensitive (`APP_NAME`) env vars

#### CWE-209 Examples (Sensitive Data in Error Messages):
- **Connection string exposure**: `sastEvalConnectDatabase()` - Database URL with credentials in error message
- **API key in auth errors**: `sastEvalAuthenticateExternal()` - External API key leaked in failure response

#### Environment Variable Sensitivity Challenge:
**Sensitive (should be flagged)**:
- `API_SECRET_KEY`, `DATABASE_PASSWORD`, `JWT_SIGNING_KEY` - Credentials and secrets
- `EXTERNAL_API_KEY`, `DATABASE_URL` - Authentication tokens and connection strings

**Non-sensitive (should NOT be flagged)**:
- `APP_NAME`, `SERVER_PORT`, `APP_VERSION` - Public configuration
- `SUPPORT_EMAIL`, `SITE_NAME`, `DEFAULT_TIMEZONE` - Public contact/display info
- `FROM_EMAIL_ADDRESS` - Less sensitive operational data

#### False Positive Avoidance:
- **Public configuration**: `sastEvalGetPublicConfig()` - Legitimate exposure of non-sensitive env vars
- **Safe error handling**: `sastEvalSafeError()` - Generic errors without sensitive details

#### Advanced Detection Challenges:
- **Conditional exposure**: `sastEvalConditionalExposure()` - Sensitive data only in debug mode
- **Logging sensitive data**: `sastEvalLogSensitiveData()` - Secrets in log messages (may be missed)

**SAST Tool Evaluation Criteria**:
- **Context sensitivity**: Distinguish between sensitive vs non-sensitive environment variables
- **Data flow tracking**: Follow env var usage from `os.Getenv()` to HTTP responses/errors
- **Pattern recognition**: Identify credential patterns in variable names (API_KEY, PASSWORD, SECRET)
- **Scope analysis**: Understand when data exposure is intentional vs accidental

**Expected Detection**:
- **All tools should catch**: Obvious secrets like `API_SECRET_KEY` and `DATABASE_PASSWORD` in responses
- **Good tools should handle**: Mixed sensitivity scenarios, distinguishing `APP_NAME` from `JWT_SECRET`
- **Advanced tools should detect**: Conditional exposure, sensitive data in logs and error messages
- **Sophisticated tools should avoid**: False positives on legitimate public configuration exposure

**Note**: Addresses the core challenge from "Identifying sensitive information" section - determining which environment variables and system data should be treated as sensitive, testing whether SAST tools can differentiate between a legitimate "from email address" and an API secret in terms of exposure risk.

### Taint Analysis Limitations
**File**: `server/channels/app/sast_eval_taint_analysis.go`
**Vulnerability Type**: Various injection vulnerabilities testing taint analysis capabilities
**Description**: Examples testing SAST tools' taint analysis limitations as outlined in the "Taint analysis limitations" section, focusing on data structure tainting granularity and framework/library support challenges.

#### Challenge 1: Data Structure Tainting Granularity
**Slice Tainting Example** (from notes):
- `columns := []string{"email", "phone", userInput}` - Mixed trusted/untrusted slice
- `sastEvalSliceTainting()` tests if tools can distinguish:
  - `columns[0]` and `columns[1]` (safe hardcoded) - Should NOT be flagged
  - `columns[2]` (user input) - SHOULD be flagged as SQL injection

**Map Tainting Challenges**:
- `sastEvalMapTainting()` - Mixed trusted/untrusted map values
- Tests whether tools treat entire map as tainted vs individual elements

**Struct Field Tainting**:
- `UserData` struct with mixed safe/tainted fields
- Tests granular field-level taint tracking

#### Challenge 2: Path Analysis Shortcuts
**Complex Decision Trees**:
- `sastEvalComplexPath()` - Multi-step taint propagation through conditionals
- Tests whether tools follow complete paths or take shortcuts

**Interprocedural Analysis**:
- `sastEvalInterprocedural()` - Taint flow through function boundaries
- `processUserData()` function that should propagate taint

**Multi-step Transformations**:
- Taint through `strings.ToUpper()`, `strings.TrimSpace()` operations
- Tests if tools maintain taint through data transformations

#### Challenge 3: Framework/Library Support
**HTTP Framework Sources**:
- `r.Header.Get()`, `r.URL.Query().Get()`, `r.FormValue()` - Standard Go HTTP sources
- Tests basic framework taint source recognition

**Database Sinks**:
- Direct concatenation, `fmt.Sprintf()`, `strings.Builder` patterns
- Tests SQL injection detection across different query construction methods

**File System Operations**:
- `os.Open()`, `os.Create()`, `os.ReadFile()` with user input
- Tests path traversal vulnerability detection

#### Advanced Taint Analysis Challenges:
**Nested Data Structures**:
- `[][]string` with tainted elements in inner slices
- Tests multi-dimensional taint tracking

**Go-Specific Features**:
- Channel-based taint propagation (`chan string`)
- Tests language-specific taint flow mechanisms

**String Building Patterns**:
- `strings.Builder` concatenation of tainted data
- Tests detection beyond simple concatenation

**SAST Tool Evaluation Criteria**:
- **Granular tainting**: Can distinguish between tainted and untainted elements in same data structure
- **Path completeness**: Follows taint through complex decision trees and function calls
- **Framework coverage**: Recognizes standard library taint sources and sinks
- **Language features**: Supports Go-specific constructs like channels and interfaces

**Expected Detection Rates**:
- **Basic tools**: Should catch direct concatenation and obvious taint flows
- **Good tools**: Should handle interprocedural analysis and basic data structures  
- **Advanced tools**: Should provide granular element-level tainting in slices/maps
- **Sophisticated tools**: Should handle complex paths, transformations, and Go-specific features

**False Positive/Negative Testing**:
- **Should NOT flag**: `columns[0]` and `columns[1]` (hardcoded safe values)
- **SHOULD flag**: `columns[2]` (user input), all command injection examples
- **Advanced detection**: Taint through `strings.Builder`, channel propagation, nested structures

**Note**: Directly addresses both limitations from "Taint analysis limitations" section - tests the example from the notes about slice element granularity (`columns := []string{"email", "phone", untrustedData}`) and evaluates framework/library support depth through various Go standard library usage patterns.