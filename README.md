# Vulnerabilities Overview

## /src/main.rs
**Example 1** - CWE-798:Use of Hard-coded Credentials (Supported)

Expected to be detected
- **Source:** Line 13
- **Sink:** Line 117  

**Example 2** - CWE-942:Permissive Cross-domain Security Policy with Untrusted Domains (Supported)

Expected to be detected
- **Source/Sink:** Line 79

**Example 3** - CWE-79:Cross-site Scripting - XSS (Supported)

Expected to be detected
- **Source:** Line 131
- **Sink:** Line 134

**Example 4** - CWE-22:Path Traversal (Supported)

Expected to be detected
- **Source/Sink:** Line 142

**Example 5** - CWE-89:SQL Injection (Supported)

Expected to be detected
- **Source:** Line 152
- **Sink:** Line 159

**Example 6** - CWE-90:LDAP Injection (Supported)

Not expected to be detected, because the sink is not present in the code. The comment indicates it would be sent to an LDAP server, but no actual sink exists here.
- **Source:** Line 176
- **Sink:** Not present

**Example 7** - CWE-78:OS Command Injection (Supported)
Expected to be detected
- **Source:** 188
- **Sink:** 192

**Example 8** - CWE-78:OS Command Injection (Supported)
Expected to be detected
- **Source:** 188
- **Sink:** 202

**Example 9** - CWE-328:Use of Weak Hash (Supported)
Expected to be detected
- **Source/Sink:** 220

**Example 10** - CWE-321:Use of Hard-coded Cryptographic Key (Not supported)
- **Source:** 14
- **Sink:** 222

**Example 11** - CWE-601:Open redirect (Supported)
Expected to be detected
- **Source/Sink:** 232

**Example 12** - CWE-918:Server-Side Request Forgery - SSRF (Supported)
Expected to be detected
- **Source/Sink:** 241

**Example 13** - CWE-1004:Sensitive Cookie Without 'HttpOnly' Flag (Supported)
- **Source:** 255
- **Sink:** 259

**Example 14** - CWE-330:Use of Insufficiently Random Values (Not supported)
- **Source/Sink:** 119

