# Pioneers25 CTF - Web Challenges Writeups

This repository contains detailed writeups for the web security challenges from the **Pioneers 2025 CTF** competition. Each writeup includes comprehensive exploitation techniques, vulnerability analysis, and source code examination.

---

## 📋 Table of Contents

- [Challenge Overview](#challenge-overview)
- [Challenge Categories](#challenge-categories)
- [Structure](#structure)
- [Quick Navigation](#quick-navigation)
- [Key Learning Outcomes](#key-learning-outcomes)

---

## 🎯 Challenge Overview

This CTF featured **7 web security challenges** covering a wide range of modern web vulnerabilities:

| Challenge | Primary Vulnerability | Technologies |
|-----------|----------------------|--------------|
| [NoSQL_True_Warrior](#nosql_true_warrior) | NoSQL Injection (Blind Regex) | Node.js, MongoDB, Express |
| [CipherNote](#ciphernote) | Server-Side Template Injection (SSTI) | Python, Flask, Jinja2 |
| [NexaCorp](#nexacorp) | GraphQL Introspection + Mass Assignment + SQL Injection | Node.js, GraphQL, SQLite |
| [Tabi3a Jemila](#tabi3a-jemila) | HTTP Parameter Pollution (HPP) | Node.js, Express |
| [RazorCTF](#razorctf) | SSTI with Filter Bypass (.NET Reflection) | ASP.NET Core, RazorLight |
| [Alwen Jemila](#alwen-jemila) | JWT Algorithm Confusion (RS256 → HS256) | Node.js, JWT |
| [SnippetVault](#snippetvault) | Prototype Pollution + SSRF + Cache Poisoning | Node.js, Redis, Express |

---

## 📂 Structure

Each challenge directory contains:

```
Challenge_Name/
├── README.md          # Complete writeup with blackbox analysis and source code examination
├── Dockerfile         # Container configuration
├── docker-compose.yml # Multi-container setup (if applicable)
├── solver/            # Automated exploitation scripts (for blackbox challenges)
└── src/               # Application source code
```

### Writeup Structure

All writeups follow a consistent format:

1. **Challenge Overview** - Description and objectives
2. **Deployment Instructions** - How to run the challenge locally
3. **Reconnaissance & Blackbox Testing** *(for blackbox challenges)* - Initial exploration without source code access
4. **Exploitation** - Step-by-step attack methodology
5. **Understanding the Source Code Vulnerabilities** *(for blackbox challenges)* - Deep dive into the code flaws
6. **Key Takeaways** - Security lessons and mitigation strategies

---

## 🚀 Quick Navigation

### NoSQL_True_Warrior

**Vulnerability:** Blind NoSQL Injection via MongoDB `$regex` operator

**Key Technique:** Character-by-character extraction using regex pattern matching as an oracle

**Location:** [`Web_Challenges/NoSQL_True_Warrior/`](./Web_Challenges/NoSQL_True_Warrior/)

- Bypass authentication using `password[$regex]=^a` pattern
- Extract admin password character-by-character
- Exploit authenticated search endpoint to leak flag

---

### CipherNote

**Vulnerability:** Jinja2 Server-Side Template Injection with WAF bypass

**Key Technique:** Hex encoding to bypass blacklist filters (`\x5f\x5f` instead of `__`)

**Location:** [`Web_Challenges/CipherNote/`](./Web_Challenges/CipherNote/)

- Enumerate blacklisted keywords
- Use `{% %}` block tags instead of `{{ }}`
- Chain `lipsum.__globals__` → `__builtins__` → `os.popen()` via `|attr()` filter
- Bypass WAF using hex-encoded strings

---

### NexaCorp

**Vulnerability:** Multi-stage exploitation chain (GraphQL Introspection → Mass Assignment → SQL Injection)

**Key Technique:** Chaining three vulnerabilities to achieve RCE

**Location:** [`Web_Challenges/nexacorps/graphql-challenge/`](./Web_Challenges/nexacorps/graphql-challenge/)

**Stage 1:** GraphQL introspection bypass via `X-Dev-Mode: 1` header
**Stage 2:** Mass assignment to escalate privileges (`role: "admin"`)
**Stage 3:** SQL injection with `UNION ALL SELECT` (bypasses `UNION SELECT` WAF filter)

---

### Tabi3a Jemila

**Vulnerability:** HTTP Parameter Pollution (HPP)

**Key Technique:** GET request with body parameter to bypass authorization

**Location:** [`Web_Challenges/Tabi3a_Jemila/`](./Web_Challenges/Tabi3a_Jemila/)

- Authorization middleware checks `req.query.id`
- Application logic uses `req.body.id || req.query.id`
- Send `GET /flower?id=3` with body `id=1` to bypass restriction

---

### RazorCTF

**Vulnerability:** ASP.NET Razor SSTI with keyword filter bypass

**Key Technique:** .NET reflection with string concatenation

**Location:** [`Web_Challenges/RazorCtf/`](./Web_Challenges/RazorCtf/)

- Bypass keyword filter using string concatenation (`"System." + "IO." + "File"`)
- Use reflection to access `System.IO.File.ReadAllText()`
- Read `/flag.txt` via `typeof(string).Assembly.GetType(...)`

---

### Alwen Jemila

**Vulnerability:** JWT Algorithm Confusion Attack

**Key Technique:** RS256 → HS256 algorithm substitution

**Location:** [`Web_Challenges/Alwen_Jemila/`](./Web_Challenges/Alwen_Jemila/)

**Note:** ⚠️ *Source code was provided to players for this challenge*

- Application uses RS256 (asymmetric) for token signing
- Weak key verification allows algorithm downgrade to HS256 (symmetric)
- Sign forged JWT using public key as HMAC secret
- Escalate privileges to admin role

---

### SnippetVault

**Vulnerability:** Prototype Pollution → SSRF → Cache Poisoning

**Key Technique:** Multi-stage attack exploiting object merging and Redis caching

**Location:** [`Web_Challenges/SnippetVault/snippetvault/`](./Web_Challenges/SnippetVault/snippetvault/)

**Note:** ⚠️ *Source code was provided to players for this challenge*

**Stage 1:** Prototype pollution via recursive object merge
**Stage 2:** Pollute `proxy` property to redirect HTTP requests
**Stage 3:** Poison Redis cache with malicious content
**Stage 4:** Extract flag from internal service

---

## 🎓 Key Learning Outcomes

### 1. **NoSQL Injection Defense**
- Never pass user-controlled objects directly to database queries
- Validate input types and sanitize regex patterns
- Use parameterized queries even with NoSQL databases

### 2. **Template Injection Mitigation**
- Never render user input through template engines
- Use sandboxed environments (e.g., Jinja2's `SandboxedEnvironment`)
- Blacklist-based filters are insufficient—use semantic analysis or whitelisting

### 3. **GraphQL Security**
- Disable introspection in production (properly)
- Implement proper authorization checks on ALL fields
- Use parameterized queries and prepared statements
- Validate input on both schema and resolver levels

### 4. **HTTP Parameter Pollution Prevention**
- Validate parameters from a **single consistent source**
- Use strict type checking and explicit parameter parsing
- Apply security checks to the same data layer used by business logic

### 5. **JWT Best Practices**
- Enforce a single algorithm in verification
- Never use public keys as HMAC secrets
- Validate the `alg` header strictly
- Use libraries that prevent algorithm confusion attacks

### 6. **Prototype Pollution Defense**
- Validate object keys before merging
- Use `Object.create(null)` for configuration objects
- Avoid recursive merging of untrusted input
- Freeze prototype objects

### 7. **Defense in Depth**
- Security filters must operate at multiple layers
- Bypass techniques exploit inconsistencies between validation and execution
- Use runtime sandboxing in addition to input validation

---

## 🔧 Running the Challenges

### Prerequisites

- Docker & Docker Compose (recommended)
- Node.js 18+ (for local setup)
- Python 3.9+ (for Flask challenges)
- .NET 8.0+ SDK (for ASP.NET challenges)

### Docker Deployment (Recommended)

Each challenge includes Docker configuration:

```bash
cd Web_Challenges/<Challenge_Name>
docker-compose up --build
```

### Local Deployment

Refer to the `README.md` in each challenge directory for specific setup instructions.

---

## 📜 License

These writeups are provided for educational purposes. The challenges and solutions are intended to teach secure coding practices and offensive security techniques.

---

## 👥 Authors

- **CTF Organizers:** Pioneers CTF Team 2025
- **Challenge Design:** Various contributors
- **Writeups:** Challenge authors and security researchers

---

## ⚠️ Disclaimer

These challenges contain intentionally vulnerable code for educational purposes. **Do not deploy these applications in production environments.** The techniques described should only be used for:

- Authorized penetration testing
- Capture The Flag (CTF) competitions
- Educational security research
- Bug bounty programs with proper authorization

Unauthorized use of these techniques against systems you don't own or have explicit permission to test is illegal.

---

## 🏆 Acknowledgments

Special thanks to all participants of Pioneers25 CTF and the security community for their contributions to web application security research.

---

**Happy Hacking! 🚩**
