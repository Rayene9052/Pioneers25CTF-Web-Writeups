# Pioneers25 CTF - Web Challenges Writeups

This repository contains detailed writeups for the web security challenges from the **Pioneers25 CTF** competition. Each writeup includes comprehensive exploitation techniques, vulnerability analysis, and source code examination.

---

## 📋 Table of Contents

- [Challenge Overview](#challenge-overview)
- [Structure](#structure)

---

## 🎯 Challenge Overview

This CTF featured **7 web security challenges** covering a wide range of modern web vulnerabilities:

| Challenge | Primary Vulnerability | Technologies |
|-----------|----------------------|--------------|
| [True_Warrior](#true_warrior) | NoSQL Injection (Blind Regex) | Node.js, MongoDB, Express |
| [CipherNote](#ciphernote) | Server-Side Template Injection (SSTI) | Python, Flask, Jinja2 |
| [NexaCorp](#nexacorp) | GraphQL Introspection + Mass Assignment + SQL Injection | Node.js, GraphQL, SQLite |
| [Tabi3a Jemila](#tabi3a-jemila) | HTTP Parameter Pollution (HPP) | Node.js, Express |
| [SecureMessenger](#securemessenger) | SSTI with Filter Bypass (.NET Reflection) | ASP.NET Core, RazorLight |
| [Alwen Jemila](#alwen-jemila) | CSS Injection (Non-Hex Escape Bypass) + Attribute Selector Exfiltration | Node.js, Express, CSS |
| [SnippetVault](#snippetvault) | 5-Stage Chain: Blind SQLi → Auth Bypass → Admin Unlock → Command Injection | Python, Flask, SQLite |

---

## 📂 Structure

Each challenge directory contains:

```
Challenge_Name/
├── README.md          
├── Dockerfile         
├── docker-compose.yml 
├── solver/            
└── src/               
```

### Writeup Structure

All writeups follow a consistent format:

1. **Challenge Overview** - Description and objectives
2. **Deployment Instructions** - How to run the challenge locally
3. **Reconnaissance & Blackbox Testing** *(for blackbox challenges)* - Initial exploration without source code access
4. **Exploitation** - Step-by-step attack methodology
5. **Understanding the Source Code Vulnerabilities**  - Deep dive into the code flaws
6. **Key Takeaways** - Security lessons and mitigation strategies
