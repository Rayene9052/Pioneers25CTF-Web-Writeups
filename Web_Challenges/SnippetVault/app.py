import json
import os
import re
import sqlite3
import hashlib
import secrets
import subprocess
import html as html_mod
from functools import wraps
from flask import (
    Flask, request, session, redirect, url_for,
    render_template, render_template_string, g, abort,
)

app = Flask(__name__, template_folder="views")
app.secret_key = secrets.token_hex(32)
DATABASE = "/tmp/snippetvault.db"
UPLOAD_DIR = "/tmp/sv_uploads"
LANGS = ("text", "python", "javascript", "c", "go", "bash", "sql", "html")

_SQLI_PATTERNS = [
    r"--", r"#", r"/\*", r"\*/", r"\bUNION\b", r"\bOR\s",
    r"\bAND\s+\d", r"\bDROP\b", r"\bDELETE\b", r"\bINSERT\b",
    r"\bUPDATE\b", r"\bEXEC\b", r"\bSLEEP\b", r"\bBENCHMARK\b",
    r"\bLOAD_FILE\b", r"\bINTO\s+OUTFILE\b", r"\bATTACH\b",
]
_SQLI_RE = re.compile("|".join(_SQLI_PATTERNS), re.IGNORECASE)

def waf_check(value):
    return _SQLI_RE.sub("", value)

_UNSAFE_SHELL = re.compile(r"[;&|`$(){}\[\]!<>\\\']")

def sanitize_input(value):
    return _UNSAFE_SHELL.sub("", value)

def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_db(_exc):
    db = getattr(g, "_database", None)
    if db:
        db.close()

def init_db():
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    con = sqlite3.connect(DATABASE)
    con.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role     TEXT NOT NULL DEFAULT 'user',
            bio      TEXT NOT NULL DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS snippets (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_id   INTEGER NOT NULL,
            title      TEXT NOT NULL,
            content    TEXT NOT NULL,
            lang       TEXT NOT NULL DEFAULT 'text',
            is_private INTEGER NOT NULL DEFAULT 1,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS uploads (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_id    INTEGER NOT NULL,
            filename    TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            stored_as   TEXT NOT NULL,
            mime_type   TEXT DEFAULT 'application/octet-stream',
            uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS settings (
            id  INTEGER PRIMARY KEY AUTOINCREMENT,
            key TEXT UNIQUE NOT NULL,
            val TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS audit_log (
            id      INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action  TEXT NOT NULL,
            detail  TEXT,
            ts      DATETIME DEFAULT CURRENT_TIMESTAMP
        );
    """)
    admin_pw = hashlib.sha256(secrets.token_hex(16).encode()).hexdigest()
    pin = secrets.token_hex(3)
    con.execute(
        "INSERT OR IGNORE INTO users (username, password, role) "
        "VALUES ('admin', ?, 'admin')", (admin_pw,),
    )
    con.execute(
        "INSERT OR IGNORE INTO users (username, password, role) "
        "VALUES ('guest', ?, 'user')",
        (hashlib.sha256(b"password123").hexdigest(),),
    )
    for k, v in [
        ("admin_pin", pin), ("motd", "Welcome to SnippetVault v2.3"),
        ("max_upload_mb", "5"), ("maintenance", "0"), ("registration", "open"),
    ]:
        con.execute(
            "INSERT OR IGNORE INTO settings (key, val) VALUES (?, ?)", (k, v),
        )
    admin_id = con.execute(
        "SELECT id FROM users WHERE username='admin'"
    ).fetchone()
    if admin_id:
        aid = admin_id[0]
        seeds = [
            (1, aid, "Hello World",
             'print("Hello, World!")', "python", 0),
            (2, aid, "Quick Sort",
             "def qsort(a):\n    if len(a)<=1: return a\n"
             "    p=a[0]\n    return qsort([x for x in a[1:] if x<p])"
             "+[p]+qsort([x for x in a[1:] if x>=p])",
             "python", 0),
            (3, aid, "Fibonacci",
             "function fib(n) {\n  if (n <= 1) return n;\n"
             "  return fib(n-1) + fib(n-2);\n}",
             "javascript", 0),
        ]
        for sid, oid, t, c, l, p in seeds:
            con.execute(
                "INSERT OR IGNORE INTO snippets "
                "(id, owner_id, title, content, lang, is_private) "
                "VALUES (?,?,?,?,?,?)", (sid, oid, t, c, l, p),
            )
    con.commit()
    con.close()

def login_required(f):
    @wraps(f)
    def wrapper(*a, **kw):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return f(*a, **kw)
    return wrapper

def admin_required(f):
    @wraps(f)
    def wrapper(*a, **kw):
        if session.get("role") != "admin":
            abort(403)
        return f(*a, **kw)
    return wrapper

def pin_required(f):
    @wraps(f)
    def wrapper(*a, **kw):
        if not session.get("pin_verified"):
            return redirect(url_for("admin_panel"))
        return f(*a, **kw)
    return wrapper

def audit(action, detail=""):
    try:
        get_db().execute(
            "INSERT INTO audit_log (user_id, action, detail) VALUES (?,?,?)",
            (session.get("user_id"), action, detail),
        )
        get_db().commit()
    except Exception:
        pass

@app.route("/")
def index():
    db = get_db()
    motd = ""
    row = db.execute("SELECT val FROM settings WHERE key='motd'").fetchone()
    if row:
        motd = row["val"]
    return render_template("index.html", motd=motd)

@app.route("/register", methods=["GET", "POST"])
def register():
    msg, cls = "", ""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not re.match(r'^[A-Za-z0-9_]{3,30}$', username):
            msg, cls = "Username must be 3-30 alphanumeric/underscore chars.", "err"
        elif len(password) < 4:
            msg, cls = "Password must be at least 4 characters.", "err"
        else:
            pw_hash = hashlib.sha256(password.encode()).hexdigest()
            try:
                get_db().execute(
                    "INSERT INTO users (username, password) VALUES (?, ?)",
                    (username, pw_hash),
                )
                get_db().commit()
                audit("register", username)
                msg, cls = "Account created! You can now log in.", "ok"
            except sqlite3.IntegrityError:
                msg, cls = "Username already taken.", "err"
    return render_template("register.html", msg=msg, cls=cls)

@app.route("/login", methods=["GET", "POST"])
def login():
    msg = ""
    if request.method == "POST":
        raw_user = request.form.get("username", "")
        password = request.form.get("password", "")
        pw_hash = hashlib.sha256(password.encode()).hexdigest()
        username = waf_check(raw_user)
        query = (
            "SELECT id, username, role FROM users "
            f"WHERE username = '{username}' "
            f"AND   password = '{pw_hash}'"
        )
        try:
            row = get_db().execute(query).fetchone()
        except Exception:
            row = None
        if row:
            session.clear()
            session["user_id"] = row["id"]
            session["username"] = row["username"]
            session["role"] = row["role"]
            audit("login", row["username"])
            return redirect(url_for("profile"))
        msg = "Invalid username or password."
    return render_template("login.html", msg=msg)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    db, msg = get_db(), ""
    if request.method == "POST":
        bio = request.form.get("bio", "")[:512]
        db.execute("UPDATE users SET bio = ? WHERE id = ?",
                   (bio, session["user_id"]))
        db.commit()
        msg = "Profile updated."
    row = db.execute(
        "SELECT username, role, bio FROM users WHERE id = ?",
        (session["user_id"],),
    ).fetchone()
    bio = row["bio"] if row and row["bio"] else "(empty)"
    return render_template("profile.html",
        username=session.get("username", ""),
        role=session.get("role", ""), bio=bio, msg=msg)

@app.route("/snippets", methods=["GET", "POST"])
@login_required
def snippets():
    db = get_db()
    if request.method == "POST":
        title = request.form.get("title", "untitled")[:128]
        content = request.form.get("content", "")[:8192]
        lang = request.form.get("lang", "text")
        is_private = 1 if request.form.get("private") else 0
        if lang not in LANGS:
            lang = "text"
        db.execute(
            "INSERT INTO snippets (owner_id, title, content, lang, is_private) "
            "VALUES (?,?,?,?,?)",
            (session["user_id"], title, content, lang, is_private),
        )
        db.commit()
        audit("create_snippet", title)
        return redirect(url_for("snippets"))
    rows = db.execute(
        "SELECT id, title, content, lang, created_at FROM snippets "
        "WHERE owner_id = ? ORDER BY id DESC",
        (session["user_id"],),
    ).fetchall()
    return render_template("snippets.html", rows=rows, langs=LANGS)

@app.route("/snippet/<int:sid>/raw")
def snippet_raw(sid):
    row = get_db().execute(
        "SELECT content FROM snippets WHERE id = ? AND is_private = 0",
        (sid,),
    ).fetchone()
    if not row:
        abort(404)
    return row["content"], 200, {"Content-Type": "text/plain; charset=utf-8"}

@app.route("/snippet/<int:sid>/embed")
def snippet_embed(sid):
    db = get_db()
    row = db.execute(
        "SELECT s.title, s.content, s.lang, u.username "
        "FROM snippets s JOIN users u ON s.owner_id = u.id "
        "WHERE s.id = ? AND s.is_private = 0",
        (sid,),
    ).fetchone()
    if not row:
        abort(404)
    theme = request.args.get("theme", "monokai")
    if not re.match(r'^[a-zA-Z0-9_-]{1,20}$', theme):
        theme = "monokai"
    embed_html = render_template_string(
        '<div class="sv-embed sv-theme-{{ theme }}">'
        '<div class="sv-hdr">{{ title }} <span>by {{ author }}</span></div>'
        '<pre class="sv-code sv-lang-{{ lang }}">{{ content | safe }}</pre>'
        '</div>',
        theme=theme,
        title=html_mod.escape(row["title"]),
        author=html_mod.escape(row["username"]),
        lang=html_mod.escape(row["lang"]),
        content=html_mod.escape(row["content"]),
    )
    callback = request.args.get("callback", "")
    if callback and re.match(r'^[a-zA-Z_]\w{0,30}$', callback):
        payload = json.dumps({"html": embed_html})
        return f"{callback}({payload})", 200, {
            "Content-Type": "application/javascript"
        }
    return embed_html

@app.route("/explore")
def explore():
    db = get_db()
    search = request.args.get("q", "").strip()
    if search:
        clean = waf_check(search)
        rows = db.execute(
            "SELECT s.id, s.title, s.lang, s.created_at, u.username "
            "FROM snippets s JOIN users u ON s.owner_id = u.id "
            "WHERE s.is_private = 0 AND s.title LIKE '%" + clean + "%' "
            "ORDER BY s.id DESC LIMIT 50"
        ).fetchall()
    else:
        rows = db.execute(
            "SELECT s.id, s.title, s.lang, s.created_at, u.username "
            "FROM snippets s JOIN users u ON s.owner_id = u.id "
            "WHERE s.is_private = 0 ORDER BY s.id DESC LIMIT 50"
        ).fetchall()
    return render_template("explore.html", rows=rows, q=search)

@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    db, msg, cls, uploaded_name = get_db(), "", "", ""
    if request.method == "POST":
        f = request.files.get("file")
        if not f or not f.filename:
            msg, cls = "No file selected.", "err"
        else:
            original_name = f.filename
            description = request.form.get("desc", "").strip()[:256]
            category = request.form.get("category", "misc").strip()[:32]
            stored_name = secrets.token_hex(8) + ".bin"
            dest = os.path.join(UPLOAD_DIR, stored_name)
            f.save(dest)
            db.execute(
                "INSERT INTO uploads "
                "(owner_id, filename, description, stored_as) "
                "VALUES (?,?,?,?)",
                (session["user_id"], original_name, description, stored_name),
            )
            db.commit()
            audit("upload", f"{original_name} cat={category}")
            uploaded_name = stored_name
            cls = "ok"
    rows = db.execute(
        "SELECT id, filename, description, stored_as FROM uploads "
        "WHERE owner_id = ?",
        (session["user_id"],),
    ).fetchall()
    return render_template("upload.html",
        msg=msg, cls=cls, uploaded_name=uploaded_name, uploads=rows)

@app.route("/admin")
@login_required
@admin_required
def admin_panel():
    if session.get("pin_verified"):
        return redirect(url_for("admin_dashboard"))
    return render_template("admin.html", error=False)

@app.route("/admin/unlock", methods=["POST"])
@login_required
@admin_required
def admin_unlock():
    pin = request.form.get("pin", "").strip()
    db = get_db()
    row = db.execute(
        "SELECT val FROM settings WHERE key = 'admin_pin'",
    ).fetchone()
    if row and secrets.compare_digest(pin, row["val"]):
        session["pin_verified"] = True
        audit("admin_unlock", "success")
        return redirect(url_for("admin_dashboard"))
    audit("admin_unlock", "fail")
    return render_template("admin.html", error=True)

@app.route("/admin/dashboard")
@login_required
@admin_required
@pin_required
def admin_dashboard():
    db = get_db()
    users = db.execute(
        "SELECT id, username, role FROM users ORDER BY id"
    ).fetchall()
    uploads = db.execute(
        "SELECT u.id, u.filename, u.description, u.stored_as, us.username "
        "FROM uploads u JOIN users us ON u.owner_id = us.id "
        "ORDER BY u.id DESC LIMIT 100"
    ).fetchall()
    logs = db.execute(
        "SELECT action, detail, ts FROM audit_log ORDER BY id DESC LIMIT 30"
    ).fetchall()
    settings = db.execute(
        "SELECT key, val FROM settings ORDER BY key"
    ).fetchall()
    return render_template("dashboard.html",
        users=users, uploads=uploads, logs=logs, settings=settings)

@app.route("/admin/scan", methods=["POST"])
@login_required
@admin_required
@pin_required
def admin_scan():
    upload_id = request.form.get("upload_id", "").strip()
    db = get_db()
    row = db.execute(
        "SELECT filename, description, stored_as FROM uploads WHERE id = ?",
        (upload_id,),
    ).fetchone()
    if not row:
        return render_template("scan.html", error="Upload not found.")
    stored_path = os.path.join(UPLOAD_DIR, row["stored_as"])
    safe_name = sanitize_input(row["filename"])
    safe_desc = sanitize_input(row["description"])
    cmd = (
        f'file {stored_path} && '
        f'echo "scan: {safe_name} - {safe_desc}" >> /tmp/sv_scan.log'
    )
    try:
        proc = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=5,
        )
        output = proc.stdout + proc.stderr
    except Exception as e:
        output = str(e)
    audit("scan_upload", f"id={upload_id}")
    return render_template("scan.html",
        stored_as=row["stored_as"], filename=row["filename"],
        description=row["description"], output=output)

with app.app_context():
    init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
