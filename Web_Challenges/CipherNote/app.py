import os
import re
import sqlite3
import secrets
from functools import wraps
from flask import (
    Flask, render_template, render_template_string, request,
    redirect, url_for, session, flash, jsonify, g
)
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

DATABASE = 'ciphernote.db'


def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DATABASE)
    db.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        is_admin INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    db.execute('''CREATE TABLE IF NOT EXISTS notes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        content TEXT NOT NULL,
        encrypted INTEGER DEFAULT 0,
        share_token TEXT UNIQUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )''')
    admin_pw = secrets.token_hex(20)
    try:
        db.execute(
            'INSERT INTO users (username, password, is_admin) VALUES (?, ?, 1)',
            ('admin', generate_password_hash(admin_pw), )
        )
    except sqlite3.IntegrityError:
        pass
    db.commit()
    db.close()


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in first.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated


BLACKLIST = [
    '{{', '}}', '__', 'config', 'class', 'import', 'os', 'popen',
    'eval', 'exec', 'subprocess', 'flag', 'self', 'request',
    'application', 'init', 'globals', 'getattr', 'builtins',
    'mro', 'base', 'subclasses', 'open', 'read', 'system',
]


def waf_check(content: str) -> bool:
    lower = content.lower()
    for word in BLACKLIST:
        if word in lower:
            return False
    return True


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        if not username or not password:
            flash('Username and password are required.', 'danger')
            return redirect(url_for('register'))
        if len(username) < 3 or len(password) < 4:
            flash('Username must be ≥3 chars, password ≥4 chars.', 'danger')
            return redirect(url_for('register'))
        db = get_db()
        try:
            db.execute(
                'INSERT INTO users (username, password) VALUES (?, ?)',
                (username, generate_password_hash(password))
            )
            db.commit()
            flash('Account created! Please log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already taken.', 'danger')
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        db = get_db()
        user = db.execute(
            'SELECT * FROM users WHERE username = ?', (username,)
        ).fetchone()
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['is_admin'] = bool(user['is_admin'])
            flash(f'Welcome back, {username}!', 'success')
            return redirect(url_for('dashboard'))
        flash('Invalid credentials.', 'danger')
    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out.', 'info')
    return redirect(url_for('index'))


@app.route('/dashboard')
@login_required
def dashboard():
    db = get_db()
    notes = db.execute(
        'SELECT * FROM notes WHERE user_id = ? ORDER BY created_at DESC',
        (session['user_id'],)
    ).fetchall()
    return render_template('dashboard.html', notes=notes)


@app.route('/create', methods=['GET', 'POST'])
@login_required
def create():
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        content = request.form.get('content', '').strip()
        encrypted = 1 if request.form.get('encrypted') else 0
        if not title or not content:
            flash('Title and content are required.', 'danger')
            return redirect(url_for('create'))
        share_token = secrets.token_urlsafe(16)
        db = get_db()
        db.execute(
            'INSERT INTO notes (user_id, title, content, encrypted, share_token) VALUES (?, ?, ?, ?, ?)',
            (session['user_id'], title, content, encrypted, share_token)
        )
        db.commit()
        flash('Note created successfully!', 'success')
        return redirect(url_for('dashboard'))
    return render_template('create.html')


@app.route('/note/<int:note_id>')
@login_required
def view_note(note_id):
    db = get_db()
    note = db.execute('SELECT * FROM notes WHERE id = ? AND user_id = ?',
                       (note_id, session['user_id'])).fetchone()
    if not note:
        flash('Note not found.', 'danger')
        return redirect(url_for('dashboard'))
    return render_template('view.html', note=note)


@app.route('/shared/<token>')
def shared_note(token):
    db = get_db()
    note = db.execute('SELECT * FROM notes WHERE share_token = ?',
                       (token,)).fetchone()
    if not note:
        flash('Shared note not found or expired.', 'danger')
        return redirect(url_for('index'))
    return render_template('view.html', note=note, shared=True)


@app.route('/delete/<int:note_id>', methods=['POST'])
@login_required
def delete_note(note_id):
    db = get_db()
    db.execute('DELETE FROM notes WHERE id = ? AND user_id = ?',
               (note_id, session['user_id']))
    db.commit()
    flash('Note deleted.', 'info')
    return redirect(url_for('dashboard'))


@app.route('/preview', methods=['POST'])
@login_required
def preview():
    content = request.form.get('content', '')

    if not waf_check(content):
        return jsonify({
            'success': False,
            'html': '<span class="text-danger">⚠ Dangerous content detected. '
                    'Your input contains blocked keywords.</span>'
        }), 400

    template = f'''
    <div class="rendered-preview">
        {content}
    </div>
    '''
    try:
        rendered = render_template_string(template)
        return jsonify({'success': True, 'html': rendered})
    except Exception as e:
        return jsonify({
            'success': False,
            'html': f'<span class="text-danger">Render error: {str(e)}</span>'
        }), 500


@app.route('/admin')
@login_required
def admin():
    if not session.get('is_admin'):
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('dashboard'))
    db = get_db()
    users = db.execute('SELECT id, username, is_admin, created_at FROM users').fetchall()
    notes = db.execute(
        'SELECT notes.*, users.username FROM notes JOIN users ON notes.user_id = users.id '
        'ORDER BY notes.created_at DESC'
    ).fetchall()
    return render_template('admin.html', users=users, notes=notes)


@app.errorhandler(404)
def not_found(e):
    return render_template('base.html', error='Page not found'), 404


@app.errorhandler(500)
def internal_error(e):
    return render_template('base.html', error='Internal server error'), 500


if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=False)
