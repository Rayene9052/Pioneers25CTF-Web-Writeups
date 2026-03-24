/**
 * ChromaLeak - CSS Injection CTF Challenge
 * 
 * A note-sharing platform with custom CSS themes.
 * Players must exploit a CSS injection vulnerability to 
 * exfiltrate the admin's secret token.
 */

const express = require('express');
const session = require('express-session');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const { sanitizeCSS } = require('./utils/sanitizer');
const { requireAuth, guestOnly } = require('./middleware/auth');
const { visitPage } = require('./bot');

const app = express();
const PORT = process.env.PORT || 3000;
const FLAG = process.env.FLAG || 'FLAG{set_me_via_env}';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || crypto.randomBytes(16).toString('hex');

// ===== In-Memory Database =====
const users = new Map();          // id -> user object
const notes = new Map();          // id -> note object
const usernameIndex = new Map();  // lowercase username -> user id

function hashPassword(password) {
    return crypto.createHash('sha256').update(password).digest('hex');
}

// Create admin user
const adminId = uuidv4();
users.set(adminId, {
    id: adminId,
    username: 'admin',
    password_hash: hashPassword(ADMIN_PASSWORD),
    csrf_secret: FLAG,
    created_at: new Date().toISOString(),
});
usernameIndex.set('admin', adminId);
console.log(`[*] Admin user created`);

// ===== Middleware =====
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(session({
    secret: crypto.randomBytes(32).toString('hex'),
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        sameSite: 'lax',
        maxAge: 3600000,
    }
}));

// Content Security Policy
app.use((req, res, next) => {
    res.setHeader('Content-Security-Policy', [
        "default-src 'self'",
        "script-src 'self'",
        "style-src 'self' 'unsafe-inline'",
        "img-src *",
        "font-src *",
        "connect-src 'self'",
        "frame-src 'none'",
        "object-src 'none'",
        "base-uri 'self'",
    ].join('; '));
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'no-referrer');
    next();
});

// Make user data available to all templates
app.use((req, res, next) => {
    res.locals.user = null;
    res.locals.csrfToken = '';
    if (req.session && req.session.userId) {
        const user = users.get(req.session.userId);
        if (user) {
            res.locals.user = { id: user.id, username: user.username };
            res.locals.csrfToken = user.csrf_secret;
        }
    }
    next();
});

// ===== Rate Limiters =====
const reportLimiter = rateLimit({
    windowMs: 30 * 1000,
    max: 1,
    message: { error: 'Too many reports. Please wait 30 seconds between reports.' },
    standardHeaders: true,
    legacyHeaders: false,
});

const authLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 10,
    message: 'Too many attempts. Please try again later.',
});

// ===== Routes =====

app.get('/', (req, res) => {
    res.render('index');
});

// Register
app.get('/register', guestOnly, (req, res) => {
    res.render('register', { error: null });
});

app.post('/register', guestOnly, authLimiter, (req, res) => {
    const { username, password } = req.body;

    if (!username || !password)
        return res.render('register', { error: 'Username and password are required.' });
    if (username.length < 3 || username.length > 20)
        return res.render('register', { error: 'Username must be 3-20 characters.' });
    if (password.length < 6)
        return res.render('register', { error: 'Password must be at least 6 characters.' });
    if (!/^[a-zA-Z0-9_]+$/.test(username))
        return res.render('register', { error: 'Username can only contain letters, numbers, and underscores.' });
    if (username.toLowerCase() === 'admin')
        return res.render('register', { error: 'This username is reserved.' });
    if (usernameIndex.has(username.toLowerCase()))
        return res.render('register', { error: 'Username already taken.' });

    const userId = uuidv4();
    users.set(userId, {
        id: userId,
        username,
        password_hash: hashPassword(password),
        csrf_secret: crypto.randomBytes(32).toString('hex'),
        created_at: new Date().toISOString(),
    });
    usernameIndex.set(username.toLowerCase(), userId);

    req.session.userId = userId;
    res.redirect('/dashboard');
});

// Login
app.get('/login', guestOnly, (req, res) => {
    res.render('login', { error: null });
});

app.post('/login', guestOnly, authLimiter, (req, res) => {
    const { username, password } = req.body;

    if (!username || !password)
        return res.render('login', { error: 'Username and password are required.' });

    const userId = usernameIndex.get(username.toLowerCase());
    const user = userId ? users.get(userId) : null;

    if (!user || user.password_hash !== hashPassword(password))
        return res.render('login', { error: 'Invalid credentials.' });

    req.session.userId = user.id;
    res.redirect('/dashboard');
});

// Logout
app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});

// Dashboard
app.get('/dashboard', requireAuth, (req, res) => {
    const userNotes = [];
    for (const note of notes.values()) {
        if (note.user_id === req.session.userId) userNotes.push(note);
    }
    userNotes.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
    res.render('dashboard', { notes: userNotes });
});

// Create note
app.get('/create', requireAuth, (req, res) => {
    res.render('create', { error: null });
});

app.post('/create', requireAuth, (req, res) => {
    const { title, content, css } = req.body;

    if (!title || !content)
        return res.render('create', { error: 'Title and content are required.' });
    if (title.length > 100)
        return res.render('create', { error: 'Title must be under 100 characters.' });
    if (content.length > 5000)
        return res.render('create', { error: 'Content must be under 5000 characters.' });
    if (css && css.length > 10000)
        return res.render('create', { error: 'Custom CSS must be under 10000 characters.' });

    const noteId = uuidv4();
    const sanitized = css ? sanitizeCSS(css) : '';

    notes.set(noteId, {
        id: noteId,
        user_id: req.session.userId,
        title,
        content,
        css: sanitized,
        created_at: new Date().toISOString(),
    });

    res.redirect(`/note/${noteId}`);
});

// View note (public)
app.get('/note/:id', (req, res) => {
    const note = notes.get(req.params.id);
    if (!note)
        return res.status(404).render('error', { message: 'Note not found.' });

    const author = users.get(note.user_id);
    res.render('note', { note: { ...note, author: author ? author.username : 'Unknown' } });
});

// Delete note
app.post('/delete/:id', requireAuth, (req, res) => {
    const note = notes.get(req.params.id);
    if (note && note.user_id === req.session.userId) notes.delete(req.params.id);
    res.redirect('/dashboard');
});

// Report page
app.get('/report', requireAuth, (req, res) => {
    res.render('report', { error: null, success: null });
});

// Report API — triggers admin bot
app.post('/api/report', requireAuth, reportLimiter, async (req, res) => {
    const { url } = req.body;
    const appUrl = process.env.APP_URL || `http://127.0.0.1:${PORT}`;

    if (!url)
        return res.status(400).json({ error: 'URL is required.' });

    if (!url.startsWith(appUrl) && !url.startsWith(`http://localhost:${PORT}`))
        return res.status(400).json({ error: `URL must start with ${appUrl}` });

    // Keep the public URL — the bot handles internal rewriting itself
    const normalizedUrl = url.replace(`http://localhost:${PORT}`, appUrl);
    console.log(`[Report] User ${req.session.userId} reported: ${normalizedUrl}`);

    res.json({ success: true, message: 'An admin will review this page shortly.' });

    try {
        await visitPage(normalizedUrl);
    } catch (error) {
        console.error(`[Report] Bot error: ${error.message}`);
    }
});

// Source code (white-box)
app.get('/source', (req, res) => {
    res.render('source');
});

// 404
app.use((req, res) => {
    res.status(404).render('error', { message: 'Page not found.' });
});

// ===== Start =====
app.listen(PORT, '0.0.0.0', () => {
    console.log(`[*] ChromaLeak running on http://0.0.0.0:${PORT}`);
});
