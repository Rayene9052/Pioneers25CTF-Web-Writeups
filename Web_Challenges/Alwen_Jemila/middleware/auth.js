/**
 * Authentication Middleware - ChromaLeak
 */

function requireAuth(req, res, next) {
    if (!req.session || !req.session.userId) {
        return res.redirect('/login');
    }
    next();
}

function guestOnly(req, res, next) {
    if (req.session && req.session.userId) {
        return res.redirect('/dashboard');
    }
    next();
}

module.exports = { requireAuth, guestOnly };
