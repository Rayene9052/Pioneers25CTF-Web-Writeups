const jwt = require('jsonwebtoken');
const crypto = require('crypto');

// Strong 64-byte secret — not brute-forceable
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');

function signToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: '24h' });
}

function verifyToken(token) {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch {
    return null;
  }
}

function getUserFromRequest(req) {
  const auth = req.headers['authorization'] || '';
  if (!auth.startsWith('Bearer ')) return null;
  const token = auth.slice(7);
  return verifyToken(token);
}

module.exports = { signToken, getUserFromRequest };
