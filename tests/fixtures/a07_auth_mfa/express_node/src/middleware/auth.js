'use strict';

const jwt = require('jsonwebtoken');
const { JWT_SECRET } = require('../config');

function bearer(req) {
  const header = req.headers.authorization || '';
  return header.startsWith('Bearer ') ? header.slice(7) : null;
}

// Mounted on every /api/v1 route.
function requireAuth(req, res, next) {
  const token = bearer(req);
  if (!token) return res.status(401).json({ error: 'unauthorized' });
  try {
    // codit-expect: CWE-308 any valid JWT is accepted, including scope=mfa_pending tokens minted by /api/v2/auth/login
    req.user = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
    return next();
  } catch (err) {
    return res.status(401).json({ error: 'unauthorized' });
  }
}

// Mounted on every /api/v2 route except the second-factor endpoints.
function requireFullAuth(req, res, next) {
  const token = bearer(req);
  if (!token) return res.status(401).json({ error: 'unauthorized' });
  let claims;
  try {
    claims = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
  } catch (err) {
    return res.status(401).json({ error: 'unauthorized' });
  }
  if (claims.scope !== 'access') {
    return res.status(401).json({ error: 'second factor required' });
  }
  // codit-safe: CWE-308 only scope=access tokens pass, mfa_pending tokens are rejected above
  req.user = claims;
  return next();
}

// Only for /api/v2/auth/2fa/*.
function requireMfaPending(req, res, next) {
  const token = bearer(req);
  try {
    const claims = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
    if (claims.scope !== 'mfa_pending') return res.status(401).json({ error: 'unauthorized' });
    req.mfa = claims;
    return next();
  } catch (err) {
    return res.status(401).json({ error: 'unauthorized' });
  }
}

module.exports = { requireAuth, requireFullAuth, requireMfaPending };
