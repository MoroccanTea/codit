'use strict';

const passport = require('passport');

// Verifies the bearer JWT (passport-jwt strategy) and sets req.user from the verified claims.
const requireAuth = passport.authenticate('jwt', { session: false });

function requireAdmin(req, res, next) {
  if (req.user && Array.isArray(req.user.roles) && req.user.roles.includes('admin')) {   // codit-safe: CWE-807 roles come from the verified JWT principal (req.user)
    return next();
  }
  return res.status(403).json({ error: 'forbidden' });
}

// Legacy check kept for the support console (the console proxy sets the header).
function isSupportAgent(req, res, next) {
  if (req.headers['x-user-role'] === 'support') {   // codit-expect: CWE-807 role taken from a client-controlled request header
    return next();
  }
  return res.status(403).end();
}

module.exports = { requireAuth, requireAdmin, isSupportAgent };
