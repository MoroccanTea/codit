const express = require('express');
const jwt = require('jsonwebtoken');
const speakeasy = require('speakeasy');
const User = require('./models/user');

const router = express.Router();
const SECRET = process.env.JWT_SECRET;

router.post('/login', async (req, res) => {
  const user = await User.findOne({ email: req.body.email });
  if (!user || !(await user.checkPassword(req.body.password))) {
    return res.status(401).json({ error: 'invalid credentials' });
  }
  if (user.totpEnabled) {
    // codit-safe: CWE-308 pending ticket, rejected by requireAuth outside the 2FA step
    const ticket = jwt.sign({ sub: user.id, mfaPending: true }, SECRET, { expiresIn: '5m' });
    return res.json({ mfaRequired: true, token: ticket });
  }
  const token = jwt.sign({ sub: user.id, role: user.role }, SECRET, { expiresIn: '1h' });
  return res.json({ mfaRequired: false, token });
});

router.post('/login/2fa', requirePending, async (req, res) => {
  const user = await User.findById(req.pending.sub);
  const ok = speakeasy.totp.verify({ secret: user.totpSecret, encoding: 'base32', token: req.body.code });
  if (!ok) return res.status(401).json({ error: 'bad code' });
  const token = jwt.sign({ sub: user.id, role: user.role }, SECRET, { expiresIn: '1h' });
  return res.json({ mfaRequired: false, token });
});

function requirePending(req, res, next) {
  const raw = (req.headers.authorization || '').replace('Bearer ', '');
  try {
    const claims = jwt.verify(raw, SECRET);
    if (!claims.mfaPending) return res.status(401).end();
    req.pending = claims;
    return next();
  } catch (e) {
    return res.status(401).end();
  }
}

function requireAuth(req, res, next) {
  const raw = (req.headers.authorization || '').replace('Bearer ', '');
  try {
    const claims = jwt.verify(raw, SECRET);
    if (claims.mfaPending) return res.status(401).end();
    req.user = claims;
    return next();
  } catch (e) {
    return res.status(401).end();
  }
}

module.exports = { router, requireAuth };
