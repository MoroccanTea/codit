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
    // codit-expect: CWE-308 the pending flag is in the token but requireAuth never checks it
    const token = jwt.sign({ sub: user.id, role: user.role, mfaPending: true }, SECRET, { expiresIn: '1h' });
    return res.json({ mfaRequired: true, token });
  }
  const token = jwt.sign({ sub: user.id, role: user.role }, SECRET, { expiresIn: '1h' });
  return res.json({ mfaRequired: false, token });
});

router.post('/login/2fa', requireAuth, async (req, res) => {
  const user = await User.findById(req.user.sub);
  const ok = speakeasy.totp.verify({ secret: user.totpSecret, encoding: 'base32', token: req.body.code });
  if (!ok) return res.status(401).json({ error: 'bad code' });
  const token = jwt.sign({ sub: user.id, role: user.role }, SECRET, { expiresIn: '1h' });
  return res.json({ mfaRequired: false, token });
});

function requireAuth(req, res, next) {
  const raw = (req.headers.authorization || '').replace('Bearer ', '');
  try {
    req.user = jwt.verify(raw, SECRET);
    return next();
  } catch (e) {
    return res.status(401).end();
  }
}

module.exports = { router, requireAuth };
