'use strict';

const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const speakeasy = require('speakeasy');
const User = require('../models/User');
const TrustedDevice = require('../models/TrustedDevice');
const jwtConfig = require('../config/jwt');
const { JWT_SECRET } = require('../config');
const { requireAuth, requireFullAuth } = require('../middleware/auth');

const router = express.Router();

// codit-expect: CWE-308 TOTP can be disabled without the password or a current code
router.post('/v1/account/2fa/disable', requireAuth, async (req, res) => {
  await User.updateOne({ _id: req.user.sub }, { $set: { totpEnabled: false, totpSecret: null } });
  res.status(204).end();
});

// codit-safe: CWE-308 requires the current password and a valid TOTP code before disabling
router.post('/v2/account/2fa/disable', requireFullAuth, async (req, res) => {
  const user = await User.findById(req.user.sub);
  const passwordOk = await bcrypt.compare(String(req.body.password || ''), user.passwordHash);
  const codeOk = speakeasy.totp.verify({
    secret: user.totpSecret, encoding: 'base32', token: String(req.body.code || ''), window: 1,
  });
  if (!passwordOk || !codeOk) return res.status(403).json({ error: 're-authentication failed' });
  user.totpEnabled = false;
  user.totpSecret = null;
  await user.save();
  return res.status(204).end();
});

router.patch('/v1/account/profile', requireAuth, async (req, res) => {
  // codit-expect: CWE-915 whole request body written to the user document (totpEnabled, role, email)
  const user = await User.findByIdAndUpdate(req.user.sub, req.body, { new: true });
  res.json(user.toPublicJSON());
});

router.patch('/v2/account/profile', requireFullAuth, async (req, res) => {
  const { displayName, locale, timezone } = req.body;
  // codit-safe: CWE-915 only an explicit allow-list of profile fields is updated
  const user = await User.findByIdAndUpdate(req.user.sub, { displayName, locale, timezone }, { new: true });
  res.json(user.toPublicJSON());
});

router.post('/v1/session/resume', async (req, res) => {
  const user = await User.findOne({ email: String(req.body.email) });
  if (!user || !(await bcrypt.compare(String(req.body.password), user.passwordHash))) {
    return res.status(401).json({ error: 'Invalid email or password' });
  }
  // codit-expect: CWE-807 second factor skipped when the plain trusted_device cookie equals 1
  if (!user.totpEnabled || req.cookies.trusted_device === '1') {
    const token = jwt.sign({ sub: user.id, scope: 'access' }, JWT_SECRET, jwtConfig.access);
    return res.json({ token });
  }
  return res.json({ mfaRequired: true });
});

router.post('/v2/session/resume', async (req, res) => {
  const user = await User.findOne({ email: String(req.body.email) });
  if (!user || !(await bcrypt.compare(String(req.body.password), user.passwordHash))) {
    return res.status(401).json({ error: 'Invalid email or password' });
  }
  const deviceToken = req.signedCookies.td;
  // codit-safe: CWE-807 signed random device token checked against a hashed server-side record of this user
  const trusted = Boolean(deviceToken) && (await TrustedDevice.isValid(user.id, deviceToken));
  if (!user.totpEnabled || trusted) {
    const token = jwt.sign({ sub: user.id, scope: 'access' }, JWT_SECRET, jwtConfig.access);
    return res.json({ token });
  }
  return res.json({ mfaRequired: true });
});

module.exports = router;
