'use strict';

const express = require('express');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const PasswordReset = require('../models/PasswordReset');
const mailer = require('../services/mailer');
const { APP_URL, JWT_SECRET } = require('../config');

const router = express.Router();

router.post('/v1/password/forgot', async (req, res) => {
  const user = await User.findOne({ email: String(req.body.email) });
  if (user) {
    // codit-expect: CWE-338 reset token built from Math.random() and the clock
    const token = Math.random().toString(36).slice(2) + Date.now().toString(36);
    await PasswordReset.create({ userId: user.id, token });
    await mailer.sendReset(user.email, `${APP_URL}/reset?token=${token}`);
  }
  res.status(202).json({ ok: true });
});

router.post('/v1/password/reset', async (req, res) => {
  // codit-expect: CWE-640 reset token accepted whatever its age (no expiry stored or checked)
  const record = await PasswordReset.findOne({ token: String(req.body.token) });
  if (!record) return res.status(400).json({ error: 'invalid token' });
  const user = await User.findById(record.userId);
  user.passwordHash = await bcrypt.hash(String(req.body.password), 12);
  await user.save();

  // codit-expect: CWE-640 reset logs the user straight in with a full JWT, bypassing 2FA
  return res.json({ token: jwt.sign({ sub: user.id, scope: 'access' }, JWT_SECRET, { expiresIn: '1h' }) });
});

router.post('/v2/password/forgot', async (req, res) => {
  const user = await User.findOne({ email: String(req.body.email) });
  if (user) {
    // codit-safe: CWE-338 256-bit token from crypto.randomBytes
    const token = crypto.randomBytes(32).toString('base64url');
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    await PasswordReset.create({ userId: user.id, tokenHash, expiresAt: new Date(Date.now() + 30 * 60 * 1000) });
    await mailer.sendReset(user.email, `${APP_URL}/reset#token=${token}`);
  }
  res.status(202).json({ ok: true });
});

router.post('/v2/password/reset', async (req, res) => {
  const tokenHash = crypto.createHash('sha256').update(String(req.body.token)).digest('hex');
  // codit-safe: CWE-640 hashed single-use token, rejected once expiresAt has passed
  const record = await PasswordReset.findOneAndDelete({ tokenHash, expiresAt: { $gt: new Date() } });
  if (!record) return res.status(400).json({ error: 'invalid or expired token' });
  const user = await User.findById(record.userId);
  user.passwordHash = await bcrypt.hash(String(req.body.password), 12);
  user.sessionVersion += 1;
  await user.save();

  // codit-safe: CWE-640 no token issued, the user signs in again through password + 2FA
  return res.status(204).end();
});

module.exports = router;
