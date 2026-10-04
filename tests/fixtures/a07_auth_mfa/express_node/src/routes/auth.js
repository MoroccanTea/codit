'use strict';

// v2 auth API: password -> mfa_pending token -> TOTP / SMS code -> access token
const express = require('express');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const speakeasy = require('speakeasy');
const logger = require('pino')();
const User = require('../models/User');
const OtpChallenge = require('../models/OtpChallenge');
const sms = require('../services/sms');
const jwtConfig = require('../config/jwt');
const { JWT_SECRET } = require('../config');
const { requireMfaPending } = require('../middleware/auth');

const router = express.Router();
const MAX_MFA_ATTEMPTS = 5;
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 20, standardHeaders: true });
const otpLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 5, standardHeaders: true });

function issueSession(user) {
  const token = jwt.sign({ sub: user.id, scope: 'access' }, JWT_SECRET, jwtConfig.access);
  return { token };
}

router.post('/login', loginLimiter, async (req, res) => {
  const user = await User.findOne({ email: String(req.body.email) });
  const ok = user && (await bcrypt.compare(String(req.body.password), user.passwordHash));
  if (!ok) {
    // codit-safe: CWE-204 identical response for unknown user and wrong password
    return res.status(401).json({ error: 'Invalid email or password' });
  }

  if (user.totpEnabled) {
    logger.info({ userId: user.id }, 'password ok, second factor required');
    // codit-safe: CWE-308 short-lived token scoped to the MFA step only (scope mfa_pending, 5 minutes)
    const mfaToken = jwt.sign({ sub: user.id, scope: 'mfa_pending' }, JWT_SECRET, jwtConfig.mfaPending);
    return res.json({ mfaRequired: true, mfaToken });
  }
  return res.json(issueSession(user));
});

router.post('/2fa/sms', otpLimiter, requireMfaPending, async (req, res) => {
  const user = await User.findById(req.mfa.sub);
  // codit-safe: CWE-338 SMS code drawn from crypto.randomInt (CSPRNG)
  const code = crypto.randomInt(0, 1000000).toString().padStart(6, '0');
  const expiresAt = new Date(Date.now() + 5 * 60 * 1000);
  await OtpChallenge.create({ userId: user.id, codeHash: await bcrypt.hash(code, 10), expiresAt });
  await sms.send(user.phone, `Your verification code is ${code}`);

  // codit-safe: CWE-532 only the user id is logged
  logger.info({ userId: user.id }, 'sms otp sent');
  res.set('Cache-Control', 'no-store');

  // codit-safe: CWE-308 the response never contains the code
  return res.status(202).json({ sent: true });
});

// codit-safe: CWE-307 rate limited and locked after 5 failed codes per user
router.post('/2fa/verify', otpLimiter, requireMfaPending, async (req, res) => {
  const user = await User.findById(req.mfa.sub);
  if (user.mfaFailedAttempts >= MAX_MFA_ATTEMPTS) {
    return res.status(429).json({ error: 'Too many attempts' });
  }
  const valid = verifyTotpStrict(user.totpSecret, String(req.body.code || ''));
  if (!valid) {
    user.mfaFailedAttempts += 1;
    await user.save();
    return res.status(401).json({ error: 'Invalid code' });
  }
  user.mfaFailedAttempts = 0;
  await user.save();
  return res.json(issueSession(user));
});

function verifyTotpStrict(secret, token) {
  if (!/^\d{6}$/.test(token)) return false;
  const opts = { secret, encoding: 'base32', token };
  try {
    // codit-safe: CWE-307 window of 1 step (+/- 30 s)
    return speakeasy.totp.verify({ ...opts, window: 1 });
  } catch (err) {
    logger.warn({ err }, 'totp verification error');
    // codit-safe: CWE-308 fail-closed on verification errors
    return false;
  }
}

module.exports = router;
