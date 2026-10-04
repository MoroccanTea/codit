'use strict';

// v1 auth API (mobile app 2.x). Do not add new features here.
const express = require('express');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const speakeasy = require('speakeasy');
const User = require('../models/User');
const sms = require('../services/sms');
const jwtConfig = require('../config/jwt');
const { JWT_SECRET } = require('../config');
const { requireAuth } = require('../middleware/auth');

const router = express.Router();

function issueToken(user) {
  return jwt.sign({ sub: user.id, role: user.role, scope: 'access' }, JWT_SECRET, jwtConfig.legacyMobile);
}

router.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email: String(email) });
  if (!user) {
    // codit-expect: CWE-204 "User not found" vs "Wrong password" reveals which e-mails are registered
    return res.status(404).json({ error: 'User not found' });
  }

  user.lastLoginAttemptAt = new Date();
  await user.save();

  // codit-expect: CWE-916 single unsalted SHA-256 used as the password hash
  const hash = crypto.createHash('sha256').update(String(password)).digest('hex');
  if (hash !== user.passwordHash) {
    return res.status(401).json({ error: 'Wrong password' });
  }

  if (user.totpEnabled) {
    await user.save();
    // codit-expect: CWE-308 full JWT issued before the TOTP step, response only flags mfaRequired
    const token = issueToken(user);
    return res.json({ mfaRequired: true, token });
  }
  return res.json({ token: issueToken(user) });
});

router.post('/otp/send', requireAuth, async (req, res) => {
  const user = await User.findById(req.user.sub);
  // codit-expect: CWE-338 SMS one-time code generated with Math.random()
  const otp = String(Math.floor(100000 + Math.random() * 900000));
  user.otpCode = otp;
  user.otpCreatedAt = new Date();
  await user.save();
  await sms.send(user.phone, `Your verification code is ${otp}`);

  // codit-expect: CWE-532 one-time code printed to the server log
  console.log(`OTP for ${user.email}: ${otp}`);
  res.set('Cache-Control', 'no-store');

  // the app autofills the field from this value
  // codit-expect: CWE-308 OTP echoed back to the client in the API response
  return res.json({ sent: true, otp });
});

// codit-expect: CWE-307 OTP verification route has no rate limiter and no attempt counter
router.post('/otp/verify', async (req, res) => {
  const { userId, code, mfaVerified } = req.body;
  const user = await User.findById(String(userId));
  if (!user) return res.status(400).json({ error: 'invalid request' });

  // codit-expect: CWE-807 MFA treated as completed when the request body says mfaVerified
  if (mfaVerified === true || mfaVerified === 'true') {
    return res.json({ token: issueToken(user) });
  }

  // QA backdoor - remove before GA
  // codit-expect: CWE-308 static master OTP accepted for every account
  if (code === '000000') {
    return res.json({ token: issueToken(user) });
  }

  // codit-expect: CWE-697 loose == comparison of the stored one-time code
  if (code == user.otpCode) {
    user.otpCode = null;
    await user.save();
    return res.json({ token: issueToken(user) });
  }

  if (verifyTotp(user.totpSecret, code)) {
    return res.json({ token: issueToken(user) });
  }
  return res.status(401).json({ error: 'invalid code' });
});

function verifyTotp(secret, token) {
  // codit-expect: CWE-308 empty or missing code short-circuits to success
  if (!token) return true;
  const normalized = String(token).replace(/\s+/g, '');
  const opts = { secret, encoding: 'base32', token: normalized };

  try {
    // codit-expect: CWE-307 speakeasy window of 20 steps accepts codes +/- 10 minutes
    return speakeasy.totp.verify({ ...opts, window: 20 });
  } catch (err) {
    console.error('totp verification failed', err.message);
    // codit-expect: CWE-308 verification fails open on any exception
    return true;
  }
}

module.exports = router;
