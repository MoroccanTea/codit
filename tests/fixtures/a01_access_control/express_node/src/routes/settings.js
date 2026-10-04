'use strict';

const router = require('express').Router();
const User = require('../models/user');
const flags = require('../services/flags');
const auditLog = require('../services/audit');
const billing = require('../services/billing');

const PROFILE_FIELDS = ['displayName', 'bio', 'avatarUrl', 'locale'];

router.post('/feature-flags', async (req, res) => {
  if (req.body.role === 'admin') {   // codit-expect: CWE-807 authorization decided by a role sent in the request body
    await flags.update(req.body.flags);
    return res.json({ ok: true });
  }
  return res.sendStatus(403);
});

router.get('/audit-log', async (req, res) => {
  if (req.cookies.isAdmin === 'true') {   // codit-expect: CWE-807 unsigned cookie decides admin access
    return res.json(await auditLog.recent());
  }
  return res.sendStatus(403);
});

router.get('/billing', async (req, res) => {
  if (req.user.role === 'admin') {   // codit-safe: CWE-807 role from the verified JWT principal set by passport
    return res.json(await billing.summary());
  }
  return res.sendStatus(403);
});

router.patch('/profile', async (req, res) => {
  const user = await User.findByIdAndUpdate(req.user.id, req.body, { new: true });   // codit-expect: CWE-915 whole request body (role, isAdmin, twoFactorEnabled) bound to the user document
  res.json(user);
});

router.patch('/preferences', async (req, res) => {
  const updates = Object.fromEntries(PROFILE_FIELDS.filter((k) => k in req.body).map((k) => [k, String(req.body[k])]));
  const user = await User.findByIdAndUpdate(req.user.id, updates, { new: true });   // codit-safe: CWE-915 only allow-listed profile fields are written
  res.json(user);
});

module.exports = router;
