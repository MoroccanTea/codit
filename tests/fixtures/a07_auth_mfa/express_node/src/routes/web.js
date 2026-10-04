'use strict';

// Server-rendered login for the customer portal and the back office.
const express = require('express');
const { authenticate, authenticateAdmin } = require('../services/passwords');

const router = express.Router();

router.post('/login', async (req, res) => {
  const user = await authenticate(req.body.email, req.body.password);
  if (!user) return res.status(401).render('login', { error: 'Invalid credentials' });
  // codit-expect: CWE-308,CWE-384 session marked as logged in (and not regenerated) before the OTP page
  req.session.userId = user.id;
  if (user.totpEnabled) return res.redirect('/login/otp');
  return res.redirect('/dashboard');
});

router.post('/v2/login', async (req, res, next) => {
  const user = await authenticate(req.body.email, req.body.password);
  if (!user) return res.status(401).render('login', { error: 'Invalid credentials' });
  req.session.regenerate((err) => {
    if (err) return next(err);
    if (user.totpEnabled) {
      // codit-safe: CWE-308 only a pending marker is stored until the OTP is verified
      req.session.pendingUserId = user.id;
      return res.redirect('/v2/login/otp');
    }

    // codit-safe: CWE-384 session id regenerated before the authenticated identity is stored
    req.session.userId = user.id;
    return res.redirect('/dashboard');
  });
});

router.post('/admin/login', async (req, res) => {
  const admin = await authenticateAdmin(req.body.username, req.body.password);
  if (!admin) return res.status(401).render('admin/login', { error: 'Invalid credentials' });
  // codit-expect: CWE-384 admin identity stored in the pre-login session id (no req.session.regenerate)
  req.session.adminId = admin.id;
  return res.redirect('/admin');
});

module.exports = router;
