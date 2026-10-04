'use strict';

const router = require('express').Router();
const passport = require('passport');
const tokens = require('../services/tokens');

router.post('/login', passport.authenticate('local', { session: false }), (req, res) => {   // codit-safe: CWE-862 login is public by design (credentials checked by passport-local)
  res.json({ token: tokens.issue(req.user) });
});

router.get('/sso/callback', (req, res) => {
  res.redirect(req.query.returnTo);   // codit-expect: CWE-601 redirect target taken from the query string
});

router.get('/logout', (req, res) => {
  const next = typeof req.query.next === 'string' ? req.query.next : '/';
  const target = next.startsWith('/') && !next.startsWith('//') && !next.startsWith('/\\') ? next : '/';
  res.redirect(target);   // codit-safe: CWE-601 only same-origin relative paths are honoured
});

module.exports = router;
