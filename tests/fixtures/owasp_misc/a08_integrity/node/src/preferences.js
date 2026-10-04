'use strict';

const express = require('express');
const cookieParser = require('cookie-parser');
const serialize = require('node-serialize');

const router = express.Router();
router.use(cookieParser(process.env.COOKIE_SECRET));

router.get('/legacy/preferences', (req, res) => {
  const raw = Buffer.from(req.cookies.prefs || '', 'base64').toString();
  // codit-expect: CWE-502 node-serialize unserialize of a cookie (IIFE gadget executes code)
  const prefs = serialize.unserialize(raw);
  res.json(prefs);
});



router.get('/preferences', (req, res) => {
  // codit-safe: CWE-502 signed cookie parsed as plain JSON
  const prefs = JSON.parse(req.signedCookies.prefs || '{}');
  res.json({ theme: String(prefs.theme || 'light'), lang: String(prefs.lang || 'en') });
});

module.exports = router;
