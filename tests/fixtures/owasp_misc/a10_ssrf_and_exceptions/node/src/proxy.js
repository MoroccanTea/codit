'use strict';

const express = require('express');
const axios = require('axios');
const jwt = require('jsonwebtoken');

const router = express.Router();
const ALLOWED_HOSTS = new Set(['images.acme-cdn.example', 'avatars.githubusercontent.com']);

function requireUserLegacy(req, res, next) {
  try {
    req.user = jwt.verify(req.headers.authorization.replace('Bearer ', ''), process.env.JWT_SECRET);
    next();
  } catch (err) {
    // codit-expect: CWE-755 token verification error falls through to next() (fail-open authentication)
    next();
  }
}



function requireUser(req, res, next) {
  try {
    req.user = jwt.verify((req.headers.authorization || '').replace('Bearer ', ''), process.env.JWT_SECRET);
    return next();
  } catch (err) {
    // codit-safe: CWE-755 invalid token rejected with 401
    return res.status(401).json({ error: 'unauthorized' });
  }
}

router.get('/legacy/image-proxy', requireUserLegacy, async (req, res) => {
  // codit-expect: CWE-918 axios fetches any URL taken from the query string
  const upstream = await axios.get(req.query.url, { responseType: 'arraybuffer' });
  res.type(upstream.headers['content-type']).send(upstream.data);
});



router.get('/image-proxy', requireUser, async (req, res) => {
  let target;
  try {
    target = new URL(String(req.query.url));
  } catch (e) {
    return res.status(400).end();
  }
  if (target.protocol !== 'https:' || !ALLOWED_HOSTS.has(target.hostname)) return res.status(400).end();
  // codit-safe: CWE-918 protocol and hostname validated against an allow-list, redirects off
  const upstream = await axios.get(target.toString(), { responseType: 'arraybuffer', maxRedirects: 0 });
  res.type(upstream.headers['content-type']).send(upstream.data);
});



router.post('/webhooks/test', requireUser, async (req, res) => {
  // codit-expect: CWE-918 fetch() to a webhook URL from the request body
  const r = await fetch(req.body.webhookUrl, { method: 'POST', body: JSON.stringify({ ping: true }) });
  res.json({ status: r.status });
});



// eslint-disable-next-line no-unused-vars
router.use((err, req, res, next) => {
  // codit-expect: CWE-209 error message and stack trace sent to the client
  res.status(500).json({ error: err.message, stack: err.stack });
});

module.exports = { router, requireUser };
