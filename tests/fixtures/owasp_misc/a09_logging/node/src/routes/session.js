'use strict';

const express = require('express');
const pino = require('pino');
const { authenticate } = require('../services/auth');

const router = express.Router();
const logger = pino({ redact: ['req.body.password', 'req.headers.authorization', 'password'] });

router.post('/legacy/login', async (req, res) => {
  // codit-expect: CWE-532 whole request body (including the password) printed to the log
  console.log('login attempt', req.body);
  const user = await authenticate(req.body.email, req.body.password);
  res.status(user ? 200 : 401).json({ ok: Boolean(user) });
});



router.post('/login', async (req, res) => {
  // codit-safe: CWE-532 only the e-mail is logged and pino redacts password fields
  logger.info({ email: req.body.email }, 'login attempt');
  const user = await authenticate(req.body.email, req.body.password);
  res.status(user ? 200 : 401).json({ ok: Boolean(user) });
});



router.use((req, res, next) => {
  // codit-expect: CWE-117 raw User-Agent header concatenated into a text log line
  logger.info('client ' + req.ip + ' ua=' + req.headers['user-agent']);
  next();
});



router.use((req, res, next) => {
  // codit-safe: CWE-117 structured JSON field (pino escapes control characters)
  logger.info({ ip: req.ip, ua: req.get('user-agent') }, 'client');
  next();
});

module.exports = router;
