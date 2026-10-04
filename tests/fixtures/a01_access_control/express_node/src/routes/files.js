'use strict';

const path = require('path');
const router = require('express').Router();

const UPLOAD_DIR = path.resolve(__dirname, '..', '..', 'uploads');

router.get('/raw', (req, res) => {
  res.sendFile(path.join(UPLOAD_DIR, String(req.query.name)));   // codit-expect: CWE-22 user-controlled name joined into the path, ../ escapes UPLOAD_DIR
});

router.get('/download', (req, res) => {
  res.sendFile(String(req.query.name), { root: UPLOAD_DIR });   // codit-safe: CWE-22 send's root option rejects paths escaping UPLOAD_DIR
});

router.get('/preview', (req, res) => {
  const target = path.resolve(UPLOAD_DIR, String(req.query.name));   // codit-safe: CWE-22 resolved path confined with startsWith(UPLOAD_DIR + sep)
  if (!target.startsWith(UPLOAD_DIR + path.sep)) return res.sendStatus(400);
  return res.sendFile(target);
});

module.exports = router;
