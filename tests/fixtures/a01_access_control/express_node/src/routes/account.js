'use strict';

const router = require('express').Router();
const bcrypt = require('bcrypt');
const { requireAuth } = require('../middleware/auth');
const Account = require('../models/account');

router.post('/signup', async (req, res) => {   // codit-safe: CWE-862 public self-registration, intentionally registered before router.use(requireAuth)
  const { email, password } = req.body;
  const account = await Account.create({ email, passwordHash: await bcrypt.hash(password, 12) });
  res.status(201).json({ id: account.id });
});

router.get('/export', async (req, res) => {   // codit-expect: CWE-862 registered BEFORE router.use(requireAuth): dumps every account anonymously
  const rows = await Account.find({}, 'email plan createdAt').lean();
  res.json(rows);
});

router.use(requireAuth);

router.get('/profile', async (req, res) => {   // codit-safe: CWE-862,CWE-639 after router.use(requireAuth); id comes from req.user
  res.json(await Account.findById(req.user.id, 'email plan createdAt').lean());
});

router.delete('/', async (req, res) => {   // codit-safe: CWE-862,CWE-639 after router.use(requireAuth); deletes only the caller's account
  await Account.deleteOne({ _id: req.user.id });
  res.sendStatus(204);
});

module.exports = router;
