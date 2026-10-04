'use strict';

// Mounted in app.js as: app.use('/admin', requireAuth, requireAdmin, adminRouter)
const router = require('express').Router();
const User = require('../models/user');
const audit = require('../services/audit');

router.get('/users', async (req, res) => {   // codit-safe: CWE-862 router mounted behind requireAuth + requireAdmin in app.js
  const users = await User.find({}, 'email roles createdAt').lean();
  res.json(users);
});

router.delete('/users/:id', async (req, res) => {   // codit-safe: CWE-862,CWE-639 admin-only via mount guard; admins may manage any account
  await User.findByIdAndDelete(req.params.id);
  await audit.log(req.user.id, 'user.delete', req.params.id);
  res.sendStatus(204);
});

module.exports = router;
