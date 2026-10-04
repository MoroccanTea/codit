'use strict';

const router = require('express').Router();
const { Invoice } = require('../models/sql');

router.get('/:id', async (req, res) => {
  const invoice = await Invoice.findByPk(req.params.id);   // codit-expect: CWE-639 Sequelize findByPk on a client id without userId scoping
  if (!invoice) return res.sendStatus(404);
  return res.json(invoice);
});

router.get('/:id/pdf', async (req, res) => {
  const invoice = await Invoice.findOne({ where: { id: req.params.id, userId: req.user.id } });   // codit-safe: CWE-639 where clause bound to req.user.id
  if (!invoice) return res.sendStatus(404);
  return res.type('application/pdf').send(invoice.pdf);
});

module.exports = router;
