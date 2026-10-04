'use strict';

const express = require('express');
const { execFile, exec } = require('child_process');
const { Pool } = require('pg');
const Order = require('../models/order');
const { requireUser } = require('../middleware/auth');

const router = express.Router();
const pool = new Pool();

router.use(requireUser);

router.get('/orders/by-owner', async (req, res) => {
  // codit-expect: CWE-943 $where clause built from a query parameter (server-side JS injection)
  const orders = await Order.find({ $where: "this.owner == '" + req.query.owner + "'" });
  res.json(orders);
});



router.get('/orders/by-owner-safe', async (req, res) => {
  // codit-safe: CWE-943 plain equality filter, value coerced to a string
  const orders = await Order.find({ owner: String(req.query.owner), tenantId: req.user.tenantId });
  res.json(orders);
});



router.get('/invoices/:id', async (req, res) => {
  // codit-expect: CWE-89 route parameter concatenated into SQL
  const { rows } = await pool.query('SELECT * FROM invoices WHERE id = ' + req.params.id);
  res.json(rows[0] || null);
});



router.get('/invoices-safe/:id', async (req, res) => {
  // codit-safe: CWE-89 parameterised query
  const { rows } = await pool.query('SELECT * FROM invoices WHERE id = $1 AND tenant_id = $2', [req.params.id, req.user.tenantId]);
  res.json(rows[0] || null);
});



router.post('/thumbnails', (req, res) => {
  // codit-expect: CWE-78 file name from the body interpolated into a shell command
  exec(`convert uploads/${req.body.file} -resize 200x200 thumbs/${req.body.file}`, (err) => {
    res.status(err ? 500 : 204).end();
  });
});



router.post('/thumbnails-safe', (req, res) => {
  const name = String(req.body.file).replace(/[^a-zA-Z0-9._-]/g, '');
  // codit-safe: CWE-78 execFile with an argument array, no shell
  execFile('convert', [`uploads/${name}`, '-resize', '200x200', `thumbs/${name}`], (err) => {
    res.status(err ? 500 : 204).end();
  });
});

module.exports = router;
