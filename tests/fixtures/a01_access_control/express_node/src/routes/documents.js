'use strict';

const router = require('express').Router();
const Document = require('../models/document');

router.get('/:id', async (req, res) => {
  const doc = await Document.findById(req.params.id);   // codit-expect: CWE-639 any document by id, no ownership check against req.user
  if (!doc) return res.sendStatus(404);
  return res.json(doc);
});

router.get('/mine/:id', async (req, res) => {
  const doc = await Document.findOne({ _id: req.params.id, owner: req.user.id });   // codit-safe: CWE-639 query scoped to the authenticated owner
  if (!doc) return res.sendStatus(404);
  return res.json(doc);
});

router.put('/:id', async (req, res) => {
  const doc = await Document.findById(req.params.id);   // codit-safe: CWE-639 explicit owner comparison before the update
  if (!doc) return res.sendStatus(404);
  if (!doc.owner.equals(req.user._id)) return res.sendStatus(403);
  doc.title = String(req.body.title);
  await doc.save();
  return res.json(doc);
});

router.delete('/:id', async (req, res) => {
  await Document.findByIdAndDelete(req.params.id);   // codit-expect: CWE-639 deletes any user's document by id
  res.sendStatus(204);
});

module.exports = router;
