'use strict';

const router = require('express').Router();
const Product = require('../models/product');

// Public, read-only catalogue (mounted under /public-api).
router.get('/products', async (req, res) => {   // codit-safe: CWE-862 public read-only catalogue, no user data
  const products = await Product.find({ published: true }, 'sku name price').lean();
  res.json(products);
});

module.exports = router;
