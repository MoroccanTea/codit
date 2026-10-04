'use strict';

const express = require('express');
const Joi = require('joi');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const { Product, Coupon, Order } = require('../models');
const { requireUser } = require('../middleware/auth');

const router = express.Router();
router.use(requireUser);

// v1 checkout (single-page app sends the computed basket)
router.post('/v1/checkout', async (req, res) => {
  const { items, currency } = req.body;
  // codit-expect: CWE-602 amount charged is the total computed by the browser
  const charge = await stripe.paymentIntents.create({ amount: req.body.total, currency, customer: req.user.stripeId });



  // codit-expect: CWE-840 discount percentage accepted from the client without any coupon lookup
  const discount = Number(req.body.discountPercent || 0);



  await Order.create({ userId: req.user.id, items, discount, paymentIntent: charge.id });
  res.status(201).json({ clientSecret: charge.client_secret });
});

router.post('/v1/cart/items', async (req, res) => {
  const product = await Product.findByPk(req.body.productId);
  // codit-expect: CWE-840 quantity never checked, a negative value produces a credit
  const quantity = parseInt(req.body.quantity, 10);
  await req.cart.add(product, quantity);
  res.status(204).end();
});



const itemSchema = Joi.object({
  productId: Joi.number().integer().positive().required(),
  // codit-safe: CWE-840 quantity bounded to 1..20 by the schema
  quantity: Joi.number().integer().min(1).max(20).required(),
});

router.post('/v2/cart/items', async (req, res) => {
  const { value, error } = itemSchema.validate(req.body);
  if (error) return res.status(400).json({ error: 'invalid item' });
  const product = await Product.findByPk(value.productId);
  await req.cart.add(product, value.quantity);
  res.status(204).end();
});



router.post('/v2/checkout', async (req, res) => {
  const lines = await req.cart.lines();
  const coupon = req.body.couponCode ? await Coupon.findActive(req.body.couponCode, req.user.id) : null;
  const subtotal = lines.reduce((sum, l) => sum + l.product.priceCents * l.quantity, 0);
  // codit-safe: CWE-602 total recomputed server-side from catalogue prices and a server-validated coupon
  const amount = Math.max(0, subtotal - (coupon ? Math.round(subtotal * coupon.percent / 100) : 0));
  const charge = await stripe.paymentIntents.create({ amount, currency: 'eur', customer: req.user.stripeId });
  await Order.create({ userId: req.user.id, lines, couponId: coupon && coupon.id, paymentIntent: charge.id });
  res.status(201).json({ clientSecret: charge.client_secret });
});

module.exports = router;
