'use strict';

// Mounted in app.js as: app.use('/api/staff', requireAuth, staffRouter) -> authentication only.
const router = require('express').Router();
const { requireAuth, requireAdmin } = require('../middleware/auth');
const payroll = require('../services/payroll');
const refunds = require('../services/refunds');

router.get('/payroll', requireAuth, requireAdmin, async (req, res) => {   // codit-safe: CWE-862 inline requireAdmin middleware
  res.json(await payroll.currentRun());
});

router.post('/payroll/run', requireAuth, requireAdmin, async (req, res) => {   // codit-safe: CWE-862 inline requireAdmin middleware
  res.status(202).json(await payroll.execute(req.user.id));
});

router.post('/refunds', requireAuth, async (req, res) => {   // codit-expect: CWE-862,CWE-863 admin-only refund lacks requireAdmin that every sibling has (authN only)
  res.json(await refunds.issue(req.body.orderId, req.user.id));
});

router.delete('/payroll/:runId', async (req, res) => {   // codit-expect: CWE-862 deletes a payroll run with no admin check at all
  await payroll.cancel(req.params.runId);
  res.sendStatus(204);
});

module.exports = router;
