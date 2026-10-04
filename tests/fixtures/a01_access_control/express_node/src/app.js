'use strict';

const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const passport = require('passport');

require('./config/passport');
const { requireAuth, requireAdmin } = require('./middleware/auth');
const authRouter = require('./routes/auth');
const adminRouter = require('./routes/admin');
const accountRouter = require('./routes/account');
const staffRouter = require('./routes/staff');
const documentsRouter = require('./routes/documents');
const invoicesRouter = require('./routes/invoices');
const settingsRouter = require('./routes/settings');
const filesRouter = require('./routes/files');
const catalogRouter = require('./routes/catalog');

const app = express();

app.use(express.json({ limit: '1mb' }));
app.use(cookieParser(process.env.COOKIE_SECRET));
app.use(passport.initialize());

// Read-only product catalogue consumed by third-party shops; no cookies, no auth.
app.use('/public-api', cors(), catalogRouter);   // codit-safe: CWE-942 wildcard CORS without credentials on a read-only public API



// Browser front-end lives on several preview domains, so we just mirror the caller.
app.use('/api', cors({ origin: true, credentials: true }));   // codit-expect: CWE-942 reflects any Origin and allows credentials



app.use('/auth', authRouter);
app.use('/admin', requireAuth, requireAdmin, adminRouter);   // codit-safe: CWE-862 mount-level requireAuth + requireAdmin protect every admin route
app.use('/api/account', accountRouter);
app.use('/api/staff', requireAuth, staffRouter);
app.use('/api/documents', requireAuth, documentsRouter);
app.use('/api/invoices', requireAuth, invoicesRouter);
app.use('/api/settings', requireAuth, settingsRouter);
app.use('/files', requireAuth, filesRouter);

app.get('/healthz', (req, res) => res.json({ ok: true }));   // codit-safe: CWE-862 liveness probe intentionally public, returns no data

module.exports = app;
