'use strict';

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');

const app = express();
const PARTNER_ORIGINS = ['https://partner-a.example', 'https://partner-b.example'];

// codit-safe: CWE-942 fixed allow-list of origins
app.use(cors({ origin: PARTNER_ORIGINS, credentials: true }));



// codit-safe: CWE-16 helmet defaults (CSP, frameguard, HSTS, noSniff)
app.use(helmet());



app.use(express.json({ limit: '100kb' }));

module.exports = app;
