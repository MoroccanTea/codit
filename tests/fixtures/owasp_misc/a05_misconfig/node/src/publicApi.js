'use strict';

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const session = require('express-session');

const app = express();

// codit-expect: CWE-942 reflects any Origin and allows credentials
app.use(cors({ origin: true, credentials: true }));



// codit-expect: CWE-16 helmet with CSP and frameguard turned off
app.use(helmet({ contentSecurityPolicy: false, frameguard: false }));



app.use(session({ secret: process.env.SESSION_SECRET, resave: false, saveUninitialized: false, cookie: { secure: true, httpOnly: true } }));
app.use(express.json());

module.exports = app;
