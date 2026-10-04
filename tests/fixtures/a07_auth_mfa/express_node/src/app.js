'use strict';

const express = require('express');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const config = require('./config');

const app = express();
app.set('view engine', 'ejs');
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser(config.COOKIE_SECRET));
app.use(session({
  secret: config.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, secure: true, sameSite: 'lax', maxAge: 30 * 60 * 1000 },
}));
app.use(express.static('public'));

app.use('/api/v1/auth', require('./routes/legacyAuth'));
app.use('/api/v2/auth', require('./routes/auth'));
app.use('/api', require('./routes/account'));
app.use('/api', require('./routes/passwordReset'));
app.use('/', require('./routes/web'));

app.listen(config.PORT, () => {
  console.log(`accounts listening on ${config.PORT}`);
});
