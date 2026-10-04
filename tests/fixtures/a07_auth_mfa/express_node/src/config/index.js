'use strict';

module.exports = {
  PORT: Number(process.env.PORT || 3000),
  APP_URL: process.env.APP_URL || 'https://accounts.acme.example',
  JWT_SECRET: process.env.JWT_SECRET,
  SESSION_SECRET: process.env.SESSION_SECRET,
  COOKIE_SECRET: process.env.COOKIE_SECRET,
};
