'use strict';

module.exports = {
  access: {
    algorithm: 'HS256',
    // codit-safe: CWE-613 access tokens live 15 minutes
    expiresIn: '15m',
  },

  mfaPending: {
    algorithm: 'HS256',
    expiresIn: '5m',
  },

  // tokens of the 2.x mobile app, which cannot refresh
  legacyMobile: {
    algorithm: 'HS256',
    // codit-expect: CWE-613 legacy mobile JWT valid for 365 days without refresh or revocation
    expiresIn: '365d',
  },
};
