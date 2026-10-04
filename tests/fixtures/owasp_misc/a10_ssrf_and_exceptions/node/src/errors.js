'use strict';

const logger = require('./logger');

// eslint-disable-next-line no-unused-vars
function errorHandler(err, req, res, next) {
  logger.error({ err, path: req.path }, 'unhandled error');
  // codit-safe: CWE-209 generic body; stack stays in the server log
  res.status(500).json({ error: 'internal error', requestId: req.id });
}

module.exports = errorHandler;
