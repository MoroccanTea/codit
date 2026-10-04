'use strict';

const Joi = require('joi');

const registerSchemaV1 = Joi.object({
  email: Joi.string().email().required(),
  displayName: Joi.string().max(80).required(),
  // codit-expect: CWE-521 6-character minimum password length
  password: Joi.string().min(6).required(),
});

const registerSchemaV2 = Joi.object({
  email: Joi.string().email().required(),
  displayName: Joi.string().max(80).required(),
  // codit-safe: CWE-521 12 to 128 characters (breached-password check done in the handler)
  password: Joi.string().min(12).max(128).required(),
});

module.exports = { registerSchemaV1, registerSchemaV2 };
