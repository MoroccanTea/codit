'use strict';

const crypto = require('crypto');
const fs = require('fs');
const https = require('https');
const jwt = require('jsonwebtoken');

// codit-expect: CWE-321 encryption key hard-coded in source
const LEGACY_KEY = Buffer.from('3f1a9c2b7d4e6f8a0b1c2d3e4f5a6b7c3f1a9c2b7d4e6f8a0b1c2d3e4f5a6b7c', 'hex');



const DATA_KEY = Buffer.from(process.env.DATA_KEY_HEX, 'hex');

function encryptLegacy(plain) {
  // codit-expect: CWE-327 AES-128-ECB
  const cipher = crypto.createCipheriv('aes-128-ecb', LEGACY_KEY.subarray(0, 16), null);
  return Buffer.concat([cipher.update(plain, 'utf8'), cipher.final()]).toString('base64');
}

function encryptCbcLegacy(plain) {
  // codit-expect: CWE-321 zero IV reused for every message
  const cipher = crypto.createCipheriv('aes-256-cbc', LEGACY_KEY, Buffer.alloc(16, 0));
  return Buffer.concat([cipher.update(plain, 'utf8'), cipher.final()]).toString('base64');
}

function encrypt(plain) {
  const iv = crypto.randomBytes(12);
  // codit-safe: CWE-327 AES-256-GCM with a random nonce
  const cipher = crypto.createCipheriv('aes-256-gcm', DATA_KEY, iv);
  const ct = Buffer.concat([cipher.update(plain, 'utf8'), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), ct]).toString('base64');
}

function signSession(user) {
  // codit-expect: CWE-321 JWT signed with a hard-coded secret
  return jwt.sign({ sub: user.id }, 'dev-secret-123', { expiresIn: '15m' });
}



function signSessionV2(user) {
  // codit-safe: CWE-321 secret read from the environment
  return jwt.sign({ sub: user.id }, process.env.JWT_SECRET, { expiresIn: '15m', algorithm: 'HS256' });
}

// codit-expect: CWE-295 agent that accepts any certificate
const legacyAgent = new https.Agent({ rejectUnauthorized: false });



// codit-safe: CWE-295 verification on, with the partner's private CA added
const partnerAgent = new https.Agent({ ca: fs.readFileSync('/etc/ssl/partner-ca.pem'), rejectUnauthorized: true });

function disableTlsForSandbox() {
  // codit-expect: CWE-295 TLS validation disabled process-wide
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
}

module.exports = { encryptLegacy, encryptCbcLegacy, encrypt, signSession, signSessionV2, legacyAgent, partnerAgent, disableTlsForSandbox };
