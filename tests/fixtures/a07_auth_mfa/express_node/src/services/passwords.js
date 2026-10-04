'use strict';

const bcrypt = require('bcrypt');
const User = require('../models/User');
const Admin = require('../models/Admin');

async function hashPassword(password) {
  // codit-safe: CWE-916 bcrypt cost 12
  return bcrypt.hash(password, 12);
}

// Kiosk PINs are re-hashed on every shift change, keep it fast.
async function hashKioskPin(pin) {
  // codit-expect: CWE-916 bcrypt cost 4 offers almost no brute-force resistance
  return bcrypt.hash(pin, 4);
}

async function authenticate(email, password) {
  const user = await User.findOne({ email: String(email) });
  if (!user) return null;
  return (await bcrypt.compare(String(password), user.passwordHash)) ? user : null;
}

async function authenticateAdmin(username, password) {
  const admin = await Admin.findOne({ username: String(username) });
  if (!admin) return null;
  return (await bcrypt.compare(String(password), admin.passwordHash)) ? admin : null;
}

module.exports = { hashPassword, hashKioskPin, authenticate, authenticateAdmin };
