const jwt = require('jsonwebtoken');
const { findById } = require('../models/User');
const { findById: findAdminById } = require('../models/Admin');

function requireUserAuth(req, res, next) {
  const token = req.cookies?.token;
  if (!token) return res.status(401).json({ error: 'Authentication required.' });

  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    if (payload.type !== 'auth') throw new Error('Invalid session.');
    req.user = payload;
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid or expired session.' });
  }
}

async function requireActiveUser(req, res, next) {
  try {
    const user = await findById(req.user.sub);
    if (!user || !user.is_active) {
      res.clearCookie('token');
      return res.status(403).json({ error: 'Your account is disabled or no longer exists.' });
    }
    req.currentUser = user;
    next();
  } catch (err) {
    console.error('User auth middleware:', err);
    res.status(500).json({ error: 'Could not verify your account.' });
  }
}

function requireAdminAuth(req, res, next) {
  const token = req.cookies?.admin_token;
  if (!token) return res.status(401).json({ error: 'Administrator authentication required.' });

  try {
    const payload = jwt.verify(token, process.env.ADMIN_JWT_SECRET);
    if (payload.type !== 'admin') throw new Error('Invalid admin session.');
    req.admin = payload;
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid or expired admin session.' });
  }
}

async function requireActiveAdmin(req, res, next) {
  try {
    const admin = await findAdminById(req.admin.sub);
    if (!admin || !admin.is_active) {
      res.clearCookie('admin_token');
      return res.status(403).json({ error: 'Administrator account is disabled.' });
    }
    req.currentAdmin = admin;
    next();
  } catch (err) {
    console.error('Admin auth middleware:', err);
    res.status(500).json({ error: 'Could not verify administrator account.' });
  }
}

module.exports = {
  requireUserAuth,
  requireActiveUser,
  requireAdminAuth,
  requireActiveAdmin
};
