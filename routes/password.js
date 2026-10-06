const express = require('express');
const bcrypt = require('bcrypt');
const { findByEmail: findUserByEmail, findById: findUserById, updateUser } = require('../models/User');
const { findByEmail: findAdminByEmail, findById: findAdminById } = require('../models/Admin');
const { createReset, consumeReset, invalidateOlderResets } = require('../models/PasswordReset');
const { logAudit } = require('../models/Audit');
const { randomToken, sha256 } = require('../utils/crypto');
const { sendPasswordResetEmail } = require('../utils/mailer');

const router = express.Router();

function clientIp(req) {
  return req.ip || req.socket?.remoteAddress || null;
}

function validEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(email || '').trim());
}

function validPassword(password) {
  return typeof password === 'string' && password.length >= 8 && password.length <= 128;
}

router.post('/forgot', async (req, res) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase();
    const accountType = req.body.accountType === 'admin' ? 'admin' : 'user';

    if (!validEmail(email)) return res.status(400).json({ error: 'Enter a valid email address.' });

    const account = accountType === 'admin'
      ? await findAdminByEmail(email)
      : await findUserByEmail(email);

    // Always return the same public message to avoid account enumeration.
    const response = {
      message: 'If an account with that email exists, a password reset link has been sent.'
    };

    if (!account || !account.is_active) return res.json(response);

    await invalidateOlderResets(
      accountType === 'admin' ? { adminId: account.id } : { userId: account.id }
    );

    const rawToken = randomToken();
    const tokenHash = sha256(rawToken);
    const expiresAt = new Date(Date.now() + 30 * 60 * 1000);

    await createReset({
      userId: accountType === 'user' ? account.id : null,
      adminId: accountType === 'admin' ? account.id : null,
      tokenHash,
      expiresAt
    });

    const base = (process.env.APP_BASE_URL || `http://localhost:${process.env.PORT || 3000}`).replace(/\/$/, '');
    const resetUrl = `${base}/reset-password.html?type=${accountType}&token=${encodeURIComponent(rawToken)}`;

    const mail = await sendPasswordResetEmail(
      account.email,
      account.full_name,
      resetUrl,
      accountType
    );

    await logAudit({
      actorType: accountType,
      actorId: account.id,
      targetUserId: accountType === 'user' ? account.id : null,
      action: 'PASSWORD_RESET_REQUEST',
      ipAddress: clientIp(req),
      userAgent: req.get('user-agent') || null
    });

    if (mail.dev) response.devResetUrl = resetUrl;

    return res.json(response);
  } catch (err) {
    console.error('Forgot password error:', err);
    res.status(500).json({ error: 'Could not create a password reset request.' });
  }
});

router.post('/reset', async (req, res) => {
  try {
    const { token, accountType, password } = req.body;
    const type = accountType === 'admin' ? 'admin' : 'user';

    if (!token) return res.status(400).json({ error: 'Reset token is required.' });
    if (!validPassword(password)) return res.status(400).json({ error: 'Password must be 8–128 characters.' });

    const reset = await consumeReset(sha256(token), type);
    if (!reset) return res.status(400).json({ error: 'This reset link is invalid, expired, or already used.' });

    const hash = await bcrypt.hash(password, 12);

    if (type === 'user') {
      const user = await findUserById(reset.user_id);
      if (!user) return res.status(400).json({ error: 'Account no longer exists.' });
      await updateUser(user.id, { passwordHash: hash });
      await logAudit({
        actorType: 'user',
        actorId: user.id,
        targetUserId: user.id,
        action: 'PASSWORD_RESET_SUCCESS',
        ipAddress: clientIp(req),
        userAgent: req.get('user-agent') || null
      });
    } else {
      const admin = await findAdminById(reset.admin_id);
      if (!admin) return res.status(400).json({ error: 'Administrator account no longer exists.' });
      await requireAdminPasswordUpdate(reset.admin_id, hash);
      await logAudit({
        actorType: 'admin',
        actorId: admin.id,
        action: 'PASSWORD_RESET_SUCCESS',
        ipAddress: clientIp(req),
        userAgent: req.get('user-agent') || null
      });
    }

    res.json({
      message: 'Password reset successfully. You can now sign in.',
      redirect: type === 'admin' ? '/admin-login.html' : '/login.html'
    });
  } catch (err) {
    console.error('Password reset error:', err);
    res.status(500).json({ error: 'Could not reset the password.' });
  }
});

async function requireAdminPasswordUpdate(id, passwordHash) {
  const { query } = require('../models/db');

  await query(
    `UPDATE users
     SET password = $1,
         updated_at = NOW()
     WHERE id = $2
       AND role = 'admin'`,
    [passwordHash, id]
  );
}

module.exports = router;