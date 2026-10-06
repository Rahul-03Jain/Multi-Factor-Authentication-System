const express = require('express');
const jwt = require('jsonwebtoken');

const {
  findById: findUserById,
  updateUser
} = require('../models/User');

const {
  findById: findAdminById,
  updateAdmin
} = require('../models/Admin');

const { logAudit } = require('../models/Audit');
const { sha256 } = require('../utils/crypto');
const { sendEmailOtp } = require('../utils/mailer');

const router = express.Router();

function clientIp(req) {
  return req.ip || req.socket?.remoteAddress || null;
}

function setCookie(res, name, token, maxAge) {
  res.cookie(name, token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge
  });
}

function getVerificationIdentity(req) {
  const token = req.cookies?.email_verify_token;

  if (!token) {
    throw new Error('Email verification session not found.');
  }

  const payload = jwt.verify(
    token,
    process.env.SETUP_JWT_SECRET
  );

  if (
    payload.type !== 'email_verify' ||
    !payload.sub ||
    !['user', 'admin'].includes(payload.role)
  ) {
    throw new Error('Invalid email verification session.');
  }

  return {
    id: payload.sub,
    role: payload.role
  };
}

function signSetupToken(id, role) {
  return jwt.sign(
    {
      sub: String(id),
      role,
      type: 'setup_pending'
    },
    process.env.SETUP_JWT_SECRET,
    {
      expiresIn: '15m'
    }
  );
}

/* =========================================================
   VERIFY EMAIL OTP
========================================================= */

router.post('/verify', async (req, res) => {
  try {
    const { id, role } =
      getVerificationIdentity(req);

    const code = String(
      req.body.code || ''
    ).replace(/\s/g, '');

    if (!/^\d{6}$/.test(code)) {
      return res.status(400).json({
        error: 'Enter the 6-digit verification code.'
      });
    }

    let account;

    if (role === 'admin') {
      account = await findAdminById(id);
    } else {
      account = await findUserById(id);
    }

    if (!account) {
      return res.status(404).json({
        error: 'Account not found.'
      });
    }

    if (!account.is_active) {
      return res.status(403).json({
        error: 'This account is disabled.'
      });
    }

    if (account.is_email_verified) {
      return res.status(400).json({
        error: 'This email is already verified.'
      });
    }

    if (
      !account.email_otp_hash ||
      !account.email_otp_expires_at
    ) {
      return res.status(400).json({
        error:
          'No active verification code exists. Please request a new code.'
      });
    }

    if (
      new Date(account.email_otp_expires_at).getTime() <
      Date.now()
    ) {
      return res.status(400).json({
        error:
          'This verification code has expired. Please request a new one.'
      });
    }

    const submittedHash = sha256(code);

    if (
      submittedHash !== account.email_otp_hash
    ) {
      await logAudit({
        actorType: role,
        actorId: id,
        action:
          role === 'admin'
            ? 'ADMIN_EMAIL_OTP_FAILED'
            : 'EMAIL_OTP_FAILED',
        ipAddress: clientIp(req),
        userAgent: req.get('user-agent') || null
      });

      return res.status(401).json({
        error: 'Invalid verification code.'
      });
    }

    if (role === 'admin') {
      await updateAdmin(id, {
        emailVerified: true
      });
    } else {
      await updateUser(id, {
        emailVerified: true
      });
    }

    const setupToken = signSetupToken(
      id,
      role
    );

    setCookie(
      res,
      'setup_token',
      setupToken,
      15 * 60 * 1000
    );

    res.clearCookie('email_verify_token');

    await logAudit({
      actorType: role,
      actorId: id,
      action:
        role === 'admin'
          ? 'ADMIN_EMAIL_VERIFIED'
          : 'EMAIL_VERIFIED',
      ipAddress: clientIp(req),
      userAgent: req.get('user-agent') || null
    });

    res.json({
      message:
        'Email verified successfully. Continue with Google Authenticator setup.',
      redirect:
        role === 'admin'
          ? '/setup-2fa.html?type=admin'
          : '/setup-2fa.html?type=user'
    });

  } catch (err) {
    console.error(
      'Email OTP verification error:',
      err
    );

    res.status(401).json({
      error:
        'Invalid or expired email verification session. Please log in again.'
    });
  }
});

/* =========================================================
   RESEND EMAIL OTP
========================================================= */

router.post('/resend', async (req, res) => {
  try {
    const { id, role } =
      getVerificationIdentity(req);

    let account;

    if (role === 'admin') {
      account = await findAdminById(id);
    } else {
      account = await findUserById(id);
    }

    if (!account) {
      return res.status(404).json({
        error: 'Account not found.'
      });
    }

    if (!account.is_active) {
      return res.status(403).json({
        error: 'This account is disabled.'
      });
    }

    if (account.is_email_verified) {
      return res.status(400).json({
        error: 'This email is already verified.'
      });
    }

    const otp = String(
      Math.floor(100000 + Math.random() * 900000)
    );

    const otpHash = sha256(otp);

    const expiresAt = new Date(
      Date.now() + 10 * 60 * 1000
    );

    if (role === 'admin') {
      await updateAdmin(id, {
        emailOtpHash: otpHash,
        emailOtpExpiresAt: expiresAt
      });
    } else {
      await updateUser(id, {
        emailOtpHash: otpHash,
        emailOtpExpiresAt: expiresAt
      });
    }

    await sendEmailOtp(
      account.email,
      account.full_name,
      otp,
      role
    );

    const verificationToken =
      jwt.sign(
        {
          sub: String(id),
          role,
          type: 'email_verify'
        },
        process.env.SETUP_JWT_SECRET,
        {
          expiresIn: '10m'
        }
      );

    setCookie(
      res,
      'email_verify_token',
      verificationToken,
      10 * 60 * 1000
    );

    res.json({
      message:
        'A new verification code has been sent to your email.'
    });

  } catch (err) {
    console.error(
      'Resend email OTP error:',
      err
    );

    res.status(401).json({
      error:
        'Unable to resend the verification code.'
    });
  }
});

module.exports = router;