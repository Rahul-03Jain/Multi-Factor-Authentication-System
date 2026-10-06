const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { authenticator } = require('otplib');
const QRCode = require('qrcode');

const {
  findByEmail,
  findById,
  createUser,
  updateUser
} = require('../models/User');

const {
  findByEmail: findAdminByEmail,
  findById: findAdminById,
  updateAdmin,
  updateLastLogin
} = require('../models/Admin');

const { logAudit } = require('../models/Audit');
const {
  encrypt,
  decrypt,
  sha256
} = require('../utils/crypto');

const {
  sendEmailOtp
} = require('../utils/mailer');

const router = express.Router();

authenticator.options = {
  window: 1
};

function clientIp(req) {
  return req.ip || req.socket?.remoteAddress || null;
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(
    String(email || '').trim()
  );
}

function setCookie(
  res,
  name,
  token,
  maxAge
) {
  res.cookie(name, token, {
    httpOnly: true,
    secure:
      process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge
  });
}

function signAuthToken(user) {
  return jwt.sign(
    {
      sub: String(user.id),
      email: user.email,
      fullName: user.full_name,
      role: 'user',
      type: 'auth'
    },
    process.env.JWT_SECRET,
    {
      expiresIn: '24h'
    }
  );
}

function signAdminToken(admin) {
  return jwt.sign(
    {
      sub: String(admin.id),
      email: admin.email,
      fullName: admin.full_name,
      role: 'admin',
      type: 'admin'
    },
    process.env.ADMIN_JWT_SECRET,
    {
      expiresIn: '24h'
    }
  );
}

function signSetupToken(
  id,
  role
) {
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

function signEmailVerifyToken(
  id,
  role
) {
  return jwt.sign(
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
}

function signMfaPendingToken(id) {
  return jwt.sign(
    {
      sub: String(id),
      type: 'mfa_pending'
    },
    process.env.SETUP_JWT_SECRET,
    {
      expiresIn: '10m'
    }
  );
}

function getSetupIdentity(req) {
  const token =
    req.cookies?.setup_token;

  if (!token) {
    throw new Error(
      'Setup session not found.'
    );
  }

  const payload = jwt.verify(
    token,
    process.env.SETUP_JWT_SECRET
  );

  if (
    payload.type !== 'setup_pending' ||
    !payload.sub ||
    !['user', 'admin'].includes(
      payload.role
    )
  ) {
    throw new Error(
      'Invalid setup session.'
    );
  }

  return {
    id: payload.sub,
    role: payload.role
  };
}

async function finishUserLogin(
  req,
  res,
  user
) {
  const token =
    signAuthToken(user);

  setCookie(
    res,
    'token',
    token,
    Number(
      process.env.COOKIE_MAX_AGE_MS
    ) || 86400000
  );

  res.clearCookie('mfa_token');
  res.clearCookie('setup_token');
  res.clearCookie(
    'email_verify_token'
  );

  await updateUser(user.id, {
    lastLoginAt: new Date()
  });

  await logAudit({
    actorType: 'user',
    actorId: user.id,
    action: 'LOGIN_SUCCESS',
    ipAddress: clientIp(req),
    userAgent:
      req.get('user-agent') || null
  });

  return res.json({
    message: 'Login successful.',
    redirect: '/dashboard.html'
  });
}

async function finishAdminLogin(
  req,
  res,
  admin
) {
  const token =
    signAdminToken(admin);

  setCookie(
    res,
    'admin_token',
    token,
    Number(
      process.env.COOKIE_MAX_AGE_MS
    ) || 86400000
  );

  res.clearCookie(
    'admin_mfa_token'
  );

  res.clearCookie(
    'setup_token'
  );

  res.clearCookie(
    'email_verify_token'
  );

  await updateLastLogin(
    admin.id
  );

  await logAudit({
    actorType: 'admin',
    actorId: admin.id,
    action: 'ADMIN_LOGIN',
    ipAddress: clientIp(req),
    userAgent:
      req.get('user-agent') || null
  });

  return res.json({
    message:
      'Administrator login successful.',
    redirect:
      '/admin-dashboard.html'
  });
}

/* =========================================================
   SIGNUP
========================================================= */

router.post(
  '/signup',
  async (req, res) => {
    try {
      const fullName =
        String(
          req.body.fullName || ''
        ).trim();

      const email =
        String(
          req.body.email || ''
        )
          .trim()
          .toLowerCase();

      const password =
        String(
          req.body.password || ''
        );

      if (
        !fullName ||
        fullName.length < 2
      ) {
        return res.status(400).json({
          error:
            'Please enter a valid full name.'
        });
      }

      if (!isValidEmail(email)) {
        return res.status(400).json({
          error:
            'Please enter a valid email address.'
        });
      }

      if (password.length < 8) {
        return res.status(400).json({
          error:
            'Password must be at least 8 characters long.'
        });
      }

      const existingUser =
        await findByEmail(email);

      const existingAdmin =
        await findAdminByEmail(
          email
        );

      if (
        existingUser ||
        existingAdmin
      ) {
        return res.status(409).json({
          error:
            'An account with this email already exists.'
        });
      }

      const passwordHash =
        await bcrypt.hash(
          password,
          12
        );

      const user =
        await createUser({
          fullName,
          email,
          passwordHash
        });

      const otp =
        String(
          Math.floor(
            100000 +
            Math.random() * 900000
          )
        );

      const otpHash =
        sha256(otp);

      const expiresAt =
        new Date(
          Date.now() +
          10 * 60 * 1000
        );

      await updateUser(
        user.id,
        {
          emailOtpHash:
            otpHash,
          emailOtpExpiresAt:
            expiresAt
        }
      );

      await sendEmailOtp(
        user.email,
        user.full_name,
        otp,
        'user'
      );

      const emailToken =
        signEmailVerifyToken(
          user.id,
          'user'
        );

      setCookie(
        res,
        'email_verify_token',
        emailToken,
        10 * 60 * 1000
      );

      await logAudit({
        actorType: 'user',
        actorId: user.id,
        action: 'SIGNUP',
        ipAddress:
          clientIp(req),
        userAgent:
          req.get('user-agent') ||
          null
      });

      res.json({
        message:
          'Account created. A verification code has been sent to your email.',
        redirect:
          '/email-otp.html?type=user'
      });

    } catch (err) {
      console.error(
        'Signup error:',
        err
      );

      res.status(500).json({
        error:
          'Server error during registration.'
      });
    }
  }
);

/* =========================================================
   USER LOGIN
========================================================= */

router.post(
  '/login',
  async (req, res) => {
    try {
      const email =
        String(
          req.body.email || ''
        )
          .trim()
          .toLowerCase();

      const password =
        String(
          req.body.password || ''
        );

      if (
        !isValidEmail(email) ||
        !password
      ) {
        return res.status(400).json({
          error:
            'Email and password are required.'
        });
      }

      const user =
        await findByEmail(email);

      if (
        !user ||
        !(await bcrypt.compare(
          password,
          user.password_hash
        ))
      ) {
        await logAudit({
          actorType: 'user',
          action:
            'LOGIN_FAILED',
          email,
          ipAddress:
            clientIp(req),
          userAgent:
            req.get('user-agent') ||
            null
        });

        return res.status(401).json({
          error:
            'Invalid email or password.'
        });
      }

      if (!user.is_active) {
        return res.status(403).json({
          error:
            'Your account has been disabled.'
        });
      }

      /*
       * EMAIL VERIFICATION
       */

      if (!user.is_email_verified) {
        const otp =
          String(
            Math.floor(
              100000 +
              Math.random() * 900000
            )
          );

        const otpHash =
          sha256(otp);

        const expiresAt =
          new Date(
            Date.now() +
            10 * 60 * 1000
          );

        await updateUser(
          user.id,
          {
            emailOtpHash:
              otpHash,
            emailOtpExpiresAt:
              expiresAt
          }
        );

        await sendEmailOtp(
          user.email,
          user.full_name,
          otp,
          'user'
        );

        const emailToken =
          signEmailVerifyToken(
            user.id,
            'user'
          );

        setCookie(
          res,
          'email_verify_token',
          emailToken,
          10 * 60 * 1000
        );

        return res.json({
          message:
            'Please verify your email before continuing.',
          redirect:
            '/email-otp.html?type=user'
        });
      }

      /*
       * MFA SETUP
       */

      if (!user.totp_enabled) {
        const setupToken =
          signSetupToken(
            user.id,
            'user'
          );

        setCookie(
          res,
          'setup_token',
          setupToken,
          15 * 60 * 1000
        );

        return res.json({
          message:
            'Please complete Google Authenticator setup.',
          redirect:
            '/setup-2fa.html?type=user'
        });
      }

      /*
       * NORMAL MFA LOGIN
       */

      const mfaToken =
        signMfaPendingToken(
          user.id
        );

      setCookie(
        res,
        'mfa_token',
        mfaToken,
        10 * 60 * 1000
      );

      res.json({
        message:
          'Enter your Google Authenticator code.',
        redirect:
          '/mfa.html'
      });

    } catch (err) {
      console.error(
        'Login error:',
        err
      );

      res.status(500).json({
        error:
          'Server error during login.'
      });
    }
  }
);

/* =========================================================
   MFA SETUP
   USER + ADMIN
========================================================= */

router.get(
  '/setup-2fa',
  async (req, res) => {
    try {
      const {
        id,
        role
      } = getSetupIdentity(req);

      let account;

      if (role === 'admin') {
        account =
          await findAdminById(id);
      } else {
        account =
          await findById(id);
      }

      if (!account) {
        return res.status(404).json({
          error:
            'Account not found.'
        });
      }

      if (!account.is_active) {
        return res.status(403).json({
          error:
            'This account is disabled.'
        });
      }

      /*
       * IMPORTANT SECURITY CHECK:
       *
       * QR setup is allowed ONLY after
       * email verification.
       */

      if (!account.is_email_verified) {
        res.clearCookie(
          'setup_token'
        );

        return res.status(403).json({
          error:
            'Please verify your email before setting up MFA.'
        });
      }

      if (account.totp_enabled) {
        return res.status(400).json({
          error:
            'Two-factor authentication is already enabled.'
        });
      }

      const secret =
        authenticator.generateSecret();

      const encryptedSecret =
        encrypt(secret);

      if (role === 'admin') {
        await updateAdmin(
          id,
          {
            totpSecret:
              encryptedSecret
          }
        );
      } else {
        await updateUser(
          id,
          {
            totpSecret:
              encryptedSecret
          }
        );
      }

      const issuer =
        'MFA Auth';

      const otpauthUrl =
        authenticator.keyuri(
          account.email,
          issuer,
          secret
        );

      const qrCode =
        await QRCode.toDataURL(
          otpauthUrl
        );

      res.json({
        fullName:
          account.full_name,
        email:
          account.email,
        role,
        issuer,
        secret,
        qrCode
      });

    } catch (err) {
      console.error(
        '2FA setup error:',
        err
      );

      res.status(401).json({
        error:
          'Invalid or expired setup session.'
      });
    }
  }
);

/* =========================================================
   VERIFY MFA SETUP
   USER + ADMIN
========================================================= */

router.post(
  '/setup-2fa/verify',
  async (req, res) => {
    try {
      const {
        id,
        role
      } = getSetupIdentity(req);

      const code =
        String(
          req.body.code || ''
        ).replace(
          /\s/g,
          ''
        );

      if (!/^\d{6}$/.test(code)) {
        return res.status(400).json({
          error:
            'Enter the 6-digit authenticator code.'
        });
      }

      let account;

      if (role === 'admin') {
        account =
          await findAdminById(id);
      } else {
        account =
          await findById(id);
      }

      if (!account) {
        return res.status(404).json({
          error:
            'Account not found.'
        });
      }

      if (!account.is_active) {
        return res.status(403).json({
          error:
            'This account is disabled.'
        });
      }

      /*
       * IMPORTANT SECURITY CHECK:
       *
       * The server verifies email again before
       * accepting MFA setup.
       */

      if (!account.is_email_verified) {
        res.clearCookie(
          'setup_token'
        );

        return res.status(403).json({
          error:
            'Email verification is required before MFA setup.'
        });
      }

      if (!account.totp_secret) {
        return res.status(400).json({
          error:
            'Authenticator setup has not been initialized.'
        });
      }

      const secret =
        decrypt(
          account.totp_secret
        );

      const isValid =
        authenticator.check(
          code,
          secret
        );

      if (!isValid) {
        await logAudit({
          actorType:
            role,
          actorId:
            id,
          action:
            role === 'admin'
              ? 'ADMIN_MFA_SETUP_FAILED'
              : 'MFA_SETUP_FAILED',
          ipAddress:
            clientIp(req),
          userAgent:
            req.get('user-agent') ||
            null
        });

        return res.status(401).json({
          error:
            'Invalid authenticator code.'
        });
      }

      if (role === 'admin') {
        await updateAdmin(
          id,
          {
            totpEnabled:
              true
          }
        );

        const updatedAdmin =
          await findAdminById(
            id
          );

        await logAudit({
          actorType:
            'admin',
          actorId:
            id,
          action:
            'ADMIN_MFA_ENABLED',
          ipAddress:
            clientIp(req),
          userAgent:
            req.get('user-agent') ||
            null
        });

        return finishAdminLogin(
          req,
          res,
          updatedAdmin
        );
      }

      await updateUser(
        id,
        {
          totpEnabled:
            true
        }
      );

      const updatedUser =
        await findById(id);

      await logAudit({
        actorType:
          'user',
        actorId:
          id,
        action:
          'MFA_ENABLED',
        ipAddress:
          clientIp(req),
        userAgent:
          req.get('user-agent') ||
          null
      });

      return finishUserLogin(
        req,
        res,
        updatedUser
      );

    } catch (err) {
      console.error(
        '2FA verification error:',
        err
      );

      res.status(401).json({
        error:
          'Invalid or expired setup session.'
      });
    }
  }
);

/* =========================================================
   USER TOTP LOGIN
========================================================= */

router.post(
  '/verify-totp',
  async (req, res) => {
    try {
      const token =
        req.cookies?.mfa_token;

      if (!token) {
        return res.status(401).json({
          error:
            'MFA session has expired. Please log in again.'
        });
      }

      const payload =
        jwt.verify(
          token,
          process.env.SETUP_JWT_SECRET
        );

      if (
        payload.type !==
          'mfa_pending' ||
        !payload.sub
      ) {
        throw new Error(
          'Invalid MFA session.'
        );
      }

      const code =
        String(
          req.body.code || ''
        ).replace(
          /\s/g,
          ''
        );

      if (!/^\d{6}$/.test(code)) {
        return res.status(400).json({
          error:
            'Enter the 6-digit authenticator code.'
        });
      }

      const user =
        await findById(
          payload.sub
        );

      if (!user) {
        return res.status(404).json({
          error:
            'User account not found.'
        });
      }

      if (!user.is_active) {
        res.clearCookie(
          'mfa_token'
        );

        return res.status(403).json({
          error:
            'Your account has been disabled.'
        });
      }

      if (!user.is_email_verified) {
        res.clearCookie(
          'mfa_token'
        );

        return res.status(403).json({
          error:
            'Email verification is required.'
        });
      }

      if (
        !user.totp_enabled ||
        !user.totp_secret
      ) {
        res.clearCookie(
          'mfa_token'
        );

        return res.status(400).json({
          error:
            'MFA is not configured for this account.'
        });
      }

      const secret =
        decrypt(
          user.totp_secret
        );

      const isValid =
        authenticator.check(
          code,
          secret
        );

      if (!isValid) {
        await logAudit({
          actorType:
            'user',
          actorId:
            user.id,
          action:
            'MFA_LOGIN_FAILED',
          ipAddress:
            clientIp(req),
          userAgent:
            req.get('user-agent') ||
            null
        });

        return res.status(401).json({
          error:
            'Invalid authenticator code.'
        });
      }

      return finishUserLogin(
        req,
        res,
        user
      );

    } catch (err) {
      console.error(
        'TOTP login error:',
        err
      );

      res.status(401).json({
        error:
          'Invalid or expired MFA session. Please log in again.'
      });
    }
  }
);

/* =========================================================
   LOGOUT
========================================================= */

router.post(
  '/logout',
  async (req, res) => {
    try {
      const token =
        req.cookies?.token;

      if (token) {
        try {
          const payload =
            jwt.verify(
              token,
              process.env.JWT_SECRET
            );

          await logAudit({
            actorType:
              'user',
            actorId:
              payload.sub,
            action:
              'LOGOUT',
            ipAddress:
              clientIp(req),
            userAgent:
              req.get('user-agent') ||
              null
          });
        } catch {
          // Ignore invalid logout token.
        }
      }

      res.clearCookie('token');
      res.clearCookie('mfa_token');
      res.clearCookie('setup_token');
      res.clearCookie(
        'email_verify_token'
      );

      res.json({
        message:
          'Logged out successfully.'
      });

    } catch (err) {
      res.clearCookie('token');
      res.clearCookie('mfa_token');
      res.clearCookie('setup_token');
      res.clearCookie(
        'email_verify_token'
      );

      res.json({
        message:
          'Logged out successfully.'
      });
    }
  }
);

/* =========================================================
   CURRENT USER
========================================================= */

router.get(
  '/me',
  async (req, res) => {
    try {
      const token =
        req.cookies?.token;

      if (!token) {
        return res.status(401).json({
          error:
            'Authentication required.'
        });
      }

      const payload =
        jwt.verify(
          token,
          process.env.JWT_SECRET
        );

      if (
        payload.type !== 'auth' ||
        payload.role !== 'user'
      ) {
        throw new Error(
          'Invalid user session.'
        );
      }

      const user =
        await findById(
          payload.sub
        );

      if (
        !user ||
        !user.is_active
      ) {
        res.clearCookie(
          'token'
        );

        return res.status(403).json({
          error:
            'Your account is disabled or no longer exists.'
        });
      }

      res.json({
        id:
          user.id,
        fullName:
          user.full_name,
        email:
          user.email,
        role:
          user.role,
        mfaEnabled:
          user.totp_enabled
      });

    } catch (err) {
      res.status(401).json({
        error:
          'Invalid or expired session.'
      });
    }
  }
);

module.exports = {
  router,
  signAuthToken,
  signAdminToken,
  signSetupToken,
  signEmailVerifyToken,
  signMfaPendingToken
};