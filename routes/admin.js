const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const {
  findByEmail,
  findById,
  updateAdmin,
  updateLastLogin
} = require('../models/Admin');

const {
  listUsers,
  findById: findUserById,
  updateUser
} = require('../models/User');

const {
  listAuditLogs,
  logAudit
} = require('../models/Audit');

const {
  sha256,
  decrypt
} = require('../utils/crypto');

const {
  sendEmailOtp
} = require('../utils/mailer');

const {
  requireAdminAuth,
  requireActiveAdmin
} = require('../middleware/auth');

const {
  signSetupToken
} = require('./auth');

const {
  authenticator
} = require('otplib');

const router = express.Router();

authenticator.options = {
  window: 1
};

function clientIp(req) {
  return req.ip || req.socket?.remoteAddress || null;
}

function setAdminCookie(
  res,
  token
) {
  res.cookie(
    'admin_token',
    token,
    {
      httpOnly: true,
      secure:
        process.env.NODE_ENV ===
        'production',
      sameSite: 'lax',
      maxAge:
        Number(
          process.env.COOKIE_MAX_AGE_MS
        ) || 86400000
    }
  );
}

function setPendingCookie(
  res,
  name,
  token,
  maxAge
) {
  res.cookie(
    name,
    token,
    {
      httpOnly: true,
      secure:
        process.env.NODE_ENV ===
        'production',
      sameSite: 'lax',
      maxAge
    }
  );
}

function signAdminMfaToken(
  adminId
) {
  return jwt.sign(
    {
      sub:
        String(adminId),
      role:
        'admin',
      type:
        'admin_mfa_pending'
    },
    process.env.SETUP_JWT_SECRET,
    {
      expiresIn:
        '10m'
    }
  );
}

/* =========================================================
   ADMIN LOGIN
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

      const admin =
        await findByEmail(email);

      if (
        !admin ||
        !(await bcrypt.compare(
          password,
          admin.password_hash
        ))
      ) {
        await logAudit({
          actorType:
            'admin',
          action:
            'ADMIN_LOGIN_FAILED',
          ipAddress:
            clientIp(req),
          userAgent:
            req.get(
              'user-agent'
            ) || null
        });

        return res.status(401).json({
          error:
            'Invalid administrator credentials.'
        });
      }

      if (!admin.is_active) {
        return res.status(403).json({
          error:
            'This administrator account is disabled.'
        });
      }

      /*
       * FIRST:
       * Verify administrator email.
       */

      if (!admin.is_email_verified) {
        const otp =
          String(
            Math.floor(
              100000 +
              Math.random() *
                900000
            )
          );

        const otpHash =
          sha256(otp);

        const expiresAt =
          new Date(
            Date.now() +
            10 * 60 * 1000
          );

        await updateAdmin(
          admin.id,
          {
            emailOtpHash:
              otpHash,
            emailOtpExpiresAt:
              expiresAt
          }
        );

        await sendEmailOtp(
          admin.email,
          admin.full_name,
          otp,
          'admin'
        );

        const emailToken =
          jwt.sign(
            {
              sub:
                String(
                  admin.id
                ),
              role:
                'admin',
              type:
                'email_verify'
            },
            process.env.SETUP_JWT_SECRET,
            {
              expiresIn:
                '10m'
            }
          );

        setPendingCookie(
          res,
          'email_verify_token',
          emailToken,
          10 * 60 * 1000
        );

        return res.json({
          message:
            'Administrator email verification is required.',
          redirect:
            '/email-otp.html?type=admin'
        });
      }

      /*
       * SECOND:
       * If admin hasn't configured MFA,
       * send them to QR setup.
       */

      if (!admin.totp_enabled) {
        const setupToken =
          signSetupToken(
            admin.id,
            'admin'
          );

        setPendingCookie(
          res,
          'setup_token',
          setupToken,
          15 * 60 * 1000
        );

        return res.json({
          message:
            'Complete Google Authenticator setup before continuing.',
          redirect:
            '/setup-2fa.html?type=admin'
        });
      }

      /*
       * THIRD:
       * MFA already configured.
       * Require TOTP.
       */

      const mfaToken =
        signAdminMfaToken(
          admin.id
        );

      setPendingCookie(
        res,
        'admin_mfa_token',
        mfaToken,
        10 * 60 * 1000
      );

      res.json({
        message:
          'Enter your Google Authenticator code.',
        redirect:
          '/admin-mfa.html'
      });

    } catch (err) {
      console.error(
        'Admin login error:',
        err
      );

      res.status(500).json({
        error:
          'Server error during administrator login.'
      });
    }
  }
);

/* =========================================================
   ADMIN TOTP LOGIN
========================================================= */

router.post(
  '/verify-totp',
  async (req, res) => {
    try {
      const token =
        req.cookies?.admin_mfa_token;

      if (!token) {
        return res.status(401).json({
          error:
            'Administrator MFA session has expired.'
        });
      }

      const payload =
        jwt.verify(
          token,
          process.env.SETUP_JWT_SECRET
        );

      if (
        payload.type !==
          'admin_mfa_pending' ||
        payload.role !== 'admin' ||
        !payload.sub
      ) {
        throw new Error(
          'Invalid admin MFA session.'
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

      const admin =
        await findById(
          payload.sub
        );

      if (!admin) {
        return res.status(404).json({
          error:
            'Administrator account not found.'
        });
      }

      if (!admin.is_active) {
        res.clearCookie(
          'admin_mfa_token'
        );

        return res.status(403).json({
          error:
            'Administrator account is disabled.'
        });
      }

      if (
        !admin.is_email_verified
      ) {
        res.clearCookie(
          'admin_mfa_token'
        );

        return res.status(403).json({
          error:
            'Administrator email is not verified.'
        });
      }

      if (
        !admin.totp_enabled ||
        !admin.totp_secret
      ) {
        res.clearCookie(
          'admin_mfa_token'
        );

        return res.status(400).json({
          error:
            'Administrator MFA is not configured.'
        });
      }

      const secret =
        decrypt(
          admin.totp_secret
        );

      const valid =
        authenticator.check(
          code,
          secret
        );

      if (!valid) {
        await logAudit({
          actorType:
            'admin',
          actorId:
            admin.id,
          action:
            'ADMIN_MFA_LOGIN_FAILED',
          ipAddress:
            clientIp(req),
          userAgent:
            req.get(
              'user-agent'
            ) || null
        });

        return res.status(401).json({
          error:
            'Invalid authenticator code.'
        });
      }

      const adminToken =
        jwt.sign(
          {
            sub:
              String(
                admin.id
              ),
            email:
              admin.email,
            fullName:
              admin.full_name,
            role:
              'admin',
            type:
              'admin'
          },
          process.env.ADMIN_JWT_SECRET,
          {
            expiresIn:
              '24h'
          }
        );

      setAdminCookie(
        res,
        adminToken
      );

      res.clearCookie(
        'admin_mfa_token'
      );

      await updateLastLogin(
        admin.id
      );

      await logAudit({
        actorType:
          'admin',
        actorId:
          admin.id,
        action:
          'ADMIN_LOGIN',
        ipAddress:
          clientIp(req),
        userAgent:
          req.get(
            'user-agent'
          ) || null
      });

      res.json({
        message:
          'Administrator login successful.',
        redirect:
          '/admin-dashboard.html'
      });

    } catch (err) {
      console.error(
        'Admin TOTP error:',
        err
      );

      res.status(401).json({
        error:
          'Invalid or expired administrator MFA session.'
      });
    }
  }
);

/* =========================================================
   ADMIN LOGOUT
========================================================= */

router.post(
  '/logout',
  requireAdminAuth,
  requireActiveAdmin,
  async (req, res) => {
    try {
      await logAudit({
        actorType:
          'admin',
        actorId:
          req.admin.sub,
        action:
          'ADMIN_LOGOUT',
        ipAddress:
          clientIp(req),
        userAgent:
          req.get(
            'user-agent'
          ) || null
      });

      res.clearCookie(
        'admin_token'
      );

      res.clearCookie(
        'admin_mfa_token'
      );

      res.json({
        message:
          'Administrator logged out.'
      });

    } catch (err) {
      res.clearCookie(
        'admin_token'
      );

      res.json({
        message:
          'Administrator logged out.'
      });
    }
  }
);

/* =========================================================
   ADMIN ME
========================================================= */

router.get(
  '/me',
  requireAdminAuth,
  requireActiveAdmin,
  (req, res) => {
    res.json({
      fullName:
        req.currentAdmin.full_name,
      email:
        req.currentAdmin.email,
      role:
        'admin'
    });
  }
);

/* =========================================================
   LIST USERS
========================================================= */

router.get(
  '/users',
  requireAdminAuth,
  requireActiveAdmin,
  async (req, res) => {
    try {
      res.json({
        users:
          await listUsers()
      });
    } catch (err) {
      console.error(
        'Admin users error:',
        err
      );

      res.status(500).json({
        error:
          'Unable to load users.'
      });
    }
  }
);

/* =========================================================
   ENABLE / DISABLE USER
========================================================= */

router.patch(
  '/users/:id/status',
  requireAdminAuth,
  requireActiveAdmin,
  async (req, res) => {
    try {
      const user =
        await findUserById(
          req.params.id
        );

      if (!user) {
        return res.status(404).json({
          error:
            'User not found.'
        });
      }

      const enabled =
        Boolean(
          req.body.enabled
        );

      const updated =
        await updateUser(
          user.id,
          {
            isActive:
              enabled
          }
        );

      await logAudit({
        actorType:
          'admin',
        actorId:
          req.admin.sub,
        targetUserId:
          user.id,
        action:
          enabled
            ? 'USER_ENABLED'
            : 'USER_DISABLED',
        ipAddress:
          clientIp(req),
        userAgent:
          req.get(
            'user-agent'
          ) || null,
        details:
          `${
            enabled
              ? 'Enabled'
              : 'Disabled'
          } user ${user.email}`
      });

      res.json({
        message:
          `User ${
            enabled
              ? 'enabled'
              : 'disabled'
          } successfully.`,
        user: {
          id:
            updated.id,
          fullName:
            updated.full_name,
          email:
            updated.email,
          isActive:
            updated.is_active
        }
      });

    } catch (err) {
      console.error(
        'Admin user status error:',
        err
      );

      res.status(500).json({
        error:
          'Unable to update user status.'
      });
    }
  }
);

/* =========================================================
   AUDIT LOG
========================================================= */

router.get(
  '/audit',
  requireAdminAuth,
  requireActiveAdmin,
  async (req, res) => {
    try {
      res.json({
        logs:
          await listAuditLogs()
      });
    } catch (err) {
      console.error(
        'Audit log error:',
        err
      );

      res.status(500).json({
        error:
          'Unable to load audit logs.'
      });
    }
  }
);

module.exports = router;