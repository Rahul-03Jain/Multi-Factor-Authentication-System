const nodemailer = require('nodemailer');

let transporter = null;

function normalizeSmtpPass(pass) {
  return (pass || '').trim().replace(/\s+/g, '');
}

function getSmtpUser() {
  return (process.env.SMTP_USER || '').trim();
}

function getSmtpPass() {
  return normalizeSmtpPass(process.env.SMTP_PASS);
}

function isSmtpConfigured() {
  const user = getSmtpUser();
  const pass = getSmtpPass();
  const host = (process.env.SMTP_HOST || '').trim();

  return Boolean(user && pass && host);
}

function getTransporter() {
  if (!isSmtpConfigured()) return null;

  if (!transporter) {
    transporter = nodemailer.createTransport({
      host: (process.env.SMTP_HOST || 'smtp.gmail.com').trim(),
      port: Number(process.env.SMTP_PORT) || 587,
      secure: process.env.SMTP_SECURE === 'true',
      auth: {
        user: getSmtpUser(),
        pass: getSmtpPass()
      },
      tls: {
        minVersion: 'TLSv1.2'
      }
    });
  }

  return transporter;
}

async function verifySmtpConnection() {
  if (!isSmtpConfigured()) {
    console.warn(
      '[Mail] SMTP not configured. Password-reset and OTP emails cannot be sent.'
    );
    return false;
  }

  try {
    await getTransporter().verify();

    console.log(
      `[Mail] SMTP ready — ${process.env.EMAIL_FROM || getSmtpUser()}`
    );

    return true;
  } catch (err) {
    console.error('[Mail] SMTP connection failed:', err.message);
    return false;
  }
}

function getEmailFrom() {
  let from = (process.env.EMAIL_FROM || getSmtpUser()).trim();

  if (
    (from.startsWith('"') && from.endsWith('"')) ||
    (from.startsWith("'") && from.endsWith("'"))
  ) {
    from = from.slice(1, -1);
  }

  return from;
}

async function sendEmail({ to, subject, text, html }) {
  const transport = getTransporter();

  if (!transport) {
    if (process.env.NODE_ENV !== 'production') {
      console.warn(
        `[DEV] SMTP not configured. Email intended for ${to}: ${subject}`
      );
      console.warn(text);

      return {
        sent: false,
        dev: true
      };
    }

    throw new Error('Email service is not configured.');
  }

  await transport.sendMail({
    from: getEmailFrom(),
    to,
    subject,
    text,
    html
  });

  return {
    sent: true
  };
}

async function sendEmailOtp(to, name, otp, accountType = 'user') {
  const label =
    accountType === 'admin'
      ? 'administrator'
      : 'user';

  const subject = `Your MFA verification code`;

  const text = `Hello ${name || 'there'},

Your verification code is:

${otp}

This code expires in 10 minutes.

If you did not request this code, please ignore this email.

MFA Auth`;

  const html = `
    <div style="font-family:Segoe UI,Tahoma,sans-serif;max-width:520px;margin:auto;padding:24px">
      <h2>Email verification</h2>

      <p>Hello ${escapeHtml(name || 'there')},</p>

      <p>
        We received a request to verify your ${label} account.
      </p>

      <p>Your verification code is:</p>

      <div style="
        font-size:32px;
        font-weight:bold;
        letter-spacing:8px;
        text-align:center;
        padding:18px;
        margin:20px 0;
        background:#f4f4f4;
        border-radius:8px;
      ">
        ${escapeHtml(otp)}
      </div>

      <p>
        This code expires in <strong>10 minutes</strong>.
      </p>

      <p style="color:#777;font-size:12px">
        If you did not request this code, please ignore this email.
      </p>

      <p style="color:#777;font-size:12px">
        MFA Auth
      </p>
    </div>
  `;

  return sendEmail({
    to,
    subject,
    text,
    html
  });
}

async function sendPasswordResetEmail(
  to,
  name,
  resetUrl,
  accountType
) {
  const label =
    accountType === 'admin'
      ? 'administrator'
      : 'user';

  const subject =
    `Reset your ${label} password`;

  const text = `Hello ${name || 'there'},

Use this link to reset your ${label} password:

${resetUrl}

This link expires in 30 minutes and can only be used once.

If you did not request this, ignore this email.`;

  const html = `
    <div style="font-family:Segoe UI,Tahoma,sans-serif;max-width:520px;margin:auto;padding:24px">
      <h2>Password reset</h2>

      <p>Hello ${escapeHtml(name || 'there')},</p>

      <p>
        Someone requested a password reset for your ${label} account.
      </p>

      <p>
        <a href="${escapeHtml(resetUrl)}">
          Reset your password
        </a>
      </p>

      <p>
        This link expires in <strong>30 minutes</strong>
        and can only be used once.
      </p>

      <p style="color:#777;font-size:12px">
        If you did not request this, you can ignore this email.
      </p>
    </div>
  `;

  return sendEmail({
    to,
    subject,
    text,
    html
  });
}

function escapeHtml(value) {
  return String(value).replace(
    /[&<>"']/g,
    ch => ({
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#039;'
    }[ch])
  );
}

module.exports = {
  isSmtpConfigured,
  verifySmtpConnection,
  sendEmailOtp,
  sendPasswordResetEmail
};