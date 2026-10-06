const { query } = require('./db');

async function findByEmail(email) {
  const result = await query(
    `SELECT
       id,
       full_name,
       email,
       password AS password_hash,
       role,
       is_disabled,
       NOT is_disabled AS is_active,
       is_email_verified,
       mfa_enabled AS totp_enabled,
       totp_secret,
       email_otp_hash,
       email_otp_expires_at,
       created_at,
       updated_at,
       last_login_at
     FROM users
     WHERE email = $1
       AND role = 'admin'
     LIMIT 1`,
    [email.trim().toLowerCase()]
  );

  return result.rows[0] || null;
}

async function findById(id) {
  const result = await query(
    `SELECT
       id,
       full_name,
       email,
       password AS password_hash,
       role,
       is_disabled,
       NOT is_disabled AS is_active,
       is_email_verified,
       mfa_enabled AS totp_enabled,
       totp_secret,
       email_otp_hash,
       email_otp_expires_at,
       created_at,
       updated_at,
       last_login_at
     FROM users
     WHERE id = $1
       AND role = 'admin'
     LIMIT 1`,
    [id]
  );

  return result.rows[0] || null;
}

async function createAdmin({ fullName, email, passwordHash }) {
  const result = await query(
    `INSERT INTO users
      (
        full_name,
        email,
        password,
        role,
        is_disabled,
        is_email_verified,
        mfa_enabled
      )
     VALUES ($1, $2, $3, 'admin', FALSE, FALSE, FALSE)
     RETURNING
       id,
       full_name,
       email,
       role,
       NOT is_disabled AS is_active,
       is_email_verified,
       mfa_enabled AS totp_enabled,
       created_at`,
    [
      fullName.trim(),
      email.trim().toLowerCase(),
      passwordHash
    ]
  );

  return result.rows[0];
}

async function updateAdmin(id, updates = {}) {
  if (Object.prototype.hasOwnProperty.call(updates, 'passwordHash')) {
    await query(
      `UPDATE users
       SET password = $1,
           updated_at = NOW()
       WHERE id = $2
         AND role = 'admin'`,
      [updates.passwordHash, id]
    );
  }

  if (Object.prototype.hasOwnProperty.call(updates, 'isActive')) {
    await query(
      `UPDATE users
       SET is_disabled = $1,
           updated_at = NOW()
       WHERE id = $2
         AND role = 'admin'`,
      [!Boolean(updates.isActive), id]
    );
  }

  if (Object.prototype.hasOwnProperty.call(updates, 'totpSecret')) {
    await query(
      `UPDATE users
       SET totp_secret = $1,
           updated_at = NOW()
       WHERE id = $2
         AND role = 'admin'`,
      [updates.totpSecret, id]
    );
  }

  if (Object.prototype.hasOwnProperty.call(updates, 'totpEnabled')) {
    await query(
      `UPDATE users
       SET mfa_enabled = $1,
           updated_at = NOW()
       WHERE id = $2
         AND role = 'admin'`,
      [Boolean(updates.totpEnabled), id]
    );
  }

  if (Object.prototype.hasOwnProperty.call(updates, 'emailOtpHash')) {
    await query(
      `UPDATE users
       SET email_otp_hash = $1,
           updated_at = NOW()
       WHERE id = $2
         AND role = 'admin'`,
      [updates.emailOtpHash, id]
    );
  }

  if (Object.prototype.hasOwnProperty.call(updates, 'emailOtpExpiresAt')) {
    await query(
      `UPDATE users
       SET email_otp_expires_at = $1,
           updated_at = NOW()
       WHERE id = $2
         AND role = 'admin'`,
      [updates.emailOtpExpiresAt, id]
    );
  }

  if (Object.prototype.hasOwnProperty.call(updates, 'emailVerified')) {
    await query(
      `UPDATE users
       SET is_email_verified = $1,
           email_otp_hash = NULL,
           email_otp_expires_at = NULL,
           updated_at = NOW()
       WHERE id = $2
         AND role = 'admin'`,
      [Boolean(updates.emailVerified), id]
    );
  }

  return findById(id);
}

async function updateLastLogin(id) {
  await query(
    `UPDATE users
     SET last_login_at = NOW(),
         updated_at = NOW()
     WHERE id = $1
       AND role = 'admin'`,
    [id]
  );
}

module.exports = {
  findByEmail,
  findById,
  createAdmin,
  updateAdmin,
  updateLastLogin
};