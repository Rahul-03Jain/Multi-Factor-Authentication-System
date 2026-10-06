const { query } = require('./db');

async function createReset({ userId = null, adminId = null, tokenHash, expiresAt }) {
  await query(
    `INSERT INTO password_resets (user_id, admin_id, token_hash, expires_at)
     VALUES ($1, $2, $3, $4)`,
    [userId, adminId, tokenHash, expiresAt]
  );
}

async function consumeReset(tokenHash, accountType) {
  const ownerCondition = accountType === 'admin'
    ? 'admin_id IS NOT NULL'
    : 'user_id IS NOT NULL';

  const result = await query(
    `UPDATE password_resets
     SET used_at = NOW()
     WHERE token_hash = $1
       AND used_at IS NULL
       AND expires_at > NOW()
       AND ${ownerCondition}
     RETURNING *`,
    [tokenHash]
  );
  return result.rows[0] || null;
}

async function invalidateOlderResets({ userId = null, adminId = null }) {
  if (userId) {
    await query(`UPDATE password_resets SET used_at = NOW() WHERE user_id = $1 AND used_at IS NULL`, [userId]);
  }
  if (adminId) {
    await query(`UPDATE password_resets SET used_at = NOW() WHERE admin_id = $1 AND used_at IS NULL`, [adminId]);
  }
}

module.exports = { createReset, consumeReset, invalidateOlderResets };
