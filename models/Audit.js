const { query } = require('./db');

async function logAudit({
  actorType,
  actorId = null,
  targetUserId = null,
  action,
  ipAddress = null,
  userAgent = null,
  details = null
}) {
  await query(
    `INSERT INTO audit_logs
      (actor_type, actor_id, target_user_id, action, ip_address, user_agent, details)
     VALUES ($1, $2, $3, $4, $5, $6, $7)`,
    [actorType, actorId, targetUserId, action, ipAddress, userAgent, details]
  );
}

async function listAuditLogs(limit = 200) {
  const result = await query(
    `SELECT
       a.id,
       a.actor_type,
       a.actor_id,
       a.target_user_id,
       a.action,
       a.ip_address,
       a.user_agent,
       a.details,
       a.created_at,
       u.email AS target_email,
       u.full_name AS target_name
     FROM audit_logs a
     LEFT JOIN users u ON u.id = a.target_user_id
     ORDER BY a.created_at DESC
     LIMIT $1`,
    [limit]
  );
  return result.rows;
}

module.exports = { logAudit, listAuditLogs };
