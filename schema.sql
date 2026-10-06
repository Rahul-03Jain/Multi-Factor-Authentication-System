-- Existing users table is preserved.
-- This project uses the existing UUID-based users table.

ALTER TABLE users
  ADD COLUMN IF NOT EXISTS last_login_at TIMESTAMPTZ;

-- Password reset tokens for both users and administrators.
-- Both user_id and admin_id reference the existing users table.
CREATE TABLE IF NOT EXISTS password_resets (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

  user_id UUID REFERENCES users(id) ON DELETE CASCADE,
  admin_id UUID REFERENCES users(id) ON DELETE CASCADE,

  token_hash TEXT UNIQUE NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  used_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  CONSTRAINT password_reset_owner_check CHECK (
    (user_id IS NOT NULL AND admin_id IS NULL)
    OR
    (user_id IS NULL AND admin_id IS NOT NULL)
  )
);

CREATE INDEX IF NOT EXISTS idx_password_reset_token
  ON password_resets(token_hash);

CREATE INDEX IF NOT EXISTS idx_password_reset_user
  ON password_resets(user_id);

CREATE INDEX IF NOT EXISTS idx_password_reset_admin
  ON password_resets(admin_id);

-- Detailed security/audit trail.
CREATE TABLE IF NOT EXISTS audit_logs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

  actor_type VARCHAR(20) NOT NULL,
  actor_id UUID,

  target_user_id UUID REFERENCES users(id) ON DELETE SET NULL,

  action VARCHAR(50) NOT NULL,

  ip_address INET,
  user_agent TEXT,
  details TEXT,

  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_created_at
  ON audit_logs(created_at DESC);

CREATE INDEX IF NOT EXISTS idx_audit_target_user
  ON audit_logs(target_user_id);