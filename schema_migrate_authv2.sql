-- Auth v2 migration: the password stops being sent to the server.
--
-- v1 accounts keep working: the client tries v2 first, gets `legacy_auth` back,
-- falls back to the old flow once, and is upgraded to v2 in the same login.
-- Run this against an existing database (schema.sql is for fresh installs and
-- drops everything).

ALTER TABLE accounts ADD COLUMN auth_version INTEGER NOT NULL DEFAULT 1;

CREATE TABLE IF NOT EXISTS login_attempts (
  key TEXT PRIMARY KEY,
  fails INTEGER NOT NULL DEFAULT 0,
  first_at INTEGER NOT NULL,
  blocked_until INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_login_attempts_blocked ON login_attempts(blocked_until);
