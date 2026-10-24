-- Adds the in-site support chat to an existing database.
CREATE TABLE IF NOT EXISTS support_messages (
  id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL,
  sender TEXT NOT NULL CHECK (sender IN ('user', 'staff')),
  iv TEXT NOT NULL,
  body TEXT NOT NULL,
  key_user TEXT NOT NULL,
  key_staff TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  read_by_user INTEGER NOT NULL DEFAULT 0,
  read_by_staff INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_support_account ON support_messages(account_id, created_at);
CREATE INDEX IF NOT EXISTS idx_support_created ON support_messages(created_at);
