DROP TABLE IF EXISTS support_messages;
DROP TABLE IF EXISTS login_attempts;
DROP TABLE IF EXISTS push_subscriptions;
DROP TABLE IF EXISTS aliases;
DROP TABLE IF EXISTS messages;
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS accounts;

CREATE TABLE accounts (
  id TEXT PRIMARY KEY,
  address TEXT UNIQUE NOT NULL,
  inbox TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  password_salt TEXT NOT NULL,
  public_key TEXT NOT NULL,
  encrypted_private_key TEXT NOT NULL,
  pk_iv TEXT NOT NULL,
  kdf_salt TEXT NOT NULL,
  auth_version INTEGER NOT NULL DEFAULT 2,
  created_at INTEGER NOT NULL
);
CREATE INDEX idx_accounts_inbox ON accounts(inbox);

CREATE TABLE messages (
  id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL,
  encrypted_aes_key TEXT NOT NULL,
  meta_iv TEXT NOT NULL,
  meta_encrypted TEXT NOT NULL,
  body_iv TEXT NOT NULL,
  body_encrypted TEXT NOT NULL,
  received_at INTEGER NOT NULL,
  seen INTEGER NOT NULL DEFAULT 0,
  -- 1 only for mail this service wrote itself, from the support desk. Mail that
  -- arrives from outside is always 0, whatever its From header claims, so a
  -- forged admin@ address cannot earn the verified mark.
  official INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX idx_messages_account ON messages(account_id, received_at DESC);
CREATE INDEX idx_messages_received ON messages(received_at);

CREATE TABLE sessions (
  token TEXT PRIMARY KEY,
  account_id TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE INDEX idx_sessions_expires ON sessions(expires_at);

CREATE TABLE push_subscriptions (
  id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL,
  endpoint TEXT UNIQUE NOT NULL,
  p256dh TEXT NOT NULL,
  auth TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX idx_push_account ON push_subscriptions(account_id);

CREATE TABLE aliases (
  address TEXT PRIMARY KEY,
  account_id TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX idx_aliases_account ON aliases(account_id, created_at DESC);

CREATE TABLE login_attempts (
  key TEXT PRIMARY KEY,
  fails INTEGER NOT NULL DEFAULT 0,
  first_at INTEGER NOT NULL,
  blocked_until INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX idx_login_attempts_blocked ON login_attempts(blocked_until);

-- The in-site support chat. One conversation per account; each line is encrypted
-- in the browser and its AES key is wrapped for the account (key_user) and for
-- the support desk (key_staff), so the server never sees the text.
CREATE TABLE support_messages (
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
CREATE INDEX idx_support_account ON support_messages(account_id, created_at);
CREATE INDEX idx_support_created ON support_messages(created_at);
