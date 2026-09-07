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
  seen INTEGER NOT NULL DEFAULT 0
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
