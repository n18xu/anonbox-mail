CREATE TABLE IF NOT EXISTS aliases (
  address TEXT PRIMARY KEY,
  account_id TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_aliases_account ON aliases(account_id, created_at DESC);
