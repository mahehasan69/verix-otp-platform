PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE COLLATE NOCASE,
  display_name TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  password_salt TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('admin', 'customer')),
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended')),
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sessions(expires_at);

CREATE TABLE IF NOT EXISTS phone_numbers (
  id TEXT PRIMARY KEY,
  phone_e164 TEXT NOT NULL UNIQUE,
  country_code TEXT NOT NULL,
  label TEXT NOT NULL DEFAULT '',
  provider TEXT NOT NULL DEFAULT 'manual',
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'paused', 'retired')),
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS number_assignments (
  number_id TEXT NOT NULL REFERENCES phone_numbers(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  assigned_at TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (number_id, user_id)
);
CREATE INDEX IF NOT EXISTS idx_assignments_user ON number_assignments(user_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_assignments_single_customer ON number_assignments(number_id);

CREATE TABLE IF NOT EXISTS inbound_messages (
  id TEXT PRIMARY KEY,
  provider_message_id TEXT,
  number_id TEXT NOT NULL REFERENCES phone_numbers(id),
  sender TEXT NOT NULL,
  body TEXT NOT NULL,
  received_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_messages_number_date ON inbound_messages(number_id, received_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS idx_messages_provider_id ON inbound_messages(provider_message_id) WHERE provider_message_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS audit_logs (
  id TEXT PRIMARY KEY,
  actor_user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
  action TEXT NOT NULL,
  target_id TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Hybrid real-SMS provider inventory (also applied by migrations/0002_hybrid_inventory.sql)
CREATE TABLE IF NOT EXISTS provider_accounts (
  id TEXT PRIMARY KEY,
  slug TEXT NOT NULL UNIQUE,
  display_name TEXT NOT NULL,
  integration_type TEXT NOT NULL CHECK (integration_type IN ('webhook','manual')),
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','active','disabled')),
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS number_metadata (
  number_id TEXT PRIMARY KEY REFERENCES phone_numbers(id) ON DELETE CASCADE,
  number_type TEXT NOT NULL CHECK (number_type IN ('public','private')),
  provider_id TEXT NOT NULL REFERENCES provider_accounts(id),
  provider_number_id TEXT NOT NULL,
  provider_status TEXT NOT NULL DEFAULT 'pending' CHECK (provider_status IN ('pending','active','paused')),
  inbound_enabled INTEGER NOT NULL DEFAULT 0 CHECK (inbound_enabled IN (0,1)),
  public_access INTEGER NOT NULL DEFAULT 0 CHECK (public_access IN (0,1)),
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  CHECK ((number_type='public' AND public_access=1) OR (number_type='private' AND public_access=0))
);
CREATE INDEX IF NOT EXISTS idx_number_metadata_public ON number_metadata(number_type,provider_status,inbound_enabled,public_access);
CREATE INDEX IF NOT EXISTS idx_number_metadata_provider ON number_metadata(provider_id,provider_status);
