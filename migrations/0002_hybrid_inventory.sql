-- VERIX hybrid real-SMS inventory migration
PRAGMA foreign_keys = ON;

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

CREATE INDEX IF NOT EXISTS idx_number_metadata_public
  ON number_metadata(number_type,provider_status,inbound_enabled,public_access);
CREATE INDEX IF NOT EXISTS idx_number_metadata_provider
  ON number_metadata(provider_id,provider_status);
