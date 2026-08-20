-- 会計管理ツール D1 スキーマ

CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  password_salt TEXT NOT NULL,
  current_workspace_id INTEGER,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS sessions (
  token TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);

-- A workspace is the shared data container: businesses/accounts/entries all
-- belong to a workspace, not directly to a user. Every user gets their own
-- workspace at signup; other users can be invited to join it so multiple
-- accounts can manage the same accounting data together.
CREATE TABLE IF NOT EXISTS workspaces (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  owner_user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS workspace_members (
  workspace_id INTEGER NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role TEXT NOT NULL DEFAULT 'member', -- 'owner' | 'member'
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (workspace_id, user_id)
);
CREATE INDEX IF NOT EXISTS idx_workspace_members_user ON workspace_members(user_id);

CREATE TABLE IF NOT EXISTS invites (
  token TEXT PRIMARY KEY,
  workspace_id INTEGER NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  created_by INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at TEXT NOT NULL,
  accepted_by INTEGER REFERENCES users(id),
  accepted_at TEXT,
  -- Optional: if set, this invite is scoped to a single business. On accept,
  -- the invited user is still added to the workspace (data is shared at the
  -- workspace level), but that business is switched into "restricted" mode
  -- (see business_members below) with the invitee added to it, so they're
  -- guaranteed access to this business specifically.
  business_id INTEGER REFERENCES businesses(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_invites_workspace ON invites(workspace_id);

CREATE TABLE IF NOT EXISTS businesses (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  workspace_id INTEGER NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  opening_cash REAL NOT NULL DEFAULT 0,
  entity_type TEXT NOT NULL DEFAULT 'individual',
  tax_settings TEXT
);
CREATE INDEX IF NOT EXISTS idx_businesses_workspace ON businesses(workspace_id);

CREATE TABLE IF NOT EXISTS accounts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  workspace_id INTEGER NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  category TEXT NOT NULL,
  name TEXT NOT NULL,
  order_num INTEGER NOT NULL DEFAULT 0,
  parent_id INTEGER REFERENCES accounts(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_accounts_workspace ON accounts(workspace_id);

CREATE TABLE IF NOT EXISTS entries (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  workspace_id INTEGER NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  business_id INTEGER NOT NULL REFERENCES businesses(id) ON DELETE CASCADE,
  account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  month TEXT NOT NULL,
  kind TEXT NOT NULL,
  amount REAL NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_entries_workspace ON entries(workspace_id);
CREATE INDEX IF NOT EXISTS idx_entries_biz_month ON entries(workspace_id, business_id, month);

CREATE TABLE IF NOT EXISTS settings (
  workspace_id INTEGER PRIMARY KEY REFERENCES workspaces(id) ON DELETE CASCADE,
  tool_name TEXT,
  logo_data_url TEXT
);

-- Per-business member access control. A business with NO rows here is open
-- to every workspace member (backward-compatible default). Once at least one
-- row exists for a business, only the workspace owner and the listed users
-- can see/manage that business's data.
CREATE TABLE IF NOT EXISTS business_members (
  business_id INTEGER NOT NULL REFERENCES businesses(id) ON DELETE CASCADE,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (business_id, user_id)
);
CREATE INDEX IF NOT EXISTS idx_business_members_business ON business_members(business_id);
CREATE INDEX IF NOT EXISTS idx_business_members_user ON business_members(user_id);
