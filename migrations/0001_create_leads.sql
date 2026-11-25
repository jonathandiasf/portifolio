CREATE TABLE IF NOT EXISTS leads (
  id TEXT PRIMARY KEY NOT NULL,
  name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 120),
  email TEXT NOT NULL CHECK (length(email) BETWEEN 3 AND 254),
  organization TEXT CHECK (organization IS NULL OR length(organization) <= 160),
  project_type TEXT NOT NULL,
  timeline TEXT,
  details TEXT NOT NULL CHECK (length(details) BETWEEN 20 AND 2000),
  consented_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_leads_created_at ON leads (created_at DESC);
