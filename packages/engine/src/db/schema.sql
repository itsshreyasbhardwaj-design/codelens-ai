-- CodeLens AI schema.
--
-- Portable SQL: integer/text keys, explicit foreign keys, no engine-specific
-- column types. Runs on SQLite (default) and PostgreSQL with the edits in
-- docs/ARCHITECTURE.md#postgres-migration.
--
-- Cascade policy:
--   organization -> project        RESTRICT  (deleting an org must be deliberate)
--   project      -> everything     CASCADE   (project deletion is a user right)
-- Secrets are never stored in plaintext: see repository_connections.

PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS schema_migrations (
  version     INTEGER PRIMARY KEY,
  applied_at  TEXT NOT NULL
);

-- ---------------------------------------------------------------- identity --

CREATE TABLE IF NOT EXISTS users (
  id             TEXT PRIMARY KEY,
  email          TEXT NOT NULL UNIQUE,
  display_name   TEXT,
  password_hash  TEXT,                     -- argon2id/scrypt output, never plaintext
  created_at     TEXT NOT NULL,
  updated_at     TEXT NOT NULL,
  last_login_at  TEXT
);

CREATE TABLE IF NOT EXISTS organizations (
  id          TEXT PRIMARY KEY,
  name        TEXT NOT NULL,
  slug        TEXT NOT NULL UNIQUE,
  created_at  TEXT NOT NULL,
  updated_at  TEXT NOT NULL,
  retention_days INTEGER NOT NULL DEFAULT 30
);

CREATE TABLE IF NOT EXISTS organization_members (
  id              TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role            TEXT NOT NULL CHECK (role IN ('owner','admin','member','viewer')),
  created_at      TEXT NOT NULL,
  UNIQUE (organization_id, user_id)
);
CREATE INDEX IF NOT EXISTS idx_org_members_user ON organization_members(user_id);

-- ---------------------------------------------------------------- projects --

CREATE TABLE IF NOT EXISTS projects (
  id              TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
  name            TEXT NOT NULL,
  slug            TEXT NOT NULL,
  kind            TEXT NOT NULL CHECK (kind IN ('source','website')) DEFAULT 'source',
  created_by      TEXT REFERENCES users(id) ON DELETE SET NULL,
  created_at      TEXT NOT NULL,
  updated_at      TEXT NOT NULL,
  deleted_at      TEXT,
  UNIQUE (organization_id, slug)
);
CREATE INDEX IF NOT EXISTS idx_projects_org ON projects(organization_id);

CREATE TABLE IF NOT EXISTS repository_connections (
  id              TEXT PRIMARY KEY,
  project_id      TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  provider        TEXT NOT NULL CHECK (provider IN ('github','gitlab','local','zip','url')),
  remote_id       TEXT,
  full_name       TEXT,
  default_branch  TEXT,
  is_private      INTEGER NOT NULL DEFAULT 0,
  -- Provider credentials are stored encrypted (AES-256-GCM) or not at all.
  token_ciphertext TEXT,
  token_nonce      TEXT,
  token_scopes     TEXT,
  granted_at      TEXT,
  revoked_at      TEXT,
  created_at      TEXT NOT NULL,
  UNIQUE (project_id, provider, remote_id)
);

CREATE TABLE IF NOT EXISTS repository_snapshots (
  id              TEXT PRIMARY KEY,
  project_id      TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  connection_id   TEXT REFERENCES repository_connections(id) ON DELETE SET NULL,
  source_kind     TEXT NOT NULL CHECK (source_kind IN ('github','zip','local','url','website')),
  commit_sha      TEXT,
  branch          TEXT,
  -- Content hash of the normalised file set: two snapshots with the same
  -- content_hash are genuinely comparable, which gates scan comparison.
  content_hash    TEXT NOT NULL,
  file_count      INTEGER NOT NULL DEFAULT 0,
  total_bytes     INTEGER NOT NULL DEFAULT 0,
  artifact_path   TEXT,
  ingested_at     TEXT NOT NULL,
  expires_at      TEXT,
  UNIQUE (project_id, content_hash)
);
CREATE INDEX IF NOT EXISTS idx_snapshots_project ON repository_snapshots(project_id, ingested_at);

CREATE TABLE IF NOT EXISTS project_files (
  id              TEXT PRIMARY KEY,
  snapshot_id     TEXT NOT NULL REFERENCES repository_snapshots(id) ON DELETE CASCADE,
  path            TEXT NOT NULL,
  language        TEXT,
  role            TEXT NOT NULL,
  bytes           INTEGER NOT NULL,
  lines           INTEGER NOT NULL,
  sha256          TEXT NOT NULL,
  parsed          INTEGER NOT NULL DEFAULT 0,
  unparsed_reason TEXT,
  generated       INTEGER NOT NULL DEFAULT 0,
  vendored        INTEGER NOT NULL DEFAULT 0,
  UNIQUE (snapshot_id, path)
);
CREATE INDEX IF NOT EXISTS idx_files_snapshot_role ON project_files(snapshot_id, role);
CREATE INDEX IF NOT EXISTS idx_files_language ON project_files(snapshot_id, language);

-- ------------------------------------------------------------------- scans --

CREATE TABLE IF NOT EXISTS scan_jobs (
  id               TEXT PRIMARY KEY,
  project_id       TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  snapshot_id      TEXT REFERENCES repository_snapshots(id) ON DELETE CASCADE,
  -- Idempotency: re-submitting the same key returns the existing job instead
  -- of starting a duplicate scan.
  idempotency_key  TEXT NOT NULL,
  status           TEXT NOT NULL CHECK (status IN ('queued','running','completed','partial','failed','cancelled')),
  requested_by     TEXT REFERENCES users(id) ON DELETE SET NULL,
  ai_provider      TEXT NOT NULL DEFAULT 'none',
  dynamic_verify   INTEGER NOT NULL DEFAULT 0,
  coverage_json    TEXT,
  error_message    TEXT,
  cancel_requested INTEGER NOT NULL DEFAULT 0,
  queued_at        TEXT NOT NULL,
  started_at       TEXT,
  finished_at      TEXT,
  UNIQUE (project_id, idempotency_key)
);
CREATE INDEX IF NOT EXISTS idx_scans_project ON scan_jobs(project_id, queued_at);
CREATE INDEX IF NOT EXISTS idx_scans_status ON scan_jobs(status);

CREATE TABLE IF NOT EXISTS scan_stages (
  id           TEXT PRIMARY KEY,
  scan_id      TEXT NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
  name         TEXT NOT NULL,
  ordinal      INTEGER NOT NULL,
  status       TEXT NOT NULL CHECK (status IN ('pending','running','completed','failed','skipped','cancelled')),
  attempts     INTEGER NOT NULL DEFAULT 0,
  message      TEXT,
  warnings_json TEXT,
  started_at   TEXT,
  finished_at  TEXT,
  duration_ms  INTEGER,
  UNIQUE (scan_id, name)
);
CREATE INDEX IF NOT EXISTS idx_stages_scan ON scan_stages(scan_id, ordinal);

CREATE TABLE IF NOT EXISTS analysis_artifacts (
  id          TEXT PRIMARY KEY,
  scan_id     TEXT NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
  kind        TEXT NOT NULL,
  path        TEXT,
  payload_json TEXT,
  bytes       INTEGER,
  created_at  TEXT NOT NULL,
  UNIQUE (scan_id, kind)
);

-- ------------------------------------------------- detection & architecture --

CREATE TABLE IF NOT EXISTS tech_detections (
  id             TEXT PRIMARY KEY,
  scan_id        TEXT NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
  kind           TEXT NOT NULL,
  name           TEXT NOT NULL,
  version        TEXT,
  confidence     REAL NOT NULL,
  analysis_depth TEXT NOT NULL CHECK (analysis_depth IN ('deep','shallow','detected_only')),
  evidence_json  TEXT NOT NULL,
  UNIQUE (scan_id, kind, name)
);

CREATE TABLE IF NOT EXISTS architecture_components (
  id          TEXT PRIMARY KEY,
  scan_id     TEXT NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
  key         TEXT NOT NULL,
  name        TEXT NOT NULL,
  kind        TEXT NOT NULL,
  provenance  TEXT NOT NULL CHECK (provenance IN ('detected','inferred')),
  files_json  TEXT NOT NULL,
  summary     TEXT,
  UNIQUE (scan_id, key)
);

CREATE TABLE IF NOT EXISTS architecture_relationships (
  id            TEXT PRIMARY KEY,
  scan_id       TEXT NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
  from_key      TEXT NOT NULL,
  to_key        TEXT NOT NULL,
  kind          TEXT NOT NULL,
  provenance    TEXT NOT NULL CHECK (provenance IN ('detected','inferred')),
  evidence_json TEXT NOT NULL,
  UNIQUE (scan_id, from_key, to_key, kind)
);
CREATE INDEX IF NOT EXISTS idx_rel_scan_from ON architecture_relationships(scan_id, from_key);

CREATE TABLE IF NOT EXISTS api_endpoints (
  id             TEXT PRIMARY KEY,
  scan_id        TEXT NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
  method         TEXT NOT NULL,
  path           TEXT NOT NULL,
  file           TEXT NOT NULL,
  line           INTEGER,
  handler_symbol TEXT,
  auth_required  TEXT NOT NULL CHECK (auth_required IN ('required','public','unknown')),
  authorization_checks_json TEXT NOT NULL DEFAULT '[]',
  request_shape  TEXT,
  response_shape TEXT,
  validation     TEXT NOT NULL DEFAULT 'unknown',
  error_handling TEXT NOT NULL DEFAULT 'unknown',
  UNIQUE (scan_id, method, path, file)
);

CREATE TABLE IF NOT EXISTS data_models (
  id             TEXT PRIMARY KEY,
  scan_id        TEXT NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
  name           TEXT NOT NULL,
  file           TEXT NOT NULL,
  kind           TEXT NOT NULL,
  fields_json    TEXT NOT NULL,
  relations_json TEXT NOT NULL,
  indexes_json   TEXT NOT NULL,
  ownership_field TEXT,
  UNIQUE (scan_id, name, file)
);

CREATE TABLE IF NOT EXISTS feature_inventory (
  id                 TEXT PRIMARY KEY,
  scan_id            TEXT NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
  key                TEXT NOT NULL,
  name               TEXT NOT NULL,
  intended_function  TEXT NOT NULL,
  status             TEXT NOT NULL,
  frontend_files_json TEXT NOT NULL DEFAULT '[]',
  backend_files_json  TEXT NOT NULL DEFAULT '[]',
  database_deps_json  TEXT NOT NULL DEFAULT '[]',
  external_services_json TEXT NOT NULL DEFAULT '[]',
  auth_requirement   TEXT NOT NULL DEFAULT 'unknown',
  evidence_json      TEXT NOT NULL DEFAULT '[]',
  tests_json         TEXT NOT NULL DEFAULT '[]',
  possible_defects_json TEXT NOT NULL DEFAULT '[]',
  UNIQUE (scan_id, key)
);

-- ---------------------------------------------------------------- findings --

CREATE TABLE IF NOT EXISTS diagnostic_findings (
  id                TEXT PRIMARY KEY,
  scan_id           TEXT NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
  project_id        TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  display_id        TEXT NOT NULL,
  fingerprint       TEXT NOT NULL,
  rule_id           TEXT NOT NULL,
  title             TEXT NOT NULL,
  category          TEXT NOT NULL,
  severity          TEXT NOT NULL CHECK (severity IN ('critical','high','medium','low','info')),
  confidence        TEXT NOT NULL CHECK (confidence IN ('confirmed','strong','moderate','weak')),
  status            TEXT NOT NULL,
  detection_source  TEXT NOT NULL,
  priority          TEXT CHECK (priority IN ('P0','P1','P2','P3')),
  priority_score    REAL,
  priority_rationale TEXT,
  files_json        TEXT NOT NULL,
  explanation       TEXT NOT NULL,
  user_impact       TEXT NOT NULL,
  likely_root_cause TEXT,
  downstream_json   TEXT NOT NULL DEFAULT '[]',
  remediation       TEXT NOT NULL,
  effort            TEXT NOT NULL,
  related_tests_json TEXT NOT NULL DEFAULT '[]',
  verification_steps_json TEXT NOT NULL DEFAULT '[]',
  related_findings_json TEXT NOT NULL DEFAULT '[]',
  references_json   TEXT NOT NULL DEFAULT '[]',
  affected_features_json TEXT NOT NULL DEFAULT '[]',
  trace_json        TEXT,
  first_detected_commit  TEXT,
  first_detected_scan_id TEXT,
  created_at        TEXT NOT NULL,
  UNIQUE (scan_id, fingerprint)
);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON diagnostic_findings(scan_id, severity);
CREATE INDEX IF NOT EXISTS idx_findings_fp ON diagnostic_findings(project_id, fingerprint);
CREATE INDEX IF NOT EXISTS idx_findings_priority ON diagnostic_findings(scan_id, priority);

CREATE TABLE IF NOT EXISTS finding_evidence (
  id          TEXT PRIMARY KEY,
  finding_id  TEXT NOT NULL REFERENCES diagnostic_findings(id) ON DELETE CASCADE,
  file        TEXT NOT NULL,
  start_line  INTEGER,
  end_line    INTEGER,
  symbol      TEXT,
  excerpt     TEXT,
  note        TEXT,
  verified    INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_evidence_finding ON finding_evidence(finding_id);

-- One row per (project, fingerprint, scan): the history of a single problem.
CREATE TABLE IF NOT EXISTS finding_occurrences (
  id           TEXT PRIMARY KEY,
  project_id   TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  fingerprint  TEXT NOT NULL,
  scan_id      TEXT NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
  severity     TEXT NOT NULL,
  confidence   TEXT NOT NULL,
  status       TEXT NOT NULL,
  observed_at  TEXT NOT NULL,
  UNIQUE (project_id, fingerprint, scan_id)
);
CREATE INDEX IF NOT EXISTS idx_occurrences_fp ON finding_occurrences(project_id, fingerprint, observed_at);

CREATE TABLE IF NOT EXISTS scan_scores (
  id             TEXT PRIMARY KEY,
  scan_id        TEXT NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
  dimension      TEXT NOT NULL,
  score          REAL,
  grade          TEXT NOT NULL,
  weight         REAL NOT NULL,
  penalty        REAL NOT NULL DEFAULT 0,
  reason         TEXT,
  counts_json    TEXT NOT NULL DEFAULT '{}',
  UNIQUE (scan_id, dimension)
);

-- -------------------------------------------------------------- fix packs --

CREATE TABLE IF NOT EXISTS fix_packs (
  id            TEXT PRIMARY KEY,
  scan_id       TEXT NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
  key           TEXT NOT NULL,
  title         TEXT NOT NULL,
  category      TEXT NOT NULL,
  ordinal       INTEGER NOT NULL,
  objective     TEXT NOT NULL,
  effort        TEXT NOT NULL,
  -- Keys of packs that must be applied before this one.
  depends_on_json TEXT NOT NULL DEFAULT '[]',
  baseline_commit TEXT,
  applied_at    TEXT,
  created_at    TEXT NOT NULL,
  UNIQUE (scan_id, key)
);

CREATE TABLE IF NOT EXISTS fix_pack_findings (
  id          TEXT PRIMARY KEY,
  fix_pack_id TEXT NOT NULL REFERENCES fix_packs(id) ON DELETE CASCADE,
  finding_id  TEXT NOT NULL REFERENCES diagnostic_findings(id) ON DELETE CASCADE,
  UNIQUE (fix_pack_id, finding_id)
);

CREATE TABLE IF NOT EXISTS fix_pack_versions (
  id            TEXT PRIMARY KEY,
  fix_pack_id   TEXT NOT NULL REFERENCES fix_packs(id) ON DELETE CASCADE,
  version       INTEGER NOT NULL,
  agent_format  TEXT NOT NULL CHECK (agent_format IN ('claude_code','codex','generic')),
  prompt_markdown TEXT NOT NULL,
  validation_json TEXT NOT NULL DEFAULT '{}',
  created_at    TEXT NOT NULL,
  UNIQUE (fix_pack_id, version, agent_format)
);

CREATE TABLE IF NOT EXISTS remediation_attempts (
  id            TEXT PRIMARY KEY,
  fix_pack_id   TEXT NOT NULL REFERENCES fix_packs(id) ON DELETE CASCADE,
  attempted_by  TEXT REFERENCES users(id) ON DELETE SET NULL,
  outcome       TEXT NOT NULL CHECK (outcome IN ('pending','applied','partially_applied','abandoned','failed')),
  notes         TEXT,
  resulting_scan_id TEXT REFERENCES scan_jobs(id) ON DELETE SET NULL,
  created_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS verification_results (
  id          TEXT PRIMARY KEY,
  scan_id     TEXT NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
  kind        TEXT NOT NULL,
  command     TEXT,
  exit_code   INTEGER,
  passed      INTEGER,
  -- Truncated, secret-redacted output.
  output_excerpt TEXT,
  duration_ms INTEGER,
  created_at  TEXT NOT NULL
);

-- ------------------------------------------------------- chat, usage, audit --

CREATE TABLE IF NOT EXISTS chat_sessions (
  id          TEXT PRIMARY KEY,
  project_id  TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  scan_id     TEXT REFERENCES scan_jobs(id) ON DELETE SET NULL,
  user_id     TEXT REFERENCES users(id) ON DELETE SET NULL,
  title       TEXT,
  created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS chat_messages (
  id          TEXT PRIMARY KEY,
  session_id  TEXT NOT NULL REFERENCES chat_sessions(id) ON DELETE CASCADE,
  role        TEXT NOT NULL CHECK (role IN ('user','assistant','system')),
  content     TEXT NOT NULL,
  citations_json TEXT NOT NULL DEFAULT '[]',
  tokens_in   INTEGER,
  tokens_out  INTEGER,
  created_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_chat_messages_session ON chat_messages(session_id, created_at);

CREATE TABLE IF NOT EXISTS usage_records (
  id              TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  project_id      TEXT REFERENCES projects(id) ON DELETE SET NULL,
  scan_id         TEXT REFERENCES scan_jobs(id) ON DELETE SET NULL,
  kind            TEXT NOT NULL,
  provider        TEXT,
  model           TEXT,
  tokens_in       INTEGER NOT NULL DEFAULT 0,
  tokens_out      INTEGER NOT NULL DEFAULT 0,
  requests        INTEGER NOT NULL DEFAULT 0,
  created_at      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_usage_org ON usage_records(organization_id, created_at);

CREATE TABLE IF NOT EXISTS audit_logs (
  id              TEXT PRIMARY KEY,
  organization_id TEXT REFERENCES organizations(id) ON DELETE SET NULL,
  actor_user_id   TEXT REFERENCES users(id) ON DELETE SET NULL,
  action          TEXT NOT NULL,
  target_kind     TEXT,
  target_id       TEXT,
  detail_json     TEXT,
  ip_address      TEXT,
  created_at      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_org ON audit_logs(organization_id, created_at);
