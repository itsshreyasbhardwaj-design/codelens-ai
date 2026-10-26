-- Migration 002 — subscriptions, credits, and payment records.
--
-- Money-adjacent values are INTEGER only: credits are whole units and prices
-- are minor units (cents/paise). No floating point touches a balance.
--
-- The ledger is the audit trail and `credit_accounts.balance` is the working
-- figure. Both are written inside one transaction, so they cannot drift; the
-- ledger carries `balance_after` so any drift would be provable after the fact.

CREATE TABLE IF NOT EXISTS subscription_plans (
  id               TEXT PRIMARY KEY,
  code             TEXT NOT NULL UNIQUE,
  name             TEXT NOT NULL,
  -- Minor units. 0 for the free plan; NULL means "contact us".
  price_cents      INTEGER,
  currency         TEXT NOT NULL DEFAULT 'usd',
  interval         TEXT NOT NULL CHECK (interval IN ('month','year','once','none')),
  -- NULL on any limit means unbounded.
  projects_limit   INTEGER,
  scans_per_month  INTEGER,
  monthly_credits  INTEGER NOT NULL DEFAULT 0,
  seats            INTEGER NOT NULL DEFAULT 1,
  max_repo_mb      INTEGER,
  features_json    TEXT NOT NULL DEFAULT '[]',
  sort_order       INTEGER NOT NULL DEFAULT 0,
  active           INTEGER NOT NULL DEFAULT 1,
  created_at       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS subscriptions (
  id                       TEXT PRIMARY KEY,
  organization_id          TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  plan_id                  TEXT NOT NULL REFERENCES subscription_plans(id) ON DELETE RESTRICT,
  status                   TEXT NOT NULL CHECK (status IN ('active','trialing','past_due','canceled','incomplete')),
  provider                 TEXT,
  provider_subscription_id TEXT,
  current_period_start     TEXT,
  current_period_end       TEXT,
  cancel_at_period_end     INTEGER NOT NULL DEFAULT 0,
  created_at               TEXT NOT NULL,
  updated_at               TEXT NOT NULL,
  UNIQUE (provider, provider_subscription_id)
);
-- One active subscription per organisation. A partial index keeps cancelled
-- rows around as history without blocking a new one.
CREATE UNIQUE INDEX IF NOT EXISTS idx_sub_one_active
  ON subscriptions(organization_id) WHERE status IN ('active','trialing','past_due');

CREATE TABLE IF NOT EXISTS one_time_purchases (
  id                  TEXT PRIMARY KEY,
  organization_id     TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  product_code        TEXT NOT NULL,
  amount_cents        INTEGER NOT NULL,
  currency            TEXT NOT NULL DEFAULT 'usd',
  credits_granted     INTEGER NOT NULL DEFAULT 0,
  provider            TEXT,
  provider_payment_id TEXT,
  status              TEXT NOT NULL CHECK (status IN ('pending','paid','failed','refunded')),
  created_at          TEXT NOT NULL,
  UNIQUE (provider, provider_payment_id)
);

CREATE TABLE IF NOT EXISTS credit_accounts (
  organization_id   TEXT PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
  balance           INTEGER NOT NULL DEFAULT 0 CHECK (balance >= 0),
  lifetime_granted  INTEGER NOT NULL DEFAULT 0,
  lifetime_spent    INTEGER NOT NULL DEFAULT 0,
  -- Start of the period the monthly allowance was last granted for.
  period_started_at TEXT,
  updated_at        TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS credit_ledger (
  id              TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  -- Positive grants, negative spends. Never zero.
  delta           INTEGER NOT NULL CHECK (delta <> 0),
  balance_after   INTEGER NOT NULL,
  reason          TEXT NOT NULL,
  scan_id         TEXT REFERENCES scan_jobs(id) ON DELETE SET NULL,
  reservation_id  TEXT,
  -- Makes every mutation replay-safe: a retried webhook or a duplicated job
  -- cannot double-charge or double-grant.
  idempotency_key TEXT NOT NULL UNIQUE,
  created_at      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ledger_org ON credit_ledger(organization_id, created_at);

CREATE TABLE IF NOT EXISTS credit_reservations (
  id              TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  scan_id         TEXT REFERENCES scan_jobs(id) ON DELETE SET NULL,
  amount          INTEGER NOT NULL CHECK (amount > 0),
  status          TEXT NOT NULL CHECK (status IN ('held','settled','released')),
  settled_amount  INTEGER,
  idempotency_key TEXT NOT NULL UNIQUE,
  created_at      TEXT NOT NULL,
  settled_at      TEXT
);
CREATE INDEX IF NOT EXISTS idx_reservations_org ON credit_reservations(organization_id, status);

CREATE TABLE IF NOT EXISTS payment_events (
  id                TEXT PRIMARY KEY,
  provider          TEXT NOT NULL,
  -- The provider's own event id. UNIQUE is the replay guard: a redelivered
  -- webhook is recorded once and processed once.
  provider_event_id TEXT NOT NULL,
  type              TEXT NOT NULL,
  payload_json      TEXT NOT NULL,
  signature_verified INTEGER NOT NULL DEFAULT 0,
  processed_at      TEXT,
  error             TEXT,
  created_at        TEXT NOT NULL,
  UNIQUE (provider, provider_event_id)
);

CREATE TABLE IF NOT EXISTS refunds (
  id                 TEXT PRIMARY KEY,
  organization_id    TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  provider           TEXT NOT NULL,
  provider_refund_id TEXT,
  amount_cents       INTEGER NOT NULL,
  reason             TEXT,
  created_at         TEXT NOT NULL,
  UNIQUE (provider, provider_refund_id)
);

CREATE TABLE IF NOT EXISTS notifications (
  id              TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  user_id         TEXT REFERENCES users(id) ON DELETE CASCADE,
  kind            TEXT NOT NULL,
  title           TEXT NOT NULL,
  body            TEXT,
  link            TEXT,
  read_at         TEXT,
  created_at      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_notifications_org ON notifications(organization_id, created_at);

-- Which plan an organisation is on without a subscription row (the free plan).
ALTER TABLE organizations ADD COLUMN plan_code TEXT NOT NULL DEFAULT 'free';
