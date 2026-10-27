-- Whether a scan counts against the plan's monthly allowance.
--
-- `scansThisMonth` counted every row queued in the month with no status
-- predicate, so a scan that delivered nothing still spent one. The reachable
-- path is not exotic: a misspelled or private GitHub reference passes
-- `parseRepoRef`, `beginScan` writes the row, and ingestion then 404s. Two of
-- those and a Free account (two scans a month) is locked out until the 1st,
-- shown an upgrade prompt for an allowance it never got the benefit of.
--
-- `HOLDS_SLOT` in entitlements.ts already takes the opposite view for project
-- slots — a failed scan holds none — so the product was charging an allowance
-- for a scan it simultaneously agreed had produced nothing. This column
-- settles that disagreement in one place; both questions read it.
--
-- Default 1, so billing is the fail-closed case: a new failure path has to opt
-- out deliberately rather than becoming free by omission.
ALTER TABLE scan_jobs ADD COLUMN billable INTEGER NOT NULL DEFAULT 1;

-- Backfill only what the status already proves. A `failed` row never reached
-- `saveScan`: no snapshot, no findings, no scorecard were stored for it, so
-- nothing was delivered and nothing should have been charged.
--
-- `cancelled` is deliberately left billable. The customer stopped that scan,
-- and one cancelled at the end has consumed the same analysis as one that
-- finished — making it free would turn "cancel at 99%" into unmetered scanning,
-- which is the shape of the banked-rows exploit docs/STATUS.md already records.
UPDATE scan_jobs SET billable = 0 WHERE status = 'failed';
