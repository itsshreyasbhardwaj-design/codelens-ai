# Operational Runbook

## Running it

```bash
pnpm install          # Node 24+ and pnpm. No other prerequisite.
pnpm scan <path>      # scan a local project
pnpm codelens --help  # list, compare, eval
pnpm dev              # web interface on http://localhost:3100
pnpm verify           # type check and tests
pnpm eval             # diagnostic accuracy against the bundled fixture
```

There is no service to start. The database is a file; by default
`.codelens/codelens.db`, overridable with `--db` or `CODELENS_DB`.

## Configuration

Every variable is optional. With none set, CodeLens runs fully offline with
deterministic analysis only. See `.env.example`.

| Variable | Default | Effect |
| --- | --- | --- |
| `CODELENS_AI_PROVIDER` | `none` | `none` / `ollama` / `anthropic` / `openai` |
| `CODELENS_AI_MODEL` | per provider | model id |
| `CODELENS_AI_TOKEN_BUDGET` | `120000` | hard ceiling; the stage aborts rather than exceed it |
| `CODELENS_AI_ACCEPT_EXTERNAL_TRANSFER` | unset | required before `anthropic`/`openai` will run |
| `CODELENS_OLLAMA_URL` | `http://127.0.0.1:11434` | local model endpoint |
| `CODELENS_SECRET_KEY` | unset | 32+ chars. **Required by the web app** to sign sessions, and to store provider tokens at all |
| `CODELENS_DB` | `.codelens/codelens.db` | database path |
| ~~`CODELENS_RETENTION_DAYS`~~ | — | read by nothing; no retention is implemented (see below) |
| `GITHUB_TOKEN` | unset | read-only token for private repositories |
| `CODELENS_DYNAMIC_VERIFY` | `off` | see the limitation below |

## Deploying safely

CodeLens processes other people's source code. If you host it for anyone but
yourself, these are not optional:

1. **Set `CODELENS_SECRET_KEY`** to a 32+ character secret. The web app refuses
   to issue sessions without it, so this is not optional.
2. **Put a rate limiter in front of `/api/auth/login`.** There is none built in,
   and the product's own security analyzer reports that as a finding.
3. **Set `CODELENS_SECRET_KEY`** to a 32+ character secret from a secrets
   manager, or provider token storage will refuse to operate.
3. **Keep dynamic verification off.** It is off by default and refuses project
   build scripts. Do not enable it without real container isolation.
4. **Do not enable an external AI provider on behalf of a user** without
   disclosure and consent. `CODELENS_AI_ACCEPT_EXTERNAL_TRANSFER` is the gate.
5. **Run the web process with a read-only filesystem** apart from the database
   path and the artifact directory.
6. **Serve over HTTPS and keep the security headers.** The app sets CSP, HSTS
   posture, `nosniff`, frame denial, and a referrer policy in `next.config.ts`.
7. **Set a reverse-proxy body size limit** ahead of ZIP upload, in addition to
   the engine's own bounds.
8. **Bound concurrency.** One scan is CPU-heavy. Run one or two per core.

## Resource bounds

Enforced in `packages/engine/src/ingest/limits.ts`, all configurable:

| Bound | Default |
| --- | --- |
| Archive size | 256 MB |
| Total uncompressed | 2 GB |
| Per-file | 32 MB |
| Compression ratio | 200× |
| Entry count | 200,000 |
| Path depth | 40 |
| Parse size per file | 2 MB |

Exceeding a bound produces a **named rejection** (`compression_bomb`,
`path_traversal`, `archive_too_large`, …) that reaches the UI. Truncation is
never silent: `coverage.truncated` and its note say what was not read.

## Failure recovery

**A stage failed.** Read the stage's `message` in the report or the scan detail.
A required stage failing ends the scan with `status: failed` and marks later
stages `skipped`. An optional stage failing gives `status: partial` — the rest of
the scan is still valid, and coverage records what was missed.

**An analyzer failed.** The error is recorded, the analyzer is reported as
skipped with the reason, and scoring then refuses to grade the dimension it
feeds. Other analyzers are unaffected.

**Python files are unparsed.** No usable `python3` on `PATH`. They are reported
as unparsed with that reason and counted against parse coverage.

**A GitHub scan is rate limited.** The rejection says so. Set `GITHUB_TOKEN` to
raise the limit.

**A ZIP was rejected.** The code identifies which bound or safety rule stopped
it. These are deliberate refusals, not bugs.

**The AI stage was skipped.** Its reason is on the stage: no provider, no key, no
model, external transfer not acknowledged, or the token budget was exhausted
mid-run (in which case the warning says how many investigations were skipped).

**A Fix Pack is missing from the roadmap.** It failed validation and was
withheld. The reason is in the `fix_pack_generation` stage warnings.

## The database is three files, not one

In WAL mode SQLite keeps `codelens.db`, `codelens.db-wal` and `codelens.db-shm`.
They are one unit. Deleting or copying only `codelens.db` leaves a stale journal
beside a fresh database, and reads then return nothing with no error — the
symptom is an empty dashboard after a scan that clearly succeeded.

```bash
# Correct: remove or move all three
rm -f .codelens/codelens.db .codelens/codelens.db-wal .codelens/codelens.db-shm
```

A clean process exit checkpoints the WAL and removes the sidecars, so a database
at rest is usually a single file. Sidecars present means a process is using it or
was killed while using it.

## Data retention and deletion

Deleting a project cascades to its snapshots, files, scans, stages, findings,
evidence, scores, Fix Packs, and chat sessions. The organisation row is
`RESTRICT`-protected so an organisation cannot be removed by accident.

```sql
-- Verify what a project deletion would remove
SELECT 'findings', COUNT(*) FROM diagnostic_findings WHERE project_id = ?
UNION ALL SELECT 'scans', COUNT(*) FROM scan_jobs WHERE project_id = ?
UNION ALL SELECT 'snapshots', COUNT(*) FROM repository_snapshots WHERE project_id = ?;
```

**Nothing is pruned automatically.** There is no retention job, no cron and no
`DELETE` anywhere in the application; `CODELENS_RETENTION_DAYS`,
`organizations.retention_days` and `repository_snapshots.expires_at` are all
vestigial — `expires_at` is never written, so it is `NULL` on every row and a
prune keyed on it would match nothing and report success.

Prune by hand, by snapshot. `scan_jobs.snapshot_id` is
`ON DELETE CASCADE` (`schema.sql`), so deleting a snapshot takes its scans and
every derived table — findings, evidence, stages, scores, Fix Packs — with it.
One statement is enough.

Three details, each of which has been tested on a real database and each of
which silently does the wrong thing if you skip it:

1. **Compare with `julianday()`, not with `datetime()`.** Timestamps are stored
   as ISO-8601 with a `T` and a `Z` (`2026-10-27T05:15:49.438Z`), while
   `datetime('now','-30 days')` returns `2026-09-27 06:07:17` — a *string*
   comparison between the two is wrong whenever the date part matches, because
   `T` sorts after a space. `julianday()` parses the stored form correctly.
2. **In the `sqlite3` CLI, turn foreign keys on first.** The CLI defaults to
   `PRAGMA foreign_keys = 0`, and the delete below then removes the snapshot and
   **leaves its scans and findings orphaned** — observed: `snapshots=0` with
   `scans=1, findings=90` still present. `node:sqlite` has them on already.
3. **Back up with `VACUUM INTO` first** (see above), not by copying
   `codelens.db`. The main file can be 4 KB with everything in the WAL; a copy
   of it alone opens as an empty database that reports no such table.

```sql
PRAGMA foreign_keys = ON;   -- required in the sqlite3 CLI; see note 2

-- What a 30-day prune would remove
SELECT COUNT(*) AS snapshots FROM repository_snapshots
 WHERE julianday(ingested_at) < julianday('now') - 30;

DELETE FROM repository_snapshots
 WHERE julianday(ingested_at) < julianday('now') - 30;

VACUUM;                     -- or the file does not shrink
```

This is unrecoverable: there is no `down` migration and no undo.

## Reading a scan correctly

Three habits that prevent a report being over-read:

1. **Check coverage before trusting a clean result.** `analyzersSkipped`,
   `parseRatio`, and `layers` tell you what was actually examined.
2. **Read severity and confidence together.** A critical-but-suspected finding
   needs verification, not panic.
3. **On a comparison, read `unverifiedAbsences` before `resolved`.** A finding
   that stopped being reported because coverage shrank is listed separately and
   is not progress.

## Checks before a release

```bash
pnpm verify    # type check + full test suite
pnpm eval      # diagnostic recall and false positives against ground truth
```

`pnpm eval` exits non-zero if required-tier recall drops below 100% or any false
positive appears on a file declared clean, which makes a regression in diagnostic
quality a build failure rather than something noticed later.
