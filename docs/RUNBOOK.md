# Operational Runbook

## Running it

```bash
pnpm install          # Node 24+ and pnpm. No other prerequisite.
pnpm scan <path>      # scan a local project
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
| `CODELENS_SECRET_KEY` | unset | 32+ chars. Required to store provider tokens at all |
| `CODELENS_DB` | `.codelens/codelens.db` | database path |
| `CODELENS_RETENTION_DAYS` | `30` | artifact retention |
| `GITHUB_TOKEN` | unset | read-only token for private repositories |
| `CODELENS_DYNAMIC_VERIFY` | `off` | see the limitation below |

## Deploying safely

CodeLens processes other people's source code. If you host it for anyone but
yourself, these are not optional:

1. **Implement authentication first.** This release has none (`docs/STATUS.md`).
   Tenant isolation is enforced in the data layer, but without identity there is
   nothing to isolate.
2. **Set `CODELENS_SECRET_KEY`** to a 32+ character secret from a secrets
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

Set `CODELENS_RETENTION_DAYS` and prune snapshots past
`repository_snapshots.expires_at`. Derived analysis is removed with its scan.

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
