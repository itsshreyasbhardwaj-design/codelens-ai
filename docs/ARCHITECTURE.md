# Architecture

## Shape of the system

Four packages with one-way dependencies:

```
@codelens/core     contracts, scoring, prioritisation, consolidation   (zero dependencies)
       ▲
@codelens/engine   db · ingest · parse · graph · detect · analyzers ·
                   ai · fixpacks · pipeline · reports · eval            (depends on: typescript)
       ▲
   ┌───┴────┐
@codelens/cli   @codelens/web                                          (web depends on: next, react)
```

`core` holds the contracts and the pure functions that must be reproducible:
the findings model, fingerprinting, the scoring rules, the prioritisation
weights, and the evidence-discipline gate. It has no dependencies at all, so
those rules can be reasoned about and tested in isolation.

`engine` is one package with enforced internal module boundaries rather than
twelve publishable packages (ADR-006). Each directory is a seam that could
become a service; none is one yet.

## The 12-stage pipeline

`packages/engine/src/pipeline/orchestrator.ts`. Every stage records its real
status, duration, attempt count, and warnings.

| # | Stage | Required | Retries |
| --- | --- | --- | --- |
| 1 | Ingestion validation | yes | 2 |
| 2 | Source normalisation | yes | 2 |
| 3 | Technology detection | yes | 2 |
| 4 | Code indexing | yes | 2 |
| 5 | Deterministic diagnostics | yes | 1 |
| 6 | Architecture reconstruction | yes | 2 |
| 7 | Dynamic verification | **optional** | 1 |
| 8 | AI semantic investigation | **optional** | 2 |
| 9 | Finding consolidation | yes | 1 |
| 10 | Risk prioritisation | yes | 1 |
| 11 | Fix Pack generation | yes | 1 |
| 12 | Report generation | yes | 1 |

Stage 6 runs before stage 5 in execution order, because the analyzers read the
repository map. The numbering follows the brief; the dependency decides the
order.

Rules that keep a partial scan honest:

- An **optional** stage that fails or is skipped degrades the scan to `partial`
  and never discards the other eleven stages' work.
- A **required** stage that fails ends the scan, and every later stage is marked
  `skipped` with the reason, so the UI cannot imply work that did not happen.
- Cancellation is checked between stages; a cancelled scan records where it
  stopped.
- `idempotencyKey` makes a resubmission return the same scan id instead of
  starting a duplicate.
- `LayerCompletion` is reported from what actually completed, never assumed.

## The four analysis layers

**Layer A — deterministic static analysis.** Parsers, rules, and scanners. No
model, no execution. Reproducible: the same snapshot yields the same findings.

**Layer B — architecture and relationship analysis.** The repository map:
resolved imports, routes with their auth posture, data models with their
ownership columns, the environment-variable map, components, relationships, and
the feature inventory. This is where the cross-file findings come from — the
ones no single file reveals.

**Layer C — AI semantic investigation.** Off by default. Investigates the
specific questions Layers A and B could not settle, over retrieved evidence.
Bounded on every axis: which questions (chosen deterministically), how much
context each gets, total token spend, and what is allowed through afterwards.

**Layer D — dynamic verification.** Off by default, and refuses project
dependency installation and build scripts (ADR-005). Without container
isolation this host cannot safely execute untrusted code, so it does not pretend
to.

## Evidence discipline

The gate that separates this from a model writing plausible prose, in
`packages/core/src/consolidate.ts`:

1. A finding with no evidence is **refused**.
2. An AI-sourced finding whose cited evidence could not be verified is
   **refused** — its only support was the model's own assertion.
3. No verified evidence from any source **caps confidence at `moderate`**.
4. An incomplete relationship trace **caps confidence at `moderate`**.
5. Status is then re-derived from the final confidence.

The gate can only ever lower confidence. Refused findings are reported in the
scan output rather than silently dropped.

For model output specifically (`packages/engine/src/ai/verify.ts`): the response
must match a schema, the cited file must exist in the snapshot, and the quoted
line must be located in that file. A model may never assert `confirmed`; the
ceiling for an AI finding is `strong`, and only when the quote was where it said.

## Scoring

`packages/core/src/scoring.ts`. Every number comes from counted findings and
measured coverage; there is no model-generated score anywhere.

Penalty per finding is `severityPenalty × confidenceWeight`, summed per
dimension, subtracted from 100. Dimension weights follow the brief
(security 25%, reliability 20%, architecture 15%, performance 10%,
scalability 10%, testing 10%, accessibility 5%, deployment 5%) and are
configurable product weights, not scientific guarantees.

Two gates stop a score from being reassuring when it should not be:

- A dimension whose analyzers did not run returns `insufficient_evidence`.
- A dimension with no findings **and** parse coverage below 40% also returns
  `insufficient_evidence` — "no findings" means nothing if the code was not read.

The overall score is renormalised over gradeable dimensions, so missing coverage
does not read as a perfect score in those areas. When under half the total
weight is gradeable, the overall score is withheld entirely.

## Prioritisation

`packages/core/src/prioritize.ts`. Ten factors with published weights, and a
written rationale per finding. Banding is gated: **an unverified finding never
reaches P0**, however severe it would be if real. Prerequisites are lifted above
the findings they block, so the roadmap is executable top to bottom.

## Fix Pack generation

Grouping (`fixpacks/grouping.ts`) assigns each finding to exactly one pack
family, splits an oversized family along file clusters so each pack stays
reviewable, and declares cross-family prerequisites — authorisation before
anything built on it, behaviour before the tests that assert it, tests before
gating a pipeline on them.

Prompt generation (`fixpacks/prompt.ts`) produces the ten required sections and
labels every finding with its confidence, so the agent knows what is confirmed
and what it must verify first.

Validation (`fixpacks/validate.ts`) runs twelve checks before a prompt is shown.
An error-level issue **withholds the pack**; warnings are surfaced with it. The
destructive-operation check scans only the sections CodeLens itself writes:
section C quotes the audited repository verbatim, and reading a quotation as an
instruction once withheld an entirely valid pack.

## Data model

30 tables in `packages/engine/src/db/schema.sql`, covering identity,
organisations, projects, repository connections and snapshots, files, scan jobs
and stages, artifacts, technology detections, architecture components and
relationships, API endpoints, data models, the feature inventory, findings with
their evidence and occurrence history, scores, Fix Packs with their versions and
remediation attempts, verification results, chat sessions, usage metering, and
audit logs.

Cascade policy is deliberate: `organization → project` is `RESTRICT`, so
deleting an organisation must be an explicit act; `project → everything` is
`CASCADE`, because project deletion is a user right.

Provider credentials are stored as AES-256-GCM ciphertext. With no
`CODELENS_SECRET_KEY` configured, token storage is **refused** rather than
silently falling back to plaintext.

### Postgres migration

`schema.sql` is written in portable SQL and applies to PostgreSQL with three
mechanical edits:

1. Drop the `PRAGMA` lines (foreign keys and WAL are defaults or irrelevant).
2. `TEXT` timestamps become `TIMESTAMPTZ`; `INTEGER` booleans become `BOOLEAN`.
3. `INSERT OR REPLACE` becomes `INSERT … ON CONFLICT … DO UPDATE`.

All SQL lives behind the `Db` class in `packages/engine/src/db/`, so no caller
changes.

## Tenant isolation

`Db.assertProjectInOrg` raises the **same** "not found" error for a project in
another organisation as for one that does not exist, so existence is not leaked
across tenants. Every request-driven read path calls it first.

This release runs single-tenant and local, and **authentication is not
implemented** — see `docs/STATUS.md`. The isolation mechanism exists and is used;
the identity layer that would make it meaningful in a hosted deployment does not.

## Asynchronous execution

Scans never run inside a request handler. The web app registers a job, starts it
detached, and the client polls for live stage status. Job state lives in a
module-level map, which is correct for a single-process local deployment; a
multi-process deployment would read the `scan_jobs` / `scan_stages` tables the
orchestrator already writes.

## Observability

Structured per-stage timing, attempt counts, and warnings on every scan; analyzer
timings and per-analyzer error isolation; AI token metering written to
`usage_records`; audit entries for scan completion. Secret redaction
(`db/crypto.ts`) is applied before any captured output is stored.
