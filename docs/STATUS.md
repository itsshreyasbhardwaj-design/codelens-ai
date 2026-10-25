# Implementation Status

Written to be read before relying on anything here. Nothing in this document is
aspirational: a feature is listed as working only if it was executed and
observed, and the gaps are stated as plainly as the capabilities.

## Verified working

Each of these was run against real input and its output inspected.

**Ingestion.** Local directories, GitHub repositories (public and, with a
read-scoped token, private), and ZIP archives. The ZIP and tar readers are
written from scratch specifically so every bound is enforced at parse time:
path traversal, absolute and drive-letter paths, null bytes, symlinks,
decompression bombs by ratio, per-entry and total size caps, entry counts, CRC
mismatches, and lying size headers are each rejected with a named code.
Adversarial archives are built in-process by the test suite rather than
committed as fixtures.

**Parsing.** TypeScript, JavaScript, TSX and JSX via the TypeScript compiler
API; Python via the interpreter's own `ast` module through `python3 -I`.
Extracts imports, exports, symbols with line ranges, calls with loop and await
context, JSX elements with attributes, member accesses, object-literal shapes,
environment reads, string literals, and try/catch presence.

**Repository map.** Import resolution against the real file list; route
extraction for Next.js App Router, Next.js Pages API, Express-family routers and
FastAPI/Flask decorators, each with its authentication posture, authorisation
checks, validation state, error handling and response shape; Prisma, SQL DDL and
ORM model extraction including ownership columns and indexes; the
environment-variable map; architecture components and relationships with
detected-versus-inferred provenance; and the feature inventory with
evidence-based status.

**Ten diagnostic analyzers** — security, reliability, performance, scalability,
accessibility, code quality, testing, DevOps, cost, AI application — with 130
distinct rules. Measured against the bundled fixture's 69 documented defects:

| Category | Required-tier recall | False positives on clean files |
| --- | --- | --- |
| Security | 13/13 | 0 |
| Reliability | 8/8 | 0 |
| DevOps | 3/3 | 0 |
| Performance | 2/2 | 0 |
| Accessibility | 2/2 | 0 |
| Code quality | 1/1 | 0 |
| Testing | 1/1 | 0 |
| AI application | 2/2 | 0 |

All 69 ground-truth defects were detected (32 required, 37 bonus), with zero
false positives on files declared clean and zero findings lacking verified
evidence. Precision is reported as a *lower bound* of 77%, because a finding
matching nothing in the list may still be a real defect the list omits — see the
known weaknesses below. `pnpm eval` reproduces these
numbers and exits non-zero on a regression, so a drop in diagnostic quality
fails the build.

**Cross-file findings.** The ones no single file reveals, each with a traced
chain citing both ends: a frontend reading a response field the handler never
returns; a route that authenticates the caller and then loads a record by URL id
without comparing it to the ownership column; an exported integration with zero
importers; a query inside a loop; an index missing on a column that queries
actually filter on; a UI control with no backend action behind it.

**The evidence gate.** A finding with no evidence is refused; an AI finding
whose quoted line cannot be located in the snapshot is refused; unverifiable
evidence or an incomplete trace caps confidence at `moderate`. Refusals are
reported, not hidden.

**Scoring and prioritisation.** Rule-based, reproducible, with coverage gating
so an unassessed dimension reads *insufficient evidence* rather than a grade,
and an overall score withheld entirely when under half the weight is gradeable.
An unverified finding can never reach P0.

**Fix Packs.** Dependency-aware grouping, ten-section prompts in three agent
formats, and twelve pre-flight validation checks that withhold a pack rather
than ship a wrong prompt. Verified by generating all packs for the fixture and
reading them.

**Re-scan comparison.** Six defects were genuinely fixed in a copy of the
fixture and the result re-scanned: 8 findings verified as resolved, 2 correctly
reported as still present in edited code rather than fixed, 1 absence correctly
marked uncertain because its file was no longer indexed, and no false
regressions.

**AI layer.** Provider-agnostic across `none`/`ollama`/`anthropic`/`openai`,
disabled by default, with a hard token ceiling, nonce-fenced untrusted content,
a fixed system prompt that repository content never enters, and independent
verification of every model finding. Its safety properties are unit-tested; the
`anthropic` and `openai` adapters' HTTP paths have **not** been executed against
a live endpoint, because doing so would spend money.

**Persistence.** 30 tables on SQLite via `node:sqlite`. Scans, stages, findings,
evidence, occurrence history, scores, Fix Packs with their prompts, usage
metering, and audit entries all round-trip. Tenant isolation returns the same
error for another organisation's project as for a missing one.

**CLI.** `scan`, `eval`, `list`, `compare`. Reports in Markdown, JSON and
printable HTML.

**Web interface.** Landing page, dashboard with live stage-by-stage scan
progress, project overview with scorecard and coverage panel, architecture
explorer, findings explorer with full evidence inspection, Fix Studio, a
repository-aware question surface, and report exports.

**122 automated tests**, zero runtime test dependencies: Node's built-in test
runner and native TypeScript.

## Not implemented

Stated plainly rather than stubbed.

- **Authentication and multi-user access.** The schema models users,
  organisations, members and roles, and the data layer enforces tenant scoping,
  but there is no sign-in, no session, and no password handling. This release is
  single-tenant and local. **Do not host it for other people as it stands.**
- **Dynamic verification (Layer D).** Off by default, and it refuses project
  dependency installation and build scripts when enabled. Those are arbitrary
  code execution and this host has no container isolation. This is ADR-005: the
  decision is to refuse rather than pretend. Consequently nothing in any report
  is runtime-verified, and no report contains a measured timing, throughput or
  code-coverage figure.
- **Deployed-website observation mode.** The brief's separate external
  assessment mode (headers, TLS, client performance, observable accessibility)
  is not built. The data model reserves `projects.kind = 'website'` for it.
- **Agent-assisted remediation.** The optional workflow where CodeLens creates a
  branch, runs an agent and opens a pull request is not implemented. The
  remediation-attempt tables exist as the integration boundary. Fix Packs are
  applied outside CodeLens, by the user, which is the deliberate ordering: get
  diagnostics and prompts right before touching anyone's repository.
- **Third-party scanner integration.** Semgrep, CodeQL, Gitleaks and dependency
  advisory feeds are not wired in. Secret detection, injection analysis and
  dependency inspection are implemented natively instead, which keeps the
  default scan offline and free. The analyzer registry is where these would plug
  in.
- **Re-exporting a stored scan from the CLI.** `codelens report <scanId>` exits
  with an explanation. The Markdown and HTML renderers need the in-memory
  repository map, which is not persisted; re-run the scan to regenerate reports.
  The web app's export routes work from stored data.
- **Deep analysis beyond TypeScript, JavaScript and Python.** Other languages
  get structural and text-level analysis. Depth per language is published in
  `docs/SUPPORTED.md` and reported per scan.
- **Horizontal scaling of the web app.** In-flight job state lives in a
  module-level map, correct for one process. The orchestrator already persists
  stages, so a multi-process deployment would read those tables instead.

## How this was verified, and what was not

Verified by execution: the type checker and the 124-test suite (unit,
integration, and a single end-to-end journey test that ingests the fixture,
diagnoses it, generates and validates Fix Packs, exports every report format,
applies fixes, re-scans and compares); the accuracy harness; a production build
of the web app; and every page of that app loaded in a browser against a real
stored scan.

Not covered by automation:

- **No browser-driven end-to-end suite.** The web journey was verified by
  loading each page and reading what rendered, not by Playwright or similar.
  Adding one would mean a browser-automation dependency; the engine-level
  journey test covers the same flow headlessly.
- **No linter.** The project has no ESLint configuration. Style is held by the
  type checker and review. A linter would be worth adding before more people
  contribute.
- **The hosted AI adapters were never called.** The `anthropic` and `openai`
  HTTP paths are unit-tested for their guard conditions but have not been
  executed against a live endpoint, because that spends money. The `ollama`
  path and the `none` default are exercised.

## Known false positive, found by self-audit

Running CodeLens on CodeLens surfaced 111 findings. Ten reached P0; eight are in
`fixtures/vulnerable-shop/`, the deliberately defective demo project, and are
correct. **Two are false positives in this repository's own code**, and they are
the worst kind this product can produce — `critical` severity at `confirmed`
confidence:

- `security.injection.sql` at `packages/web/app/lib/store.ts:292` and `:467`.

Both interpolate `PRIORITY_ORDER`, a module-scope `const` holding a literal SQL
`CASE` fragment, into an `ORDER BY`. No user input reaches either site; the bound
values are passed as parameters. The rule flags any `${}` inside a query string
without asking whether the interpolated expression is a compile-time constant.

Interpolating a constant ordering fragment is a common and safe pattern, so this
will fire on real codebases. **The fix is in the rule, not the code**: resolve
each interpolated expression, and suppress the finding when every one of them is
an identifier bound to a module-scope string literal. It is not yet implemented.

Reported here rather than quietly silenced, because a tool that hides its own
false positives has no standing to ask anyone to trust its findings.

## Known weaknesses

- **Ground truth is one fixture.** Recall is measured against 69 documented
  defects in one deliberately defective Next.js/Prisma project. That is enough
  to catch regressions and nowhere near enough to characterise accuracy across
  ecosystems. Precision is reported only as a *lower bound* for exactly this
  reason: a finding matching no ground-truth entry may be a real defect the list
  omits.
- **Fingerprint sensitivity.** A finding's fingerprint includes its source
  excerpt, so two distinct problems from one rule in one file stay distinct. The
  cost is that editing the line changes the fingerprint. Comparison pairs these
  back up and reports them as *still present, in edited code*, but the pairing is
  by rule and file, so an edit that moves code between files will still read as
  resolved-plus-new.
- **`auth: unknown` is common in middleware-heavy projects.** Where enforcement
  lives in middleware CodeLens does not model, confidence is lowered and the
  note says so — but a project relying heavily on middleware will see more
  uncertainty than one enforcing in handlers.
- **Feature clustering is heuristic.** Features are grouped by resource name
  from routes, models and component paths. An unconventional layout will produce
  odd groupings.
- **Single-writer database.** SQLite is correct for one node. Concurrent scans
  work, but a multi-node deployment needs the PostgreSQL migration in
  `docs/ARCHITECTURE.md`.

## Suggested next improvements

In the order I would do them:

1. **Authentication**, before any hosted deployment. The isolation mechanism
   exists; the identity layer that makes it meaningful does not.
2. **A second and third ground-truth fixture** in different ecosystems — a
   Django/Postgres project and a Go service — to turn recall from a regression
   guard into a real accuracy measurement.
3. **Container-isolated dynamic verification**, which would unlock honest
   runtime findings, real coverage figures and build-failure detection. It is
   the single biggest capability gap.
4. **Deep support for one more language**, chosen by demand. The
   `ParsedModule` interface is parser-agnostic precisely for this.
5. **Incremental re-scan**, reusing parse results for unchanged files by content
   hash. The infrastructure is in place; a large monorepo would benefit most.
6. **Website observation mode**, which is self-contained and already has a place
   in the data model.
