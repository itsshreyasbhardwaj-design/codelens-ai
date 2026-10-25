# Architecture Decision Record

Decisions made independently during implementation, with the reasoning and the
trade-off accepted. Each one is reversible; the "Reversal path" says how.

## ADR-001 — SQLite via `node:sqlite` instead of PostgreSQL

**Context.** The build brief proposes PostgreSQL + Redis + object storage. The
target machine has no Docker, no `psql`, no `redis-server`, and a standing
operator constraint of free/local-first tooling.

**Decision.** Use `node:sqlite` (built into Node >= 22.5, stable in Node 24) as
the application database. Schema is written in portable SQL: integer/text
primary keys, explicit foreign keys, no SQLite-only types in table definitions.

**Consequences.** Zero install, zero services, zero cost, and the full relational
model from the brief is implemented rather than stubbed. Single-writer
concurrency — adequate for a single-node analysis server, not for multi-tenant
production scale.

**Reversal path.** `packages/engine/src/db/` isolates all SQL behind a `Database`
interface. `schema.sql` applies to PostgreSQL with three mechanical edits
documented in `docs/ARCHITECTURE.md#postgres-migration`.

## ADR-002 — SQLite-backed job store instead of Redis/BullMQ

**Decision.** Scan jobs and their 12 stages are rows in `scan_jobs` /
`scan_stages`. The worker is an in-process loop that claims a stage, runs it,
and records real status. Resumability, bounded retries, cancellation, and
idempotency keys are implemented against those rows.

**Consequences.** Durable across restarts with no broker. Scans run on the API
process by default, so long scans must not be awaited inside a request handler
— the CLI and the web API both enqueue and poll.

## ADR-003 — AI semantic analysis is OFF by default

**Context.** A hard operator constraint: never spend the operator's money on API
calls. A codebase auditor that only works with a paid key is also a worse
product — findings would be unreproducible and unverifiable.

**Decision.** `CODELENS_AI_PROVIDER=none` is the default. Layers A (deterministic
static analysis) and B (architecture/relationship analysis) carry the product and
produce every finding on their own. Layer C is an optional enrichment with three
adapters: `ollama` (local, free), `anthropic`, `openai` (both BYO key, explicit
opt-in). A hard token ceiling aborts Layer C rather than overspending.

**Consequences.** Default scans are $0, fully offline, and byte-for-byte
reproducible. The product's headline feature (Fix Packs) is built from
deterministic evidence and templated generation, so it works with AI disabled.

## ADR-004 — Tree-sitter WASM, not native bindings

**Decision.** `web-tree-sitter` + `tree-sitter-wasms` for AST parsing.

**Rationale.** No native compilation, no Rust toolchain (unavailable), one
install works across architectures. Costs some parse throughput versus native
bindings; correctness is identical since the grammars are the same.

**Fallback.** When a grammar is unavailable, the file is indexed structurally and
marked `parsed: false`, and coverage reporting counts it as unparsed rather than
silently treating it as clean.

## ADR-005 — Layer D does not claim to be a sandbox

**Context.** The brief requires isolated execution for builds/tests. Real
isolation needs containers or VMs. This machine has neither.

**Decision.** `CODELENS_DYNAMIC_VERIFY=off` by default. When enabled it runs a
restricted subprocess with a timeout, an output cap, and a deny-list, and it
**refuses** to run dependency installation or build scripts from an ingested
project, because those are arbitrary code execution by design.

**Consequences.** Dynamic verification is limited to commands the operator
explicitly authorises on code they trust. The UI reports Layer D as `skipped`
with a reason instead of implying runtime verification happened.
This is recorded as a product limitation, not solved by pretending.

## ADR-006 — Four packages, modular inside

**Decision.** `@codelens/core` (contracts, scoring, prioritisation — zero
dependencies), `@codelens/engine` (db, ingest, index, detect, parse, graph,
analyzers, ai, fixpacks, reports, pipeline), `@codelens/cli`, `@codelens/web`.

**Rationale.** The brief's 20 service modules exist as directories inside
`engine` with enforced one-way dependencies, rather than 20 publishable packages
with 20 build steps. Avoids premature distribution while keeping the seams that
would let any module become a service later.

## ADR-007 — Confidence and severity are independent axes

**Decision.** Severity describes blast radius if real. Confidence describes
strength of evidence. They are never multiplied into a single number for display,
and the UI must show both. A `critical` + `suspected` finding is labelled exactly
that, never promoted to a confirmed critical to look impressive.

## ADR-008 — TypeScript compiler API for TS/JS, `python3 -m ast` for Python

**Supersedes the TS/JS half of ADR-004.**

**Decision.** Parse TypeScript/JavaScript/TSX/JSX with the TypeScript compiler
API, and Python by shelling out to the interpreter's own `ast` module.

**Rationale.** Both are more accurate than a tree-sitter grammar for these
languages, and both are already present: `typescript` is a dependency the
project needs anyway, and `python3` ships with macOS. That removes a ~50 MB
WASM grammar download from the install path, which matters for an offline-first
tool.

**Consequences.** Python parsing degrades gracefully: if no usable `python3` is
on PATH, those files are marked `parsed: false` with that reason and counted as
unparsed in coverage rather than treated as clean. Tree-sitter remains the
intended path for adding further deep languages; the `ParsedModule` interface in
`packages/engine/src/parse/types.ts` is parser-agnostic for exactly that reason.
