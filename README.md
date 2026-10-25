# CodeLens AI

**Understand any codebase. Diagnose what matters. Fix it with precision.**

CodeLens AI ingests a real software project, reconstructs how it is built, finds
problems with evidence attached to each one, prioritises them, and produces a
small number of detailed remediation briefs you can hand to a coding agent such
as Claude Code or Codex.

It is built on one rule: **a claim about your code must point at your code.**
Every finding carries a file, a line, and the excerpt it was derived from, and a
finding whose evidence cannot be re-verified against the analysed snapshot is
refused rather than reported.

## What makes it different

Most tools either run a linter and hand you 400 warnings, or send your
repository to a model and hand you plausible prose. CodeLens does neither.

- **Four analysis layers, and it tells you which ones ran.** Deterministic static
  analysis, cross-file relationship analysis, optional AI investigation, optional
  dynamic verification. The report states which completed. A category that was
  not assessed scores *insufficient evidence*, never a reassuring grade.
- **Severity and confidence stay separate.** Severity is what it costs if real.
  Confidence is how strong the evidence is. A critical-but-suspected finding is
  labelled exactly that and can never be promoted to P0.
- **Cross-file findings no single file reveals.** A frontend reading a field the
  backend never returns; a route that authenticates the caller then loads a
  record by URL id without checking ownership; an integration that is
  implemented but never invoked. Each comes with a traced chain citing both ends.
- **Fix Packs, not a wall of warnings.** Findings are grouped into a handful of
  dependency-ordered briefs, each small enough for one agent session and one
  human review, each validated by twelve pre-flight checks before you see it.
- **Runs on nothing.** No Docker, no database server, no API key, no network.
  The default scan is free, offline, and reproducible.

## Install and run

Requires **Node 24+** (for built-in SQLite and native TypeScript) and `pnpm`.

```bash
pnpm install
pnpm scan ./path/to/your/project
```

That is the whole setup. There is no service to start and no key to configure.

```bash
# Scan a local directory
pnpm scan ./my-app --name "My App"

# Scan a GitHub repository (public needs no token)
pnpm scan owner/repo
pnpm scan owner/repo@some-branch
GITHUB_TOKEN=... pnpm scan owner/private-repo

# See the bundled demonstration project, with its defects documented up front
pnpm scan ./fixtures/vulnerable-shop --name "Vulnerable Shop"

# Measure diagnostic accuracy against that fixture's ground truth
pnpm eval

# Stored scans, and a comparison between two of them
node --experimental-strip-types packages/cli/src/bin.ts list
node --experimental-strip-types packages/cli/src/bin.ts compare <baseScanId> <headScanId>
```

A scan writes to `./codelens-report/`:

| File | For |
| --- | --- |
| `executive-summary.md` | A founder or lead: what this is, where it stands, what to do next |
| `technical-report.md` | An engineer: architecture, API surface, data models, every finding in full |
| `findings.json` | Tooling, with coverage and limitations embedded in the document |
| `technical-report.html` | Printing — open it and use the browser's Save as PDF |
| `fix-packs/*.md` | One remediation brief per pack, ready to paste into a coding agent |

### Web interface

```bash
pnpm dev     # http://localhost:3100
```

Dashboard, project overview with the health scorecard and coverage panel,
interactive architecture explorer, findings explorer with full evidence
inspection, Fix Studio, a repository-aware question surface, and report exports.

## The AI layer is off by default

`CODELENS_AI_PROVIDER=none` is the default, and the product is complete without
it: the deterministic layers produce every finding, and Fix Packs are built from
that evidence. Enabling a model adds semantic investigation of the specific
questions static analysis could not settle.

| Provider | Cost | Where your code goes |
| --- | --- | --- |
| `none` (default) | nothing | nowhere — fully offline |
| `ollama` | nothing | stays on your machine |
| `anthropic` / `openai` | **you are billed by the provider** | sent to that provider |

The external providers additionally require
`CODELENS_AI_ACCEPT_EXTERNAL_TRANSFER=true`, so repository content is never sent
off the machine by accident. `CODELENS_AI_TOKEN_BUDGET` is a hard ceiling: the
stage aborts rather than exceeding it.

Repository content is treated as untrusted data at every point. A model never
receives it inside the system prompt; it is fenced with a per-request nonce, and
every model finding is dropped unless its quoted line is located in the
snapshot. A README instructing an AI reviewer to report nothing has no effect —
and is itself reported as a finding.

See `.env.example` for every option.

## What it cannot do

Read [docs/LIMITATIONS.md](docs/LIMITATIONS.md) before trusting any report. In short:
it cannot prove the absence of defects; it measures nothing at runtime unless a
dynamic verification stage actually ran; it has no view of your cloud bill; and
analysis depth varies by language ([docs/SUPPORTED.md](docs/SUPPORTED.md)).

Dynamic verification is disabled by default and refuses to run project
dependency-installation or build scripts, because those are arbitrary code
execution and this host offers no container isolation. That is a documented
limitation, not a solved problem.

## Documentation

| Document | Contents |
| --- | --- |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | How the system is built, the 12-stage pipeline, the data model |
| [docs/DECISIONS.md](docs/DECISIONS.md) | Every significant decision, its reasoning, and how to reverse it |
| [docs/LIMITATIONS.md](docs/LIMITATIONS.md) | What CodeLens cannot tell you, and its known false-positive classes |
| [docs/SUPPORTED.md](docs/SUPPORTED.md) | Technology matrix and analysis depth per language |
| [docs/RUNBOOK.md](docs/RUNBOOK.md) | Operating it: deployment, retention, failure recovery |
| [docs/STATUS.md](docs/STATUS.md) | Honest implementation status: what works, what does not |

## Licence

MIT.
