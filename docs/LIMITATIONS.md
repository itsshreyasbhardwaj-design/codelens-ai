# Analysis Limitations

Read this before trusting any CodeLens report. Everything here is a real limit
of the current implementation, stated so reports are not over-read.

## What CodeLens cannot tell you

- **It cannot prove the absence of vulnerabilities or bugs.** Static analysis
  over a snapshot finds patterns and traceable relationships. A clean report
  means "these checks found nothing", not "this code is secure".
- **It cannot measure runtime behaviour** with dynamic verification disabled
  (the default). No throughput number, latency figure, concurrent-user capacity,
  or real query timing is produced unless an actual measurement ran. Where a
  number is absent, the report says `not measured`, never an estimate dressed as
  a measurement.
- **It cannot see your infrastructure or cloud bill.** Cost findings are
  structural (duplicate services, unbounded queries, inefficient AI calls). No
  dollar figure is produced without billing data.
- **It cannot look at a deployed URL at all.** Website observation mode is
  **not implemented in this release** (`docs/SUPPORTED.md`, `docs/STATUS.md`).
  The three ingestion methods that exist are a local directory, a GitHub
  repository and a ZIP. The data model reserves `projects.kind = 'website'` and
  `source_kind = 'url' | 'website'` for the mode, and nothing writes either
  value. When it is built it will read only what a client can observe — headers,
  TLS, page metadata, client-side signals — never your backend, schema or
  source.

## Coverage is reported, not assumed

Every scan records which files were parsed, which languages had a grammar
available, which analyzers ran, and which of the four analysis layers completed.
A category with insufficient evidence scores `Insufficient evidence` rather than
a misleading grade. A large repository that exceeded a bound reports what was
dropped — truncation is never silent.

## Analysis depth is not uniform

A universal interface is not uniform diagnostic depth. Depth by language is
published in `docs/SUPPORTED.md` and surfaced per scan. Deep support means AST
parsing, import/symbol resolution, and cross-file tracing. Shallow support means
structural indexing, manifest/config analysis, and text-level rules only.

## Known false-positive and false-negative classes

- Dynamic imports, reflection, metaprogramming, and string-built routes are not
  resolvable statically; related findings are capped at `suspected`.
- Authorisation enforced by a framework convention or middleware CodeLens does
  not model may be reported as missing. Trace the evidence before acting.
- Secret detection matches shape and entropy. Test fixtures and examples are
  excluded by path heuristics, which can over- or under-exclude.
- Monorepos with unconventional layouts may have entry points misattributed.

## Dynamic verification

Disabled by default. Without container isolation this host cannot safely execute
untrusted code, so dependency installation and project build scripts are refused
outright — they are arbitrary code execution by design. See ADR-005.
