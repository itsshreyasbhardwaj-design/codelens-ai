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

**Authentication and tenant isolation.** Registration and sign-in with scrypt
password verifiers (N=32768) and HMAC-signed session cookies, built on
`node:crypto` with no dependency. Verified at runtime, not just in tests:
unauthenticated requests to `/dashboard` redirect to sign-in, unauthenticated
API requests get 401, a forged cookie is rejected, a duplicate email is refused
case-insensitively, and a wrong password and an unknown account return
byte-identical responses so accounts cannot be enumerated. Every store query
that reaches project data is organisation-scoped, and membership is re-checked
from the database on each request so removing a member revokes access
immediately rather than at token expiry.

**CLI.** `scan`, `eval`, `list`, `compare`. Reports in Markdown, JSON and
printable HTML. The CLI is single-user by nature and uses a fixed local
organisation.

**Web interface.** Landing page, dashboard with live stage-by-stage scan
progress, project overview with scorecard and coverage panel, architecture
explorer, findings explorer with full evidence inspection, Fix Studio, a
repository-aware question surface, and report exports.

**Plans, limits and the credit ledger.** Five plans seeded into the database
(free, solo, pro, team, enterprise) with per-plan project, scan, seat and
monthly-credit limits. Entitlements are enforced where the work starts, not in
the UI: `/api/scans` returns 402 with a machine-readable remedy when a project
or scan limit is hit. Credits use reserve → settle → release with an
`InsufficientCredits` check *before* anything is written, a `CHECK (balance >= 0)`
constraint behind that, and a unique idempotency key on every ledger row so a
retried request cannot double-charge. Settlement is clamped to the reserved
ceiling: an under-estimate is a bug in estimation, not a licence to charge more.

**What is never metered.** Deterministic analysis — the layer the recall numbers
above come from — costs nothing to run and is never gated on credits. An
organisation at zero credits still gets a complete scan; only the optional AI
layer draws on the balance, and a refusal skips that one stage with the reason
attached rather than failing the scan. Both behaviours are covered by tests in
`packages/engine/src/pipeline/pipeline.test.ts`.

**Payments.** A `PaymentProvider` interface with a Stripe adapter and a
`NoPaymentProvider` default. Signature verification is a pure exported function
tested offline against a known-good HMAC, a replayed timestamp outside the 300s
tolerance, a tampered body, and multiple `v1` signatures during secret rotation.
Webhook application is idempotent on `(provider, provider_event_id)`. With no
provider configured the app says so and leaves every account on the free plan;
with Stripe selected but no webhook secret it **refuses to run billing at all**,
because entitlements would otherwise rest on an unverified request.

**213 automated tests**, zero runtime test dependencies: Node's built-in test
runner and native TypeScript.

## Not implemented

Stated plainly rather than stubbed.

- **Team invitations, roles beyond owner, and agency workspaces.**
  Authentication exists (below), and every account gets its own organisation,
  but there is no invite flow, no role management UI, and no way to add a second
  member to an organisation. The schema and the role column support it; the
  product surface does not.
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
- **Billing beyond checkout and webhooks.** No dunning, no invoices, no
  proration, no tax handling, no customer-portal integration, and no email of
  any kind — there is a `notifications` table and nothing that sends. Stripe's
  own hosted pages cover most of this; none of it is wired into this UI. Only
  the Stripe adapter exists, though the provider interface was written for a
  second one.
- **Single-session revocation.** Sessions are stateless signed cookies, so
  revoking one session means rotating `CODELENS_SECRET_KEY`, which invalidates
  all of them. Noted in `packages/engine/src/db/auth.ts`.
- **Horizontal scaling of the web app.** In-flight job state lives in a
  module-level map, correct for one process. The orchestrator already persists
  stages, so a multi-process deployment would read those tables instead.

## How this was verified, and what was not

Verified by execution: the type checker and the 213-test suite (unit,
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

## What the second self-audit found

Running CodeLens on the newly written authentication code surfaced three
findings. One was a true positive — `CODELENS_SECRET_KEY` was read but missing
from `.env.example`, now fixed. One was a **false positive worth more than the
finding**: the account-enumeration rule matched a *comment* explaining why the
login response is deliberately uniform. That was the third false positive of the
same shape, so the fix went into `handlerSymbolText`, which every security rule
draws its text from, rather than into the one rule.

The third stands and is not fixed: the authentication routes have no automated
test. The logic beneath them has 19, and the routes were verified by hand
against a running server, but there is no test that would catch a regression in
the route glue itself. It is reported here rather than argued away.

## Third self-audit (after the billing work)

CodeLens was run against its own repository again once plans, credits,
entitlements and payments were in place. It reported **four things in our own
code**; all four were acted on, and the split is the useful part.

**One real defect, in the application.** `GET` and `DELETE /api/scans/:jobId`
authenticated the caller through the middleware and then looked the job up by id
without checking who owned it. Any signed-in user with another tenant's job id
could read that scan's project name and progress, and **cancel the scan**.
Classic broken object-level authorisation — the exact class the tool detects —
found by the tool, in the tool. Jobs now carry their organisation, a job
belonging to someone else is reported as absent exactly as a missing one is, and
the fix was verified live with two accounts: before, a second tenant got 200 on
the read and 202 on the cancel; after, both are 404.

**Three false positives, each a rule defect worth fixing rather than
suppressing.**

- `reliability.http.no_timeout` fired on all three outbound calls (Anthropic,
  OpenAI, Stripe) although every one of them passes
  `signal: AbortSignal.timeout(...)`. The rule tested the parser's captured
  argument text, which is truncated at 200 characters, so a `signal` placed
  after a large `body` was invisible. It now reads the call's own source back
  from the file, paren-balanced and comment-stripped. *Worth recording that the
  first attempt at this was wrong: the finding was taken at face value and
  timeouts were "added" that were already there. Re-reading the code is what
  found the real defect.*
- `security.authz.missing_authentication` fired at high severity on four routes
  that do authenticate, because the auth-helper list held framework names only
  and this project's helper is called `sessionOr401`. A fixed list can never
  cover what a project calls its own helper. Project-local helpers are now
  recognised by shape — a verb meaning "obtain or demand" beside a noun meaning
  "caller identity" — narrow enough that `createSession` and `sessionStorage`
  still do not count.
- `quality.duplication.divergent_logic` fired at high severity on two
  three-line query wrappers, claiming they had drifted and now computed
  different answers. They differ only in their SQL string, which is the entire
  point of each. A differing *number* or *operator* supports the drift claim;
  a differing opaque *string* does not, and every thin wrapper around a query,
  route, config key or storage path has that shape. Strings no longer promote a
  pair to `drift`; such a pair is still reported as the tidiness finding it is.

All three rule changes were made without losing a single ground-truth detection:
recall stayed at 69/69 and the suite at 204 passing. Our own code now has
**zero P0 findings**.

## What an external review caught that we did not

An automated review on PR #1 reported five defects. All five were independently
reproduced before anything was changed, and all five were real. They are
recorded here because the pattern matters more than the individual bugs: every
one of them sat in code that the test suite passed, that typechecked, and that
had been exercised by hand.

- **Cross-tenant data exposure (the worst of them).** The web runner derived a
  project's id from its name alone, and `ensureProject` looked that id up
  without an organisation predicate. Two organisations scanning a directory
  with the same name shared one project row: the second organisation's
  snapshot, findings and fix packs were written under the first organisation's
  project — readable by them, and not by its owner, whose dashboard simply came
  back empty. One free signup and a guessable project name was the whole attack.
  Project ids are now tenant-scoped and `ensureProject` is organisation-scoped,
  so a colliding id fails loudly instead of attaching silently.
- **The AI layer never ran, for anyone.** `credit_ledger.scan_id` is a foreign
  key to `scan_jobs`, and the scan row was only written *after* the pipeline
  finished — so every credit reservation failed with `FOREIGN KEY constraint
  failed`, which the orchestrator reported as a credit refusal. A customer with
  a full balance saw a database error in the billing-refusal slot and no AI
  analysis, on every scan, 100% of the time. The scan row is now registered
  before the pipeline starts and completed by an upsert afterwards.
- **Every subscription event granted a full month's credits.** The grant was
  keyed on the provider event id, and Stripe sends
  `customer.subscription.updated` for renewals, card changes, cancellation
  toggles and `past_due` recoveries. A separate monthly key could never collide
  with it, so the scan path added one more on top. Both paths now share one key
  of (organisation, plan, month) — which also fixes a silent under-grant for
  anyone upgrading mid-month, and stops an Enterprise subscription throwing on
  its zero allowance.
- **A plan change would have billed the customer twice.** Stripe Checkout is
  always `mode=subscription`: it can only create a subscription, never replace
  one, and nothing in this codebase cancels or modifies a subscription at the
  provider. An ordinary Solo → Pro upgrade would have left both billing while
  the UI showed Pro. Changing plan is now refused with an explanation until the
  Subscriptions API is wired in; credit top-ups are unaffected.
- **Re-scanning your own project was refused as a new one.** The entitlement
  check slugified the *optional* `name` field, so an unnamed scan looked up the
  literal slug `project` while persistence used the directory, repository or
  archive name; the stored slug was also truncated to 24 characters where the id
  was not. A Free account was told to upgrade to do something its plan allowed.
  Both now resolve the same identity through one function.

Each has a regression test that fails if its fix is reverted — verified by
reverting them. The honest lesson is that the suite passing said nothing about
any of this: the pipeline tests stubbed the credit hooks, and no test had ever
created two organisations and had them scan the same directory.

## Self-audit false positives, found and fixed

Running CodeLens on CodeLens reported two `critical` / `confirmed` SQL injection
findings in this repository's own `packages/web/app/lib/store.ts`. Both were
false positives, and at that severity and confidence they are the most damaging
error this product can make.

Both interpolated a module-scope `const` holding a literal SQL `ORDER BY`
fragment. No request can influence such a value, and interpolating one is a
common, safe pattern that would have fired on real codebases.

Fixed in both directions:

- **The rule** now resolves each `${...}` expression and suppresses the finding
  only when *every* one is a bare identifier bound to a module-scope string
  literal. It is deliberately strict — a call, a property access or a parameter
  leaves the finding in place — so the failure mode is reporting, not silence.
- **The code** dropped a `.replace()` applied to that constant at the call site
  in favour of two plain constants, which the rule can prove and which reads
  better anyway.

Verified afterwards: the fixture's genuine SQL injection is still detected,
required-tier recall is still 100%, and the self-audit now reports **no P0
findings in this project's own code** — the remaining eight are in
`fixtures/vulnerable-shop`, where they belong.

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

1. **A test for the authentication routes**, which this project's own audit
   reports as a critical gap and which is the one place "verified by hand" is
   weakest.
2. **Team invitations and roles**, so an organisation can have more than the
   account that created it.
3. **A second and third ground-truth fixture** in different ecosystems — a
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
