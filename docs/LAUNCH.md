# Launch checklist

What is done, what you must do yourself, and what is deliberately not built.
Nothing here is aspirational: every "done" item is something that has been run.

---

## 1. What already works with zero accounts and zero spend

| Capability | State |
|---|---|
| Deterministic analysis (10 analyzers, 130 rules) | Works offline, no keys |
| Architecture reconstruction and the repository map | Works offline |
| Fix Pack generation with pre-flight validation | Works offline |
| Scan comparison and regression detection | Works offline |
| Accounts, sessions, organisation isolation | Works; needs `CODELENS_SECRET_KEY` |
| Plans, limits, credit ledger, entitlement gating | Works; free plan is the default |
| CLI (`scan`, `report`, `eval`) | Works offline |

The free plan is not a crippled trial. The deterministic analysis — which is
where the measured 100% recall on 69 ground-truth defects comes from — runs in
full at zero credits. Credits only buy the optional AI semantic layer.

**You can launch with billing switched off** and the product is still complete.

---

## 2. What needs your own accounts

These are the only blockers to charging money, and all three are yours to
create. None of them can be done from this repository.

### 2.1 A payment account — required to take money

1. Create a Stripe account and complete its identity/business verification.
   (Razorpay is the India-facing alternative; the provider interface in
   `packages/engine/src/billing/payments.ts` is written for a second adapter,
   but only the Stripe adapter exists today.)
2. Create one Stripe **Price** per plan code and per credit pack code. The codes
   come from `DEFAULT_PLANS` and `DEFAULT_PRODUCTS` in
   `packages/engine/src/billing/plans.ts`.
3. Set `CODELENS_PAYMENT_PROVIDER=stripe`, `STRIPE_SECRET_KEY`,
   `STRIPE_WEBHOOK_SECRET`, and one `STRIPE_PRICE_<CODE>` per price —
   `STRIPE_PRICE_SOLO`, `_PRO`, `_TEAM`, `_CREDITS_10`, `_CREDITS_30`,
   `_CREDITS_80`. Free needs none; Enterprise is agreed, not bought. A code with
   no price id is refused at checkout, naming the variable to set.
4. Point a Stripe webhook endpoint at `https://<your-host>/api/billing/webhook`.

Until `STRIPE_WEBHOOK_SECRET` is set the app **refuses to run billing at all**,
rather than granting entitlements from an unverified request. That is
deliberate: a checkout return URL is attacker-controllable and grants nothing.

**Test it in Stripe test mode first.** Use Stripe's published test card numbers
and confirm in the credit ledger on `/billing` that the grant landed.

### 2.2 A host — required to be reachable

**Build the image once before you rely on it.** The Dockerfile has never been
run — the machine it was written on has no Docker. Its runtime layout was
verified by assembling the same file set and starting it, but the build itself
is unproven. `docker compose up --build` on any machine with Docker settles it,
and a failure will be loud and at build time.


See `docs/DEPLOYMENT.md`. The short version: a container host with a
**persistent volume** and a **single instance**. Storage is SQLite via
`node:sqlite`, which is a file with one writer, and scans are CPU-bound
in-process jobs that take seconds to minutes. Serverless platforms break both
assumptions.

### 2.3 A domain and TLS

Session cookies are signed, and should be served over HTTPS only. Most container
hosts terminate TLS for you.

---

## 3. Before you charge anyone

- [ ] Run the migrations on the production database. They run on boot; confirm
      via `/api/health`, which reports the schema version and any pending
      migration.
- [ ] Set `CODELENS_SECRET_KEY` to 32+ random characters. **Rotating it
      invalidates every session and makes every stored provider token
      undecryptable.** Back it up where you back up the database.
- [ ] Take one backup and restore it. The runbook explains why the `-wal` and
      `-shm` sidecars must move with the main file.
- [ ] Decide your retention period (`CODELENS_RETENTION_DAYS`, default 30) and
      say so in your privacy policy. Scans hold customer source code.
- [ ] Write the terms and privacy policy. Not in this repository: they are a
      legal document about your business, and a generated one would be worse
      than none.
- [ ] Confirm `/pricing` matches your Stripe prices. The page renders from the
      database, so an edited price in the database and an unedited Stripe price
      will disagree silently.

---

## 4. Known limitations to disclose, not hide

These are in `docs/LIMITATIONS.md` in full. The ones a paying customer will
notice first:

- **Nothing is runtime-verified.** Dynamic verification (Layer D) is refused,
  not stubbed: installing dependencies and running build scripts is arbitrary
  code execution, and this release provides no container isolation. Every
  finding is static or AI-assisted. Do not let marketing copy imply otherwise.
- **Precision is reported as a lower bound (77%), not a point estimate**, because
  ground truth cannot be proven complete. Recall is 100% on the 69 labelled
  defects in the corpus.
- **Deep parsing covers TypeScript, JavaScript, TSX and Python.** Other
  languages are indexed and pattern-matched, not parsed. `docs/SUPPORTED.md`
  lists exactly which is which, and coverage-gated scoring returns
  `insufficient_evidence` rather than a flattering grade.
- **One web process only.** The job registry is in-memory and SQLite has one
  writer. Horizontal scaling needs the job table as the reader; the orchestrator
  already persists stage state, so that is a change of reader, not of design.
- **Session revocation is per-key, not per-session.** Sessions are stateless
  signed cookies, so a single session cannot be revoked without rotating the
  key. Noted in the code at `packages/engine/src/db/auth.ts`.
- **Auth routes have no automated test.** The engine's auth functions are
  tested; the three HTTP routes over them are not.

---

## 5. Not built, on purpose

Asking for these is reasonable; they are absent and should not be implied:

- Per-seat invitations and a team-management UI (the schema supports seats; the
  screen does not exist).
- GitHub App installation flow. GitHub ingestion works with a personal access
  token.
- Dunning, invoices, proration, tax handling. Stripe's own hosted pages and
  customer portal cover most of this; none of it is wired into the UI.
- Email of any kind. There is a `notifications` table and nothing that sends.
- SSO, SCIM, audit-log export.
