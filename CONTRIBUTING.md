# Contributing

## Running it

Requires Node 24+ (for built-in SQLite and native TypeScript) and pnpm.

```bash
pnpm install
pnpm verify      # typecheck, tests, diagnostic accuracy, web build
```

## The rules that matter

This project's value is that its findings can be trusted. Two rules follow from
that, and a change that breaks either will not be merged:

1. **Every finding carries evidence that resolves.** A finding whose cited line
   cannot be located in the analysed snapshot is refused, not downgraded.
2. **Severity and confidence stay independent.** Severity is the cost if the
   finding is real; confidence is the strength of the evidence. Never merge them
   into one number, and never let an unverified finding reach P0.

Nothing may claim a measurement that was not measured. If dynamic verification
did not run, there is no timing, no throughput, and no coverage percentage.

## Adding an analyzer rule

Read `packages/engine/src/analyzers/security.ts` first — it is the reference for
the expected depth of explanation, user impact, remediation and verification
steps. Then:

- Add the rule to the relevant analyzer. Rule ids are category-prefixed; the
  category is derived from the prefix, so the two cannot disagree.
- Match on comment-free text via `codeText()`. Matching raw source means a
  comment describing a problem reads as the problem itself — that bug has been
  found here twice.
- Add the defect to `fixtures/vulnerable-shop/` and to its `GROUND_TRUTH.json`.
- Run `pnpm eval`. Required-tier recall must stay at 100% with no false
  positives on files declared clean.

A rule that fires on idiomatic framework code is a bug, however technically
defensible. Precision is the product.

## Before opening a pull request

```bash
pnpm verify
```

CI runs the same checks on Node 24 and 25, plus a scan of this repository by
itself. Read that report — it has found real problems here.
