import type { Finding } from '@codelens/core';
import type { RepoMap } from '../graph/repomap.ts';

/**
 * Remediation ordering inputs.
 *
 * `blockedBy` is what makes the roadmap executable rather than merely sorted.
 * The rules below are deliberately few and explicit: a wrong dependency sends an
 * engineer to do work in an order that wastes effort, so only orderings that are
 * genuinely load-bearing are encoded.
 */

/** How many architecture components a finding touches. Feeds the blast-radius factor. */
export function computeDependentComponents(findings: Finding[], map: RepoMap): Record<string, number> {
  const out: Record<string, number> = {};
  for (const f of findings) {
    const touching = map.components.filter((c) => c.files.some((p) => f.files.includes(p)));
    const componentKeys = new Set(touching.map((c) => c.id));
    // Components that depend on a touched component are also exposed.
    for (const rel of map.relationships) {
      if (componentKeys.has(rel.to)) componentKeys.add(rel.from);
    }
    out[f.fingerprint] = componentKeys.size;
  }
  return out;
}

/**
 * Which findings must be remediated before which.
 *
 * Rule 1 — authentication before authorisation.
 *   Scoping a query to "the caller" is meaningless until the handler reliably
 *   knows who the caller is. Fixing the ownership check first produces code that
 *   reads correctly but enforces nothing.
 *
 * Rule 2 — behaviour before tests.
 *   A test written against behaviour that is about to change either gets
 *   rewritten immediately or, worse, pins the defective behaviour in place.
 *
 * Rule 3 — tests before gating the pipeline on them.
 *   Adding a test step to a deployment pipeline that has no meaningful tests
 *   gives false assurance; the tests have to exist first.
 */
export function computeBlockedBy(findings: Finding[]): Record<string, string[]> {
  const out: Record<string, string[]> = {};
  const add = (f: Finding, blocker: Finding) => {
    if (f.fingerprint === blocker.fingerprint) return;
    const list = out[f.fingerprint] ?? [];
    if (!list.includes(blocker.fingerprint)) list.push(blocker.fingerprint);
    out[f.fingerprint] = list;
  };

  const authzFindings = findings.filter((f) => f.ruleId.startsWith('security.authz.'));
  const missingAuth = authzFindings.filter((f) => f.ruleId.includes('missing_authentication') || f.ruleId.includes('unauthenticated'));
  const objectLevel = authzFindings.filter((f) => f.ruleId.includes('broken_object_level'));

  // Rule 1: same-file ownership checks wait for authentication to exist.
  for (const bola of objectLevel) {
    for (const auth of missingAuth) {
      if (auth.files.some((p) => bola.files.includes(p))) add(bola, auth);
    }
  }

  // Rule 2: tests follow the behavioural fixes they would assert.
  const behavioural = findings.filter(
    (f) =>
      (f.category === 'security' || f.category === 'reliability') &&
      (f.severity === 'critical' || f.severity === 'high') &&
      (f.confidence === 'confirmed' || f.confidence === 'strong'),
  );
  for (const test of findings.filter((f) => f.category === 'testing')) {
    for (const b of behavioural) add(test, b);
  }

  // Rule 3: pipeline gating follows the existence of tests.
  const testFindings = findings.filter((f) => f.category === 'testing');
  for (const ops of findings.filter((f) => f.category === 'devops' && /ci|pipeline|test|deploy/i.test(f.ruleId))) {
    for (const t of testFindings) add(ops, t);
  }

  return out;
}
