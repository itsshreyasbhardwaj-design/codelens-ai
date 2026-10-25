import type { EffortBand, Finding } from './types.ts';
import { CONFIDENCE_WEIGHT, SEVERITY_RANK } from './types.ts';

/**
 * Prioritisation.
 *
 * Produces P0..P3 from ten explicit factors with published weights, plus a
 * written rationale per finding. Banding is gated so that an unverified issue
 * cannot reach P0 no matter how severe it would be if real — and so that not
 * everything collapses into "critical".
 */

export type Priority = 'P0' | 'P1' | 'P2' | 'P3';

export interface PrioritizationContext {
  /** fingerprint -> number of architecture components touching the finding's files. */
  dependentComponents?: Record<string, number>;
  /** fingerprint -> fingerprints that must be remediated first. */
  blockedBy?: Record<string, string[]>;
  /** fingerprint -> 0..1 estimated likelihood the failure is reachable in practice. */
  failureLikelihood?: Record<string, number>;
}

export interface PrioritizedFinding {
  finding: Finding;
  priority: Priority;
  score: number;
  factors: Record<string, number>;
  rationale: string;
  blockedBy: string[];
}

const EFFORT_SCORE: Record<EffortBand, number> = {
  trivial: 1.0, small: 0.85, medium: 0.6, large: 0.3, unknown: 0.5,
};

/** Categories where a defect means data loss or unauthorised access. */
const CRITICAL_PATH_CATEGORIES = new Set(['security', 'reliability']);

/** Regression risk by effort — bigger changes are likelier to break something. */
const REGRESSION_RISK: Record<EffortBand, number> = {
  trivial: 0.05, small: 0.15, medium: 0.35, large: 0.6, unknown: 0.35,
};

export const FACTOR_WEIGHTS = {
  severity: 30,
  confidence: 20,
  userImpact: 12,
  security: 12,
  failureLikelihood: 8,
  dependents: 6,
  effort: 6,
  regressionSafety: 3,
  unblocked: 3,
} as const;

function userImpactScore(f: Finding): number {
  const text = `${f.userImpact} ${f.explanation}`.toLowerCase();
  // Keyword signals, bounded. Deliberately crude and transparent rather than
  // an opaque model score; the rationale string shows what fired.
  let s = 0.3;
  if (/\b(data loss|corrupt|lose|deleted|unauthoris|unauthoriz|exposed|leak)\b/.test(text)) s = 1.0;
  else if (/\b(cannot|fails?|broken|crash|error|unavailable|blocked)\b/.test(text)) s = 0.75;
  else if (/\b(slow|delay|confus|inconsistent|degrade)\b/.test(text)) s = 0.5;
  if (f.affectedFeatures.length > 2) s = Math.min(1, s + 0.15);
  return s;
}

export function scoreFinding(f: Finding, ctx: PrioritizationContext = {}): {
  score: number; factors: Record<string, number>;
} {
  const sevNorm = 1 - SEVERITY_RANK[f.severity] / 4; // critical=1.0, info=0.0
  const confNorm = CONFIDENCE_WEIGHT[f.confidence];
  const impact = userImpactScore(f);
  const security = f.category === 'security' ? 1 : 0;
  const likelihood = ctx.failureLikelihood?.[f.fingerprint] ?? (f.trace?.complete ? 0.8 : 0.5);
  const dependents = Math.min(1, (ctx.dependentComponents?.[f.fingerprint] ?? 0) / 8);
  const effort = EFFORT_SCORE[f.effort];
  const regressionSafety = 1 - REGRESSION_RISK[f.effort];
  const unblocked = (ctx.blockedBy?.[f.fingerprint]?.length ?? 0) === 0 ? 1 : 0;

  const factors = {
    severity: sevNorm, confidence: confNorm, userImpact: impact, security,
    failureLikelihood: likelihood, dependents, effort, regressionSafety, unblocked,
  };

  let score = 0;
  for (const [k, w] of Object.entries(FACTOR_WEIGHTS)) {
    score += (factors as Record<string, number>)[k]! * w;
  }
  return { score: Math.round(score * 100) / 100, factors };
}

function band(f: Finding, score: number): Priority {
  const verified = f.confidence === 'confirmed' || f.confidence === 'strong';
  const needsRuntime = f.status === 'needs_runtime_verification';

  // P0 is reserved for confirmed, consequential, production-blocking problems.
  // An unverified finding never reaches P0 however severe it would be if real.
  if (
    f.severity === 'critical' && verified && !needsRuntime &&
    CRITICAL_PATH_CATEGORIES.has(f.category)
  ) return 'P0';

  if (f.severity === 'critical' || (f.severity === 'high' && verified)) return 'P1';
  if (f.severity === 'high' || score >= 45) return 'P2';
  if (f.severity === 'info') return 'P3';
  return score >= 30 ? 'P2' : 'P3';
}

function explain(f: Finding, p: Priority, factors: Record<string, number>, blockedBy: string[]): string {
  const bits: string[] = [];
  bits.push(`${f.severity} severity with ${f.confidence} confidence`);
  if (factors.security === 1) bits.push('security-relevant');
  if (factors.userImpact >= 0.75) bits.push('direct user-visible impact');
  if (factors.dependents >= 0.5) bits.push('touches many components');
  if (f.effort === 'trivial' || f.effort === 'small') bits.push('low remediation effort');
  if (f.effort === 'large') bits.push('large change with real regression risk');
  if (blockedBy.length > 0) bits.push(`must wait for ${blockedBy.length} prerequisite fix(es)`);
  if (p === 'P0') return `P0: ${bits.join(', ')}. Confirmed and consequential enough to block release.`;
  if (f.severity === 'critical' && !(f.confidence === 'confirmed' || f.confidence === 'strong')) {
    return `P1: ${bits.join(', ')}. Severity would justify P0 but the evidence is not yet strong enough to confirm it — verify first.`;
  }
  return `${p}: ${bits.join(', ')}.`;
}

/**
 * Prioritise and order findings. Prerequisites are ordered ahead of the
 * findings that depend on them, so the roadmap is executable top to bottom.
 */
export function prioritize(
  findings: Finding[],
  ctx: PrioritizationContext = {},
): PrioritizedFinding[] {
  const scored: PrioritizedFinding[] = findings.map((f) => {
    const { score, factors } = scoreFinding(f, ctx);
    const blockedBy = ctx.blockedBy?.[f.fingerprint] ?? [];
    const priority = band(f, score);
    return { finding: f, priority, score, factors, rationale: explain(f, priority, factors, blockedBy), blockedBy };
  });

  const order: Record<Priority, number> = { P0: 0, P1: 1, P2: 2, P3: 3 };
  scored.sort((a, b) => order[a.priority] - order[b.priority] || b.score - a.score);

  // Stable topological lift: a blocker must appear before anything it blocks.
  const index = new Map(scored.map((s, i) => [s.finding.fingerprint, i]));
  for (let pass = 0; pass < 3; pass++) {
    let moved = false;
    for (const s of scored) {
      for (const dep of s.blockedBy) {
        const di = index.get(dep);
        const si = index.get(s.finding.fingerprint);
        if (di !== undefined && si !== undefined && di > si) {
          const [item] = scored.splice(di, 1);
          scored.splice(si, 0, item!);
          scored.forEach((x, i) => index.set(x.finding.fingerprint, i));
          moved = true;
        }
      }
    }
    if (!moved) break;
  }
  return scored;
}

export function roadmap(prioritized: PrioritizedFinding[]): Record<Priority, PrioritizedFinding[]> {
  const out: Record<Priority, PrioritizedFinding[]> = { P0: [], P1: [], P2: [], P3: [] };
  for (const p of prioritized) out[p.priority].push(p);
  return out;
}
