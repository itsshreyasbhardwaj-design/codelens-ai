import { createHash } from 'node:crypto';
import type { Category, Finding } from './types.ts';

/** Normalise an excerpt so cosmetic edits (indentation, line shifts) don't change the fingerprint. */
function normaliseExcerpt(s: string | undefined): string {
  if (!s) return '';
  return s.replace(/\s+/g, ' ').trim().slice(0, 240);
}

/**
 * Content fingerprint for a finding, stable across scans.
 *
 * Deliberately excludes line numbers: adding an import above a vulnerable
 * function must not look like "old finding resolved, new finding introduced".
 * Includes the symbol and the normalised excerpt so two genuinely different
 * problems from the same rule in the same file stay distinct.
 */
export function fingerprintFinding(input: {
  ruleId: string;
  category: Category;
  files: string[];
  symbol?: string;
  excerpt?: string;
}): string {
  const h = createHash('sha256');
  h.update(input.ruleId);
  h.update('\u0000');
  h.update(input.category);
  h.update('\u0000');
  h.update([...input.files].sort().join(','));
  h.update('\u0000');
  h.update(input.symbol ?? '');
  h.update('\u0000');
  h.update(normaliseExcerpt(input.excerpt));
  return h.digest('hex').slice(0, 16);
}

const CATEGORY_PREFIX: Record<Category, string> = {
  security: 'SEC',
  reliability: 'REL',
  performance: 'PERF',
  scalability: 'SCALE',
  accessibility: 'A11Y',
  quality: 'QUAL',
  testing: 'TEST',
  devops: 'OPS',
  cost: 'COST',
  ai_app: 'AI',
  architecture: 'ARCH',
};

/**
 * Assign human-facing ids (SEC-001, REL-002, ...) in the order given.
 * Callers pass findings already sorted by priority so ids read meaningfully.
 */
export function assignDisplayIds(findings: Finding[]): Finding[] {
  const counters = new Map<string, number>();
  return findings.map((f) => {
    const prefix = CATEGORY_PREFIX[f.category] ?? 'GEN';
    const n = (counters.get(prefix) ?? 0) + 1;
    counters.set(prefix, n);
    return { ...f, id: `${prefix}-${String(n).padStart(3, '0')}` };
  });
}

export function shortHash(s: string): string {
  return createHash('sha256').update(s).digest('hex').slice(0, 12);
}
