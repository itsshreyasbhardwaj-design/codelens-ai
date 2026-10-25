import type { Coverage, Finding } from './types.ts';
import { fingerprintFinding } from './ids.ts';

/** Test helper: a complete, valid Finding with overridable fields. */
export function makeFinding(over: Partial<Finding> = {}): Finding {
  const base = {
    ruleId: over.ruleId ?? 'test.rule',
    category: over.category ?? ('security' as const),
    files: over.files ?? ['src/a.ts'],
    symbol: 'handler',
    excerpt: 'const x = 1',
  };
  return {
    id: 'TMP-000',
    fingerprint: fingerprintFinding(base),
    ruleId: base.ruleId,
    title: 'Test finding',
    category: base.category,
    severity: 'high',
    confidence: 'strong',
    status: 'strongly_supported',
    detectionSource: 'static',
    files: base.files,
    evidence: [{ file: base.files[0]!, startLine: 1, excerpt: base.excerpt, verified: true }],
    explanation: 'Something is wrong.',
    userImpact: 'Users may be affected.',
    remediation: 'Fix it.',
    effort: 'small',
    downstreamConsequences: [],
    relatedTests: [],
    verificationSteps: [],
    relatedFindings: [],
    references: [],
    affectedFeatures: [],
    ...over,
  };
}

export function makeCoverage(over: Partial<Coverage> = {}): Coverage {
  return {
    filesTotal: 100, filesIndexed: 100, filesParsed: 90, filesSkipped: 0,
    skippedReasons: {},
    languagesDeep: ['typescript'], languagesShallow: [], languagesUnsupported: [],
    analyzersRun: ['security', 'reliability', 'quality', 'performance', 'scalability', 'testing', 'accessibility', 'devops'],
    analyzersSkipped: [],
    layers: { static: true, graph: true, ai: false, dynamic: false },
    parseRatio: 0.9, truncated: false,
    ...over,
  };
}
