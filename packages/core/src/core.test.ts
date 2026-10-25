import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { assignDisplayIds, fingerprintFinding } from './ids.ts';
import { buildScorecard, scoreDimension } from './scoring.ts';
import { prioritize } from './prioritize.ts';
import { consolidateFindings, enforceEvidenceDiscipline } from './consolidate.ts';
import { makeCoverage, makeFinding } from './testing.ts';

describe('fingerprinting', () => {
  it('is stable when line numbers shift but code does not', () => {
    const a = fingerprintFinding({ ruleId: 'r', category: 'security', files: ['a.ts'], symbol: 'f', excerpt: 'const x = 1' });
    const b = fingerprintFinding({ ruleId: 'r', category: 'security', files: ['a.ts'], symbol: 'f', excerpt: '  const   x = 1  ' });
    assert.equal(a, b);
  });

  it('distinguishes different symbols in the same file', () => {
    const a = fingerprintFinding({ ruleId: 'r', category: 'security', files: ['a.ts'], symbol: 'f' });
    const b = fingerprintFinding({ ruleId: 'r', category: 'security', files: ['a.ts'], symbol: 'g' });
    assert.notEqual(a, b);
  });

  it('assigns per-category sequential display ids', () => {
    const out = assignDisplayIds([
      makeFinding({ category: 'security' }),
      makeFinding({ category: 'security', files: ['src/b.ts'] }),
      makeFinding({ category: 'testing', files: ['src/c.ts'] }),
    ]);
    assert.deepEqual(out.map((f) => f.id), ['SEC-001', 'SEC-002', 'TEST-001']);
  });
});

describe('scoring', () => {
  it('reports insufficient evidence when the analyzer did not run', () => {
    const d = scoreDimension('security', [], makeCoverage({ analyzersRun: ['reliability'] }));
    assert.equal(d.grade, 'insufficient_evidence');
    assert.equal(d.score, null);
    assert.match(d.reason!, /security/);
  });

  it('refuses to grade a clean result when little source was parsed', () => {
    assert.equal(scoreDimension('security', [], makeCoverage({ parseRatio: 0.1 })).grade, 'insufficient_evidence');
  });

  it('gives a clean, well-covered dimension a perfect score', () => {
    assert.equal(scoreDimension('security', [], makeCoverage()).score, 100);
  });

  it('penalises a confirmed critical more than a weak one', () => {
    const cov = makeCoverage();
    const strong = scoreDimension('security', [makeFinding({ severity: 'critical', confidence: 'confirmed' })], cov);
    const weak = scoreDimension('security', [makeFinding({ severity: 'critical', confidence: 'weak' })], cov);
    assert.ok(strong.score! < weak.score!, `${strong.score} should be < ${weak.score}`);
  });

  it('withholds an overall score when too little was assessed', () => {
    const card = buildScorecard([], makeCoverage({ analyzersRun: ['security'] }));
    assert.equal(card.overall, null);
    assert.equal(card.overallGrade, 'insufficient_evidence');
    assert.ok(card.unassessedDimensions.length > 0);
  });

  it('renormalises over assessed dimensions only', () => {
    // security + reliability + architecture = 0.60 of total weight, all clean.
    const card = buildScorecard([], makeCoverage({ analyzersRun: ['security', 'reliability', 'quality'] }));
    assert.equal(card.assessedWeight, 0.6);
    // 100, not 60: unassessed areas are reported as unassessed, not scored as failure.
    assert.equal(card.overall, 100);
  });
});

describe('prioritisation', () => {
  it('never puts an unverified critical in P0', () => {
    const [p] = prioritize([makeFinding({ severity: 'critical', confidence: 'weak', status: 'suspected' })]);
    assert.notEqual(p!.priority, 'P0');
    assert.match(p!.rationale, /not yet strong enough/);
  });

  it('puts a confirmed critical security issue in P0', () => {
    assert.equal(prioritize([makeFinding({ severity: 'critical', confidence: 'confirmed', status: 'confirmed' })])[0]!.priority, 'P0');
  });

  it('does not put a low-severity issue in P0 or P1', () => {
    const p = prioritize([makeFinding({ severity: 'low', confidence: 'confirmed', category: 'quality' })])[0]!.priority;
    assert.ok(['P2', 'P3'].includes(p), `got ${p}`);
  });

  it('orders a blocker ahead of the finding it blocks', () => {
    const blocker = makeFinding({ severity: 'medium', confidence: 'moderate', files: ['src/blocker.ts'] });
    const blocked = makeFinding({ severity: 'critical', confidence: 'confirmed', files: ['src/blocked.ts'] });
    const out = prioritize([blocked, blocker], { blockedBy: { [blocked.fingerprint]: [blocker.fingerprint] } });
    const names = out.map((o) => o.finding.files[0]);
    assert.ok(names.indexOf('src/blocker.ts') < names.indexOf('src/blocked.ts'));
  });
});

describe('evidence discipline', () => {
  it('refuses a finding with no evidence', () => {
    const r = enforceEvidenceDiscipline([makeFinding({ evidence: [] })]);
    assert.equal(r.kept.length, 0);
    assert.match(r.rejected[0]!.reason, /no evidence/);
  });

  it('refuses an AI finding whose evidence could not be verified', () => {
    const r = enforceEvidenceDiscipline([makeFinding({
      detectionSource: 'ai',
      evidence: [{ file: 'src/a.ts', excerpt: 'imagined', verified: false }],
    })]);
    assert.equal(r.kept.length, 0);
    assert.match(r.rejected[0]!.reason, /could not be verified/);
  });

  it('caps confidence when nothing could be verified', () => {
    const r = enforceEvidenceDiscipline([makeFinding({
      confidence: 'confirmed',
      evidence: [{ file: 'src/a.ts', excerpt: 'x', verified: false }],
    })]);
    assert.equal(r.kept[0]!.confidence, 'moderate');
    assert.equal(r.kept[0]!.status, 'suspected');
  });

  it('caps confidence when a relationship trace is incomplete', () => {
    const r = enforceEvidenceDiscipline([makeFinding({
      confidence: 'confirmed',
      trace: { kind: 'route_authorization', steps: [], complete: false },
    })]);
    assert.equal(r.kept[0]!.confidence, 'moderate');
  });

  it('keeps a confirmed finding backed by verified evidence', () => {
    const r = enforceEvidenceDiscipline([makeFinding({ confidence: 'confirmed' })]);
    assert.equal(r.kept[0]!.confidence, 'confirmed');
    assert.equal(r.kept[0]!.status, 'confirmed');
  });
});

describe('consolidation', () => {
  it('merges duplicates and unions their evidence', () => {
    const a = makeFinding({ confidence: 'moderate' });
    const b = makeFinding({ confidence: 'strong', evidence: [{ file: 'src/a.ts', startLine: 9, excerpt: 'other', verified: true }] });
    const out = consolidateFindings([a, b]);
    assert.equal(out.length, 1);
    assert.equal(out[0]!.confidence, 'strong');
    assert.equal(out[0]!.evidence.length, 2);
  });

  it('cross-links siblings from the same rule in the same file', () => {
    const a = makeFinding({ ruleId: 'same.rule' });
    const b = { ...makeFinding({ ruleId: 'same.rule' }), fingerprint: 'deadbeefdeadbeef' };
    const out = consolidateFindings([a, b]);
    assert.equal(out.length, 2);
    assert.ok(out[0]!.relatedFindings.includes('deadbeefdeadbeef'));
  });
});
