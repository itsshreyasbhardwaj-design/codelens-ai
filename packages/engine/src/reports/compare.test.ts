import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import type { Coverage, Finding } from '@codelens/core';
import { makeCoverage, makeFinding } from '@codelens/core';
import { compareScans, type ScanSide } from './compare.ts';

function side(over: Partial<ScanSide> & { findings: Finding[] }): ScanSide {
  const files = new Set(over.findings.flatMap((f) => f.files));
  return {
    scanId: 'scan_x',
    coverage: makeCoverage(),
    contentHash: 'hash-' + Math.min(files.size, 9),
    indexedFiles: files,
    fingerprintsBeforeThisScan: new Set(),
    ...over,
  };
}

describe('scan comparison', () => {
  it('counts a finding present in both as persistent', () => {
    const f = makeFinding();
    const cmp = compareScans(side({ scanId: 'a', findings: [f] }), side({ scanId: 'b', findings: [f] }));
    assert.equal(cmp.persistent.length, 1);
    assert.equal(cmp.resolved.length, 0);
  });

  it('verifies a fix as resolved when the file was still indexed', () => {
    const f = makeFinding({ files: ['src/a.ts'] });
    const base = side({ scanId: 'a', findings: [f] });
    // The newer scan still indexed src/a.ts but no longer reports the finding.
    const head = side({ scanId: 'b', findings: [], indexedFiles: new Set(['src/a.ts']) });
    const cmp = compareScans(base, head);
    assert.equal(cmp.resolved.length, 1);
    assert.equal(cmp.unverifiedAbsences.length, 0);
  });

  it('refuses to call an absence a fix when the file was not indexed', () => {
    const f = makeFinding({ files: ['src/a.ts'] });
    const base = side({ scanId: 'a', findings: [f] });
    const head = side({ scanId: 'b', findings: [], indexedFiles: new Set(['src/other.ts']) });
    const cmp = compareScans(base, head);
    assert.equal(cmp.resolved.length, 0);
    assert.equal(cmp.unverifiedAbsences.length, 1);
    assert.match(cmp.unverifiedAbsences[0]!.caveat!, /were indexed by the newer scan/);
  });

  it('refuses to call an absence a fix when the analyzer did not run', () => {
    const f = makeFinding({ ruleId: 'security.authz.x', files: ['src/a.ts'] });
    const base = side({ scanId: 'a', findings: [f] });
    const head = side({
      scanId: 'b', findings: [], indexedFiles: new Set(['src/a.ts']),
      coverage: makeCoverage({
        analyzersRun: ['reliability'],
        analyzersSkipped: [{ analyzer: 'security', reason: 'analyzer failed: boom' }],
      }),
    });
    const cmp = compareScans(base, head);
    assert.equal(cmp.resolved.length, 0);
    assert.equal(cmp.unverifiedAbsences.length, 1);
    assert.match(cmp.unverifiedAbsences[0]!.caveat!, /did not run in the newer scan/);
  });

  it('does not count an unrelated file deletion against other fixes', () => {
    // Regression: comparing total file counts made every fix in the scan
    // unverifiable whenever any two unrelated files were removed.
    const fixed = makeFinding({ files: ['src/a.ts'] });
    const base = side({
      scanId: 'a', findings: [fixed],
      indexedFiles: new Set(['src/a.ts', 'src/gone-1.ts', 'src/gone-2.ts']),
      coverage: makeCoverage({ filesIndexed: 3 }),
    });
    const head = side({
      scanId: 'b', findings: [],
      indexedFiles: new Set(['src/a.ts']),
      coverage: makeCoverage({ filesIndexed: 1 }),
    });
    const cmp = compareScans(base, head);
    assert.equal(cmp.resolved.length, 1, 'the fix must still be verified as resolved');
    assert.equal(cmp.unverifiedAbsences.length, 0);
  });

  it('reports an edited-but-unfixed finding as still present, not as a fix', () => {
    // The fingerprint includes the source excerpt, so editing the line changes
    // it. Without pairing, that reads as "one resolved, one new".
    const before = makeFinding({ ruleId: 'performance.query.unbounded', files: ['src/db.ts'], excerpt: 'findMany()' });
    const after = { ...makeFinding({ ruleId: 'performance.query.unbounded', files: ['src/db.ts'], excerpt: 'findMany({ where })' }), fingerprint: 'different-fingerprint' };
    const cmp = compareScans(
      side({ scanId: 'a', findings: [before] }),
      side({ scanId: 'b', findings: [after], indexedFiles: new Set(['src/db.ts']) }),
    );
    assert.equal(cmp.resolved.length, 0, 'must not be reported as fixed');
    assert.equal(cmp.introduced.length, 0, 'must not be reported as new');
    assert.equal(cmp.relocated.length, 1);
    assert.match(cmp.relocated[0]!.caveat!, /same problem in modified code/);
  });

  it('reports a genuinely new finding as new, not as a regression', () => {
    // Regression: checking the base's own "seen in other scans" set matched
    // every head-only finding by construction.
    const existing = makeFinding({ files: ['src/a.ts'] });
    const brandNew = makeFinding({ ruleId: 'quality.other', category: 'quality', files: ['src/b.ts'] });
    const cmp = compareScans(
      side({ scanId: 'a', findings: [existing] }),
      side({ scanId: 'b', findings: [existing, brandNew] }),
    );
    assert.equal(cmp.introduced.length, 1);
    assert.equal(cmp.regressed.length, 0);
  });

  it('reports a returning finding as a regression', () => {
    const f = makeFinding({ files: ['src/a.ts'] });
    const base = side({
      scanId: 'a', findings: [],
      // Seen in a scan older than the base, absent in the base.
      fingerprintsBeforeThisScan: new Set([f.fingerprint]),
    });
    const head = side({ scanId: 'b', findings: [f] });
    const cmp = compareScans(base, head);
    assert.equal(cmp.regressed.length, 1);
    assert.equal(cmp.introduced.length, 0);
  });

  it('withholds a score delta when either side was not gradeable', () => {
    const cmp = compareScans(
      side({ scanId: 'a', findings: [], scorecard: undefined }),
      side({ scanId: 'b', findings: [], scorecard: undefined }),
    );
    assert.equal(cmp.scoreDelta?.change, null);
    assert.match(cmp.scoreDelta!.note!, /cannot be diffed against an absence/);
  });

  it('says so when both scans analysed an identical file set', () => {
    const f = makeFinding();
    const cmp = compareScans(
      side({ scanId: 'a', findings: [f], contentHash: 'same' }),
      side({ scanId: 'b', findings: [f], contentHash: 'same' }),
    );
    assert.match(cmp.summary, /identical file set/);
  });

  it('notes a newly added analyzer so its findings are not read as new defects', () => {
    const newFinding = makeFinding({ ruleId: 'testing.x', category: 'testing', files: ['t.ts'] });
    const cmp = compareScans(
      side({ scanId: 'a', findings: [], coverage: makeCoverage({ analyzersRun: ['security'] }) }),
      side({ scanId: 'b', findings: [newFinding], coverage: makeCoverage({ analyzersRun: ['security', 'testing'] }) }),
    );
    assert.match(cmp.summary, /newly looked for rather than newly introduced/);
  });
});
