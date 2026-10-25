import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { makeFinding, prioritize, type PrioritizedFinding } from '@codelens/core';
import { buildFixPacks, MAX_FINDINGS_PER_PACK } from './grouping.ts';
import { generateFixPackPrompt, type PromptContext } from './prompt.ts';
import { instructionsOnly, validateFixPack } from './validate.ts';

function ctx(over: Partial<PromptContext> = {}): PromptContext {
  return {
    projectName: 'Test Project',
    scanId: 'scan_test_1',
    contentHash: 'abcdef0123456789abcdef',
    tech: [],
    routeCount: 3,
    modelCount: 2,
    coverage: {
      filesTotal: 10, filesIndexed: 10, filesParsed: 9, filesSkipped: 0, skippedReasons: {},
      languagesDeep: ['typescript'], languagesShallow: [], languagesUnsupported: [],
      analyzersRun: ['security'], analyzersSkipped: [],
      layers: { static: true, graph: true, ai: false, dynamic: false },
      parseRatio: 0.9, truncated: false,
    },
    totalPacks: 1,
    ...over,
  };
}

function prioritizedOf(findings: ReturnType<typeof makeFinding>[]): PrioritizedFinding[] {
  return prioritize(findings);
}

describe('fix pack grouping', () => {
  it('produces no packs when there are no actionable findings', () => {
    assert.equal(buildFixPacks([]).length, 0);
  });

  it('excludes informational findings from packs', () => {
    const packs = buildFixPacks(prioritizedOf([makeFinding({ severity: 'info', ruleId: 'quality.x' })]));
    assert.equal(packs.length, 0);
  });

  it('groups authorisation findings into the access-control pack', () => {
    const packs = buildFixPacks(prioritizedOf([
      makeFinding({ ruleId: 'security.authz.missing_authentication', files: ['a.ts'] }),
      makeFinding({ ruleId: 'security.authz.broken_object_level', files: ['b.ts'] }),
    ]));
    assert.equal(packs.length, 1);
    assert.equal(packs[0]!.family, 'security-access-control');
    assert.equal(packs[0]!.findings.length, 2);
  });

  it('keeps unrelated categories in separate packs', () => {
    const packs = buildFixPacks(prioritizedOf([
      makeFinding({ ruleId: 'security.authz.missing_authentication', files: ['a.ts'] }),
      makeFinding({ ruleId: 'accessibility.img.alt', category: 'accessibility', files: ['b.tsx'] }),
    ]));
    assert.equal(packs.length, 2);
  });

  it('splits an oversized family so each pack stays reviewable', () => {
    const many = Array.from({ length: MAX_FINDINGS_PER_PACK + 4 }, (_, i) =>
      makeFinding({ ruleId: 'security.authz.missing_authentication', files: [`src/area${i}/route.ts`] }),
    );
    const packs = buildFixPacks(prioritizedOf(many));
    assert.ok(packs.length >= 2, 'should split into at least two packs');
    for (const p of packs) {
      assert.ok(p.findings.length <= MAX_FINDINGS_PER_PACK, `${p.key} has ${p.findings.length} findings`);
    }
    // The later part must declare the earlier one as a prerequisite.
    assert.ok(packs[1]!.dependsOn.includes(packs[0]!.key));
  });

  it('never declares a dependency on a family that produced no pack', () => {
    // Testing depends on access-control and backend-reliability; with neither
    // present, the dependency must be dropped rather than dangling.
    const packs = buildFixPacks(prioritizedOf([
      makeFinding({ ruleId: 'testing.flows.untested', category: 'testing', files: ['t.ts'] }),
    ]));
    assert.equal(packs.length, 1);
    assert.deepEqual(packs[0]!.dependsOn, []);
  });

  it('assigns every actionable finding to exactly one pack', () => {
    const findings = [
      makeFinding({ ruleId: 'security.authz.missing_authentication', files: ['a.ts'] }),
      makeFinding({ ruleId: 'performance.query.n_plus_one', category: 'performance', files: ['b.ts'] }),
      makeFinding({ ruleId: 'devops.docker.root', category: 'devops', files: ['Dockerfile'] }),
      makeFinding({ ruleId: 'weird.unmatched.rule', category: 'quality', files: ['c.ts'] }),
    ];
    const packs = buildFixPacks(prioritizedOf(findings));
    const placed = packs.flatMap((p) => p.findings.map((f) => f.finding.fingerprint));
    assert.equal(new Set(placed).size, findings.length, 'every finding placed exactly once');
  });
});

describe('fix pack prompt', () => {
  it('contains all ten required sections', () => {
    const packs = buildFixPacks(prioritizedOf([makeFinding({ ruleId: 'security.authz.missing_authentication' })]));
    const prompt = generateFixPackPrompt(packs[0]!, ctx(), 'generic');
    for (const section of [
      'A. Role and objective', 'B. Repository context', 'C. Identified problems',
      'D. Required investigation', 'E. Exact remediation objectives', 'F. Engineering constraints',
      'G. Implementation strategy', 'H. Verification', 'I. Acceptance criteria', 'J. Final report',
    ]) {
      assert.ok(prompt.includes(section), `missing section: ${section}`);
    }
  });

  it('records the scan id and baseline so the result ties back to this scan', () => {
    const packs = buildFixPacks(prioritizedOf([makeFinding({ ruleId: 'security.authz.missing_authentication' })]));
    const prompt = generateFixPackPrompt(packs[0]!, ctx({ baselineCommit: 'deadbeefcafe' }), 'generic');
    assert.ok(prompt.includes('scan_test_1'));
    assert.ok(prompt.includes('deadbeefcafe'));
  });

  it('marks uncertainty for a finding that is not confirmed', () => {
    const packs = buildFixPacks(prioritizedOf([
      makeFinding({ ruleId: 'security.authz.missing_authentication', confidence: 'moderate', status: 'suspected' }),
    ]));
    const prompt = generateFixPackPrompt(packs[0]!, ctx(), 'generic');
    assert.ok(/SUSPECTED/.test(prompt), 'should label a suspected finding');
  });

  it('forbids a security guarantee rather than inviting one', () => {
    const packs = buildFixPacks(prioritizedOf([makeFinding({ ruleId: 'security.authz.missing_authentication' })]));
    const prompt = generateFixPackPrompt(packs[0]!, ctx(), 'generic');
    assert.ok(/Do not claim a security guarantee/i.test(prompt));
  });
});

describe('fix pack validation', () => {
  function validate(prompt: string, over: { knownFiles?: Set<string> } = {}) {
    const packs = buildFixPacks(prioritizedOf([makeFinding({ ruleId: 'security.authz.missing_authentication', files: ['src/a.ts'] })]));
    const pack = packs[0]!;
    return validateFixPack({
      pack,
      prompt,
      ctx: ctx(),
      knownFiles: over.knownFiles ?? new Set(['src/a.ts']),
      scanFingerprints: new Set(pack.findings.map((f) => f.finding.fingerprint)),
      allPackKeys: new Set([pack.key]),
      packDependencies: new Map([[pack.key, pack.dependsOn]]),
    });
  }

  it('passes a well-formed prompt', () => {
    const packs = buildFixPacks(prioritizedOf([makeFinding({ ruleId: 'security.authz.missing_authentication', files: ['src/a.ts'] })]));
    const prompt = generateFixPackPrompt(packs[0]!, ctx(), 'generic');
    const r = validate(prompt);
    assert.equal(r.presentable, true, JSON.stringify(r.issues));
  });

  it('withholds a pack whose evidence cites a file outside the snapshot', () => {
    const packs = buildFixPacks(prioritizedOf([makeFinding({ ruleId: 'security.authz.missing_authentication', files: ['src/a.ts'] })]));
    const prompt = generateFixPackPrompt(packs[0]!, ctx(), 'generic');
    const r = validate(prompt, { knownFiles: new Set(['other.ts']) });
    assert.equal(r.presentable, false);
    assert.ok(r.issues.some((i) => i.check === 'referenced_files_exist'));
  });

  it('withholds a prompt that genuinely requests a destructive operation', () => {
    const packs = buildFixPacks(prioritizedOf([makeFinding({ ruleId: 'security.authz.missing_authentication', files: ['src/a.ts'] })]));
    const base = generateFixPackPrompt(packs[0]!, ctx(), 'generic');
    const r = validate(base.replace('## J. Final report', '## J. Final report\n\n- Finish with `git push --force` to tidy history.'));
    assert.equal(r.presentable, false);
    assert.ok(r.issues.some((i) => i.check === 'no_destructive_operations'));
  });

  it('does NOT treat a quoted repository command as a requested operation', () => {
    // Regression: a trace step describing a CI workflow that deploys to
    // production must not be read as an instruction to deploy.
    const finding = makeFinding({
      ruleId: 'testing.ci.deploys_without_running_tests',
      category: 'testing',
      files: ['.github/workflows/deploy.yml'],
      evidence: [{
        file: '.github/workflows/deploy.yml', startLine: 20,
        excerpt: 'run: npx vercel deploy --prod --token=$VERCEL_TOKEN', verified: true,
      }],
      trace: {
        kind: 'import',
        steps: [{ file: '.github/workflows/deploy.yml', line: 20, detail: 'workflow step deploys: run: npx vercel deploy --prod --token=$VERCEL_TOKEN' }],
        complete: true,
      },
    });
    const packs = buildFixPacks(prioritizedOf([finding]));
    const pack = packs[0]!;
    const prompt = generateFixPackPrompt(pack, ctx(), 'generic');
    assert.ok(prompt.includes('vercel deploy --prod'), 'the quotation should appear in the prompt');

    const r = validateFixPack({
      pack, prompt, ctx: ctx(),
      knownFiles: new Set(['.github/workflows/deploy.yml']),
      scanFingerprints: new Set([finding.fingerprint]),
      allPackKeys: new Set([pack.key]),
      packDependencies: new Map([[pack.key, pack.dependsOn]]),
    });
    assert.equal(r.presentable, true, `should not be withheld: ${JSON.stringify(r.issues)}`);
  });

  it('strips quoted content and section C from the instruction view', () => {
    const prompt = [
      '# Fix Pack 1 of 1 — Test',
      '> provenance caveat with rm -rf /tmp/x',
      '## C. Identified problems',
      'the workflow runs git push --force origin main',
      '```',
      'DROP TABLE users;',
      '```',
      '## D. Required investigation',
      'read the files',
    ].join('\n');
    const io = instructionsOnly(prompt);
    assert.ok(!io.includes('git push --force'), 'section C should be excluded');
    assert.ok(!io.includes('DROP TABLE'), 'fenced blocks should be excluded');
    assert.ok(!io.includes('rm -rf'), 'blockquotes should be excluded');
    assert.ok(io.includes('read the files'), 'instruction sections must survive');
  });

  it('withholds a pack whose finding belongs to a different scan', () => {
    const packs = buildFixPacks(prioritizedOf([makeFinding({ ruleId: 'security.authz.missing_authentication', files: ['src/a.ts'] })]));
    const pack = packs[0]!;
    const prompt = generateFixPackPrompt(pack, ctx(), 'generic');
    const r = validateFixPack({
      pack, prompt, ctx: ctx(),
      knownFiles: new Set(['src/a.ts']),
      scanFingerprints: new Set(['a-different-scans-fingerprint']),
      allPackKeys: new Set([pack.key]),
      packDependencies: new Map([[pack.key, pack.dependsOn]]),
    });
    assert.equal(r.presentable, false);
    assert.ok(r.issues.some((i) => i.check === 'findings_belong_to_scan'));
  });

  it('detects a dependency cycle', () => {
    const packs = buildFixPacks(prioritizedOf([makeFinding({ ruleId: 'security.authz.missing_authentication', files: ['src/a.ts'] })]));
    const pack = packs[0]!;
    const prompt = generateFixPackPrompt(pack, ctx(), 'generic');
    const r = validateFixPack({
      pack, prompt, ctx: ctx(),
      knownFiles: new Set(['src/a.ts']),
      scanFingerprints: new Set(pack.findings.map((f) => f.finding.fingerprint)),
      allPackKeys: new Set([pack.key, 'other']),
      // A cycle: this pack -> other -> this pack.
      packDependencies: new Map([[pack.key, ['other']], ['other', [pack.key]]]),
    });
    assert.equal(r.presentable, false);
    assert.ok(r.issues.some((i) => i.detail.includes('cycle')));
  });
});
