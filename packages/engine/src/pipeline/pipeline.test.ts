import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Db, NotFoundError } from '../db/index.ts';
import { CredentialStorageUnavailable, encryptToken, decryptToken, redactSecrets } from '../db/crypto.ts';
import { runScan } from './orchestrator.ts';
import { saveScan, loadScanSide, listScans } from './persist.ts';
import { securityAnalyzer } from '../analyzers/security.ts';
import type { Analyzer } from '../analyzers/types.ts';

/**
 * Integration tests for the scan pipeline.
 *
 * These cover the failure modes that decide whether a partial result is honest:
 * an analyzer that throws, a cancelled scan, a source that does not exist, a
 * duplicate submission, and cross-tenant access.
 */

function tempProject(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), 'codelens-test-'));
  for (const [path, content] of Object.entries(files)) {
    const full = join(dir, path);
    mkdirSync(full.slice(0, full.lastIndexOf('/')), { recursive: true });
    writeFileSync(full, content);
  }
  return dir;
}

const MINIMAL_APP = {
  'package.json': JSON.stringify({ name: 'tiny', dependencies: { next: '15.0.0', react: '18.3.1' } }),
  'src/app/api/items/route.ts': `
import { NextResponse } from 'next/server';
export async function GET() {
  return NextResponse.json({ items: [] });
}
`.trim(),
  'src/lib/util.ts': 'export function add(a: number, b: number) { return a + b; }',
};

describe('scan orchestration', () => {
  it('completes a scan of a minimal project and reports every stage', async (t) => {
    const dir = tempProject(MINIMAL_APP);
    t.after(() => rmSync(dir, { recursive: true, force: true }));

    const outcome = await runScan({
      projectId: 'p1', projectName: 'Tiny',
      source: { kind: 'local', path: dir },
      analyzers: [securityAnalyzer],
    });

    assert.ok(['completed', 'partial'].includes(outcome.status), `status was ${outcome.status}`);
    assert.equal(outcome.stages.length, 12, 'all twelve stages must be reported');
    // Every stage has a real, non-pending status.
    for (const s of outcome.stages) {
      assert.notEqual(s.status, 'pending', `${s.name} was left pending`);
    }
    assert.ok(outcome.map, 'a repository map must be produced');
    assert.equal(outcome.map!.routes.length, 1);
    assert.equal(outcome.map!.routes[0]!.method, 'GET');
  });

  it('reports dynamic verification as skipped with a reason, never as done', async (t) => {
    const dir = tempProject(MINIMAL_APP);
    t.after(() => rmSync(dir, { recursive: true, force: true }));

    const outcome = await runScan({
      projectId: 'p1', projectName: 'Tiny',
      source: { kind: 'local', path: dir },
      analyzers: [securityAnalyzer],
    });
    const stage = outcome.stages.find((s) => s.name === 'dynamic_verification')!;
    assert.equal(stage.status, 'skipped');
    assert.match(stage.message!, /container isolation|disabled/);
    assert.equal(outcome.coverage.layers.dynamic, false);
  });

  it('refuses dynamic verification even when explicitly requested', async (t) => {
    const dir = tempProject(MINIMAL_APP);
    t.after(() => rmSync(dir, { recursive: true, force: true }));

    const outcome = await runScan({
      projectId: 'p1', projectName: 'Tiny',
      source: { kind: 'local', path: dir },
      analyzers: [securityAnalyzer],
      dynamicVerify: { enabled: true, reason: 'operator asked' },
    });
    const stage = outcome.stages.find((s) => s.name === 'dynamic_verification')!;
    assert.equal(stage.status, 'skipped');
    assert.match(stage.message!, /not implemented|Refusing/);
    assert.equal(outcome.coverage.layers.dynamic, false, 'the layer must never be claimed as completed');
  });

  it('reports the AI stage as skipped with its reason when no provider is configured', async (t) => {
    const dir = tempProject(MINIMAL_APP);
    t.after(() => rmSync(dir, { recursive: true, force: true }));

    const outcome = await runScan({
      projectId: 'p1', projectName: 'Tiny',
      source: { kind: 'local', path: dir },
      analyzers: [securityAnalyzer],
      aiConfig: {
        provider: 'none', model: '', tokenBudget: 1000,
        ollamaUrl: '', externalTransferAcknowledged: true,
      },
    });
    const stage = outcome.stages.find((s) => s.name === 'ai_semantic_investigation')!;
    assert.equal(stage.status, 'skipped');
    assert.match(stage.message!, /no AI provider configured/);
    assert.equal(outcome.coverage.layers.ai, false);
  });

  it('skips the AI layer with the billing reason when credits are refused, and still delivers the scan', async (t) => {
    const dir = tempProject(MINIMAL_APP);
    t.after(() => rmSync(dir, { recursive: true, force: true }));

    let settled = false;
    const outcome = await runScan({
      projectId: 'p1', projectName: 'Tiny',
      source: { kind: 'local', path: dir },
      analyzers: [securityAnalyzer],
      // A configured provider, so the stage is reachable and the refusal under
      // test is the credit refusal rather than a missing provider.
      aiConfig: {
        provider: 'ollama', model: 'qwen2.5-coder', tokenBudget: 10_000,
        ollamaUrl: 'http://127.0.0.1:1', externalTransferAcknowledged: false,
      },
      aiCredits: {
        estimate: () => 40,
        reserve: () => ({ ok: false, reason: 'This would use up to 40 credits and 0 are available.' }),
        settle: () => { settled = true; },
      },
    });

    const stage = outcome.stages.find((s) => s.name === 'ai_semantic_investigation')!;
    assert.equal(stage.status, 'skipped');
    assert.match(stage.message!, /40 credits and 0 are available/);
    assert.equal(outcome.coverage.layers.ai, false, 'a refused layer must not be reported as having run');
    assert.equal(settled, false, 'nothing may be settled when nothing was reserved');

    // The point of metering only the AI layer: the deterministic scan still ran.
    assert.equal(outcome.stages.find((s) => s.name === 'deterministic_diagnostics')!.status, 'completed');
    assert.ok(outcome.map, 'the scan must still produce a repository map');
    assert.notEqual(outcome.status, 'failed');
  });

  it('settles the hold against metered usage even when the AI layer fails', async (t) => {
    const dir = tempProject(MINIMAL_APP);
    t.after(() => rmSync(dir, { recursive: true, force: true }));

    const calls: Array<{ id: string; tokensIn: number; tokensOut: number }> = [];
    const outcome = await runScan({
      projectId: 'p1', projectName: 'Tiny',
      source: { kind: 'local', path: dir },
      analyzers: [securityAnalyzer],
      // Port 1 refuses the connection, so the layer fails after reserving.
      aiConfig: {
        provider: 'ollama', model: 'qwen2.5-coder', tokenBudget: 10_000,
        ollamaUrl: 'http://127.0.0.1:1', externalTransferAcknowledged: false,
      },
      aiCredits: {
        estimate: () => 40,
        reserve: () => ({ ok: true, reservationId: 'res_1' }),
        settle: (id, tokensIn, tokensOut) => { calls.push({ id, tokensIn, tokensOut }); },
      },
    });

    assert.equal(calls.length, 1, 'a hold must be settled exactly once');
    assert.equal(calls[0]!.id, 'res_1');
    // Nothing reached the provider, so nothing is charged and the whole hold
    // comes back. A dangling hold would silently cost the customer credits.
    assert.equal(calls[0]!.tokensIn, 0);
    assert.equal(calls[0]!.tokensOut, 0);
    assert.notEqual(outcome.status, 'failed', 'a failed AI layer must not fail the scan');
  });

  it('survives an analyzer that throws, and records it as skipped', async (t) => {
    const dir = tempProject(MINIMAL_APP);
    t.after(() => rmSync(dir, { recursive: true, force: true }));

    const exploding: Analyzer = {
      id: 'exploding', category: 'quality', description: 'always throws',
      run() { throw new Error('simulated analyzer crash'); },
    };

    const outcome = await runScan({
      projectId: 'p1', projectName: 'Tiny',
      source: { kind: 'local', path: dir },
      analyzers: [securityAnalyzer, exploding],
    });

    // One analyzer failing must not fail the scan.
    assert.notEqual(outcome.status, 'failed');
    assert.ok(outcome.coverage.analyzersRun.includes('security'));
    const skipped = outcome.coverage.analyzersSkipped.find((s) => s.analyzer === 'exploding');
    assert.ok(skipped, 'the failed analyzer must be reported as skipped');
    assert.match(skipped!.reason, /simulated analyzer crash/);
  });

  it('refuses to grade a dimension whose analyzer did not run', async (t) => {
    const dir = tempProject(MINIMAL_APP);
    t.after(() => rmSync(dir, { recursive: true, force: true }));

    const outcome = await runScan({
      projectId: 'p1', projectName: 'Tiny',
      source: { kind: 'local', path: dir },
      analyzers: [securityAnalyzer], // only security
    });

    const reliability = outcome.scorecard!.dimensions.find((d) => d.dimension === 'reliability')!;
    assert.equal(reliability.grade, 'insufficient_evidence');
    assert.equal(reliability.score, null);
    assert.match(reliability.reason!, /did not run/);
    // And with so little gradeable, no overall score is produced.
    assert.equal(outcome.scorecard!.overall, null);
  });

  it('fails cleanly on a source that does not exist and marks later stages skipped', async () => {
    const outcome = await runScan({
      projectId: 'p1', projectName: 'Missing',
      source: { kind: 'local', path: '/nonexistent/path/for/a/test' },
      analyzers: [securityAnalyzer],
    });
    assert.equal(outcome.status, 'failed');
    assert.ok(outcome.errorMessage);
    assert.equal(outcome.stages[0]!.status, 'failed');
    for (const s of outcome.stages.slice(1)) {
      assert.equal(s.status, 'skipped', `${s.name} should be skipped after ingestion failed`);
    }
  });

  it('stops promptly when cancelled', async (t) => {
    const dir = tempProject(MINIMAL_APP);
    t.after(() => rmSync(dir, { recursive: true, force: true }));

    const outcome = await runScan({
      projectId: 'p1', projectName: 'Tiny',
      source: { kind: 'local', path: dir },
      analyzers: [securityAnalyzer],
      isCancelled: () => true, // cancelled before the first checkpoint
    });
    assert.equal(outcome.status, 'cancelled');
  });

  it('gives the same scan id for the same idempotency key', async (t) => {
    const dir = tempProject(MINIMAL_APP);
    t.after(() => rmSync(dir, { recursive: true, force: true }));

    const req = {
      projectId: 'p1', projectName: 'Tiny',
      source: { kind: 'local' as const, path: dir },
      analyzers: [securityAnalyzer],
      idempotencyKey: 'fixed-key-1',
    };
    const a = await runScan(req);
    const b = await runScan(req);
    assert.equal(a.scanId, b.scanId, 'a resubmission must not create a second scan id');
  });

  it('produces an identical content hash for identical input', async (t) => {
    const a = tempProject(MINIMAL_APP);
    const b = tempProject(MINIMAL_APP);
    t.after(() => { rmSync(a, { recursive: true, force: true }); rmSync(b, { recursive: true, force: true }); });

    const one = await runScan({ projectId: 'p', projectName: 'A', source: { kind: 'local', path: a }, analyzers: [] });
    const two = await runScan({ projectId: 'p', projectName: 'B', source: { kind: 'local', path: b }, analyzers: [] });
    assert.equal(one.snapshot!.contentHash, two.snapshot!.contentHash);
  });

  it('counts an unsupported language as present but unparsed, not as clean', async (t) => {
    const dir = tempProject({
      'package.json': '{"name":"x"}',
      'main.zig': 'pub fn main() void {}',
      'lib.erl': '-module(lib).',
    });
    t.after(() => rmSync(dir, { recursive: true, force: true }));

    const outcome = await runScan({
      projectId: 'p', projectName: 'Exotic',
      source: { kind: 'local', path: dir },
      analyzers: [securityAnalyzer],
    });
    assert.ok(outcome.coverage.filesIndexed >= 3);
    // No deep-support source at all, so the parse ratio must not read as full.
    assert.equal(outcome.coverage.parseRatio, 0);
    const unparsedReasons = Object.keys(outcome.coverage.skippedReasons).join(' ');
    assert.match(unparsedReasons, /no parser/);
  });

  it('runs concurrent scans without interference', async (t) => {
    const a = tempProject(MINIMAL_APP);
    const b = tempProject({ ...MINIMAL_APP, 'src/extra.ts': 'export const x = 1;' });
    t.after(() => { rmSync(a, { recursive: true, force: true }); rmSync(b, { recursive: true, force: true }); });

    const [one, two] = await Promise.all([
      runScan({ projectId: 'c1', projectName: 'One', source: { kind: 'local', path: a }, analyzers: [securityAnalyzer] }),
      runScan({ projectId: 'c2', projectName: 'Two', source: { kind: 'local', path: b }, analyzers: [securityAnalyzer] }),
    ]);
    assert.notEqual(one.scanId, two.scanId);
    assert.notEqual(one.snapshot!.contentHash, two.snapshot!.contentHash);
    assert.ok(one.coverage.filesIndexed < two.coverage.filesIndexed);
  });
});

describe('persistence and tenant isolation', () => {
  it('stores a scan and reads it back for comparison', async (t) => {
    const dir = tempProject(MINIMAL_APP);
    const db = new Db(':memory:');
    db.migrate();
    t.after(() => { db.close(); rmSync(dir, { recursive: true, force: true }); });

    const outcome = await runScan({
      projectId: 'proj-a', projectName: 'Tiny',
      source: { kind: 'local', path: dir },
      analyzers: [securityAnalyzer],
    });
    saveScan(db, outcome, { organizationId: 'org-1', projectId: 'proj-a', projectName: 'Tiny' });

    const scans = listScans(db, 'proj-a');
    assert.equal(scans.length, 1);
    assert.equal(scans[0]!.id, outcome.scanId);

    const side = loadScanSide(db, outcome.scanId);
    assert.ok(side);
    assert.equal(side!.findings.length, outcome.findings.length);
    assert.ok(side!.indexedFiles && side!.indexedFiles.size > 0, 'the file list must be stored for comparison');
    assert.ok(side!.coverage.analyzersRun.includes('security'), 'coverage must be stored');
  });

  it('writes an audit entry when a scan completes', async (t) => {
    const dir = tempProject(MINIMAL_APP);
    const db = new Db(':memory:');
    db.migrate();
    t.after(() => { db.close(); rmSync(dir, { recursive: true, force: true }); });

    const outcome = await runScan({
      projectId: 'proj-a', projectName: 'Tiny',
      source: { kind: 'local', path: dir },
      analyzers: [securityAnalyzer],
    });
    saveScan(db, outcome, { organizationId: 'org-1', projectId: 'proj-a', projectName: 'Tiny' });

    const entries = db.all<{ action: string }>('SELECT action FROM audit_logs WHERE organization_id = ?', 'org-1');
    assert.ok(entries.some((e) => e.action === 'scan.completed'));
  });

  it('hides another organisation\'s project behind the same error as a missing one', () => {
    const db = new Db(':memory:');
    db.migrate();
    try {
      db.run('INSERT INTO organizations (id,name,slug,created_at,updated_at) VALUES (?,?,?,?,?)', 'org-1', 'One', 'one', 'now', 'now');
      db.run('INSERT INTO organizations (id,name,slug,created_at,updated_at) VALUES (?,?,?,?,?)', 'org-2', 'Two', 'two', 'now', 'now');
      db.run('INSERT INTO projects (id,organization_id,name,slug,kind,created_at,updated_at) VALUES (?,?,?,?,?,?,?)',
        'secret-project', 'org-1', 'Secret', 'secret', 'source', 'now', 'now');

      // The owner can read it.
      db.assertProjectInOrg('secret-project', 'org-1');

      // Another tenant gets "not found" — the same error as for a project that
      // does not exist, so existence is not disclosed.
      let crossTenantError: Error | undefined;
      try { db.assertProjectInOrg('secret-project', 'org-2'); } catch (e) { crossTenantError = e as Error; }
      let missingError: Error | undefined;
      try { db.assertProjectInOrg('no-such-project', 'org-2'); } catch (e) { missingError = e as Error; }

      assert.ok(crossTenantError instanceof NotFoundError);
      assert.ok(missingError instanceof NotFoundError);
      assert.equal(crossTenantError!.message.replace('secret-project', 'X'), missingError!.message.replace('no-such-project', 'X'));
    } finally {
      db.close();
    }
  });

  it('enforces the foreign key that stops an orphaned finding', () => {
    const db = new Db(':memory:');
    db.migrate();
    try {
      assert.throws(() => {
        db.run(
          `INSERT INTO finding_evidence (id, finding_id, file, verified) VALUES (?,?,?,?)`,
          'e1', 'no-such-finding', 'a.ts', 1,
        );
      }, /FOREIGN KEY|constraint/i);
    } finally {
      db.close();
    }
  });

  it('protects an organisation from being deleted while projects exist', () => {
    const db = new Db(':memory:');
    db.migrate();
    try {
      db.run('INSERT INTO organizations (id,name,slug,created_at,updated_at) VALUES (?,?,?,?,?)', 'o', 'O', 'o', 'n', 'n');
      db.run('INSERT INTO projects (id,organization_id,name,slug,kind,created_at,updated_at) VALUES (?,?,?,?,?,?,?)',
        'p', 'o', 'P', 'p', 'source', 'n', 'n');
      assert.throws(() => db.run('DELETE FROM organizations WHERE id = ?', 'o'), /FOREIGN KEY|constraint/i);
    } finally {
      db.close();
    }
  });
});

describe('credential handling', () => {
  it('refuses to store a token when no secret key is configured', () => {
    const prior = process.env.CODELENS_SECRET_KEY;
    delete process.env.CODELENS_SECRET_KEY;
    try {
      assert.throws(() => encryptToken('ghp_something'), CredentialStorageUnavailable);
    } finally {
      if (prior) process.env.CODELENS_SECRET_KEY = prior;
    }
  });

  it('round-trips a token under authenticated encryption', () => {
    const prior = process.env.CODELENS_SECRET_KEY;
    process.env.CODELENS_SECRET_KEY = 'k'.repeat(40);
    try {
      const { ciphertext, nonce } = encryptToken('ghp_abcdefghijklmnop');
      assert.doesNotMatch(ciphertext, /ghp_/, 'the plaintext must not be recoverable from the ciphertext');
      assert.equal(decryptToken(ciphertext, nonce), 'ghp_abcdefghijklmnop');
    } finally {
      if (prior) process.env.CODELENS_SECRET_KEY = prior;
      else delete process.env.CODELENS_SECRET_KEY;
    }
  });

  it('detects a tampered ciphertext instead of returning wrong plaintext', () => {
    const prior = process.env.CODELENS_SECRET_KEY;
    process.env.CODELENS_SECRET_KEY = 'k'.repeat(40);
    try {
      const { ciphertext, nonce } = encryptToken('ghp_abcdefghijklmnop');
      const raw = Buffer.from(ciphertext, 'base64');
      raw[0] = raw[0]! ^ 0xff;
      assert.throws(() => decryptToken(raw.toString('base64'), nonce));
    } finally {
      if (prior) process.env.CODELENS_SECRET_KEY = prior;
      else delete process.env.CODELENS_SECRET_KEY;
    }
  });

  it('redacts secret shapes before anything is logged or stored', () => {
    const out = redactSecrets(
      'token=ghp_abcdefghijklmnopqrstuvwxyz0123456789 key=sk-ant-abcdefghijklmnopqrst ' +
      'aws=AKIAIOSFODNN7EXAMPLE db=postgres://user:hunter2@host/db',
    );
    assert.doesNotMatch(out, /ghp_abcdefghijklmnop/);
    assert.doesNotMatch(out, /hunter2/);
    assert.doesNotMatch(out, /AKIAIOSFODNN7EXAMPLE/);
    assert.match(out, /REDACTED/);
  });
});
