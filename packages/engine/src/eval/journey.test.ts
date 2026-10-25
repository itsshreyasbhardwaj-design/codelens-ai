import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { Db } from '../db/index.ts';
import { runScan } from '../pipeline/orchestrator.ts';
import { listScans, loadScanSide, saveScan } from '../pipeline/persist.ts';
import { ALL_ANALYZERS } from '../analyzers/all.ts';
import { compareScans } from '../reports/compare.ts';
import { exportFindingsJson } from '../reports/json.ts';
import { renderExecutiveSummary, renderFixPackBundle, renderTechnicalReport } from '../reports/markdown.ts';
import { renderHtmlReport } from '../reports/html.ts';
import { evaluate, loadGroundTruth } from './harness.ts';

/**
 * The end-to-end journey.
 *
 * This is the product's headline claim exercised in one test: ingest a real
 * project, understand it, diagnose it, prioritise, generate Fix Packs, export
 * reports, apply fixes, re-scan, and report honestly on what improved.
 *
 * It runs against the bundled fixture, so it needs no network, no service, and
 * no API key.
 */

const FIXTURE = resolve(import.meta.dirname, '../../../../fixtures/vulnerable-shop');

describe('end-to-end journey', () => {
  it('goes from a real project to verified improvement', async (t) => {
    const work = mkdtempSync(join(tmpdir(), 'codelens-journey-'));
    const db = new Db(join(work, 'journey.db'));
    db.migrate();
    t.after(() => { db.close(); rmSync(work, { recursive: true, force: true }); });

    const org = 'org-journey';
    const projectId = 'journey-shop';
    const projectName = 'Journey Shop';

    // ---- 1. Scan a real project ----
    const first = await runScan({
      projectId, projectName,
      source: { kind: 'local', path: FIXTURE },
      analyzers: ALL_ANALYZERS,
    });
    assert.equal(first.status, 'completed', first.errorMessage);

    // ---- 2. It understood the project ----
    assert.ok(first.map, 'a repository map must be produced');
    assert.ok(first.map!.routes.length >= 8, `expected the API surface, got ${first.map!.routes.length} routes`);
    assert.ok(first.map!.models.length >= 5, 'expected the data models');
    assert.ok(first.map!.features.length >= 8, 'expected a feature inventory');
    assert.ok(first.map!.components.length >= 10, 'expected architecture components');
    assert.ok(first.tech.some((tch) => tch.name === 'Next.js'), 'expected Next.js to be detected');

    // ---- 3. Every finding has verified evidence ----
    assert.ok(first.findings.length > 40, `expected a substantial diagnosis, got ${first.findings.length}`);
    for (const f of first.findings) {
      assert.ok(f.evidence.length > 0, `${f.id} has no evidence`);
      assert.ok(f.evidence.some((e) => e.verified), `${f.id} has no verified evidence`);
      assert.ok(f.explanation.length > 40, `${f.id} has a thin explanation`);
      assert.ok(f.userImpact.length > 20, `${f.id} has no user impact`);
      assert.ok(f.remediation.length > 40, `${f.id} has no actionable remediation`);
    }

    // ---- 4. It found the cross-file defects no single file reveals ----
    const crossFile = first.findings.filter((f) => f.detectionSource === 'graph' && f.trace);
    assert.ok(crossFile.length >= 3, `expected traced cross-file findings, got ${crossFile.length}`);
    const contract = first.findings.find((f) => f.ruleId.includes('contract'));
    assert.ok(contract, 'expected the frontend/backend contract break');
    assert.ok(contract!.files.length >= 2, 'a contract break must cite both ends');
    assert.equal(contract!.trace?.complete, true);

    // ---- 5. Prioritisation is honest ----
    for (const p of first.prioritized) {
      if (p.priority !== 'P0') continue;
      assert.ok(
        p.finding.confidence === 'confirmed' || p.finding.confidence === 'strong',
        `${p.finding.id} reached P0 on ${p.finding.confidence} confidence`,
      );
    }

    // ---- 6. Fix Packs are generated, validated, and reviewable ----
    assert.ok(first.fixPacks.length >= 4, `expected several Fix Packs, got ${first.fixPacks.length}`);
    assert.ok(first.fixPacks.length <= 20, 'packs should be grouped, not one per finding');
    const packKeys = new Set(first.fixPacks.map((p) => p.key));
    for (const pack of first.fixPacks) {
      const validation = first.packValidations.get(pack.key);
      assert.ok(validation?.presentable, `pack ${pack.key} was presented despite failing validation`);
      for (const dep of pack.dependsOn) {
        assert.ok(packKeys.has(dep), `pack ${pack.key} depends on '${dep}', which was not presented`);
      }
      const prompt = first.packPrompts.get(pack.key)?.claude_code;
      assert.ok(prompt, `pack ${pack.key} has no prompt`);
      for (const section of ['A. Role and objective', 'C. Identified problems', 'H. Verification', 'I. Acceptance criteria', 'J. Final report']) {
        assert.ok(prompt!.includes(section), `pack ${pack.key} prompt is missing section ${section}`);
      }
      assert.ok(prompt!.includes(first.scanId), `pack ${pack.key} prompt does not record its scan`);
    }

    // ---- 7. Reports export with their coverage and limitations ----
    const exec = renderExecutiveSummary(first, projectName);
    const tech = renderTechnicalReport(first, projectName);
    const jsonExport = exportFindingsJson(first, projectName);
    const html = renderHtmlReport(first, { projectName, kind: 'technical' });
    const bundle = renderFixPackBundle(first, 'claude_code');

    assert.match(exec, /Limitations of this report/);
    assert.match(tech, /Limitations of this report/);
    assert.ok(jsonExport.limitations.length >= 4, 'the JSON export must carry its limitations');
    assert.ok(jsonExport.coverage.analyzersRun.length > 0, 'the JSON export must carry coverage');
    assert.equal(jsonExport.findings.length, first.findings.length);
    assert.match(html, /<!doctype html>/i);
    assert.match(html, /Save as PDF/);
    assert.ok(bundle.length > 2000, 'the Fix Pack bundle should contain the prompts');

    // No report may claim a runtime measurement when nothing ran.
    assert.equal(first.coverage.layers.dynamic, false);
    assert.match(tech, /Dynamic verification \(builds\/tests\): no/);

    // ---- 8. Persisted, and readable back ----
    saveScan(db, first, { organizationId: org, projectId, projectName });
    assert.equal(listScans(db, projectId).length, 1);

    // ---- 9. A developer applies fixes ----
    const fixedDir = join(work, 'fixed');
    cpSync(FIXTURE, fixedDir, { recursive: true });
    rmSync(join(fixedDir, 'GROUND_TRUTH.json'), { force: true });

    const dbFile = join(fixedDir, 'src/lib/db.ts');
    writeFileSync(dbFile, readFileSync(dbFile, 'utf8').replace(
      'const sql = `SELECT * FROM "Product" WHERE name LIKE \'%${term}%\'`;\n  const result = await pool.query(sql);',
      "const result = await pool.query('SELECT * FROM \"Product\" WHERE name LIKE $1 LIMIT 100', [`%${term}%`]);",
    ));

    const pageFile = join(fixedDir, 'src/app/products/page.tsx');
    writeFileSync(pageFile, readFileSync(pageFile, 'utf8').replace(
      '<img src={`/img/${p.id}.jpg`} width={200} height={200} />',
      '<img src={`/img/${p.id}.jpg`} alt={p.name} width={200} height={200} />',
    ));

    // ---- 10. Re-scan the changed project ----
    const second = await runScan({
      projectId, projectName,
      source: { kind: 'local', path: fixedDir },
      analyzers: ALL_ANALYZERS,
    });
    assert.equal(second.status, 'completed', second.errorMessage);
    saveScan(db, second, { organizationId: org, projectId, projectName });
    assert.equal(listScans(db, projectId).length, 2);

    // ---- 11. The comparison is honest about what improved ----
    const base = loadScanSide(db, first.scanId)!;
    const head = loadScanSide(db, second.scanId)!;
    const cmp = compareScans(base, head);

    assert.ok(cmp.resolved.length > 0, 'the applied fixes should be verified as resolved');
    assert.ok(
      cmp.resolved.some((c) => /SQL|interpolation/i.test(c.title)),
      `the SQL injection fix should be verified; resolved: ${cmp.resolved.map((c) => c.title).join(' | ')}`,
    );
    assert.ok(
      cmp.resolved.some((c) => /alt text|alt/i.test(c.title)) || cmp.relocated.length > 0,
      'the alt-text fix should be accounted for',
    );
    // Nothing may be reported as a regression here: nothing came back.
    assert.equal(cmp.regressed.length, 0, `unexpected regressions: ${cmp.regressed.map((c) => c.title).join(', ')}`);
    // And every absence that was counted as resolved had its file re-examined.
    for (const c of cmp.resolved) {
      assert.equal(c.caveat, undefined, `a resolved finding should carry no caveat: ${c.title}`);
    }

    // ---- 12. Deleting the project removes its derived data ----
    db.run('DELETE FROM projects WHERE id = ?', projectId);
    assert.equal(
      db.get<{ n: number }>('SELECT COUNT(*) AS n FROM diagnostic_findings WHERE project_id = ?', projectId)!.n,
      0,
      'findings must be removed with the project',
    );
    assert.equal(
      db.get<{ n: number }>('SELECT COUNT(*) AS n FROM scan_jobs WHERE project_id = ?', projectId)!.n,
      0,
      'scans must be removed with the project',
    );
  });

  it('meets the diagnostic accuracy bar on the fixture', async () => {
    const gtPath = join(FIXTURE, 'GROUND_TRUTH.json');
    assert.ok(existsSync(gtPath), 'the fixture must ship its ground truth');
    const gt = loadGroundTruth(gtPath);

    const outcome = await runScan({
      projectId: 'accuracy', projectName: gt.project,
      source: { kind: 'local', path: FIXTURE },
      analyzers: ALL_ANALYZERS,
    });
    const result = evaluate(outcome.findings, gt);

    // A drop in required-tier recall is a regression in diagnostic quality.
    assert.equal(
      result.recallRequired, 1,
      `required recall fell to ${(result.recallRequired * 100).toFixed(0)}%; missed: ${result.missed.filter((m) => m.tier === 'required').map((m) => m.key).join(', ')}`,
    );
    assert.equal(
      result.falsePositivesOnCleanFiles.length, 0,
      `false positives on files declared clean: ${result.falsePositivesOnCleanFiles.map((f) => f.ruleId).join(', ')}`,
    );
    assert.equal(
      result.findingsWithUnresolvedEvidence.length, 0,
      'every finding must carry evidence that re-verifies against the snapshot',
    );
  });
});
