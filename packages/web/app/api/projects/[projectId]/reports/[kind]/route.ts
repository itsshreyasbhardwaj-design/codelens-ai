import { NextResponse } from 'next/server';
import type {
  Finding, Priority, PrioritizedFinding, ScoreDimension, Scorecard, StageResult, TechDetection,
} from '@codelens/core';
import { MIN_ASSESSED_WEIGHT } from '@codelens/core';
import type { ScanOutcome } from '@codelens/engine/pipeline/orchestrator.ts';
import type { RepoMap } from '@codelens/engine/graph/repomap.ts';
import type { Snapshot } from '@codelens/engine/ingest/normalize.ts';
import type { FixPack } from '@codelens/engine/fixpacks/grouping.ts';
import type { ValidationResult } from '@codelens/engine/fixpacks/validate.ts';
import { loadScanSide } from '@codelens/engine/pipeline/persist.ts';
import { compareScans } from '@codelens/engine/reports/compare.ts';
import { exportComparisonJson, exportFindingsJson } from '@codelens/engine/reports/json.ts';
import {
  renderExecutiveSummary, renderFixPackBundle, renderTechnicalReport,
} from '@codelens/engine/reports/markdown.ts';
import { renderHtmlReport } from '@codelens/engine/reports/html.ts';
import {
  assessedWeight, db, getProject, latestScan, listScans, overallScore, scanComponents,
  scanFeatures, scanFindings, scanFixPacks, scanModels, scanRelationships, scanRoutes,
  scanScores, scanStages, scanTech, type ScanRow,
} from '../../../../../lib/store.ts';

/**
 * Report exports.
 *
 * ## The constraint, and the choice made about it
 *
 * The engine's renderers take a full in-memory `ScanOutcome`, including the
 * repository map, which is not persisted. There were two ways to produce an
 * export of a stored scan: re-run the scan on demand, or rebuild the renderer
 * inputs from the stored tables.
 *
 * This route rebuilds from the stored tables (option b). Re-running was not a
 * real option: the snapshot row records `source_kind` but no source location
 * (`artifact_path` is null for a local scan), so the original tree cannot be
 * found from stored state at all — a re-run would have to ask the operator for
 * the path again, and would then be a new scan rather than an export of the one
 * on screen. Rebuilding also keeps an export of a scan byte-stable: the document
 * describes the scan that was recorded, not the code as it is this minute.
 *
 * The engine's renderers are reused as they are. What rebuilding cannot supply
 * is listed in `NOT_PERSISTED` and printed inside every document, because the
 * difference between "absent from the data" and "absent from the project" is the
 * whole honesty of the product.
 */

export const dynamic = 'force-dynamic';

const KINDS = [
  'exec-md', 'tech-md', 'findings-json', 'exec-html', 'tech-html', 'fix-packs-md', 'comparison-json',
] as const;
type Kind = (typeof KINDS)[number];

function isKind(k: string): k is Kind {
  return (KINDS as readonly string[]).includes(k);
}

/**
 * What a stored scan cannot give back. Printed in every export.
 */
const NOT_PERSISTED = [
  'The environment-variable map (which variables the code reads, which are documented, which have a fallback) is built during a scan and never written to the database. Where this document has an environment-variable section, its emptiness means the data was not stored, not that the project reads no configuration.',
  'Findings refused by the evidence gate are not persisted, so no "refused findings" section appears. That is not a statement that none were refused.',
  'The AI layer\'s own report (targets attempted, tokens, model findings rejected by verification) is not persisted. The coverage section still records whether the AI layer ran at all.',
  'Per-finding priority factors and blocking relationships are not persisted; they are omitted rather than exported as empty values.',
  'The parsed module graph and file texts are not persisted, so nothing in this document was re-derived from source at export time. Every excerpt shown is the one recorded at scan time.',
];

// ----------------------------------------------------------- rehydration --

/** Snapshot metadata store.ts does not expose (branch), read from the same Db. */
function snapshotMeta(scanId: string): { contentHash?: string; commitSha?: string; branch?: string } {
  const row = db().get<{ content_hash: string | null; commit_sha: string | null; branch: string | null }>(
    `SELECT r.content_hash, r.commit_sha, r.branch
       FROM scan_jobs s JOIN repository_snapshots r ON r.id = s.snapshot_id
      WHERE s.id = ?`,
    scanId,
  );
  return {
    contentHash: row?.content_hash ?? undefined,
    commitSha: row?.commit_sha ?? undefined,
    branch: row?.branch ?? undefined,
  };
}

/** Same thresholds as the engine's scorer, applied to the stored weighted total. */
function overallGrade(score: number | null): Scorecard['overallGrade'] {
  if (score === null) return 'insufficient_evidence';
  if (score >= 90) return 'A';
  if (score >= 75) return 'B';
  if (score >= 60) return 'C';
  if (score >= 40) return 'D';
  return 'F';
}

function buildScorecard(scanId: string, findings: Finding[]): Scorecard | undefined {
  const rows = scanScores(scanId);
  if (rows.length === 0) return undefined;
  const overall = overallScore(scanId);
  const dimensions = rows.map((r) => ({
    dimension: r.dimension as ScoreDimension,
    score: r.score,
    grade: r.grade as Scorecard['overallGrade'],
    weight: r.weight,
    findingCounts: {
      critical: r.counts.critical ?? 0,
      high: r.counts.high ?? 0,
      medium: r.counts.medium ?? 0,
      low: r.counts.low ?? 0,
      info: r.counts.info ?? 0,
    },
    penalty: r.penalty,
    reason: r.reason,
  }));
  // `rules` is only partly persisted: the per-dimension weights are, the penalty
  // and confidence tables are not. Only the real values are supplied, so nothing
  // in an export is a reconstructed rule.
  const rules = {
    weights: Object.fromEntries(rows.map((r) => [r.dimension, r.weight])),
    minAssessedWeight: MIN_ASSESSED_WEIGHT,
  };
  return {
    overall,
    overallGrade: overallGrade(overall),
    dimensions,
    assessedWeight: assessedWeight(scanId),
    criticalCount: findings.filter((f) => f.severity === 'critical').length,
    unassessedDimensions: rows.filter((r) => r.score === null).map((r) => r.dimension as ScoreDimension),
    rules,
  } as unknown as Scorecard;
}

interface Rehydrated { outcome: ScanOutcome; projectName: string }

/**
 * Rebuild the renderer input from the stored tables.
 *
 * The `map` handed to the renderers is not a real RepoMap: it carries the six
 * collections the renderers read and none of the scan-time machinery (file
 * texts, parsed modules, evidence helpers). It must never be passed to an
 * analyzer, which is why it is built here and not exported.
 */
function rehydrate(scan: ScanRow, projectName: string): Rehydrated | undefined {
  const side = loadScanSide(db(), scan.id);
  if (!side) return undefined;

  const byDisplayId = new Map(side.findings.map((f) => [f.id, f]));
  const stored = scanFindings(scan.id);

  const prioritized: PrioritizedFinding[] = [];
  for (const row of stored) {
    const finding = byDisplayId.get(row.displayId);
    if (!finding) continue;
    prioritized.push({
      finding,
      // Every finding in the seeded data carries a stored priority; the fallback
      // is labelled rather than silently presented as a judgement.
      priority: (row.priority ?? 'P3') as Priority,
      score: row.priorityScore ?? 0,
      // The per-factor breakdown is not persisted, only the total score and the
      // rationale. It is left empty rather than recomputed: scoreFinding() with
      // no prioritisation context would default `dependents` to 0 and
      // `unblocked` to 1, which would state as fact something the scan may have
      // found otherwise. It is stripped from the JSON export rather than shipped
      // as zeroes.
      factors: {} as PrioritizedFinding['factors'],
      rationale: row.priorityRationale
        ?? (row.priority ? 'Priority rationale was not persisted for this finding.' : 'No priority was persisted for this finding.'),
      blockedBy: [],
    });
  }

  const packRows = scanFixPacks(scan.id);
  const packPrompts = new Map<string, Record<string, string>>();
  const packValidations = new Map<string, ValidationResult>();
  const fixPacks: FixPack[] = packRows.map((p) => {
    packPrompts.set(p.key, p.prompts);
    packValidations.set(p.key, {
      packKey: p.key,
      presentable: p.validation.presentable,
      issues: p.validation.issues as ValidationResult['issues'],
      checksRun: p.validation.checksRun,
    });
    const members = p.findingIds
      .map((id) => prioritized.find((pf) => pf.finding.id === id))
      .filter((x): x is PrioritizedFinding => Boolean(x));
    const order: Priority[] = ['P0', 'P1', 'P2', 'P3'];
    const topPriority = order.find((o) => members.some((m) => m.priority === o)) ?? 'P3';
    return {
      key: p.key,
      title: p.title,
      family: p.family,
      ordinal: p.ordinal,
      objective: p.objective,
      effort: p.effort,
      dependsOn: p.dependsOn,
      findings: members,
      affectedFiles: [...new Set(members.flatMap((m) => m.finding.files))],
      affectedFeatures: [...new Set(members.flatMap((m) => m.finding.affectedFeatures ?? []))],
      topPriority,
    } as FixPack;
  });

  const meta = snapshotMeta(scan.id);

  const map = {
    routes: scanRoutes(scan.id),
    models: scanModels(scan.id),
    features: scanFeatures(scan.id).map((f) => ({
      id: f.key,
      name: f.name,
      intendedFunction: f.intendedFunction,
      status: f.status,
      frontendFiles: f.frontendFiles,
      backendFiles: f.backendFiles,
      databaseDeps: f.databaseDeps,
      externalServices: f.externalServices,
      authRequirement: f.authRequirement,
      implementationEvidence: f.evidence,
      tests: f.tests,
      possibleDefects: f.possibleDefects,
    })),
    components: scanComponents(scan.id).map((c) => ({
      id: c.key, name: c.name, kind: c.kind, files: c.files,
      provenance: c.provenance, summary: c.summary,
    })),
    relationships: scanRelationships(scan.id),
    // Not persisted. The renderers print a heading and no rows; every export
    // says so explicitly rather than letting the gap read as "none".
    env: { usages: [], documentedNames: new Set<string>(), templateFiles: [], committedEnvFiles: [] },
  } as unknown as RepoMap;

  const outcome: ScanOutcome = {
    scanId: scan.id,
    status: scan.status as ScanOutcome['status'],
    stages: scanStages(scan.id) as unknown as StageResult[],
    coverage: side.coverage,
    map,
    snapshot: meta.contentHash ? ({ contentHash: meta.contentHash } as unknown as Snapshot) : undefined,
    tech: scanTech(scan.id) as unknown as TechDetection[],
    findings: side.findings,
    prioritized,
    scorecard: buildScorecard(scan.id, side.findings),
    fixPacks,
    packPrompts: packPrompts as unknown as ScanOutcome['packPrompts'],
    packValidations,
    commitSha: meta.commitSha,
    branch: meta.branch,
    // Not persisted; an empty array means "not recorded", which the provenance
    // section in every document states.
    rejectedFindings: [],
    errorMessage: scan.errorMessage,
  };

  return { outcome, projectName };
}

// ------------------------------------------------------------- provenance --

function provenanceMarkdown(scan: ScanRow): string {
  const lines: string[] = [];
  lines.push('');
  lines.push('## How this document was produced');
  lines.push('');
  lines.push(
    `Assembled on ${new Date().toISOString()} from the stored tables of scan \`${scan.id}\`, which ran `
    + `${scan.finishedAt ? `and finished at ${scan.finishedAt}` : 'with no recorded finish time'}. `
    + 'The scan was **not** re-run for this export, so the document describes the code as it was when '
    + 'the scan read it. The renderers are the engine\'s own; their inputs were rebuilt from the '
    + 'findings, evidence, score, route, model, feature, component, relationship, technology, stage '
    + 'and Fix Pack tables.',
  );
  lines.push('');
  lines.push('Re-running on demand was not available for this scan: the stored snapshot records the source kind but not the source location, so the original tree cannot be located from stored state.');
  lines.push('');
  lines.push('What rebuilding cannot supply, and which must not be read as absence in the project:');
  lines.push('');
  for (const n of NOT_PERSISTED) lines.push(`- ${n}`);
  return lines.join('\n');
}

function provenanceHtml(scan: ScanRow): string {
  const esc = (s: string) => s
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  return [
    '<h2>How this document was produced</h2>',
    `<p>Assembled on ${esc(new Date().toISOString())} from the stored tables of scan <code>${esc(scan.id)}</code>. `
    + 'The scan was not re-run for this export, so the document describes the code as it was when the scan read it. '
    + 'The renderers are the engine&rsquo;s own; their inputs were rebuilt from the stored findings, evidence, scores, '
    + 'routes, models, features, components, relationships, technology, stages and Fix Packs.</p>',
    '<p>Re-running on demand was not available for this scan: the stored snapshot records the source kind but not the '
    + 'source location, so the original tree cannot be located from stored state.</p>',
    '<p>What rebuilding cannot supply, and which must not be read as absence in the project:</p>',
    `<ul>${NOT_PERSISTED.map((n) => `<li>${esc(n)}</li>`).join('')}</ul>`,
  ].join('\n');
}

/**
 * Mark the empty environment-variable table in the technical report.
 * Without this, a heading followed by an empty table reads as "no environment
 * variables are used", which would be a fabrication by omission.
 */
function annotateEnvGap(markdown: string): string {
  const heading = '### Environment variables';
  if (!markdown.includes(heading)) return markdown;
  return markdown.replace(
    heading,
    `${heading}\n\n**No data in this export.** The environment-variable map is built during a scan and is not `
    + 'persisted, so the table below has no rows because the data was not stored — not because the project reads '
    + 'no environment variables.',
  );
}

// ---------------------------------------------------------------- comparison --

/** The two most recent scans that can be compared, newest first. */
function comparableScans(projectId: string): ScanRow[] {
  return listScans(projectId)
    .filter((s) => (s.status === 'completed' || s.status === 'partial') && s.coverage !== undefined)
    .slice(0, 2);
}

// ------------------------------------------------------------------ handler --

function safe(s: string): string {
  return s.replace(/[^a-zA-Z0-9._-]+/g, '-').replace(/^-|-$/g, '').slice(0, 60) || 'codelens';
}

function send(body: string, type: string, filename: string, disposition: 'inline' | 'attachment'): Response {
  return new Response(body, {
    status: 200,
    headers: {
      'content-type': type,
      'content-disposition': `${disposition}; filename="${filename}"`,
      'cache-control': 'no-store',
    },
  });
}

export async function GET(_request: Request, { params }: { params: Promise<{ projectId: string; kind: string }> }) {
  const { projectId, kind } = await params;

  if (!isKind(kind)) {
    return NextResponse.json(
      { error: `unknown report kind '${kind}'`, supported: KINDS },
      { status: 400 },
    );
  }

  const project = getProject(projectId);
  if (!project) {
    return NextResponse.json({ error: `no project '${projectId}' in this organisation` }, { status: 404 });
  }
  const scan = latestScan(projectId);
  if (!scan) {
    return NextResponse.json({ error: `project '${projectId}' has no scan to export` }, { status: 409 });
  }

  const stem = `${safe(projectId)}-${safe(scan.id)}`;

  // --- the comparison export is built from two scans, not one ---
  if (kind === 'comparison-json') {
    const [head, base] = comparableScans(projectId);
    if (!head || !base) {
      return NextResponse.json(
        {
          error: 'a comparison needs two comparable scans of this project',
          detail: `found ${comparableScans(projectId).length} scan(s) with recorded coverage; `
            + 'a scan without coverage cannot be compared because absences could not be judged against it',
        },
        { status: 409 },
      );
    }
    const headSide = loadScanSide(db(), head.id);
    const baseSide = loadScanSide(db(), base.id);
    if (!headSide || !baseSide) {
      return NextResponse.json({ error: 'one of the two scans could not be loaded for comparison' }, { status: 409 });
    }
    const doc = {
      ...exportComparisonJson(compareScans(baseSide, headSide)),
      project: { id: project.id, name: project.name },
      baseScan: { id: base.id, queuedAt: base.queuedAt, findings: base.findings },
      headScan: { id: head.id, queuedAt: head.queuedAt, findings: head.findings },
      provenance: {
        assembledFrom: 'stored scan tables',
        scanReRun: false,
        notPersisted: NOT_PERSISTED,
      },
    };
    return send(
      `${JSON.stringify(doc, null, 2)}\n`,
      'application/json; charset=utf-8',
      `${safe(projectId)}-scan-comparison.json`,
      'attachment',
    );
  }

  const hydrated = rehydrate(scan, project.name);
  if (!hydrated) {
    return NextResponse.json(
      { error: `scan '${scan.id}' could not be loaded from the store, so no export can be produced` },
      { status: 409 },
    );
  }
  const { outcome, projectName } = hydrated;

  switch (kind) {
    case 'exec-md':
      return send(
        `${renderExecutiveSummary(outcome, projectName)}\n${provenanceMarkdown(scan)}\n`,
        'text/markdown; charset=utf-8',
        `${stem}-executive-summary.md`,
        'attachment',
      );

    case 'tech-md':
      return send(
        `${annotateEnvGap(renderTechnicalReport(outcome, projectName))}\n${provenanceMarkdown(scan)}\n`,
        'text/markdown; charset=utf-8',
        `${stem}-technical-report.md`,
        'attachment',
      );

    case 'fix-packs-md': {
      // The bundle is rendered from the stored `claude_code` prompts, which is
      // the format the packs were generated in for this scan.
      const bundle = renderFixPackBundle(outcome, 'claude_code');
      const withheld = outcome.fixPacks.filter((p) => outcome.packValidations.get(p.key)?.presentable === false);
      const note = withheld.length > 0
        ? `\n\n> ${withheld.length} pack(s) are withheld from this bundle because their prompts did not pass `
          + `validation: ${withheld.map((p) => p.key).join(', ')}.\n`
        : '';
      return send(
        `${bundle}${note}\n${provenanceMarkdown(scan)}\n`,
        'text/markdown; charset=utf-8',
        `${stem}-fix-packs.md`,
        'attachment',
      );
    }

    case 'findings-json': {
      const base = exportFindingsJson(outcome, projectName);
      const doc = {
        ...base,
        // Priority factors and blocking relationships are not persisted; they are
        // dropped rather than exported as empty objects that look like findings.
        findings: base.findings.map((f) => {
          const { priorityFactors, blockedBy, ...rest } = f as Record<string, unknown>;
          void priorityFactors;
          void blockedBy;
          return rest;
        }),
        provenance: {
          assembledFrom: 'stored scan tables',
          assembledAt: new Date().toISOString(),
          scanReRun: false,
          notPersisted: NOT_PERSISTED,
        },
      };
      return send(
        `${JSON.stringify(doc, null, 2)}\n`,
        'application/json; charset=utf-8',
        `${stem}-findings.json`,
        'attachment',
      );
    }

    case 'exec-html':
    case 'tech-html': {
      const html = renderHtmlReport(outcome, {
        projectName,
        kind: kind === 'exec-html' ? 'executive' : 'technical',
      });
      // Served inline so the browser renders it and its own "Save as PDF" can
      // produce the PDF. That is the whole PDF story: no extra dependency.
      const withProvenance = html.includes('</body>')
        ? html.replace('</body>', `${provenanceHtml(scan)}\n</body>`)
        : `${html}\n${provenanceHtml(scan)}`;
      return send(
        withProvenance,
        'text/html; charset=utf-8',
        `${stem}-${kind === 'exec-html' ? 'executive-summary' : 'technical-report'}.html`,
        'inline',
      );
    }
  }
}
