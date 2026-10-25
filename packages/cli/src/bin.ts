#!/usr/bin/env node
import { mkdirSync, writeFileSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { Db } from '@codelens/engine/db/index.ts';
import { runScan } from '@codelens/engine/pipeline/orchestrator.ts';
import { listScans, loadScanSide, saveScan } from '@codelens/engine/pipeline/persist.ts';
import { ALL_ANALYZERS } from '@codelens/engine/analyzers/all.ts';
import { loadAiConfig } from '@codelens/engine/ai/provider.ts';
import {
  exportComparisonJson, exportFindingsJson, renderExecutiveSummary, renderFixPackBundle,
  renderHtmlReport, renderTechnicalReport, compareScans,
} from '@codelens/engine/reports/index.ts';
import { evaluate, formatEvalReport, loadGroundTruth } from '@codelens/engine/eval/harness.ts';

/**
 * CodeLens AI command line interface.
 *
 * The CLI is the primary way to run a scan: it needs no server, no database
 * service, and no network. A scan of a local directory is entirely offline.
 */

const HELP = `codelens — understand any codebase, diagnose what matters, fix it with precision

Usage:
  codelens scan <path|owner/repo> [options]   Run a full scan
  codelens eval [fixture-path]                Measure precision/recall against a ground-truth fixture
  codelens list [--project <id>]              List stored scans
  codelens compare <baseScanId> <headScanId>  Compare two scans of the same project
  codelens report <scanId> [options]          Re-export reports for a stored scan

Scan options:
  --name <name>        Project display name (default: directory or repo name)
  --project <id>       Project id to attach the scan to (default: derived from the name)
  --out <dir>          Write reports to this directory (default: ./codelens-report)
  --db <path>          SQLite database path (default: .codelens/codelens.db)
  --github-token <t>   Token for a private repository (read-only scopes only)
  --format <list>      Comma-separated: exec,tech,json,html,packs  (default: all)
  --agent <name>       Fix Pack prompt format: claude_code | codex | generic (default: claude_code)
  --no-save            Do not write to the database
  --quiet              Only print the summary

AI (optional, off by default):
  Configure via the environment: CODELENS_AI_PROVIDER=none|ollama|anthropic|openai
  With no provider configured, every deterministic layer still runs and the scan is complete.
`;

interface Args {
  command: string;
  positionals: string[];
  flags: Record<string, string | boolean>;
}

function parseArgs(argv: string[]): Args {
  const [command = 'help', ...rest] = argv;
  const positionals: string[] = [];
  const flags: Record<string, string | boolean> = {};
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i]!;
    if (!a.startsWith('--')) { positionals.push(a); continue; }
    const key = a.slice(2);
    const next = rest[i + 1];
    if (next && !next.startsWith('--')) { flags[key] = next; i++; }
    else flags[key] = true;
  }
  return { command, positionals, flags };
}

function str(flags: Args['flags'], key: string): string | undefined {
  const v = flags[key];
  return typeof v === 'string' ? v : undefined;
}

function openDb(path: string): Db {
  const dir = path.slice(0, path.lastIndexOf('/'));
  if (dir) mkdirSync(dir, { recursive: true });
  const db = new Db(path);
  db.migrate();
  return db;
}

function slugify(s: string): string {
  return s.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 40) || 'project';
}

async function cmdScan(args: Args): Promise<number> {
  const target = args.positionals[0];
  if (!target) {
    console.error('error: scan requires a path or owner/repo\n');
    console.error(HELP);
    return 2;
  }

  const isLocalPath = target.startsWith('.') || target.startsWith('/') || target.startsWith('~');
  const defaultName = isLocalPath
    ? resolve(target.replace(/^~/, process.env.HOME ?? '~')).split('/').filter(Boolean).pop() ?? 'project'
    : target;
  const projectName = str(args.flags, 'name') ?? defaultName;
  const projectId = str(args.flags, 'project') ?? slugify(projectName);
  const quiet = args.flags.quiet === true;

  const aiConfig = loadAiConfig();
  if (!quiet) {
    console.log(`CodeLens AI — scanning ${target}`);
    console.log(`  project: ${projectName} (${projectId})`);
    console.log(`  AI layer: ${aiConfig.provider === 'none' ? 'disabled (deterministic analysis only)' : `${aiConfig.provider}/${aiConfig.model}`}`);
    console.log('');
  }

  const source = isLocalPath
    ? { kind: 'local' as const, path: resolve(target.replace(/^~/, process.env.HOME ?? '~')) }
    : { kind: 'github' as const, ref: target, token: str(args.flags, 'github-token') ?? process.env.GITHUB_TOKEN };

  const started = Date.now();
  const outcome = await runScan({
    projectId,
    projectName,
    source,
    analyzers: ALL_ANALYZERS,
    aiConfig,
    onStageChange: quiet ? undefined : (stage) => {
      if (stage.status === 'running') process.stdout.write(`  ${stage.name} … `);
      else if (stage.status === 'completed') console.log(`${stage.status}${stage.durationMs !== undefined ? ` (${stage.durationMs}ms)` : ''}`);
      else console.log(stage.status);
    },
  });

  if (!quiet) console.log('');
  printSummary(outcome, projectName, Date.now() - started);

  // --- persist ---
  if (args.flags['no-save'] !== true) {
    const dbPath = str(args.flags, 'db') ?? '.codelens/codelens.db';
    const db = openDb(dbPath);
    try {
      saveScan(db, outcome, { organizationId: 'local', projectId, projectName });
      if (!quiet) console.log(`\nStored scan ${outcome.scanId} in ${dbPath}`);
    } finally {
      db.close();
    }
  }

  // --- reports ---
  const outDir = str(args.flags, 'out') ?? 'codelens-report';
  const formats = (str(args.flags, 'format') ?? 'exec,tech,json,html,packs').split(',').map((s) => s.trim());
  const agent = (str(args.flags, 'agent') ?? 'claude_code') as 'claude_code' | 'codex' | 'generic';
  mkdirSync(outDir, { recursive: true });
  const written: string[] = [];

  if (formats.includes('exec')) {
    const p = join(outDir, 'executive-summary.md');
    writeFileSync(p, renderExecutiveSummary(outcome, projectName));
    written.push(p);
  }
  if (formats.includes('tech')) {
    const p = join(outDir, 'technical-report.md');
    writeFileSync(p, renderTechnicalReport(outcome, projectName));
    written.push(p);
  }
  if (formats.includes('json')) {
    const p = join(outDir, 'findings.json');
    writeFileSync(p, JSON.stringify(exportFindingsJson(outcome, projectName), null, 2));
    written.push(p);
  }
  if (formats.includes('html')) {
    const p = join(outDir, 'technical-report.html');
    writeFileSync(p, renderHtmlReport(outcome, { projectName, kind: 'technical' }));
    written.push(p);
    const p2 = join(outDir, 'executive-summary.html');
    writeFileSync(p2, renderHtmlReport(outcome, { projectName, kind: 'executive' }));
    written.push(p2);
  }
  if (formats.includes('packs') && outcome.fixPacks.length > 0) {
    const bundle = join(outDir, 'fix-packs.md');
    writeFileSync(bundle, renderFixPackBundle(outcome, agent));
    written.push(bundle);
    const packDir = join(outDir, 'fix-packs');
    mkdirSync(packDir, { recursive: true });
    for (const pack of outcome.fixPacks) {
      const prompt = outcome.packPrompts.get(pack.key)?.[agent];
      if (!prompt) continue;
      const p = join(packDir, `${String(pack.ordinal).padStart(2, '0')}-${pack.key}.md`);
      writeFileSync(p, prompt);
      written.push(p);
    }
  }

  if (!quiet && written.length > 0) {
    console.log(`\nReports written to ${resolve(outDir)}:`);
    for (const p of written) console.log(`  ${p}`);
    console.log('\nOpen a .html report in a browser and use "Save as PDF" to produce a PDF.');
  }

  return outcome.status === 'failed' ? 1 : 0;
}

function printSummary(outcome: Awaited<ReturnType<typeof runScan>>, projectName: string, elapsedMs: number): void {
  const counts: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of outcome.findings) counts[f.severity] = (counts[f.severity] ?? 0) + 1;

  console.log('='.repeat(68));
  console.log(`${projectName} — scan ${outcome.status} in ${(elapsedMs / 1000).toFixed(1)}s`);
  console.log('='.repeat(68));

  const card = outcome.scorecard;
  if (card?.overall !== null && card?.overall !== undefined) {
    console.log(`Health score      ${card.overall}/100 (${card.overallGrade}), graded from ${(card.assessedWeight * 100).toFixed(0)}% of assessment weight`);
  } else {
    console.log(`Health score      insufficient evidence${card ? ` (only ${(card.assessedWeight * 100).toFixed(0)}% of weight gradeable)` : ''}`);
  }
  console.log(`Findings          ${outcome.findings.length} — ${counts.critical} critical, ${counts.high} high, ${counts.medium} medium, ${counts.low} low, ${counts.info} info`);

  const byPriority: Record<string, number> = { P0: 0, P1: 0, P2: 0, P3: 0 };
  for (const p of outcome.prioritized) byPriority[p.priority] = (byPriority[p.priority] ?? 0) + 1;
  console.log(`Priority          P0:${byPriority.P0} P1:${byPriority.P1} P2:${byPriority.P2} P3:${byPriority.P3}`);
  console.log(`Coverage          ${outcome.coverage.filesIndexed} files indexed, ${outcome.coverage.filesParsed} parsed (${(outcome.coverage.parseRatio * 100).toFixed(0)}% of deep-support source)`);
  console.log(`Layers completed  static:${yn(outcome.coverage.layers.static)} cross-file:${yn(outcome.coverage.layers.graph)} ai:${yn(outcome.coverage.layers.ai)} dynamic:${yn(outcome.coverage.layers.dynamic)}`);
  if (outcome.map) {
    console.log(`Architecture      ${outcome.map.components.length} components, ${outcome.map.relationships.length} relationships, ${outcome.map.routes.length} routes, ${outcome.map.models.length} models, ${outcome.map.features.length} features`);
  }
  console.log(`Fix Packs         ${outcome.fixPacks.length} ready`);
  if (outcome.rejectedFindings.length > 0) {
    console.log(`Refused findings  ${outcome.rejectedFindings.length} withheld by the evidence gate`);
  }

  const skipped = outcome.stages.filter((s) => s.status === 'skipped');
  const failed = outcome.stages.filter((s) => s.status === 'failed');
  if (failed.length > 0) {
    console.log('\nFAILED STAGES:');
    for (const s of failed) console.log(`  ${s.name}: ${s.message}`);
  }
  if (skipped.length > 0) {
    console.log('\nSkipped stages:');
    for (const s of skipped) console.log(`  ${s.name}: ${truncate(s.message ?? '', 150)}`);
  }
  if (outcome.coverage.analyzersSkipped.length > 0) {
    console.log('\nAnalyzers not run:');
    for (const s of outcome.coverage.analyzersSkipped) console.log(`  ${s.analyzer}: ${truncate(s.reason, 120)}`);
  }

  const p0 = outcome.prioritized.filter((p) => p.priority === 'P0');
  if (p0.length > 0) {
    console.log('\nNeeds attention before release (P0):');
    for (const p of p0) {
      const ev = p.finding.evidence[0];
      console.log(`  ${p.finding.id}  ${p.finding.title}`);
      console.log(`         ${ev?.file}${ev?.startLine ? `:${ev.startLine}` : ''}`);
    }
  }
  if (outcome.fixPacks.length > 0) {
    console.log('\nRemediation roadmap:');
    for (const pack of outcome.fixPacks) {
      console.log(`  ${pack.ordinal}. ${pack.title} — ${pack.findings.length} finding(s), ${pack.effort} effort${pack.dependsOn.length ? `, after ${pack.dependsOn.join(', ')}` : ''}`);
    }
  }
}

function yn(b: boolean): string { return b ? 'yes' : 'no'; }
function truncate(s: string, n: number): string { return s.length > n ? `${s.slice(0, n - 1)}…` : s; }

async function cmdEval(args: Args): Promise<number> {
  const fixture = args.positionals[0] ?? 'fixtures/vulnerable-shop';
  const gtPath = join(fixture, 'GROUND_TRUTH.json');
  let gt;
  try {
    gt = loadGroundTruth(gtPath);
  } catch (e) {
    console.error(`error: could not read ground truth at ${gtPath}: ${(e as Error).message}`);
    return 2;
  }

  console.log(`Running scan of ${fixture} …\n`);
  const outcome = await runScan({
    projectId: 'eval', projectName: gt.project,
    source: { kind: 'local', path: resolve(fixture) },
    analyzers: ALL_ANALYZERS,
  });

  const result = evaluate(outcome.findings, gt);
  console.log(formatEvalReport(result));
  console.log('');
  console.log('Stage status:');
  for (const s of outcome.stages) {
    if (s.status !== 'completed') console.log(`  ${s.name}: ${s.status} — ${truncate(s.message ?? '', 120)}`);
  }
  // A missed required defect is a real regression in diagnostic quality.
  return result.recallRequired < 1 || result.falsePositivesOnCleanFiles.length > 0 ? 1 : 0;
}

function cmdList(args: Args): number {
  const db = openDb(str(args.flags, 'db') ?? '.codelens/codelens.db');
  try {
    const projectId = str(args.flags, 'project');
    const projects = projectId
      ? [{ id: projectId, name: projectId }]
      : db.all<{ id: string; name: string }>('SELECT id, name FROM projects WHERE deleted_at IS NULL ORDER BY name');
    if (projects.length === 0) {
      console.log('No projects stored yet. Run `codelens scan <path>` first.');
      return 0;
    }
    for (const p of projects) {
      console.log(`\n${p.name} (${p.id})`);
      const scans = listScans(db, p.id);
      if (scans.length === 0) { console.log('  no scans'); continue; }
      for (const s of scans) {
        console.log(`  ${s.id}  ${s.status.padEnd(10)} ${s.findings} findings  ${s.queuedAt}`);
      }
    }
    return 0;
  } finally {
    db.close();
  }
}

function cmdCompare(args: Args): number {
  const [baseId, headId] = args.positionals;
  if (!baseId || !headId) {
    console.error('error: compare requires two scan ids\n');
    console.error(HELP);
    return 2;
  }
  const db = openDb(str(args.flags, 'db') ?? '.codelens/codelens.db');
  try {
    const base = loadScanSide(db, baseId);
    const head = loadScanSide(db, headId);
    if (!base) { console.error(`error: scan ${baseId} not found`); return 2; }
    if (!head) { console.error(`error: scan ${headId} not found`); return 2; }

    const cmp = compareScans(base, head);
    console.log(`Comparing ${baseId} -> ${headId}`);
    console.log('='.repeat(68));
    console.log(cmp.summary);
    console.log('');
    console.log(`Verified resolved         ${cmp.resolved.length}`);
    console.log(`Unverified absences      ${cmp.unverifiedAbsences.length}  (NOT counted as fixed)`);
    console.log(`Still present            ${cmp.persistent.length}`);
    console.log(`Newly reported           ${cmp.introduced.length}`);
    console.log(`Regressed                ${cmp.regressed.length}`);

    if (cmp.resolved.length > 0) {
      console.log('\nResolved:');
      for (const c of cmp.resolved) console.log(`  [${c.severity}] ${c.title}`);
    }
    if (cmp.unverifiedAbsences.length > 0) {
      console.log('\nNo longer reported, but NOT confirmed fixed:');
      for (const c of cmp.unverifiedAbsences) {
        console.log(`  [${c.severity}] ${c.title}`);
        console.log(`      ${c.caveat}`);
      }
    }
    if (cmp.regressed.length > 0) {
      console.log('\nRegressed (previously resolved, present again):');
      for (const c of cmp.regressed) console.log(`  [${c.severity}] ${c.title}`);
    }
    if (cmp.introduced.length > 0) {
      console.log('\nNewly reported:');
      for (const c of cmp.introduced) console.log(`  [${c.severity}] ${c.title}`);
    }

    const outDir = str(args.flags, 'out');
    if (outDir) {
      mkdirSync(outDir, { recursive: true });
      const p = join(outDir, 'comparison.json');
      writeFileSync(p, JSON.stringify(exportComparisonJson(cmp), null, 2));
      console.log(`\nWrote ${p}`);
    }
    return 0;
  } finally {
    db.close();
  }
}

function cmdReport(args: Args): number {
  const scanId = args.positionals[0];
  if (!scanId) {
    console.error('error: report requires a scan id');
    return 2;
  }
  console.error(
    'error: re-exporting a stored scan is not implemented in this release.\n' +
    'A stored scan keeps its findings, coverage, and Fix Pack prompts in the database, but the renderers need the\n' +
    'full in-memory repository map, which is not persisted. Re-run `codelens scan` to regenerate reports.\n' +
    'Stored Fix Pack prompts can be read directly:\n' +
    `  sqlite3 .codelens/codelens.db "SELECT prompt_markdown FROM fix_pack_versions v JOIN fix_packs p ON p.id = v.fix_pack_id WHERE p.scan_id = '${scanId}' AND v.agent_format = 'claude_code';"`,
  );
  return 3;
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  let code = 0;
  switch (args.command) {
    case 'scan': code = await cmdScan(args); break;
    case 'eval': code = await cmdEval(args); break;
    case 'list': code = cmdList(args); break;
    case 'compare': code = cmdCompare(args); break;
    case 'report': code = cmdReport(args); break;
    case 'help': case '--help': case '-h': console.log(HELP); break;
    case 'version': case '--version': {
      const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')) as { version: string };
      console.log(pkg.version);
      break;
    }
    default:
      console.error(`error: unknown command '${args.command}'\n`);
      console.error(HELP);
      code = 2;
  }
  process.exitCode = code;
}

main().catch((e) => {
  console.error(`\nfatal: ${e instanceof Error ? e.message : String(e)}`);
  if (process.env.CODELENS_DEBUG) console.error(e);
  process.exitCode = 1;
});
