import { randomUUID } from 'node:crypto';
import type {
  Coverage, Finding, LayerCompletion, PrioritizedFinding, ScanStatus, StageName, StageResult, TechDetection,
} from '@codelens/core';
import {
  assignDisplayIds, buildScorecard, consolidateFindings, enforceEvidenceDiscipline, prioritize,
  type Scorecard,
} from '@codelens/core';
import { DEFAULT_LIMITS, IngestRejected, type IngestLimits } from '../ingest/limits.ts';
import { readLocalDir, type RawEntry } from '../ingest/local.ts';
import { readZip } from '../ingest/zip.ts';
import { readTarGz } from '../ingest/tar.ts';
import { downloadRepoTarball, fetchRepoMetadata, parseRepoRef, resolveCommitSha } from '../ingest/github.ts';
import { normalizeEntries, type Snapshot } from '../ingest/normalize.ts';
import { parseSnapshot, type ParseReport } from '../parse/index.ts';
import { detectTechnologies } from '../detect/index.ts';
import { buildRepoMap, type RepoMap } from '../graph/repomap.ts';
import { DEEP_LANGUAGES, SHALLOW_LANGUAGES } from '../index/classify.ts';
import { runAnalyzers, type AnalyzerRunResult } from '../analyzers/registry.ts';
import type { Analyzer } from '../analyzers/types.ts';
import { detectInjectionAttempts } from '../ai/safety.ts';
import { ModelClient, loadAiConfig, type AiConfig } from '../ai/provider.ts';
import { investigate, type InvestigationReport } from '../ai/investigate.ts';
import { buildFixPacks, type FixPack } from '../fixpacks/grouping.ts';
import { generateFixPackPrompt, type AgentFormat, type PromptContext } from '../fixpacks/prompt.ts';
import { validateFixPack, type ValidationResult } from '../fixpacks/validate.ts';
import { StageTracker, specFor, STAGE_SPECS } from './stages.ts';
import { computeBlockedBy, computeDependentComponents } from './dependencies.ts';

/**
 * The scan orchestrator.
 *
 * Twelve stages, each reporting its real status. The design rules:
 *  - An optional stage that fails degrades the scan to `partial`; it never
 *    discards the work the other eleven stages did.
 *  - Cancellation is checked between stages, so a cancelled scan stops promptly
 *    and records where it stopped.
 *  - Nothing is inferred about a stage that did not run. `LayerCompletion` is
 *    reported from what actually completed.
 */

export type SourceSpec =
  | { kind: 'local'; path: string }
  | { kind: 'zip'; buffer: Buffer; filename?: string }
  | { kind: 'tarball'; buffer: Buffer }
  | { kind: 'github'; ref: string; token?: string };

export interface ScanRequest {
  projectId: string;
  projectName: string;
  source: SourceSpec;
  analyzers: Analyzer[];
  limits?: IngestLimits;
  aiConfig?: AiConfig;
  /** Explicitly authorised dynamic verification. Off unless set. */
  dynamicVerify?: { enabled: boolean; reason?: string };
  /** Resubmitting the same key must not start a second scan. */
  idempotencyKey?: string;
  /** Checked between stages. */
  isCancelled?: () => boolean;
  onStageChange?: (stage: StageResult) => void;
}

export interface ScanOutcome {
  scanId: string;
  status: ScanStatus;
  stages: StageResult[];
  coverage: Coverage;
  /** Undefined when ingestion failed. */
  map?: RepoMap;
  snapshot?: Snapshot;
  tech: TechDetection[];
  findings: Finding[];
  prioritized: PrioritizedFinding[];
  scorecard?: Scorecard;
  fixPacks: FixPack[];
  packPrompts: Map<string, Record<AgentFormat, string>>;
  packValidations: Map<string, ValidationResult>;
  commitSha?: string;
  branch?: string;
  /** Findings refused by the discipline gate, surfaced rather than hidden. */
  rejectedFindings: Array<{ title: string; reason: string }>;
  aiReport?: InvestigationReport;
  errorMessage?: string;
}

const EMPTY_COVERAGE: Coverage = {
  filesTotal: 0, filesIndexed: 0, filesParsed: 0, filesSkipped: 0, skippedReasons: {},
  languagesDeep: [], languagesShallow: [], languagesUnsupported: [],
  analyzersRun: [], analyzersSkipped: [],
  layers: { static: false, graph: false, ai: false, dynamic: false },
  parseRatio: 0, truncated: false,
};

export async function runScan(req: ScanRequest): Promise<ScanOutcome> {
  const scanId = req.idempotencyKey ? `scan_${req.idempotencyKey}` : `scan_${randomUUID()}`;
  const tracker = new StageTracker();
  const limits = req.limits ?? DEFAULT_LIMITS;
  const aiConfig = req.aiConfig ?? loadAiConfig();

  const outcome: ScanOutcome = {
    scanId, status: 'running', stages: tracker.all(), coverage: { ...EMPTY_COVERAGE },
    tech: [], findings: [], prioritized: [], fixPacks: [],
    packPrompts: new Map(), packValidations: new Map(), rejectedFindings: [],
  };

  const emit = (name: StageName) => req.onStageChange?.(tracker.get(name));
  const cancelled = () => req.isCancelled?.() === true;

  const cancelRemaining = (): ScanOutcome => {
    for (const s of STAGE_SPECS) tracker.cancel(s.name);
    outcome.status = 'cancelled';
    outcome.stages = tracker.all();
    return outcome;
  };

  /** Run one stage with attempt accounting and optional-stage tolerance. */
  const runStage = async <T>(name: StageName, fn: () => Promise<T> | T): Promise<T | undefined> => {
    const spec = specFor(name);
    for (let attempt = 1; attempt <= spec.maxAttempts; attempt++) {
      const t0 = performance.now();
      tracker.start(name);
      emit(name);
      try {
        const value = await fn();
        tracker.complete(name, t0);
        emit(name);
        return value;
      } catch (e) {
        const message = e instanceof Error ? e.message : String(e);
        const retryable = attempt < spec.maxAttempts && !(e instanceof IngestRejected);
        if (retryable) {
          tracker.warn(name, `attempt ${attempt} failed (${message}); retrying`);
          continue;
        }
        tracker.fail(name, message, t0);
        emit(name);
        return undefined;
      }
    }
    return undefined;
  };

  // ---------------------------------------------- 1. ingestion validation ---
  let entries: RawEntry[] = [];
  let preSkipped: Array<{ path: string; reason: string }> = [];
  let commitSha: string | undefined;
  let branch: string | undefined;

  const ingested = await runStage('ingestion_validation', async () => {
    switch (req.source.kind) {
      case 'local': {
        const r = readLocalDir(req.source.path, limits);
        return { entries: r.entries, skipped: r.skipped };
      }
      case 'zip': {
        const r = readZip(req.source.buffer, limits);
        return { entries: r.entries, skipped: r.skipped };
      }
      case 'tarball': {
        const r = readTarGz(req.source.buffer, limits, true);
        return { entries: r.entries, skipped: r.skipped };
      }
      case 'github': {
        const ref = parseRepoRef(req.source.ref);
        const meta = await fetchRepoMetadata(ref, req.source.token);
        branch = ref.ref ?? meta.defaultBranch;
        commitSha = await resolveCommitSha(ref, req.source.token);
        const r = await downloadRepoTarball({ ...ref, ref: commitSha }, req.source.token, limits);
        return { entries: r.entries, skipped: r.skipped };
      }
    }
  });

  if (!ingested) {
    outcome.status = 'failed';
    outcome.errorMessage = tracker.get('ingestion_validation').message ?? 'ingestion failed';
    outcome.stages = tracker.all();
    for (const s of STAGE_SPECS.slice(1)) tracker.skip(s.name, 'ingestion did not complete');
    outcome.stages = tracker.all();
    return outcome;
  }
  entries = ingested.entries;
  preSkipped = ingested.skipped;
  outcome.commitSha = commitSha;
  outcome.branch = branch;

  if (cancelled()) return cancelRemaining();

  // --------------------------------------------- 2. source normalization ----
  const snapshot = await runStage('source_normalization', () =>
    normalizeEntries(entries, limits, preSkipped),
  );
  if (!snapshot) {
    outcome.status = 'failed';
    outcome.errorMessage = tracker.get('source_normalization').message;
    outcome.stages = tracker.all();
    return outcome;
  }
  outcome.snapshot = snapshot;
  if (cancelled()) return cancelRemaining();

  // --------------------------------------------- 3. technology detection ----
  const detection = await runStage('technology_detection', () => {
    const report = detectTechnologies(snapshot);
    for (const err of report.adapterErrors) {
      tracker.warn('technology_detection', `adapter '${err.adapter}' failed: ${err.error}`);
    }
    return report;
  });
  outcome.tech = detection?.detections ?? [];
  if (cancelled()) return cancelRemaining();

  // ------------------------------------------------------ 4. code indexing --
  const parsed = await runStage('code_indexing', () => {
    const report = parseSnapshot(snapshot, limits);
    for (const p of report.unavailableParsers) {
      tracker.warn('code_indexing', `no parser available for ${p}; those files were indexed but not parsed`);
    }
    return report;
  });
  if (!parsed) {
    outcome.status = 'failed';
    outcome.errorMessage = tracker.get('code_indexing').message;
    outcome.stages = tracker.all();
    return outcome;
  }
  if (cancelled()) return cancelRemaining();

  // ------------------------------------- 6. architecture reconstruction -----
  // Built before diagnostics because the analyzers read the repository map.
  const map = await runStage('architecture_reconstruction', () =>
    buildRepoMap({ snapshot, modules: parsed.modules, tech: outcome.tech }),
  );
  if (!map) {
    outcome.status = 'failed';
    outcome.errorMessage = tracker.get('architecture_reconstruction').message;
    outcome.stages = tracker.all();
    return outcome;
  }
  outcome.map = map;
  if (cancelled()) return cancelRemaining();

  // ----------------------------------------- 5. deterministic diagnostics ---
  const analysis = await runStage('deterministic_diagnostics', () => {
    const result = runAnalyzers(map, req.analyzers);
    for (const err of result.errors) {
      tracker.warn('deterministic_diagnostics', `analyzer '${err.analyzer}' failed: ${err.error}`);
    }
    return result;
  });
  const analyzerResult: AnalyzerRunResult = analysis ?? {
    findings: [], analyzersRun: [], analyzersSkipped: [], errors: [], timings: [],
  };
  let allFindings = [...analyzerResult.findings];
  if (cancelled()) return cancelRemaining();

  // Prompt-injection content in the repository is checked regardless of whether
  // the AI layer runs: it is a property of the repository, not of our analysis.
  for (const file of snapshot.files) {
    if (!file.text || file.binary) continue;
    if (file.role !== 'documentation' && file.role !== 'config' && file.role !== 'source' && file.role !== 'component') continue;
    const attempts = detectInjectionAttempts(file.text);
    for (const a of attempts.slice(0, 2)) {
      allFindings.push(injectionFinding(file.path, a.line, a.excerpt, a.what, map));
    }
  }

  // --------------------------------------------- 7. dynamic verification ----
  const dyn = req.dynamicVerify;
  if (!dyn?.enabled) {
    tracker.skip(
      'dynamic_verification',
      'dynamic verification is disabled. Without container isolation this host cannot safely execute untrusted ' +
      'project code, so no build, test, or browser check was run. Nothing in this report is runtime-verified. ' +
      'See docs/LIMITATIONS.md.',
    );
  } else {
    tracker.skip(
      'dynamic_verification',
      `dynamic verification was requested${dyn.reason ? ` (${dyn.reason})` : ''} but is not implemented in this ` +
      'release: dependency installation and build scripts are arbitrary code execution, and this host provides no ' +
      'container isolation. Refusing rather than running untrusted code. See ADR-005.',
    );
  }
  emit('dynamic_verification');
  if (cancelled()) return cancelRemaining();

  // ----------------------------------------- 8. AI semantic investigation ---
  const client = new ModelClient(aiConfig);
  const aiUnavailable = client.unavailableReason();
  if (aiUnavailable) {
    tracker.skip('ai_semantic_investigation', aiUnavailable);
    emit('ai_semantic_investigation');
  } else {
    const aiReport = await runStage('ai_semantic_investigation', () => investigate(map, client));
    if (aiReport) {
      outcome.aiReport = aiReport;
      allFindings.push(...aiReport.findings);
      for (const w of aiReport.warnings) tracker.warn('ai_semantic_investigation', w);
      for (const r of aiReport.rejected) {
        tracker.warn('ai_semantic_investigation', `rejected a model finding: ${r.reason}`);
      }
    }
  }
  if (cancelled()) return cancelRemaining();

  // ------------------------------------------- 9. finding consolidation -----
  const consolidated = await runStage('finding_consolidation', () => {
    const merged = consolidateFindings(allFindings);
    const discipline = enforceEvidenceDiscipline(merged);
    for (const r of discipline.rejected) {
      tracker.warn('finding_consolidation', `refused "${r.finding.title}": ${r.reason}`);
      outcome.rejectedFindings.push({ title: r.finding.title, reason: r.reason });
    }
    for (const a of discipline.adjustments) {
      tracker.warn(
        'finding_consolidation',
        `lowered confidence ${a.from} -> ${a.to} for ${a.fingerprint}: ${a.reason}`,
      );
    }
    return discipline.kept;
  });
  const kept = consolidated ?? [];

  // ------------------------------------------- 10. risk prioritization ------
  const prioritized = await runStage('risk_prioritization', () => {
    const ctx = {
      dependentComponents: computeDependentComponents(kept, map),
      blockedBy: computeBlockedBy(kept),
    };
    const ranked = prioritize(kept, ctx);
    // Display ids follow priority order so they read meaningfully in a report.
    const withIds = assignDisplayIds(ranked.map((p) => p.finding));
    return ranked.map((p, i) => ({ ...p, finding: withIds[i]! }));
  });
  outcome.prioritized = prioritized ?? [];
  outcome.findings = outcome.prioritized.map((p) => p.finding);

  // ------------------------------------------- 12. coverage (for scoring) ---
  const coverage = buildCoverage({
    snapshot, parsed, analyzerResult, tracker,
    aiRan: tracker.statusOf('ai_semantic_investigation') === 'completed',
  });
  outcome.coverage = coverage;

  // -------------------------------------------- 11. fix pack generation -----
  const packs = await runStage('fix_pack_generation', () => {
    const built = buildFixPacks(outcome.prioritized);
    const promptCtx: PromptContext = {
      projectName: req.projectName,
      scanId,
      baselineCommit: commitSha,
      branch,
      contentHash: snapshot.contentHash,
      tech: outcome.tech,
      routeCount: map.routes.length,
      modelCount: map.models.length,
      coverage,
      ...detectCommands(map),
      totalPacks: built.length,
    };

    const knownFiles = new Set(snapshot.files.map((f) => f.path));
    const scanFingerprints = new Set(outcome.findings.map((f) => f.fingerprint));
    const allPackKeys = new Set(built.map((p) => p.key));
    const packDependencies = new Map(built.map((p) => [p.key, p.dependsOn]));

    for (const pack of built) {
      const prompts: Record<AgentFormat, string> = {
        claude_code: generateFixPackPrompt(pack, promptCtx, 'claude_code'),
        codex: generateFixPackPrompt(pack, promptCtx, 'codex'),
        generic: generateFixPackPrompt(pack, promptCtx, 'generic'),
      };
      const validation = validateFixPack({
        pack, prompt: prompts.generic, ctx: promptCtx,
        knownFiles, scanFingerprints, allPackKeys, packDependencies,
      });
      outcome.packPrompts.set(pack.key, prompts);
      outcome.packValidations.set(pack.key, validation);
      if (!validation.presentable) {
        tracker.warn(
          'fix_pack_generation',
          `pack '${pack.key}' withheld: ${validation.issues.filter((i) => i.level === 'error').map((i) => i.detail).join('; ')}`,
        );
      }
    }
    // Only validated packs are presented.
    return built.filter((p) => outcome.packValidations.get(p.key)?.presentable);
  });
  outcome.fixPacks = packs ?? [];

  // ---------------------------------------------- 12. report generation -----
  const scorecard = await runStage('report_generation', () => buildScorecard(outcome.findings, coverage));
  outcome.scorecard = scorecard;

  outcome.status = tracker.anyFailed()
    ? 'partial'
    : tracker.allRequiredCompleted()
      ? 'completed'
      : 'partial';
  outcome.stages = tracker.all();
  return outcome;
}

/** Coverage is computed from what actually happened, never assumed. */
function buildCoverage(input: {
  snapshot: Snapshot;
  parsed: ParseReport;
  analyzerResult: AnalyzerRunResult;
  tracker: StageTracker;
  aiRan: boolean;
}): Coverage {
  const { snapshot, parsed, analyzerResult, tracker, aiRan } = input;

  const skippedReasons: Record<string, number> = {};
  for (const s of snapshot.skipped) {
    const key = s.reason.replace(/'[^']*'/g, "'…'").replace(/\d+/g, 'N');
    skippedReasons[key] = (skippedReasons[key] ?? 0) + 1;
  }
  for (const u of parsed.unparsed) {
    const key = u.reason.replace(/'[^']*'/g, "'…'").replace(/\d+/g, 'N');
    skippedReasons[key] = (skippedReasons[key] ?? 0) + 1;
  }

  const languages = new Set(
    snapshot.files.filter((f) => f.language && !f.generated && !f.vendored && !f.binary).map((f) => f.language!),
  );
  const languagesDeep = [...languages].filter((l) => DEEP_LANGUAGES.has(l)).sort();
  const languagesShallow = [...languages].filter((l) => !DEEP_LANGUAGES.has(l) && SHALLOW_LANGUAGES.has(l)).sort();
  const languagesUnsupported = [...languages]
    .filter((l) => !DEEP_LANGUAGES.has(l) && !SHALLOW_LANGUAGES.has(l)).sort();

  // Parse ratio is measured against files a parser exists for, so a repository
  // of mostly YAML is not reported as unparseable source.
  const parseable = snapshot.files.filter(
    (f) => f.language && DEEP_LANGUAGES.has(f.language) && !f.generated && !f.vendored && !f.binary,
  );
  const parsedCount = parseable.filter((f) => f.parsed).length;

  const layers: LayerCompletion = {
    static: tracker.statusOf('deterministic_diagnostics') === 'completed',
    graph: tracker.statusOf('architecture_reconstruction') === 'completed',
    ai: aiRan,
    dynamic: tracker.statusOf('dynamic_verification') === 'completed',
  };

  return {
    filesTotal: snapshot.files.length + snapshot.skipped.length,
    filesIndexed: snapshot.files.length,
    filesParsed: parsed.parsedCount,
    filesSkipped: snapshot.skipped.length,
    skippedReasons,
    languagesDeep,
    languagesShallow,
    languagesUnsupported,
    analyzersRun: analyzerResult.analyzersRun,
    analyzersSkipped: analyzerResult.analyzersSkipped,
    layers,
    parseRatio: parseable.length === 0 ? 0 : parsedCount / parseable.length,
    truncated: snapshot.truncated,
    truncationNote: snapshot.truncationNote,
  };
}

/** Test/typecheck/lint commands declared by the project, for the prompt's verification section. */
function detectCommands(map: RepoMap): Pick<PromptContext, 'testCommand' | 'typecheckCommand' | 'lintCommand'> {
  const manifest = map.files.find((f) => f.path === 'package.json')
    ?? map.files.find((f) => f.path.endsWith('/package.json'));
  if (!manifest?.text) return {};
  try {
    const pkg = JSON.parse(manifest.text) as { scripts?: Record<string, string> };
    const scripts = pkg.scripts ?? {};
    const runner = map.hasTech('pnpm') ? 'pnpm' : map.hasTech('yarn') ? 'yarn' : map.hasTech('bun') ? 'bun' : 'npm run';
    const pick = (...names: string[]) => {
      const hit = names.find((n) => scripts[n]);
      return hit ? `${runner} ${hit}` : undefined;
    };
    return {
      testCommand: pick('test', 'test:unit', 'vitest', 'jest'),
      typecheckCommand: pick('typecheck', 'type-check', 'tsc'),
      lintCommand: pick('lint', 'eslint'),
    };
  } catch {
    return {};
  }
}

/** A repository containing text addressed to an AI reviewer is itself a finding. */
function injectionFinding(
  path: string, line: number, excerpt: string, what: string, map: RepoMap,
): Finding {
  const evidence = map.evidenceLine(path, line, `${what}; repository content is treated as data, never as instructions`);
  return {
    id: 'PENDING',
    fingerprint: `inj-${path}-${line}`.slice(0, 40),
    ruleId: 'security.supply_chain.prompt_injection_content',
    title: 'Repository content contains text addressed to an automated reviewer',
    category: 'security',
    severity: 'medium',
    confidence: 'strong',
    status: 'strongly_supported',
    detectionSource: 'static',
    files: [path],
    evidence: [evidence],
    explanation:
      `${path}:${line} contains ${what}. Text like this is aimed at AI code review, AI agents, or AI-assisted ` +
      'tooling that reads the repository, and its purpose is to change their behaviour — typically to suppress ' +
      'findings or extract secrets. CodeLens treats all repository content as untrusted data and ignored it, but ' +
      'other tooling in your pipeline may not.',
    userImpact:
      'If any automated reviewer or agent in this project\'s workflow follows instructions found in the code, it can ' +
      'be made to approve unsafe changes or disclose configuration.',
    likelyRootCause:
      'Either a deliberate injection attempt, or content copied from an untrusted source such as a dependency, ' +
      'a generated file, or a third-party template.',
    downstreamConsequences: [
      'Any agent or AI review step reading this repository is a potential target.',
      'If the text arrived through a dependency or template, other repositories may be affected.',
    ],
    remediation:
      'Establish how this text got here. Remove it if it is not legitimate. Ensure every tool in the pipeline that ' +
      'reads repository content treats it as data: fixed system instructions, content fenced as untrusted, and output ' +
      'validated independently rather than trusted.',
    effort: 'small',
    relatedTests: [],
    verificationSteps: [
      'Confirm the text is gone or justified.',
      'Confirm no automated reviewer changes its behaviour because of repository content.',
    ],
    relatedFindings: [],
    references: ['OWASP LLM01 Prompt Injection', 'CWE-77 Command Injection (analogous instruction-channel confusion)'],
    affectedFeatures: [],
  };
}
