import 'server-only';
import { existsSync, mkdirSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { Db } from '@codelens/engine/db/index.ts';

/**
 * Server-side data access for the web application.
 *
 * Every read is scoped by organisation through `Db.assertProjectInOrg`, which
 * raises the same "not found" error for a project in another tenant as for one
 * that does not exist. Existence is not leaked across tenants.
 *
 * This release runs single-tenant and local: the organisation is fixed, and
 * authentication is intentionally not implemented. That is stated in the UI
 * rather than faked — see docs/LIMITATIONS.md.
 */

export const LOCAL_ORG = 'local';

/**
 * Locate the workspace root.
 *
 * A relative database path must not resolve against the process working
 * directory: the CLI runs from the repository root and writes there, while the
 * Next server runs from packages/web. Resolving relative would have the web app
 * looking in a different place from the tool that populates it, and the symptom
 * is an empty dashboard with no error.
 */
function workspaceRoot(): string {
  let dir = process.cwd();
  for (let i = 0; i < 6; i++) {
    if (existsSync(join(dir, 'pnpm-workspace.yaml'))) return dir;
    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return process.cwd();
}

const DB_PATH = process.env.CODELENS_DB
  ? resolve(process.env.CODELENS_DB)
  : join(workspaceRoot(), '.codelens', 'codelens.db');

/** The resolved database path, shown in the UI so an empty state is explainable. */
export function databasePath(): string {
  return DB_PATH;
}

let cached: Db | undefined;

export function db(): Db {
  if (cached) return cached;
  mkdirSync(dirname(DB_PATH), { recursive: true });
  const d = new Db(DB_PATH);
  d.migrate();
  cached = d;
  return d;
}

function json<T>(raw: unknown, fallback: T): T {
  if (typeof raw !== 'string' || raw.length === 0) return fallback;
  try {
    return JSON.parse(raw) as T;
  } catch {
    return fallback;
  }
}

// ---------------------------------------------------------------- projects --

export interface ProjectRow {
  id: string;
  name: string;
  kind: string;
  createdAt: string;
  scanCount: number;
  latestScanId?: string;
  latestScanStatus?: string;
  latestScanAt?: string;
  latestFindings: number;
  latestCritical: number;
  latestScore: number | null;
}

export function listProjects(): ProjectRow[] {
  const rows = db().all<Record<string, unknown>>(
    `SELECT p.id, p.name, p.kind, p.created_at,
            (SELECT COUNT(*) FROM scan_jobs s WHERE s.project_id = p.id) AS scan_count,
            (SELECT s.id FROM scan_jobs s WHERE s.project_id = p.id ORDER BY s.queued_at DESC LIMIT 1) AS latest_id,
            (SELECT s.status FROM scan_jobs s WHERE s.project_id = p.id ORDER BY s.queued_at DESC LIMIT 1) AS latest_status,
            (SELECT s.queued_at FROM scan_jobs s WHERE s.project_id = p.id ORDER BY s.queued_at DESC LIMIT 1) AS latest_at
       FROM projects p
      WHERE p.organization_id = ? AND p.deleted_at IS NULL
      ORDER BY latest_at DESC NULLS LAST, p.name`,
    LOCAL_ORG,
  );

  return rows.map((r) => {
    const latestId = r.latest_id ? String(r.latest_id) : undefined;
    const counts = latestId
      ? db().get<{ total: number; critical: number }>(
          `SELECT COUNT(*) AS total,
                  SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) AS critical
             FROM diagnostic_findings WHERE scan_id = ?`,
          latestId,
        )
      : undefined;
    return {
      id: String(r.id),
      name: String(r.name),
      kind: String(r.kind),
      createdAt: String(r.created_at),
      scanCount: Number(r.scan_count ?? 0),
      latestScanId: latestId,
      latestScanStatus: r.latest_status ? String(r.latest_status) : undefined,
      latestScanAt: r.latest_at ? String(r.latest_at) : undefined,
      latestFindings: Number(counts?.total ?? 0),
      latestCritical: Number(counts?.critical ?? 0),
      latestScore: latestId ? overallScore(latestId) : null,
    };
  });
}

export function getProject(projectId: string): ProjectRow | undefined {
  return listProjects().find((p) => p.id === projectId);
}

// ------------------------------------------------------------------- scans --

export interface ScanRow {
  id: string;
  projectId: string;
  status: string;
  queuedAt: string;
  finishedAt?: string;
  aiProvider: string;
  coverage: Coverage | undefined;
  errorMessage?: string;
  findings: number;
  critical: number;
  score: number | null;
  commitSha?: string;
  contentHash?: string;
}

interface Coverage {
  filesTotal: number; filesIndexed: number; filesParsed: number; filesSkipped: number;
  parseRatio: number; analyzersRun: string[];
  analyzersSkipped: Array<{ analyzer: string; reason: string }>;
  languagesDeep: string[]; languagesShallow: string[]; languagesUnsupported: string[];
  layers: { static: boolean; graph: boolean; ai: boolean; dynamic: boolean };
  truncated: boolean; truncationNote?: string;
  skippedReasons: Record<string, number>;
}

export function listScans(projectId: string): ScanRow[] {
  db().assertProjectInOrg(projectId, LOCAL_ORG);
  const rows = db().all<Record<string, unknown>>(
    `SELECT s.id, s.project_id, s.status, s.queued_at, s.finished_at, s.ai_provider,
            s.coverage_json, s.error_message,
            r.commit_sha, r.content_hash,
            (SELECT COUNT(*) FROM diagnostic_findings d WHERE d.scan_id = s.id) AS findings,
            (SELECT COUNT(*) FROM diagnostic_findings d WHERE d.scan_id = s.id AND d.severity = 'critical') AS critical
       FROM scan_jobs s
       LEFT JOIN repository_snapshots r ON r.id = s.snapshot_id
      WHERE s.project_id = ?
      ORDER BY s.queued_at DESC`,
    projectId,
  );
  return rows.map((r) => ({
    id: String(r.id),
    projectId: String(r.project_id),
    status: String(r.status),
    queuedAt: String(r.queued_at),
    finishedAt: r.finished_at ? String(r.finished_at) : undefined,
    aiProvider: String(r.ai_provider ?? 'none'),
    coverage: json<Coverage | undefined>(r.coverage_json, undefined),
    errorMessage: r.error_message ? String(r.error_message) : undefined,
    findings: Number(r.findings ?? 0),
    critical: Number(r.critical ?? 0),
    score: overallScore(String(r.id)),
    commitSha: r.commit_sha ? String(r.commit_sha) : undefined,
    contentHash: r.content_hash ? String(r.content_hash) : undefined,
  }));
}

export function getScan(scanId: string): ScanRow | undefined {
  const row = db().get<{ project_id: string }>('SELECT project_id FROM scan_jobs WHERE id = ?', scanId);
  if (!row) return undefined;
  return listScans(row.project_id).find((s) => s.id === scanId);
}

export function latestScan(projectId: string): ScanRow | undefined {
  return listScans(projectId)[0];
}

export interface StageRow {
  name: string; ordinal: number; status: string; attempts: number;
  message?: string; warnings: string[]; durationMs?: number;
}

export function scanStages(scanId: string): StageRow[] {
  return db().all<Record<string, unknown>>(
    'SELECT name, ordinal, status, attempts, message, warnings_json, duration_ms FROM scan_stages WHERE scan_id = ? ORDER BY ordinal',
    scanId,
  ).map((r) => ({
    name: String(r.name),
    ordinal: Number(r.ordinal),
    status: String(r.status),
    attempts: Number(r.attempts ?? 0),
    message: r.message ? String(r.message) : undefined,
    warnings: json<string[]>(r.warnings_json, []),
    durationMs: r.duration_ms === null ? undefined : Number(r.duration_ms),
  }));
}

// ------------------------------------------------------------------ scores --

export interface ScoreRow {
  dimension: string; score: number | null; grade: string; weight: number;
  penalty: number; reason?: string; counts: Record<string, number>;
}

export function scanScores(scanId: string): ScoreRow[] {
  return db().all<Record<string, unknown>>(
    'SELECT dimension, score, grade, weight, penalty, reason, counts_json FROM scan_scores WHERE scan_id = ? ORDER BY weight DESC',
    scanId,
  ).map((r) => ({
    dimension: String(r.dimension),
    score: r.score === null ? null : Number(r.score),
    grade: String(r.grade),
    weight: Number(r.weight),
    penalty: Number(r.penalty ?? 0),
    reason: r.reason ? String(r.reason) : undefined,
    counts: json<Record<string, number>>(r.counts_json, {}),
  }));
}

export function overallScore(scanId: string): number | null {
  const rows = scanScores(scanId);
  const graded = rows.filter((r) => r.score !== null);
  const assessed = graded.reduce((s, r) => s + r.weight, 0);
  if (assessed < 0.5) return null;
  return Math.round(graded.reduce((s, r) => s + (r.score as number) * r.weight, 0) / assessed);
}

export function assessedWeight(scanId: string): number {
  const graded = scanScores(scanId).filter((r) => r.score !== null);
  return Math.round(graded.reduce((s, r) => s + r.weight, 0) * 100) / 100;
}

// ---------------------------------------------------------------- findings --

export interface EvidenceRow {
  file: string; startLine?: number; endLine?: number; symbol?: string;
  excerpt?: string; note?: string; verified: boolean;
}

export interface FindingRow {
  id: string;
  displayId: string;
  fingerprint: string;
  ruleId: string;
  title: string;
  category: string;
  severity: string;
  confidence: string;
  status: string;
  detectionSource: string;
  priority?: string;
  priorityScore?: number;
  priorityRationale?: string;
  files: string[];
  explanation: string;
  userImpact: string;
  likelyRootCause?: string;
  downstream: string[];
  remediation: string;
  effort: string;
  verificationSteps: string[];
  references: string[];
  affectedFeatures: string[];
  relatedTests: string[];
  trace?: { kind: string; complete: boolean; steps: Array<{ file: string; line?: number; symbol?: string; detail: string }> };
  evidence: EvidenceRow[];
  firstDetectedScanId?: string;
}

const PRIORITY_ORDER = "CASE priority WHEN 'P0' THEN 0 WHEN 'P1' THEN 1 WHEN 'P2' THEN 2 WHEN 'P3' THEN 3 ELSE 4 END";

export function scanFindings(scanId: string): FindingRow[] {
  const rows = db().all<Record<string, unknown>>(
    `SELECT * FROM diagnostic_findings WHERE scan_id = ?
      ORDER BY ${PRIORITY_ORDER}, priority_score DESC`,
    scanId,
  );
  return rows.map((r) => ({
    id: String(r.id),
    displayId: String(r.display_id),
    fingerprint: String(r.fingerprint),
    ruleId: String(r.rule_id),
    title: String(r.title),
    category: String(r.category),
    severity: String(r.severity),
    confidence: String(r.confidence),
    status: String(r.status),
    detectionSource: String(r.detection_source),
    priority: r.priority ? String(r.priority) : undefined,
    priorityScore: r.priority_score === null ? undefined : Number(r.priority_score),
    priorityRationale: r.priority_rationale ? String(r.priority_rationale) : undefined,
    files: json<string[]>(r.files_json, []),
    explanation: String(r.explanation),
    userImpact: String(r.user_impact),
    likelyRootCause: r.likely_root_cause ? String(r.likely_root_cause) : undefined,
    downstream: json<string[]>(r.downstream_json, []),
    remediation: String(r.remediation),
    effort: String(r.effort),
    verificationSteps: json<string[]>(r.verification_steps_json, []),
    references: json<string[]>(r.references_json, []),
    affectedFeatures: json<string[]>(r.affected_features_json, []),
    relatedTests: json<string[]>(r.related_tests_json, []),
    trace: r.trace_json ? json<FindingRow['trace']>(r.trace_json, undefined) : undefined,
    evidence: db().all<Record<string, unknown>>(
      'SELECT file, start_line, end_line, symbol, excerpt, note, verified FROM finding_evidence WHERE finding_id = ?',
      String(r.id),
    ).map((e) => ({
      file: String(e.file),
      startLine: e.start_line === null ? undefined : Number(e.start_line),
      endLine: e.end_line === null ? undefined : Number(e.end_line),
      symbol: e.symbol ? String(e.symbol) : undefined,
      excerpt: e.excerpt ? String(e.excerpt) : undefined,
      note: e.note ? String(e.note) : undefined,
      verified: Number(e.verified) === 1,
    })),
    firstDetectedScanId: r.first_detected_scan_id ? String(r.first_detected_scan_id) : undefined,
  }));
}

export function getFinding(scanId: string, displayId: string): FindingRow | undefined {
  return scanFindings(scanId).find((f) => f.displayId === displayId);
}

// ------------------------------------------------------------ architecture --

export interface ComponentRow { key: string; name: string; kind: string; provenance: string; files: string[]; summary?: string }
export interface RelationshipRow { from: string; to: string; kind: string; provenance: string; evidence: EvidenceRow[] }
export interface RouteRow {
  method: string; path: string; file: string; line?: number; handlerSymbol?: string;
  authRequired: string; authorizationChecks: string[]; requestShape?: string;
  responseShape?: string; validation: string; errorHandling: string;
}
export interface ModelRow {
  name: string; file: string; kind: string; ownershipField?: string;
  fields: Array<{ name: string; type?: string; nullable?: boolean; unique?: boolean }>;
  relations: Array<{ to: string; kind: string }>;
  indexes: string[];
}
export interface FeatureRow {
  key: string; name: string; intendedFunction: string; status: string;
  frontendFiles: string[]; backendFiles: string[]; databaseDeps: string[];
  externalServices: string[]; authRequirement: string;
  evidence: EvidenceRow[]; tests: string[]; possibleDefects: string[];
}

export function scanComponents(scanId: string): ComponentRow[] {
  return db().all<Record<string, unknown>>(
    'SELECT key, name, kind, provenance, files_json, summary FROM architecture_components WHERE scan_id = ? ORDER BY kind, name',
    scanId,
  ).map((r) => ({
    key: String(r.key), name: String(r.name), kind: String(r.kind),
    provenance: String(r.provenance), files: json<string[]>(r.files_json, []),
    summary: r.summary ? String(r.summary) : undefined,
  }));
}

export function scanRelationships(scanId: string): RelationshipRow[] {
  return db().all<Record<string, unknown>>(
    'SELECT from_key, to_key, kind, provenance, evidence_json FROM architecture_relationships WHERE scan_id = ?',
    scanId,
  ).map((r) => ({
    from: String(r.from_key), to: String(r.to_key), kind: String(r.kind),
    provenance: String(r.provenance), evidence: json<EvidenceRow[]>(r.evidence_json, []),
  }));
}

export function scanRoutes(scanId: string): RouteRow[] {
  return db().all<Record<string, unknown>>(
    'SELECT * FROM api_endpoints WHERE scan_id = ? ORDER BY path, method', scanId,
  ).map((r) => ({
    method: String(r.method), path: String(r.path), file: String(r.file),
    line: r.line === null ? undefined : Number(r.line),
    handlerSymbol: r.handler_symbol ? String(r.handler_symbol) : undefined,
    authRequired: String(r.auth_required),
    authorizationChecks: json<string[]>(r.authorization_checks_json, []),
    requestShape: r.request_shape ? String(r.request_shape) : undefined,
    responseShape: r.response_shape ? String(r.response_shape) : undefined,
    validation: String(r.validation), errorHandling: String(r.error_handling),
  }));
}

export function scanModels(scanId: string): ModelRow[] {
  return db().all<Record<string, unknown>>(
    'SELECT * FROM data_models WHERE scan_id = ? ORDER BY name', scanId,
  ).map((r) => ({
    name: String(r.name), file: String(r.file), kind: String(r.kind),
    ownershipField: r.ownership_field ? String(r.ownership_field) : undefined,
    fields: json<ModelRow['fields']>(r.fields_json, []),
    relations: json<ModelRow['relations']>(r.relations_json, []),
    indexes: json<string[]>(r.indexes_json, []),
  }));
}

export function scanFeatures(scanId: string): FeatureRow[] {
  return db().all<Record<string, unknown>>(
    'SELECT * FROM feature_inventory WHERE scan_id = ? ORDER BY name', scanId,
  ).map((r) => ({
    key: String(r.key), name: String(r.name), intendedFunction: String(r.intended_function),
    status: String(r.status),
    frontendFiles: json<string[]>(r.frontend_files_json, []),
    backendFiles: json<string[]>(r.backend_files_json, []),
    databaseDeps: json<string[]>(r.database_deps_json, []),
    externalServices: json<string[]>(r.external_services_json, []),
    authRequirement: String(r.auth_requirement),
    evidence: json<EvidenceRow[]>(r.evidence_json, []),
    tests: json<string[]>(r.tests_json, []),
    possibleDefects: json<string[]>(r.possible_defects_json, []),
  }));
}

export interface TechRow { kind: string; name: string; version?: string; confidence: number; analysisDepth: string; evidence: EvidenceRow[] }

export function scanTech(scanId: string): TechRow[] {
  return db().all<Record<string, unknown>>(
    'SELECT kind, name, version, confidence, analysis_depth, evidence_json FROM tech_detections WHERE scan_id = ? ORDER BY confidence DESC, name',
    scanId,
  ).map((r) => ({
    kind: String(r.kind), name: String(r.name),
    version: r.version ? String(r.version) : undefined,
    confidence: Number(r.confidence), analysisDepth: String(r.analysis_depth),
    evidence: json<EvidenceRow[]>(r.evidence_json, []),
  }));
}

// --------------------------------------------------------------- fix packs --

export interface FixPackRow {
  id: string; key: string; title: string; family: string; ordinal: number;
  objective: string; effort: string; dependsOn: string[]; appliedAt?: string;
  baselineCommit?: string;
  findingIds: string[];
  prompts: Record<string, string>;
  validation: { presentable: boolean; issues: Array<{ level: string; check: string; detail: string }>; checksRun: string[] };
}

export function scanFixPacks(scanId: string): FixPackRow[] {
  const rows = db().all<Record<string, unknown>>(
    'SELECT * FROM fix_packs WHERE scan_id = ? ORDER BY ordinal', scanId,
  );
  return rows.map((r) => {
    const id = String(r.id);
    const versions = db().all<{ agent_format: string; prompt_markdown: string; validation_json: string }>(
      'SELECT agent_format, prompt_markdown, validation_json FROM fix_pack_versions WHERE fix_pack_id = ? ORDER BY version DESC',
      id,
    );
    const prompts: Record<string, string> = {};
    for (const v of versions) if (!prompts[v.agent_format]) prompts[v.agent_format] = v.prompt_markdown;
    const findingIds = db().all<{ display_id: string }>(
      `SELECT d.display_id FROM fix_pack_findings fp
         JOIN diagnostic_findings d ON d.id = fp.finding_id
        WHERE fp.fix_pack_id = ?
        ORDER BY ${PRIORITY_ORDER.replace(/priority/g, 'd.priority')}, d.priority_score DESC`,
      id,
    ).map((x) => x.display_id);

    return {
      id,
      key: String(r.key),
      title: String(r.title),
      family: String(r.category),
      ordinal: Number(r.ordinal),
      objective: String(r.objective),
      effort: String(r.effort),
      dependsOn: json<string[]>(r.depends_on_json, []),
      appliedAt: r.applied_at ? String(r.applied_at) : undefined,
      baselineCommit: r.baseline_commit ? String(r.baseline_commit) : undefined,
      findingIds,
      prompts,
      validation: json<FixPackRow['validation']>(
        versions[0]?.validation_json,
        { presentable: true, issues: [], checksRun: [] },
      ),
    };
  });
}

export function markPackApplied(packId: string, applied: boolean): void {
  db().run('UPDATE fix_packs SET applied_at = ? WHERE id = ?', applied ? new Date().toISOString() : null, packId);
}

export function setFindingStatus(findingId: string, status: string): void {
  const allowed = ['confirmed', 'strongly_supported', 'suspected', 'needs_runtime_verification', 'resolved', 'accepted_risk', 'false_positive'];
  if (!allowed.includes(status)) throw new Error(`invalid status '${status}'`);
  db().run('UPDATE diagnostic_findings SET status = ? WHERE id = ?', status, findingId);
}
