/**
 * Shared contracts for CodeLens AI.
 *
 * Two rules govern everything in this file:
 *  1. Severity (blast radius if real) and confidence (strength of evidence) are
 *     independent. Never collapse them into one number.
 *  2. A claim about a repository must carry evidence that points at real code,
 *     or it must not be stored. See `Evidence`.
 */

// ---------------------------------------------------------------------------
// Severity & confidence
// ---------------------------------------------------------------------------

export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const;
export type Severity = (typeof SEVERITIES)[number];

/** How strongly the collected evidence supports the claim. */
export const CONFIDENCES = ['confirmed', 'strong', 'moderate', 'weak'] as const;
export type Confidence = (typeof CONFIDENCES)[number];

/** Lifecycle of a finding as a human triages it. */
export const FINDING_STATUSES = [
  'confirmed',
  'strongly_supported',
  'suspected',
  'needs_runtime_verification',
  'resolved',
  'accepted_risk',
  'false_positive',
] as const;
export type FindingStatus = (typeof FINDING_STATUSES)[number];

/** Which analysis layer produced a finding. Layers are defined in ARCHITECTURE.md. */
export const DETECTION_SOURCES = [
  'static',    // Layer A: deterministic parsers, rules, scanners
  'graph',     // Layer B: cross-file / architectural relationship analysis
  'ai',        // Layer C: LLM reasoning over retrieved evidence
  'dynamic',   // Layer D: authorised execution (build/test/browser)
  'website',   // external observation of a deployed URL
  'external',  // third-party tool output (semgrep, audit, gitleaks)
] as const;
export type DetectionSource = (typeof DETECTION_SOURCES)[number];

export const CATEGORIES = [
  'security',
  'reliability',
  'performance',
  'scalability',
  'accessibility',
  'quality',
  'testing',
  'devops',
  'cost',
  'ai_app',
  'architecture',
] as const;
export type Category = (typeof CATEGORIES)[number];

/** Engineering effort bands. Deliberately coarse — precise estimates would be fiction. */
export const EFFORT_BANDS = ['trivial', 'small', 'medium', 'large', 'unknown'] as const;
export type EffortBand = (typeof EFFORT_BANDS)[number];

// ---------------------------------------------------------------------------
// Evidence
// ---------------------------------------------------------------------------

/**
 * A pointer at real code plus the excerpt that was actually read.
 * `verified` is set by the evidence validator after re-reading the file at the
 * recorded snapshot: it means the excerpt still matches the file on disk.
 */
export interface Evidence {
  /** Repository-relative POSIX path. */
  file: string;
  startLine?: number;
  endLine?: number;
  /** Symbol (function/class/route) the evidence sits in, when resolvable. */
  symbol?: string;
  /** The exact source excerpt supporting the claim. */
  excerpt?: string;
  /** Why this excerpt supports the claim. */
  note?: string;
  verified: boolean;
}

/** A traced relationship across files, for findings no single file could reveal. */
export interface RelationshipTrace {
  kind:
    | 'frontend_backend_contract'
    | 'schema_validation'
    | 'route_authorization'
    | 'env_var'
    | 'webhook_idempotency'
    | 'job_recovery'
    | 'data_policy'
    | 'unused_integration'
    | 'dead_ui_action'
    | 'import'
    | 'call';
  steps: Array<{ file: string; symbol?: string; line?: number; detail: string }>;
  /** False when a step could not be resolved; the finding must then be downgraded. */
  complete: boolean;
}

// ---------------------------------------------------------------------------
// Findings
// ---------------------------------------------------------------------------

export interface Finding {
  /** Human-facing stable id, e.g. "SEC-001". Assigned per scan in priority order. */
  id: string;
  /**
   * Content fingerprint, stable across scans for the same underlying problem.
   * Used to match findings between scans for resolution tracking.
   */
  fingerprint: string;
  ruleId: string;
  title: string;
  category: Category;
  severity: Severity;
  confidence: Confidence;
  status: FindingStatus;
  detectionSource: DetectionSource;

  files: string[];
  evidence: Evidence[];
  trace?: RelationshipTrace;

  /** What is technically wrong. */
  explanation: string;
  /** What a user of the application would experience. */
  userImpact: string;
  likelyRootCause?: string;
  downstreamConsequences: string[];
  /** What to change. Defensive guidance only. */
  remediation: string;
  effort: EffortBand;

  relatedTests: string[];
  verificationSteps: string[];
  relatedFindings: string[];

  /** Commit the problem was first observed in, when repository history is available. */
  firstDetectedCommit?: string;
  firstDetectedScanId?: string;
  /** Standards references, e.g. ["OWASP A01:2021", "CWE-639"]. */
  references: string[];
  /** Feature inventory entries this finding affects. */
  affectedFeatures: string[];
}

/** Severity ordering helpers (lower rank = more severe). */
export const SEVERITY_RANK: Record<Severity, number> = {
  critical: 0, high: 1, medium: 2, low: 3, info: 4,
};
export const CONFIDENCE_WEIGHT: Record<Confidence, number> = {
  confirmed: 1.0, strong: 0.8, moderate: 0.55, weak: 0.3,
};

// ---------------------------------------------------------------------------
// Technology detection & repository map
// ---------------------------------------------------------------------------

export type TechKind =
  | 'language' | 'frontend' | 'backend' | 'database' | 'orm'
  | 'infrastructure' | 'ai' | 'testing' | 'build' | 'ci' | 'package_manager'
  // A notable library that is not itself an application framework, such as an
  // auth or validation library. Kept distinct so prose describing the project
  // does not call it a framework.
  | 'library';

export interface TechDetection {
  kind: TechKind;
  name: string;
  version?: string;
  /** 0..1. Derived from how direct the evidence is, never guessed. */
  confidence: number;
  evidence: Evidence[];
  /** How deeply this technology can be analysed. See docs/SUPPORTED.md. */
  analysisDepth: 'deep' | 'shallow' | 'detected_only';
}

export interface IndexedFile {
  path: string;
  bytes: number;
  lines: number;
  language?: string;
  role: FileRole;
  /** True when an AST was successfully produced for this file. */
  parsed: boolean;
  /** Reason parsing did not happen, when parsed === false. */
  unparsedReason?: string;
  sha256: string;
  generated: boolean;
  vendored: boolean;
}

export type FileRole =
  | 'source' | 'test' | 'config' | 'manifest' | 'migration' | 'schema'
  | 'route' | 'component' | 'documentation' | 'ci' | 'infrastructure'
  | 'generated' | 'vendored' | 'asset' | 'unknown';

export interface ApiEndpoint {
  method: string;
  path: string;
  file: string;
  line?: number;
  handlerSymbol?: string;
  /** Resolved from middleware/guards when traceable; `unknown` when not. */
  authRequired: 'required' | 'public' | 'unknown';
  authorizationChecks: string[];
  requestShape?: string;
  responseShape?: string;
  validation: 'present' | 'absent' | 'partial' | 'unknown';
  errorHandling: 'present' | 'absent' | 'partial' | 'unknown';
}

export interface DataModel {
  name: string;
  file: string;
  kind: 'orm_model' | 'sql_table' | 'schema' | 'type';
  fields: Array<{ name: string; type?: string; nullable?: boolean; unique?: boolean }>;
  relations: Array<{ to: string; kind: string }>;
  indexes: string[];
  ownershipField?: string;
}

// ---------------------------------------------------------------------------
// Architecture & features
// ---------------------------------------------------------------------------

export interface ArchComponent {
  id: string;
  name: string;
  kind:
    | 'app' | 'page' | 'component' | 'service' | 'api_route' | 'middleware'
    | 'job' | 'datastore' | 'external_service' | 'package' | 'module';
  files: string[];
  /** Detected from evidence vs. inferred from convention. Shown differently in UI. */
  provenance: 'detected' | 'inferred';
  summary?: string;
}

export interface ArchRelationship {
  from: string;
  to: string;
  kind: 'imports' | 'calls' | 'renders' | 'queries' | 'publishes' | 'subscribes' | 'deploys_to' | 'authenticates_with';
  provenance: 'detected' | 'inferred';
  evidence: Evidence[];
}

export const FEATURE_STATUSES = [
  'implemented_verified',
  'implemented_unverified',
  'partially_implemented',
  'placeholder_or_mock',
  'broken_confirmed',
  'unknown',
] as const;
export type FeatureStatus = (typeof FEATURE_STATUSES)[number];

export interface Feature {
  id: string;
  name: string;
  intendedFunction: string;
  status: FeatureStatus;
  frontendFiles: string[];
  backendFiles: string[];
  databaseDeps: string[];
  externalServices: string[];
  authRequirement: 'required' | 'public' | 'unknown';
  implementationEvidence: Evidence[];
  tests: string[];
  possibleDefects: string[];
}

// ---------------------------------------------------------------------------
// Scan lifecycle
// ---------------------------------------------------------------------------

export const STAGE_NAMES = [
  'ingestion_validation',
  'source_normalization',
  'technology_detection',
  'code_indexing',
  'deterministic_diagnostics',
  'architecture_reconstruction',
  'dynamic_verification',
  'ai_semantic_investigation',
  'finding_consolidation',
  'risk_prioritization',
  'fix_pack_generation',
  'report_generation',
] as const;
export type StageName = (typeof STAGE_NAMES)[number];

export type StageStatus = 'pending' | 'running' | 'completed' | 'failed' | 'skipped' | 'cancelled';

export interface StageResult {
  name: StageName;
  status: StageStatus;
  startedAt?: string;
  finishedAt?: string;
  durationMs?: number;
  /** Operator-readable reason for skipped/failed. Never hidden from the UI. */
  message?: string;
  /** Non-fatal problems. An optional tool failing must not fail the scan. */
  warnings: string[];
  attempts: number;
}

export type ScanStatus = 'queued' | 'running' | 'completed' | 'partial' | 'failed' | 'cancelled';

/** Which of the four layers actually completed, for honest UI reporting. */
export interface LayerCompletion {
  static: boolean;
  graph: boolean;
  ai: boolean;
  dynamic: boolean;
}

export interface Coverage {
  filesTotal: number;
  filesIndexed: number;
  filesParsed: number;
  filesSkipped: number;
  skippedReasons: Record<string, number>;
  languagesDeep: string[];
  languagesShallow: string[];
  languagesUnsupported: string[];
  analyzersRun: string[];
  analyzersSkipped: Array<{ analyzer: string; reason: string }>;
  layers: LayerCompletion;
  /** 0..1 — share of indexed source files an AST was produced for. */
  parseRatio: number;
  truncated: boolean;
  truncationNote?: string;
}
