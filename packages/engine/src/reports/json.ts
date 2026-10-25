import type { ScanOutcome } from '../pipeline/orchestrator.ts';
import type { ScanComparison } from './compare.ts';

/**
 * JSON export.
 *
 * Carries the limitations and the coverage inside the document. An exported
 * findings file outlives the UI it came from, and a consumer that sees only a
 * findings array will treat it as a complete assessment unless the document says
 * otherwise.
 */

export const EXPORT_SCHEMA_VERSION = '1.0.0';

export interface FindingsExport {
  schemaVersion: string;
  generatedBy: string;
  scan: {
    id: string;
    status: string;
    projectName: string;
    commitSha?: string;
    branch?: string;
    contentHash?: string;
    stages: Array<{ name: string; status: string; durationMs?: number; message?: string; warnings: string[] }>;
  };
  coverage: ScanOutcome['coverage'];
  limitations: string[];
  scorecard?: ScanOutcome['scorecard'];
  technology: ScanOutcome['tech'];
  architecture?: {
    components: number;
    relationships: number;
    routes: unknown[];
    models: unknown[];
    features: unknown[];
  };
  findings: Array<Record<string, unknown>>;
  refusedFindings: Array<{ title: string; reason: string }>;
  fixPacks: Array<{
    key: string;
    title: string;
    ordinal: number;
    objective: string;
    effort: string;
    dependsOn: string[];
    topPriority: string;
    findingIds: string[];
    affectedFiles: string[];
    validation: { presentable: boolean; issues: Array<{ level: string; check: string; detail: string }> };
  }>;
  ai?: {
    ran: boolean;
    skippedReason?: string;
    provider: string;
    model: string;
    tokensIn: number;
    tokensOut: number;
    requests: number;
    rejectedFindings: number;
  };
}

const STANDARD_LIMITATIONS = [
  'This document reports static analysis of a code snapshot. It cannot prove the absence of vulnerabilities or defects.',
  'Severity and confidence are independent axes. Severity is the cost if the finding is real; confidence is the strength of the evidence.',
  'No value in this document is a runtime measurement unless a dynamic verification stage is recorded as completed.',
  'Coverage is reported in the `coverage` object. A category with no findings may simply not have been assessed — check `coverage.analyzersRun` and `coverage.analyzersSkipped`.',
  'Files reported as unparsed were not analysed in depth and must not be read as clean.',
  'Findings produced by the AI layer carry detectionSource "ai" and were accepted only after their quoted source line was located in the snapshot.',
];

export function exportFindingsJson(outcome: ScanOutcome, projectName: string): FindingsExport {
  return {
    schemaVersion: EXPORT_SCHEMA_VERSION,
    generatedBy: 'CodeLens AI',
    scan: {
      id: outcome.scanId,
      status: outcome.status,
      projectName,
      commitSha: outcome.commitSha,
      branch: outcome.branch,
      contentHash: outcome.snapshot?.contentHash,
      stages: outcome.stages.map((s) => ({
        name: s.name,
        status: s.status,
        durationMs: s.durationMs,
        message: s.message,
        warnings: s.warnings,
      })),
    },
    coverage: outcome.coverage,
    limitations: STANDARD_LIMITATIONS,
    scorecard: outcome.scorecard,
    technology: outcome.tech,
    architecture: outcome.map
      ? {
          components: outcome.map.components.length,
          relationships: outcome.map.relationships.length,
          routes: outcome.map.routes,
          models: outcome.map.models,
          features: outcome.map.features,
        }
      : undefined,
    findings: outcome.prioritized.map((p) => ({
      ...p.finding,
      priority: p.priority,
      priorityScore: p.score,
      priorityRationale: p.rationale,
      priorityFactors: p.factors,
      blockedBy: p.blockedBy,
    })),
    refusedFindings: outcome.rejectedFindings,
    fixPacks: outcome.fixPacks.map((p) => {
      const v = outcome.packValidations.get(p.key);
      return {
        key: p.key,
        title: p.title,
        ordinal: p.ordinal,
        objective: p.objective,
        effort: p.effort,
        dependsOn: p.dependsOn,
        topPriority: p.topPriority,
        findingIds: p.findings.map((f) => f.finding.id),
        affectedFiles: p.affectedFiles,
        validation: {
          presentable: v?.presentable ?? false,
          issues: v?.issues ?? [],
        },
      };
    }),
    ai: outcome.aiReport
      ? {
          ran: !outcome.aiReport.skippedReason,
          skippedReason: outcome.aiReport.skippedReason,
          provider: outcome.aiReport.usage.provider,
          model: outcome.aiReport.usage.model,
          tokensIn: outcome.aiReport.usage.tokensIn,
          tokensOut: outcome.aiReport.usage.tokensOut,
          requests: outcome.aiReport.usage.requests,
          rejectedFindings: outcome.aiReport.rejected.length,
        }
      : undefined,
  };
}

export function exportComparisonJson(comparison: ScanComparison): Record<string, unknown> {
  return {
    schemaVersion: EXPORT_SCHEMA_VERSION,
    generatedBy: 'CodeLens AI',
    comparison,
    note:
      'resolved[] contains findings whose absence was verified against equivalent coverage. ' +
      'unverifiedAbsences[] contains findings that are no longer reported but whose absence could NOT be ' +
      'attributed to a fix, because the newer scan covered different ground. Do not count the second group as progress.',
  };
}
