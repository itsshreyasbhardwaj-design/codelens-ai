import type { Category, Confidence, Evidence, Finding, FindingStatus, DetectionSource, EffortBand, RelationshipTrace, Severity } from '@codelens/core';
import { fingerprintFinding } from '@codelens/core';
import type { RepoMap } from '../graph/repomap.ts';

/**
 * The analyzer contract.
 *
 * An analyzer is a pure function from the repository map to findings. It must:
 *   - read only from the map (never re-read or re-parse files);
 *   - attach evidence that points at real code for every finding;
 *   - set confidence honestly, and never above what the evidence supports;
 *   - be independent of every other analyzer, so they can run in any order.
 *
 * `ctx.finding()` computes the stable fingerprint, so analyzers never do.
 */

export interface FindingInput {
  ruleId: string;
  title: string;
  severity: Severity;
  confidence: Confidence;
  /** Defaults to the value implied by confidence. */
  status?: FindingStatus;
  /** Defaults to 'static'; set 'graph' for cross-file findings. */
  detectionSource?: DetectionSource;
  files: string[];
  evidence: Evidence[];
  trace?: RelationshipTrace;
  explanation: string;
  userImpact: string;
  likelyRootCause?: string;
  downstreamConsequences?: string[];
  remediation: string;
  effort: EffortBand;
  relatedTests?: string[];
  verificationSteps?: string[];
  references?: string[];
  affectedFeatures?: string[];
  /** Symbol the finding sits in; improves fingerprint stability. */
  symbol?: string;
}

export interface AnalyzerContext {
  map: RepoMap;
  /** Build a complete Finding, computing its fingerprint. */
  finding(input: FindingInput): Finding;
}

export interface Analyzer {
  /** Stable id, used in coverage reporting and score gating. */
  id: string;
  category: Category;
  /** One-line description shown in the UI. */
  description: string;
  /**
   * Return a human-readable reason to skip, or undefined to run.
   * Example: "no AI provider SDK detected in this project".
   */
  precondition?(map: RepoMap): string | undefined;
  run(ctx: AnalyzerContext): Finding[];
}

/** Which features a set of files belongs to, for `affectedFeatures`. */
export function featuresForFiles(map: RepoMap, files: string[]): string[] {
  const out = new Set<string>();
  for (const f of map.features) {
    const all = [...f.frontendFiles, ...f.backendFiles];
    if (files.some((p) => all.includes(p))) out.add(f.name);
  }
  return [...out];
}

export function makeContext(map: RepoMap): AnalyzerContext {
  return {
    map,
    finding(input) {
      const primaryEvidence = input.evidence[0];
      return {
        // Display ids are assigned later, in priority order.
        id: 'PENDING',
        fingerprint: fingerprintFinding({
          ruleId: input.ruleId,
          category: categoryOf(input.ruleId),
          files: input.files,
          symbol: input.symbol,
          excerpt: primaryEvidence?.excerpt,
        }),
        ruleId: input.ruleId,
        title: input.title,
        category: categoryOf(input.ruleId),
        severity: input.severity,
        confidence: input.confidence,
        status: input.status ?? statusFor(input.confidence),
        detectionSource: input.detectionSource ?? 'static',
        files: input.files,
        evidence: input.evidence,
        trace: input.trace,
        explanation: input.explanation,
        userImpact: input.userImpact,
        likelyRootCause: input.likelyRootCause,
        downstreamConsequences: input.downstreamConsequences ?? [],
        remediation: input.remediation,
        effort: input.effort,
        relatedTests: input.relatedTests ?? [],
        verificationSteps: input.verificationSteps ?? [],
        relatedFindings: [],
        references: input.references ?? [],
        affectedFeatures: input.affectedFeatures ?? featuresForFiles(map, input.files),
      };
    },
  };
}

/** Category is derived from the rule id prefix, so the two can never disagree. */
export function categoryOf(ruleId: string): Category {
  const prefix = ruleId.split('.')[0];
  switch (prefix) {
    case 'security': return 'security';
    case 'reliability': return 'reliability';
    case 'performance': return 'performance';
    case 'scalability': return 'scalability';
    case 'accessibility': return 'accessibility';
    case 'quality': return 'quality';
    case 'testing': return 'testing';
    case 'devops': return 'devops';
    case 'cost': return 'cost';
    case 'ai': return 'ai_app';
    case 'architecture': return 'architecture';
    default: return 'quality';
  }
}

function statusFor(confidence: Confidence): FindingStatus {
  switch (confidence) {
    case 'confirmed': return 'confirmed';
    case 'strong': return 'strongly_supported';
    default: return 'suspected';
  }
}
