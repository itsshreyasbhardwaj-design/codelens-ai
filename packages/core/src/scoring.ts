import type { Category, Confidence, Coverage, Finding, Severity } from './types.ts';
import { CONFIDENCE_WEIGHT } from './types.ts';

/**
 * Health scoring.
 *
 * Every number here comes from counted findings and measured coverage. There is
 * no model-generated score anywhere in this file, and a dimension whose
 * evidence is too thin returns `insufficient_evidence` instead of a grade.
 */

export type ScoreDimension =
  | 'security' | 'reliability' | 'architecture' | 'performance'
  | 'scalability' | 'testing' | 'accessibility' | 'deployment';

/** Initial product weights (configurable, not scientific guarantees). */
export const DIMENSION_WEIGHTS: Record<ScoreDimension, number> = {
  security: 0.25,
  reliability: 0.20,
  architecture: 0.15,
  performance: 0.10,
  scalability: 0.10,
  testing: 0.10,
  accessibility: 0.05,
  deployment: 0.05,
};

/** Which finding categories feed which score dimension. */
const DIMENSION_CATEGORIES: Record<ScoreDimension, Category[]> = {
  security: ['security'],
  reliability: ['reliability'],
  architecture: ['quality', 'architecture'],
  performance: ['performance'],
  scalability: ['scalability'],
  testing: ['testing'],
  accessibility: ['accessibility'],
  deployment: ['devops', 'cost'],
};

/** Analyzers that must have run for a dimension to be gradeable at all. */
const DIMENSION_REQUIRED_ANALYZERS: Record<ScoreDimension, string[]> = {
  security: ['security'],
  reliability: ['reliability'],
  architecture: ['quality'],
  performance: ['performance'],
  scalability: ['scalability'],
  testing: ['testing'],
  accessibility: ['accessibility'],
  deployment: ['devops'],
};

/** Penalty per finding before confidence weighting. */
const SEVERITY_PENALTY: Record<Severity, number> = {
  critical: 40, high: 18, medium: 7, low: 2, info: 0,
};

/** Minimum share of source files parsed for a code-derived dimension to be gradeable. */
export const MIN_PARSE_RATIO = 0.4;

export interface DimensionScore {
  dimension: ScoreDimension;
  /** null when the dimension is not gradeable. */
  score: number | null;
  grade: 'A' | 'B' | 'C' | 'D' | 'F' | 'insufficient_evidence';
  weight: number;
  findingCounts: Record<Severity, number>;
  penalty: number;
  /** Present when grade === 'insufficient_evidence'. */
  reason?: string;
}

export interface Scorecard {
  /** null when too little of the project could be assessed to total a score. */
  overall: number | null;
  overallGrade: 'A' | 'B' | 'C' | 'D' | 'F' | 'insufficient_evidence';
  dimensions: DimensionScore[];
  /** Share of total weight that was gradeable, 0..1. */
  assessedWeight: number;
  criticalCount: number;
  unassessedDimensions: ScoreDimension[];
  /** Rules used, so a score can be explained and reproduced. */
  rules: {
    severityPenalty: Record<Severity, number>;
    confidenceWeight: Record<Confidence, number>;
    weights: Record<ScoreDimension, number>;
    minParseRatio: number;
    minAssessedWeight: number;
  };
}

export const MIN_ASSESSED_WEIGHT = 0.5;

function toGrade(score: number): 'A' | 'B' | 'C' | 'D' | 'F' {
  if (score >= 90) return 'A';
  if (score >= 75) return 'B';
  if (score >= 60) return 'C';
  if (score >= 40) return 'D';
  return 'F';
}

function emptyCounts(): Record<Severity, number> {
  return { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
}

/**
 * Score one dimension. Returns `insufficient_evidence` when the analyzers that
 * feed it did not run, or when too little of the codebase could be parsed for a
 * "no findings" result to mean anything.
 */
export function scoreDimension(
  dimension: ScoreDimension,
  findings: Finding[],
  coverage: Coverage,
): DimensionScore {
  const weight = DIMENSION_WEIGHTS[dimension];
  const required = DIMENSION_REQUIRED_ANALYZERS[dimension];
  const missing = required.filter((a) => !coverage.analyzersRun.includes(a));

  const cats = DIMENSION_CATEGORIES[dimension];
  const relevant = findings.filter(
    (f) => cats.includes(f.category) && f.status !== 'false_positive' && f.status !== 'resolved',
  );
  const counts = emptyCounts();
  for (const f of relevant) counts[f.severity] += 1;

  if (missing.length > 0) {
    return {
      dimension, score: null, grade: 'insufficient_evidence', weight,
      findingCounts: counts, penalty: 0,
      reason: `analyzer(s) did not run: ${missing.join(', ')}`,
    };
  }

  // A clean result only means something if we could actually read the code.
  // Dimensions derived from configuration rather than source are exempt.
  const needsParsedSource = dimension !== 'deployment';
  if (needsParsedSource && relevant.length === 0 && coverage.parseRatio < MIN_PARSE_RATIO) {
    return {
      dimension, score: null, grade: 'insufficient_evidence', weight,
      findingCounts: counts, penalty: 0,
      reason: `only ${(coverage.parseRatio * 100).toFixed(0)}% of source files were parsed (need ${MIN_PARSE_RATIO * 100}%)`,
    };
  }

  let penalty = 0;
  for (const f of relevant) {
    penalty += SEVERITY_PENALTY[f.severity] * CONFIDENCE_WEIGHT[f.confidence];
  }
  penalty = Math.round(penalty * 100) / 100;
  const score = Math.max(0, Math.round(100 - penalty));
  return { dimension, score, grade: toGrade(score), weight, findingCounts: counts, penalty };
}

export function buildScorecard(findings: Finding[], coverage: Coverage): Scorecard {
  const dimensions = (Object.keys(DIMENSION_WEIGHTS) as ScoreDimension[]).map((d) =>
    scoreDimension(d, findings, coverage),
  );
  const graded = dimensions.filter((d) => d.score !== null);
  const assessedWeight = graded.reduce((s, d) => s + d.weight, 0);

  let overall: number | null = null;
  if (assessedWeight >= MIN_ASSESSED_WEIGHT) {
    // Renormalise over gradeable dimensions so missing coverage does not
    // silently read as a perfect score in those areas.
    const weighted = graded.reduce((s, d) => s + (d.score as number) * d.weight, 0);
    overall = Math.round(weighted / assessedWeight);
  }

  return {
    overall,
    overallGrade: overall === null ? 'insufficient_evidence' : toGrade(overall),
    dimensions,
    assessedWeight: Math.round(assessedWeight * 100) / 100,
    criticalCount: findings.filter(
      (f) => f.severity === 'critical' && f.status !== 'false_positive' && f.status !== 'resolved',
    ).length,
    unassessedDimensions: dimensions.filter((d) => d.score === null).map((d) => d.dimension),
    rules: {
      severityPenalty: SEVERITY_PENALTY,
      confidenceWeight: CONFIDENCE_WEIGHT,
      weights: DIMENSION_WEIGHTS,
      minParseRatio: MIN_PARSE_RATIO,
      minAssessedWeight: MIN_ASSESSED_WEIGHT,
    },
  };
}
