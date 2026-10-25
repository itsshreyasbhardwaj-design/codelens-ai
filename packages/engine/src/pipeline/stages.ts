import type { StageName, StageResult, StageStatus } from '@codelens/core';
import { STAGE_NAMES } from '@codelens/core';

/**
 * Stage bookkeeping.
 *
 * Every stage records what actually happened. A stage that was skipped says why;
 * a stage that failed says how. The UI reads these directly, which is what stops
 * a partial scan from being presented as a complete one.
 */

export interface StageSpec {
  name: StageName;
  ordinal: number;
  /** An optional stage failing degrades the scan to 'partial'; a required one fails it. */
  optional: boolean;
  /** Attempts allowed, including the first. */
  maxAttempts: number;
  description: string;
}

export const STAGE_SPECS: StageSpec[] = [
  { name: 'ingestion_validation', ordinal: 1, optional: false, maxAttempts: 2, description: 'Confirm authorisation, accessibility, size, and input integrity.' },
  { name: 'source_normalization', ordinal: 2, optional: false, maxAttempts: 2, description: 'Normalise contents and exclude unsuitable files, recording why.' },
  { name: 'technology_detection', ordinal: 3, optional: false, maxAttempts: 2, description: 'Identify languages, frameworks, dependencies, and analysis adapters.' },
  { name: 'code_indexing', ordinal: 4, optional: false, maxAttempts: 2, description: 'Parse supported languages and build structural indexes.' },
  { name: 'deterministic_diagnostics', ordinal: 5, optional: false, maxAttempts: 1, description: 'Run non-executing analyzers over the repository map.' },
  { name: 'architecture_reconstruction', ordinal: 6, optional: false, maxAttempts: 2, description: 'Build components, relationships, and the feature inventory.' },
  { name: 'dynamic_verification', ordinal: 7, optional: true, maxAttempts: 1, description: 'Run explicitly authorised builds or tests. Disabled by default.' },
  { name: 'ai_semantic_investigation', ordinal: 8, optional: true, maxAttempts: 2, description: 'Investigate unresolved questions with a model over retrieved evidence.' },
  { name: 'finding_consolidation', ordinal: 9, optional: false, maxAttempts: 1, description: 'Deduplicate findings and enforce the evidence discipline.' },
  { name: 'risk_prioritization', ordinal: 10, optional: false, maxAttempts: 1, description: 'Rank findings and produce the remediation roadmap.' },
  { name: 'fix_pack_generation', ordinal: 11, optional: false, maxAttempts: 1, description: 'Group findings into dependency-aware Fix Packs and validate each prompt.' },
  { name: 'report_generation', ordinal: 12, optional: false, maxAttempts: 1, description: 'Produce the scorecard, coverage report, and exports.' },
];

export function specFor(name: StageName): StageSpec {
  const spec = STAGE_SPECS.find((s) => s.name === name);
  if (!spec) throw new Error(`unknown stage '${name}'`);
  return spec;
}

export class StageTracker {
  private readonly results = new Map<StageName, StageResult>();

  constructor() {
    for (const name of STAGE_NAMES) {
      this.results.set(name, { name, status: 'pending', warnings: [], attempts: 0 });
    }
  }

  get(name: StageName): StageResult {
    return this.results.get(name)!;
  }

  all(): StageResult[] {
    return STAGE_SPECS.map((s) => this.results.get(s.name)!);
  }

  start(name: StageName): void {
    const r = this.get(name);
    r.status = 'running';
    r.attempts += 1;
    r.startedAt = new Date().toISOString();
  }

  complete(name: StageName, startedMs: number, warnings: string[] = []): void {
    const r = this.get(name);
    r.status = 'completed';
    r.finishedAt = new Date().toISOString();
    r.durationMs = Math.round(performance.now() - startedMs);
    r.warnings.push(...warnings);
  }

  fail(name: StageName, message: string, startedMs: number): void {
    const r = this.get(name);
    r.status = 'failed';
    r.message = message;
    r.finishedAt = new Date().toISOString();
    r.durationMs = Math.round(performance.now() - startedMs);
  }

  skip(name: StageName, reason: string): void {
    const r = this.get(name);
    r.status = 'skipped';
    r.message = reason;
    r.finishedAt = new Date().toISOString();
  }

  cancel(name: StageName): void {
    const r = this.get(name);
    if (r.status === 'pending' || r.status === 'running') {
      r.status = 'cancelled';
      r.message = 'cancelled before completion';
    }
  }

  warn(name: StageName, warning: string): void {
    this.get(name).warnings.push(warning);
  }

  statusOf(name: StageName): StageStatus {
    return this.get(name).status;
  }

  /** Did every required stage complete? */
  allRequiredCompleted(): boolean {
    return STAGE_SPECS.filter((s) => !s.optional).every((s) => this.statusOf(s.name) === 'completed');
  }

  anyFailed(): boolean {
    return STAGE_SPECS.some((s) => this.statusOf(s.name) === 'failed');
  }
}
