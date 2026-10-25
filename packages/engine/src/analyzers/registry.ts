import type { Finding } from '@codelens/core';
import type { RepoMap } from '../graph/repomap.ts';
import type { Analyzer } from './types.ts';
import { makeContext } from './types.ts';

/**
 * Analyzer registry and runner.
 *
 * One analyzer failing never fails the scan: the error is recorded, that
 * analyzer is reported as skipped with the reason, and scoring then refuses to
 * grade the dimension it fed. That is how a partial scan stays honest instead
 * of looking clean.
 */

export interface AnalyzerRunResult {
  findings: Finding[];
  analyzersRun: string[];
  analyzersSkipped: Array<{ analyzer: string; reason: string }>;
  errors: Array<{ analyzer: string; error: string }>;
  timings: Array<{ analyzer: string; ms: number; findings: number }>;
}

export function runAnalyzers(map: RepoMap, analyzers: Analyzer[]): AnalyzerRunResult {
  const findings: Finding[] = [];
  const analyzersRun: string[] = [];
  const analyzersSkipped: AnalyzerRunResult['analyzersSkipped'] = [];
  const errors: AnalyzerRunResult['errors'] = [];
  const timings: AnalyzerRunResult['timings'] = [];
  const ctx = makeContext(map);

  for (const analyzer of analyzers) {
    const skip = analyzer.precondition?.(map);
    if (skip) {
      analyzersSkipped.push({ analyzer: analyzer.id, reason: skip });
      continue;
    }
    const started = performance.now();
    try {
      const produced = analyzer.run(ctx);
      findings.push(...produced);
      analyzersRun.push(analyzer.id);
      timings.push({
        analyzer: analyzer.id,
        ms: Math.round(performance.now() - started),
        findings: produced.length,
      });
    } catch (e) {
      const message = e instanceof Error ? e.message : String(e);
      errors.push({ analyzer: analyzer.id, error: message });
      analyzersSkipped.push({ analyzer: analyzer.id, reason: `analyzer failed: ${message}` });
    }
  }

  return { findings, analyzersRun, analyzersSkipped, errors, timings };
}
