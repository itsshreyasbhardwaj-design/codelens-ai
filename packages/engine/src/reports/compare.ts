import type { Coverage, Finding, Severity } from '@codelens/core';
import type { Scorecard } from '@codelens/core';

/**
 * Scan comparison and improvement tracking.
 *
 * The rule that matters most here: a finding that is absent from the newer scan
 * is NOT automatically a repair. It is only a repair if the newer scan actually
 * looked at the same ground. If the analyzer that found it did not run, or the
 * file is no longer parsed, or coverage otherwise shrank, the honest answer is
 * "no longer reported, but not verified as fixed".
 *
 * Getting this wrong would make the product actively harmful: a team would read
 * a falling finding count as progress while the real cause was a scan that
 * covered less.
 */

export type ChangeKind =
  | 'resolved'              // gone, and the newer scan covered the same ground
  | 'unverified_absence'    // gone, but coverage changed, so not proven fixed
  | 'persistent'            // present in both
  | 'new'                   // only in the newer scan
  | 'regressed'             // resolved in an earlier scan, present again now
  | 'severity_increased'
  | 'severity_decreased';

export interface FindingChange {
  kind: ChangeKind;
  fingerprint: string;
  title: string;
  category: string;
  severity: Severity;
  previousSeverity?: Severity;
  /** Why an absence could not be confirmed as a fix. */
  caveat?: string;
}

export interface ScanComparison {
  /** False when the two scans are not meaningfully comparable. */
  comparable: boolean;
  /** Why not, when comparable is false. */
  incomparableReason?: string;

  baseScanId: string;
  headScanId: string;

  resolved: FindingChange[];
  unverifiedAbsences: FindingChange[];
  persistent: FindingChange[];
  introduced: FindingChange[];
  regressed: FindingChange[];
  severityChanges: FindingChange[];

  /** Coverage deltas, which decide whether absences count as fixes. */
  coverageDelta: {
    filesIndexed: number;
    filesParsed: number;
    parseRatio: number;
    analyzersAdded: string[];
    analyzersRemoved: string[];
    layersGained: string[];
    layersLost: string[];
  };

  scoreDelta?: {
    overallBefore: number | null;
    overallAfter: number | null;
    /** null when either side was not gradeable: a score cannot be diffed against 'insufficient evidence'. */
    change: number | null;
    note?: string;
  };

  summary: string;
}

export interface ScanSide {
  scanId: string;
  findings: Finding[];
  coverage: Coverage;
  scorecard?: Scorecard;
  /** Content hash of the analysed file set. */
  contentHash: string;
  /** Fingerprints resolved in scans before this one, for regression detection. */
  previouslyResolved?: Set<string>;
}

const SEVERITY_RANK: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

export function compareScans(base: ScanSide, head: ScanSide): ScanComparison {
  const coverageDelta = {
    filesIndexed: head.coverage.filesIndexed - base.coverage.filesIndexed,
    filesParsed: head.coverage.filesParsed - base.coverage.filesParsed,
    parseRatio: Math.round((head.coverage.parseRatio - base.coverage.parseRatio) * 100) / 100,
    analyzersAdded: head.coverage.analyzersRun.filter((a) => !base.coverage.analyzersRun.includes(a)),
    analyzersRemoved: base.coverage.analyzersRun.filter((a) => !head.coverage.analyzersRun.includes(a)),
    layersGained: layerNames(head.coverage).filter((l) => !layerNames(base.coverage).includes(l)),
    layersLost: layerNames(base.coverage).filter((l) => !layerNames(head.coverage).includes(l)),
  };

  // Identical content means nothing changed in the project; comparing is valid
  // but any difference in findings comes from the analyser, not the code.
  if (base.contentHash === head.contentHash) {
    const result = buildComparison(base, head, coverageDelta, true);
    result.summary =
      'Both scans analysed an identical file set, so the project did not change between them. ' +
      'Any difference in findings reflects a change in CodeLens itself, not in the code. ' +
      result.summary;
    return result;
  }

  return buildComparison(base, head, coverageDelta, true);
}

function layerNames(c: Coverage): string[] {
  return Object.entries(c.layers).filter(([, v]) => v).map(([k]) => k);
}

function toChange(f: Finding, kind: ChangeKind, extra: Partial<FindingChange> = {}): FindingChange {
  return {
    kind,
    fingerprint: f.fingerprint,
    title: f.title,
    category: f.category,
    severity: f.severity,
    ...extra,
  };
}

function buildComparison(
  base: ScanSide, head: ScanSide, coverageDelta: ScanComparison['coverageDelta'], comparable: boolean,
): ScanComparison {
  const baseByFp = new Map(base.findings.map((f) => [f.fingerprint, f]));
  const headByFp = new Map(head.findings.map((f) => [f.fingerprint, f]));

  const resolved: FindingChange[] = [];
  const unverifiedAbsences: FindingChange[] = [];
  const persistent: FindingChange[] = [];
  const introduced: FindingChange[] = [];
  const regressed: FindingChange[] = [];
  const severityChanges: FindingChange[] = [];

  for (const [fp, before] of baseByFp) {
    const after = headByFp.get(fp);
    if (after) {
      persistent.push(toChange(after, 'persistent'));
      if (after.severity !== before.severity) {
        severityChanges.push(
          toChange(after,
            SEVERITY_RANK[after.severity] < SEVERITY_RANK[before.severity] ? 'severity_increased' : 'severity_decreased',
            { previousSeverity: before.severity }),
        );
      }
      continue;
    }

    // The finding is gone. Was the newer scan able to see it?
    const caveat = absenceCaveat(before, base, head, coverageDelta);
    if (caveat) {
      unverifiedAbsences.push(toChange(before, 'unverified_absence', { caveat }));
    } else {
      resolved.push(toChange(before, 'resolved'));
    }
  }

  for (const [fp, after] of headByFp) {
    if (baseByFp.has(fp)) continue;
    if (head.previouslyResolved?.has(fp) || base.previouslyResolved?.has(fp)) {
      regressed.push(toChange(after, 'regressed'));
    } else {
      introduced.push(toChange(after, 'new'));
    }
  }

  const scoreDelta = buildScoreDelta(base, head);

  const summary = buildSummary({
    resolved, unverifiedAbsences, persistent, introduced, regressed, coverageDelta, scoreDelta,
  });

  return {
    comparable,
    baseScanId: base.scanId,
    headScanId: head.scanId,
    resolved, unverifiedAbsences, persistent, introduced, regressed, severityChanges,
    coverageDelta,
    scoreDelta,
    summary,
  };
}

/**
 * Why a finding's absence cannot be treated as a fix.
 *
 * Returns undefined when the absence is trustworthy.
 */
function absenceCaveat(
  f: Finding, base: ScanSide, head: ScanSide, delta: ScanComparison['coverageDelta'],
): string | undefined {
  // 1. The analyzer that produced it did not run.
  const analyzerId = f.ruleId.split('.')[0];
  const analyzerMap: Record<string, string> = {
    security: 'security', reliability: 'reliability', performance: 'performance',
    scalability: 'scalability', accessibility: 'accessibility', quality: 'quality',
    testing: 'testing', devops: 'devops', cost: 'cost', ai: 'ai',
  };
  const needed = analyzerMap[analyzerId ?? ''];
  if (needed && !head.coverage.analyzersRun.includes(needed)) {
    const skip = head.coverage.analyzersSkipped.find((s) => s.analyzer === needed);
    return `the '${needed}' analyzer did not run in the newer scan${skip ? ` (${skip.reason})` : ''}, so this finding could not have been reported either way`;
  }

  // 2. The file it was found in is no longer indexed or parsed.
  if (f.files.length > 0 && delta.filesIndexed < 0) {
    return `the newer scan indexed ${Math.abs(delta.filesIndexed)} fewer file(s); confirm '${f.files[0]}' is still part of the project rather than merely excluded`;
  }

  // 3. The layer that produced it was not completed.
  if (f.detectionSource === 'ai' && !head.coverage.layers.ai) {
    return 'this finding came from AI semantic investigation, which did not run in the newer scan';
  }
  if (f.detectionSource === 'dynamic' && !head.coverage.layers.dynamic) {
    return 'this finding came from dynamic verification, which did not run in the newer scan';
  }
  if (f.detectionSource === 'graph' && !head.coverage.layers.graph) {
    return 'this finding came from cross-file relationship analysis, which did not complete in the newer scan';
  }

  // 4. Parse coverage fell materially, so the code may simply not have been read.
  if (delta.parseRatio <= -0.1) {
    return `parse coverage fell by ${Math.abs(delta.parseRatio * 100).toFixed(0)} percentage points, so the newer scan read less of the source`;
  }

  // 5. The newer scan was truncated.
  if (head.coverage.truncated && !base.coverage.truncated) {
    return 'the newer scan hit an ingestion limit and did not read the whole project';
  }

  return undefined;
}

function buildScoreDelta(base: ScanSide, head: ScanSide): ScanComparison['scoreDelta'] {
  const before = base.scorecard?.overall ?? null;
  const after = head.scorecard?.overall ?? null;
  if (before === null || after === null) {
    return {
      overallBefore: before,
      overallAfter: after,
      change: null,
      note:
        'One of the two scans had insufficient evidence for an overall score, so no change can be stated. ' +
        'A score cannot be diffed against an absence of one.',
    };
  }
  return { overallBefore: before, overallAfter: after, change: after - before };
}

function buildSummary(input: {
  resolved: FindingChange[];
  unverifiedAbsences: FindingChange[];
  persistent: FindingChange[];
  introduced: FindingChange[];
  regressed: FindingChange[];
  coverageDelta: ScanComparison['coverageDelta'];
  scoreDelta: ScanComparison['scoreDelta'];
}): string {
  const parts: string[] = [];
  const { resolved, unverifiedAbsences, persistent, introduced, regressed, coverageDelta, scoreDelta } = input;

  parts.push(
    `${resolved.length} finding(s) verified as resolved, ${persistent.length} still present, ` +
    `${introduced.length} newly reported.`,
  );
  if (regressed.length > 0) {
    parts.push(`${regressed.length} previously resolved finding(s) have returned.`);
  }
  if (unverifiedAbsences.length > 0) {
    parts.push(
      `${unverifiedAbsences.length} finding(s) are no longer reported but could NOT be confirmed as fixed, ` +
      'because the newer scan did not cover the same ground. They are listed separately rather than counted as progress.',
    );
  }
  if (coverageDelta.analyzersRemoved.length > 0) {
    parts.push(`Analyzers that ran before but not now: ${coverageDelta.analyzersRemoved.join(', ')}.`);
  }
  if (coverageDelta.analyzersAdded.length > 0) {
    parts.push(
      `Analyzers new in this scan: ${coverageDelta.analyzersAdded.join(', ')} — some "new" findings are newly ` +
      'looked for rather than newly introduced.',
    );
  }
  if (scoreDelta?.change !== null && scoreDelta?.change !== undefined) {
    const dir = scoreDelta.change > 0 ? 'up' : scoreDelta.change < 0 ? 'down' : 'unchanged';
    parts.push(`Overall score ${dir}${scoreDelta.change === 0 ? '' : ` by ${Math.abs(scoreDelta.change)}`} (${scoreDelta.overallBefore} to ${scoreDelta.overallAfter}).`);
  } else if (scoreDelta?.note) {
    parts.push(scoreDelta.note);
  }
  return parts.join(' ');
}
