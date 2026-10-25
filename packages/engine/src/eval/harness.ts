import { readFileSync } from 'node:fs';
import type { Category, Finding } from '@codelens/core';

/**
 * Diagnostic precision and recall measurement.
 *
 * This is the objective check on the analyzers. It scores findings against a
 * hand-written ground truth for a fixture whose defects are known.
 *
 * An honesty note that matters for reading the output: ground truth is a human
 * list and is probably incomplete, so a finding that matches nothing in it is
 * not automatically wrong. Reporting it as a false positive would make the
 * numbers look worse than reality; reporting it as a true positive would make
 * them look better. So unmatched findings are listed separately for review,
 * precision is given as a LOWER BOUND, and only two things count as confirmed
 * false positives: a finding on a file declared clean, and a finding whose
 * evidence does not resolve against the snapshot.
 */

export interface GroundTruthItem {
  key: string;
  category: Category;
  file: string;
  severity?: string;
  tier: 'required' | 'bonus';
  description: string;
}

export interface GroundTruth {
  project: string;
  synthetic: boolean;
  expected: GroundTruthItem[];
  cleanFiles: string[];
}

export function loadGroundTruth(path: string): GroundTruth {
  return JSON.parse(readFileSync(path, 'utf8')) as GroundTruth;
}

export interface MatchedItem {
  item: GroundTruthItem;
  finding: Finding;
}

export interface EvalResult {
  project: string;
  totalFindings: number;

  requiredTotal: number;
  requiredDetected: number;
  /** Required-tier recall, 0..1. */
  recallRequired: number;

  bonusTotal: number;
  bonusDetected: number;

  allTotal: number;
  allDetected: number;
  recallAll: number;

  /** matched / totalFindings — a lower bound, because ground truth is incomplete. */
  precisionLowerBound: number;

  matched: MatchedItem[];
  missed: GroundTruthItem[];
  /** Findings matching no ground-truth item: for human review, not scored as wrong. */
  unmatched: Finding[];
  /** Confirmed false positives: on a declared-clean file. */
  falsePositivesOnCleanFiles: Finding[];
  /** Confirmed defects in the finding itself: evidence that does not resolve. */
  findingsWithUnresolvedEvidence: Finding[];

  byCategory: Array<{
    category: Category;
    requiredTotal: number;
    requiredDetected: number;
    recall: number;
    findings: number;
  }>;
}

/**
 * Does this finding point at the same place as the ground-truth item?
 *
 * Category and file must agree. The file may be named either in `files` or in
 * any evidence entry, because a cross-file finding legitimately cites a second
 * location.
 */
function addresses(finding: Finding, item: GroundTruthItem): boolean {
  if (finding.category !== item.category) return false;
  if (finding.files.includes(item.file)) return true;
  return finding.evidence.some((e) => e.file === item.file);
}

const STOPWORDS = new Set([
  'the', 'a', 'an', 'is', 'are', 'was', 'were', 'and', 'or', 'but', 'not', 'no',
  'in', 'on', 'at', 'to', 'of', 'for', 'with', 'without', 'from', 'by', 'into',
  'it', 'its', 'this', 'that', 'there', 'then', 'than', 'so', 'as', 'be', 'been',
]);

function keywords(text: string): Set<string> {
  return new Set(
    text
      .toLowerCase()
      .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
      .split(/[^a-z0-9]+/)
      .filter((w) => w.length > 2 && !STOPWORDS.has(w)),
  );
}

/**
 * How well a finding matches a specific ground-truth item, beyond sharing a file.
 *
 * Several findings commonly share one file — an endpoint can have an
 * authorisation gap, a missing null check, and no rate limiting at once. Matching
 * on (category, file) alone then pairs the item with whichever finding happens to
 * come first, which leaves the genuinely corresponding finding in the "unmatched"
 * list and makes the precision figure look worse than it is.
 *
 * So candidates are ranked by keyword overlap between the item's key and
 * description and the finding's rule id and title. The score only ever reorders
 * candidates that already share a category and a file, so it cannot manufacture
 * a match that does not exist.
 */
function matchScore(finding: Finding, item: GroundTruthItem): number {
  const want = keywords(`${item.key} ${item.description}`);
  const have = keywords(`${finding.ruleId} ${finding.title}`);
  let shared = 0;
  for (const w of want) if (have.has(w)) shared++;
  // Normalise by the item's own keyword count so a verbose finding is not favoured.
  const overlap = want.size === 0 ? 0 : shared / want.size;
  // A severity agreement is weak corroboration, worth a nudge only.
  const severityBonus = item.severity && finding.severity === item.severity ? 0.05 : 0;
  return overlap + severityBonus;
}

export function evaluate(findings: Finding[], gt: GroundTruth): EvalResult {
  const matched: MatchedItem[] = [];
  const usedFindings = new Set<Finding>();
  const missed: GroundTruthItem[] = [];

  // Each ground-truth item is satisfied by at most one finding, and each finding
  // can satisfy at most one item, so two findings for the same defect do not
  // inflate recall.
  //
  // Items are matched in order of how confidently they can be paired: an item
  // with a strong, unambiguous candidate claims it before a vaguer item can take
  // it by position alone.
  const ranked = gt.expected
    .map((item) => {
      const candidates = findings
        .filter((f) => addresses(f, item))
        .map((f) => ({ finding: f, score: matchScore(f, item) }))
        .sort((a, b) => b.score - a.score);
      return { item, candidates, best: candidates[0]?.score ?? -1 };
    })
    .sort((a, b) => b.best - a.best);

  for (const { item, candidates } of ranked) {
    const hit = candidates.find((c) => !usedFindings.has(c.finding));
    if (hit) {
      usedFindings.add(hit.finding);
      matched.push({ item, finding: hit.finding });
    } else {
      missed.push(item);
    }
  }
  // Restore ground-truth order for stable, readable output.
  const order = new Map(gt.expected.map((e, i) => [e.key, i]));
  matched.sort((a, b) => (order.get(a.item.key) ?? 0) - (order.get(b.item.key) ?? 0));
  missed.sort((a, b) => (order.get(a.key) ?? 0) - (order.get(b.key) ?? 0));

  const unmatched = findings.filter((f) => !usedFindings.has(f));

  // A finding is a false positive on a clean file when it is ABOUT that file,
  // not merely when it mentions it. A cross-file finding legitimately cites a
  // second location as supporting evidence — an "undocumented variable" finding
  // points at the env template precisely because the declaration is missing
  // there — and treating that as a false positive would penalise the product's
  // most valuable findings.
  const cleanSet = new Set(gt.cleanFiles);
  const falsePositivesOnCleanFiles = findings.filter(
    (f) =>
      (f.category === 'security' || f.category === 'reliability') &&
      f.files.length > 0 &&
      cleanSet.has(f.files[0]!),
  );

  const findingsWithUnresolvedEvidence = findings.filter(
    (f) => f.evidence.length === 0 || !f.evidence.some((e) => e.verified),
  );

  const required = gt.expected.filter((e) => e.tier === 'required');
  const bonus = gt.expected.filter((e) => e.tier === 'bonus');
  const matchedKeys = new Set(matched.map((m) => m.item.key));
  const requiredDetected = required.filter((e) => matchedKeys.has(e.key)).length;
  const bonusDetected = bonus.filter((e) => matchedKeys.has(e.key)).length;

  const categories = [...new Set(gt.expected.map((e) => e.category))];
  const byCategory = categories.map((category) => {
    const reqs = required.filter((e) => e.category === category);
    const det = reqs.filter((e) => matchedKeys.has(e.key)).length;
    return {
      category,
      requiredTotal: reqs.length,
      requiredDetected: det,
      recall: reqs.length === 0 ? 1 : det / reqs.length,
      findings: findings.filter((f) => f.category === category).length,
    };
  }).sort((a, b) => b.requiredTotal - a.requiredTotal);

  return {
    project: gt.project,
    totalFindings: findings.length,
    requiredTotal: required.length,
    requiredDetected,
    recallRequired: required.length === 0 ? 1 : requiredDetected / required.length,
    bonusTotal: bonus.length,
    bonusDetected,
    allTotal: gt.expected.length,
    allDetected: matched.length,
    recallAll: gt.expected.length === 0 ? 1 : matched.length / gt.expected.length,
    precisionLowerBound: findings.length === 0 ? 0 : matched.length / findings.length,
    matched,
    missed,
    unmatched,
    falsePositivesOnCleanFiles,
    findingsWithUnresolvedEvidence,
    byCategory,
  };
}

export function formatEvalReport(r: EvalResult): string {
  const pct = (n: number) => `${(n * 100).toFixed(0)}%`;
  const lines: string[] = [];

  lines.push(`Diagnostic accuracy — ${r.project}`);
  lines.push('='.repeat(64));
  lines.push(`findings produced            ${r.totalFindings}`);
  lines.push(`required defects detected    ${r.requiredDetected}/${r.requiredTotal}  (recall ${pct(r.recallRequired)})`);
  lines.push(`bonus defects detected       ${r.bonusDetected}/${r.bonusTotal}`);
  lines.push(`all ground-truth detected    ${r.allDetected}/${r.allTotal}  (recall ${pct(r.recallAll)})`);
  lines.push(`precision (lower bound)      ${pct(r.precisionLowerBound)}  — ground truth is incomplete, see note`);
  lines.push(`false positives on clean     ${r.falsePositivesOnCleanFiles.length}`);
  lines.push(`findings w/ bad evidence     ${r.findingsWithUnresolvedEvidence.length}`);
  lines.push('');

  lines.push('By category (required tier):');
  for (const c of r.byCategory) {
    lines.push(
      `  ${c.category.padEnd(14)} ${String(c.requiredDetected).padStart(2)}/${String(c.requiredTotal).padEnd(2)} ` +
      `recall ${pct(c.recall).padStart(4)}   (${c.findings} finding${c.findings === 1 ? '' : 's'} emitted)`,
    );
  }

  if (r.missed.length > 0) {
    lines.push('');
    lines.push(`MISSED (${r.missed.length}):`);
    for (const m of r.missed) {
      lines.push(`  [${m.tier}] ${m.category}/${m.key} — ${m.file}`);
      lines.push(`      ${m.description}`);
    }
  }

  if (r.falsePositivesOnCleanFiles.length > 0) {
    lines.push('');
    lines.push(`FALSE POSITIVES on files declared clean (${r.falsePositivesOnCleanFiles.length}):`);
    for (const f of r.falsePositivesOnCleanFiles) {
      lines.push(`  ${f.ruleId} — ${f.files.join(', ')} — ${f.title}`);
    }
  }

  if (r.findingsWithUnresolvedEvidence.length > 0) {
    lines.push('');
    lines.push(`FINDINGS WITH NO VERIFIED EVIDENCE (${r.findingsWithUnresolvedEvidence.length}) — these are dropped by the discipline gate:`);
    for (const f of r.findingsWithUnresolvedEvidence) {
      lines.push(`  ${f.ruleId} — ${f.files.join(', ')}`);
    }
  }

  if (r.unmatched.length > 0) {
    lines.push('');
    lines.push(`UNMATCHED findings (${r.unmatched.length}) — not in ground truth, needs human review.`);
    lines.push('A real defect here means ground truth is incomplete; a wrong one is a false positive.');
    for (const f of r.unmatched) {
      const ev = f.evidence[0];
      lines.push(`  ${f.severity.padEnd(8)} ${f.confidence.padEnd(9)} ${f.ruleId}`);
      lines.push(`      ${f.files[0]}:${ev?.startLine ?? '?'} — ${f.title}`);
    }
  }

  return lines.join('\n');
}
