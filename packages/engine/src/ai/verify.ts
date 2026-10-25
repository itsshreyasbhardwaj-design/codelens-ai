import type { Confidence, Evidence, Finding, Severity } from '@codelens/core';
import { fingerprintFinding } from '@codelens/core';
import type { RepoMap } from '../graph/repomap.ts';
import { categoryOf } from '../analyzers/types.ts';

/**
 * Evidence verification for model-produced findings.
 *
 * This is the gate that makes Layer C safe to ship. A model asserting something
 * is not evidence; a quoted line that genuinely exists in the snapshot is. Every
 * AI finding is checked here before it becomes a Finding, and anything that
 * cannot be located is rejected with a reason rather than downgraded, because an
 * AI claim with no verifiable anchor has nothing behind it at all.
 */

/** Shape the model is asked to produce. Anything else is rejected. */
export interface RawAiFinding {
  ruleId?: string;
  title?: string;
  severity?: string;
  confidence?: string;
  file?: string;
  line?: number;
  quotedLine?: string;
  explanation?: string;
  userImpact?: string;
  remediation?: string;
  references?: string[];
}

export const AI_FINDING_SCHEMA = {
  type: 'object',
  properties: {
    findings: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          ruleId: { type: 'string', description: 'category-prefixed id, e.g. reliability.contract.missing_field' },
          title: { type: 'string' },
          severity: { type: 'string', enum: ['critical', 'high', 'medium', 'low', 'info'] },
          confidence: { type: 'string', enum: ['strong', 'moderate', 'weak'] },
          file: { type: 'string', description: 'exact path as shown in the excerpts' },
          line: { type: 'number' },
          quotedLine: { type: 'string', description: 'the exact source line this claim relies on, copied verbatim' },
          explanation: { type: 'string' },
          userImpact: { type: 'string' },
          remediation: { type: 'string' },
          references: { type: 'array', items: { type: 'string' } },
        },
        required: ['ruleId', 'title', 'severity', 'confidence', 'file', 'line', 'quotedLine', 'explanation', 'userImpact', 'remediation'],
      },
    },
  },
  required: ['findings'],
} as const;

export interface VerificationOutcome {
  accepted: Finding[];
  rejected: Array<{ raw: RawAiFinding; reason: string }>;
}

const SEVERITIES = new Set(['critical', 'high', 'medium', 'low', 'info']);

/** Normalise whitespace so an excerpt matches despite reindentation. */
function norm(s: string): string {
  return s.replace(/\s+/g, ' ').trim();
}

export function verifyAiFindings(raw: RawAiFinding[], map: RepoMap): VerificationOutcome {
  const accepted: Finding[] = [];
  const rejected: VerificationOutcome['rejected'] = [];

  for (const r of raw) {
    // --- structural validation ---
    const missing = (['ruleId', 'title', 'file', 'quotedLine', 'explanation', 'userImpact', 'remediation'] as const)
      .filter((k) => !r[k] || String(r[k]).trim().length === 0);
    if (missing.length > 0) {
      rejected.push({ raw: r, reason: `malformed: missing ${missing.join(', ')}` });
      continue;
    }
    if (!r.severity || !SEVERITIES.has(r.severity)) {
      rejected.push({ raw: r, reason: `invalid severity '${r.severity}'` });
      continue;
    }

    // --- the file must exist in the snapshot ---
    const file = map.filesByPath.get(r.file!);
    if (!file) {
      rejected.push({ raw: r, reason: `cites '${r.file}', which is not in the analysed snapshot` });
      continue;
    }
    if (!file.text) {
      rejected.push({ raw: r, reason: `cites '${r.file}', which has no readable text content` });
      continue;
    }

    // --- the quoted line must actually appear in that file ---
    const lines = file.text.split('\n');
    const quoted = norm(r.quotedLine!);
    if (quoted.length < 3) {
      rejected.push({ raw: r, reason: 'quoted line is too short to verify' });
      continue;
    }

    let foundLine = -1;
    // Prefer the claimed line, allowing a small drift.
    const claimed = r.line ?? 0;
    for (const candidate of nearbyFirst(claimed, lines.length)) {
      if (norm(lines[candidate - 1] ?? '').includes(quoted)) { foundLine = candidate; break; }
    }
    if (foundLine === -1) {
      rejected.push({
        raw: r,
        reason: `the quoted line does not appear in '${r.file}'; the claim has no verifiable anchor`,
      });
      continue;
    }

    const evidence: Evidence = {
      file: r.file!,
      startLine: foundLine,
      excerpt: (lines[foundLine - 1] ?? '').trim().slice(0, 300),
      note:
        foundLine === claimed
          ? 'quoted line located in the snapshot at the stated position'
          : `quoted line located at line ${foundLine}; the model stated ${claimed}`,
      verified: true,
    };

    // A model may not assert 'confirmed'. The strongest an AI finding can be is
    // 'strong', and only when its quote was found exactly where it claimed.
    let confidence: Confidence = (r.confidence === 'strong' ? 'strong' : r.confidence === 'moderate' ? 'moderate' : 'weak');
    if (foundLine !== claimed && confidence === 'strong') confidence = 'moderate';

    const ruleId = r.ruleId!.includes('.') ? r.ruleId! : `quality.ai.${r.ruleId}`;

    accepted.push({
      id: 'PENDING',
      fingerprint: fingerprintFinding({
        ruleId,
        category: categoryOf(ruleId),
        files: [r.file!],
        excerpt: evidence.excerpt,
      }),
      ruleId,
      title: r.title!,
      category: categoryOf(ruleId),
      severity: r.severity as Severity,
      confidence,
      status: confidence === 'strong' ? 'strongly_supported' : 'suspected',
      detectionSource: 'ai',
      files: [r.file!],
      evidence: [evidence],
      explanation: r.explanation!,
      userImpact: r.userImpact!,
      downstreamConsequences: [],
      remediation: r.remediation!,
      effort: 'unknown',
      relatedTests: [],
      verificationSteps: [
        'This finding came from model reasoning over retrieved code, so confirm the described condition in the file before acting on it.',
      ],
      relatedFindings: [],
      references: r.references ?? [],
      affectedFeatures: [],
    });
  }

  return { accepted, rejected };
}

/** Line numbers to try, closest to the claim first, within a drift window. */
function nearbyFirst(claimed: number, total: number): number[] {
  const out: number[] = [];
  const window = 25;
  if (claimed >= 1 && claimed <= total) out.push(claimed);
  for (let d = 1; d <= window; d++) {
    if (claimed - d >= 1) out.push(claimed - d);
    if (claimed + d <= total) out.push(claimed + d);
  }
  // Fall back to a whole-file scan: a correct quote at the wrong line is still
  // useful, and the note records the discrepancy.
  for (let i = 1; i <= total; i++) if (!out.includes(i)) out.push(i);
  return out;
}

/** Parse a model response as JSON, tolerating a fenced code block. */
export function parseJsonResponse<T>(text: string): { ok: true; value: T } | { ok: false; error: string } {
  const trimmed = text.trim();
  const fenced = /```(?:json)?\s*([\s\S]*?)```/.exec(trimmed);
  const candidate = fenced ? fenced[1]!.trim() : trimmed;
  try {
    return { ok: true, value: JSON.parse(candidate) as T };
  } catch (e) {
    // A model sometimes emits prose before the object; take the outermost braces.
    const start = candidate.indexOf('{');
    const end = candidate.lastIndexOf('}');
    if (start !== -1 && end > start) {
      try {
        return { ok: true, value: JSON.parse(candidate.slice(start, end + 1)) as T };
      } catch { /* fall through */ }
    }
    return { ok: false, error: `response was not valid JSON: ${(e as Error).message}` };
  }
}
