import type { Finding } from '@codelens/core';
import type { FixPack } from './grouping.ts';
import type { PromptContext } from './prompt.ts';

/**
 * Fix Pack validation, run before a prompt is ever shown.
 *
 * A wrong prompt is worse than no prompt: it sends a coding agent to edit a file
 * that does not exist, or to act on a finding from a different scan. So the
 * checks below gate presentation. An `error` withholds the pack; a `warning` is
 * surfaced alongside it.
 */

export type IssueLevel = 'error' | 'warning';

export interface ValidationIssue {
  level: IssueLevel;
  check: string;
  detail: string;
}

export interface ValidationResult {
  packKey: string;
  /** False when any error-level issue was found; the pack must then be withheld. */
  presentable: boolean;
  issues: ValidationIssue[];
  checksRun: string[];
}

export interface ValidationInput {
  pack: FixPack;
  prompt: string;
  ctx: PromptContext;
  /** Every path in the analysed snapshot. */
  knownFiles: Set<string>;
  /** Fingerprints of findings belonging to this scan. */
  scanFingerprints: Set<string>;
  /** Keys of all packs in this scan, for dependency validation. */
  allPackKeys: Set<string>;
  /** Dependency edges across the whole scan, for cycle detection. */
  packDependencies: Map<string, string[]>;
}

/** Operations a generated prompt must never request. */
const DESTRUCTIVE_PATTERNS: Array<{ re: RegExp; what: string }> = [
  { re: /\bgit\s+push\s+--force\b|\bgit\s+push\s+-f\b/i, what: 'force push' },
  { re: /\bgit\s+reset\s+--hard\b/i, what: 'hard reset' },
  { re: /\brm\s+-rf\s+[^\s]/i, what: 'recursive delete' },
  { re: /\bDROP\s+(?:TABLE|DATABASE|SCHEMA)\b/i, what: 'dropping a table or database' },
  { re: /\bTRUNCATE\s+TABLE\b/i, what: 'truncating a table' },
  { re: /\bDELETE\s+FROM\s+\w+\s*(?:;|$)/i, what: 'unqualified delete' },
  { re: /\bgit\s+filter-branch\b|\bfilter-repo\b/i, what: 'history rewrite' },
  { re: /\bnpm\s+publish\b|\bpnpm\s+publish\b/i, what: 'publishing a package' },
  { re: /\bdeploy\s+--prod\b|\bvercel\s+deploy\s+--prod\b/i, what: 'deploying to production' },
];

/** Phrases that would overstate what a fix achieves. */
const OVERCLAIM_PATTERNS: Array<{ re: RegExp; what: string }> = [
  { re: /\b(?:guarantee|guaranteed|guarantees)\s+(?:security|safety|no\s+vulnerabilit)/i, what: 'a security guarantee' },
  { re: /\b(?:fully|completely|100%)\s+secure\b/i, what: 'a claim of complete security' },
  { re: /\ball\s+vulnerabilities\s+(?:are\s+)?(?:fixed|removed|eliminated)\b/i, what: 'a claim that all vulnerabilities are fixed' },
];

export function validateFixPack(input: ValidationInput): ValidationResult {
  const { pack, prompt, ctx, knownFiles, scanFingerprints, allPackKeys, packDependencies } = input;
  const issues: ValidationIssue[] = [];
  const checksRun: string[] = [];

  // --- 1. Referenced files must exist in the analysed snapshot ---
  checksRun.push('referenced_files_exist');
  const missingFiles = pack.affectedFiles.filter((p) => !knownFiles.has(p));
  for (const p of missingFiles) {
    issues.push({
      level: 'error',
      check: 'referenced_files_exist',
      detail: `pack references '${p}', which is not in the analysed snapshot — the prompt would send an agent to a non-existent file`,
    });
  }
  const evidenceFiles = new Set(
    pack.findings.flatMap((pf) => pf.finding.evidence.map((e) => e.file)),
  );
  for (const p of evidenceFiles) {
    if (!knownFiles.has(p)) {
      issues.push({
        level: 'error',
        check: 'referenced_files_exist',
        detail: `evidence cites '${p}', which is not in the analysed snapshot`,
      });
    }
  }

  // --- 2. Cited findings must belong to this scan ---
  checksRun.push('findings_belong_to_scan');
  for (const pf of pack.findings) {
    if (!scanFingerprints.has(pf.finding.fingerprint)) {
      issues.push({
        level: 'error',
        check: 'findings_belong_to_scan',
        detail: `finding ${pf.finding.id} (${pf.finding.fingerprint}) is not part of scan ${ctx.scanId}`,
      });
    }
  }

  // --- 3. Dependencies must exist and must not cycle ---
  checksRun.push('dependencies_valid');
  for (const dep of pack.dependsOn) {
    if (!allPackKeys.has(dep)) {
      issues.push({
        level: 'error',
        check: 'dependencies_valid',
        detail: `declares a dependency on '${dep}', which is not a pack in this scan`,
      });
    }
  }
  const cycle = findCycle(pack.key, packDependencies);
  if (cycle) {
    issues.push({
      level: 'error',
      check: 'dependencies_valid',
      detail: `dependency cycle: ${cycle.join(' -> ')} — the roadmap would not be executable`,
    });
  }

  // --- 4. Every finding must carry verified evidence ---
  checksRun.push('evidence_verified');
  for (const pf of pack.findings) {
    const f = pf.finding;
    if (f.evidence.length === 0) {
      issues.push({
        level: 'error',
        check: 'evidence_verified',
        detail: `finding ${f.id} has no evidence and must not be put in front of an agent`,
      });
      continue;
    }
    if (!f.evidence.some((e) => e.verified)) {
      issues.push({
        level: 'warning',
        check: 'evidence_verified',
        detail: `finding ${f.id} has no evidence that could be re-verified against the snapshot; the prompt marks it, but consider withholding it`,
      });
    }
  }

  // --- 5. No contradictory instructions ---
  checksRun.push('no_contradictions');
  for (const c of findContradictions(pack.findings.map((p) => p.finding))) {
    issues.push({ level: 'warning', check: 'no_contradictions', detail: c });
  }

  // --- 6. No redundant findings (same rule, same file, same line) ---
  checksRun.push('no_redundancy');
  const seen = new Map<string, string>();
  for (const pf of pack.findings) {
    const f = pf.finding;
    const key = `${f.ruleId}|${f.files.join(',')}|${f.evidence[0]?.startLine ?? ''}`;
    const prior = seen.get(key);
    if (prior) {
      issues.push({
        level: 'warning',
        check: 'no_redundancy',
        detail: `${f.id} duplicates ${prior}: same rule, file, and line. The consolidation step should have merged these.`,
      });
    } else {
      seen.set(key, f.id);
    }
  }

  // --- 7. Acceptance criteria must be present ---
  checksRun.push('acceptance_criteria_present');
  if (!/##\s*I\.\s*Acceptance criteria/.test(prompt)) {
    issues.push({
      level: 'error',
      check: 'acceptance_criteria_present',
      detail: 'the prompt has no acceptance criteria section, so completion would be unfalsifiable',
    });
  } else {
    const section = prompt.split(/##\s*I\.\s*Acceptance criteria/)[1]?.split(/\n##\s/)[0] ?? '';
    const bullets = (section.match(/^\s*-\s+/gm) ?? []).length;
    if (bullets < pack.findings.length) {
      issues.push({
        level: 'warning',
        check: 'acceptance_criteria_present',
        detail: `${bullets} acceptance criteria for ${pack.findings.length} findings; some findings may have no observable completion condition`,
      });
    }
  }

  // --- 8. No destructive operation requested ---
  //
  // Scanned against the INSTRUCTION text only. Evidence excerpts quote the
  // audited repository verbatim, so a CI file that deploys to production, or a
  // migration that drops a table, legitimately appears inside a fenced block.
  // Treating a quotation as an instruction withheld an entirely valid pack
  // during development, which is worse than the risk this check guards against.
  checksRun.push('no_destructive_operations');
  const instructionText = instructionsOnly(prompt);
  for (const { re, what } of DESTRUCTIVE_PATTERNS) {
    const m = re.exec(instructionText);
    if (!m) continue;
    // The constraints section legitimately forbids these by name.
    const idx = m.index;
    const constraintsStart = instructionText.indexOf('## F. Engineering constraints');
    const constraintsEnd = instructionText.indexOf('## G. Implementation strategy');
    const insideConstraints = constraintsStart !== -1 && idx > constraintsStart && (constraintsEnd === -1 || idx < constraintsEnd);
    if (insideConstraints) continue;
    issues.push({
      level: 'error',
      check: 'no_destructive_operations',
      detail: `the prompt appears to request ${what} ("${m[0]}") outside the constraints section`,
    });
  }

  // --- 9. Scope must suit one independent session ---
  checksRun.push('scope_reasonable');
  if (pack.findings.length > 12) {
    issues.push({
      level: 'warning',
      check: 'scope_reasonable',
      detail: `${pack.findings.length} findings in one pack is more than a single review can absorb; it should have been split`,
    });
  }
  if (pack.affectedFiles.length > 40) {
    issues.push({
      level: 'warning',
      check: 'scope_reasonable',
      detail: `${pack.affectedFiles.length} files in scope is likely too broad for one reviewable change`,
    });
  }
  if (pack.findings.length === 0) {
    issues.push({
      level: 'error',
      check: 'scope_reasonable',
      detail: 'pack contains no findings',
    });
  }

  // --- 10. Uncertainty must be marked ---
  checksRun.push('uncertainty_marked');
  const uncertain = pack.findings.filter(
    (p) => p.finding.confidence === 'moderate' || p.finding.confidence === 'weak',
  );
  if (uncertain.length > 0) {
    const marksUncertainty = /SUSPECTED|UNCERTAIN|verify (?:this|the) |treat with suspicion|false positive/i.test(prompt);
    if (!marksUncertainty) {
      issues.push({
        level: 'error',
        check: 'uncertainty_marked',
        detail: `${uncertain.length} finding(s) are not confirmed but the prompt does not mark uncertainty anywhere`,
      });
    }
  }

  // --- 11. Baseline reference must be present ---
  checksRun.push('baseline_recorded');
  const hasScan = prompt.includes(ctx.scanId);
  const hasAnchor = ctx.baselineCommit ? prompt.includes(ctx.baselineCommit) : prompt.includes(ctx.contentHash.slice(0, 16));
  if (!hasScan || !hasAnchor) {
    issues.push({
      level: 'error',
      check: 'baseline_recorded',
      detail: 'the prompt does not record the scan id and the baseline commit or content hash, so the result could not be tied back to this scan',
    });
  }

  // --- 12. No overclaiming ---
  checksRun.push('no_overclaiming');
  for (const { re, what } of OVERCLAIM_PATTERNS) {
    const m = re.exec(prompt);
    if (!m) continue;
    // "Do not claim a security guarantee" is itself a legitimate instruction.
    const context = prompt.slice(Math.max(0, m.index - 60), m.index + m[0].length);
    if (/\b(?:do not|don't|never|avoid|without)\b/i.test(context)) continue;
    issues.push({
      level: 'error',
      check: 'no_overclaiming',
      detail: `the prompt makes or invites ${what} ("${m[0]}")`,
    });
  }

  return {
    packKey: pack.key,
    presentable: !issues.some((i) => i.level === 'error'),
    issues,
    checksRun,
  };
}

/**
 * Contradictory remediation within one pack.
 *
 * The realistic case is two findings on the same file where one asks for a value
 * to be removed and another asks for it to be used, or where a field is both
 * added and removed from a response.
 */
function findContradictions(findings: Finding[]): string[] {
  const out: string[] = [];
  for (let i = 0; i < findings.length; i++) {
    for (let j = i + 1; j < findings.length; j++) {
      const a = findings[i]!;
      const b = findings[j]!;
      if (!a.files.some((p) => b.files.includes(p))) continue;

      const aRemoves = /\b(?:remove|delete|drop|strip|stop (?:sending|returning)|no longer)\b/i.test(a.remediation);
      const bAdds = /\b(?:add|include|return|send|expose|populate)\b/i.test(b.remediation);
      const aAdds = /\b(?:add|include|return|send|expose|populate)\b/i.test(a.remediation);
      const bRemoves = /\b(?:remove|delete|drop|strip|stop (?:sending|returning)|no longer)\b/i.test(b.remediation);

      // Only a contradiction when they name the same subject.
      const subjects = sharedQuotedSubjects(a.remediation, b.remediation);
      if (subjects.length === 0) continue;

      if ((aRemoves && bAdds) || (aAdds && bRemoves)) {
        out.push(
          `${a.id} and ${b.id} touch ${a.files.filter((p) => b.files.includes(p)).join(', ')} and give opposing instructions about ${subjects.join(', ')}; resolve which is correct before presenting this pack`,
        );
      }
    }
  }
  return out;
}

/** Identifier-like tokens mentioned in both strings. */
function sharedQuotedSubjects(a: string, b: string): string[] {
  const tokens = (s: string) =>
    new Set([...s.matchAll(/[`'"]([A-Za-z_$][\w$.]{2,})[`'"]/g)].map((m) => m[1]!));
  const ta = tokens(a);
  const tb = tokens(b);
  return [...ta].filter((t) => tb.has(t));
}

/**
 * The prompt reduced to the parts that actually instruct the agent.
 *
 * Section C ("Identified problems") is a DESCRIPTION of the repository under
 * audit. It legitimately quotes that repository's own commands — a trace step
 * explaining that a CI workflow deploys to production has to say so, and an
 * evidence excerpt reproduces the line verbatim. Scanning it for destructive
 * operations reads a quotation as a request: during development that withheld a
 * perfectly valid Fix Pack because the CI file it was reporting on contained
 * `vercel deploy --prod`.
 *
 * So the scan covers sections A, B and D through J, with fenced blocks and
 * blockquotes dropped throughout. Those are the parts CodeLens writes as
 * instructions; everything excluded is either our own provenance caveat or the
 * audited project speaking.
 */
export function instructionsOnly(prompt: string): string {
  const blank = (m: string) => '\n'.repeat((m.match(/\n/g) ?? []).length);
  return prompt
    // Drop the findings description, keeping line count so offsets stay usable.
    .replace(/##\s*C\.\s*Identified problems[\s\S]*?(?=##\s*D\.\s*Required investigation)/, blank)
    // Fenced blocks hold quoted source.
    .replace(/```[\s\S]*?```/g, blank)
    // Markdown blockquotes hold our provenance caveat.
    .replace(/^>.*$/gm, '');
}

/** Depth-first cycle detection from one node. */
function findCycle(start: string, deps: Map<string, string[]>): string[] | undefined {
  const path: string[] = [];
  const visiting = new Set<string>();

  const walk = (node: string): string[] | undefined => {
    if (visiting.has(node)) return [...path, node];
    visiting.add(node);
    path.push(node);
    for (const next of deps.get(node) ?? []) {
      const found = walk(next);
      if (found) return found;
    }
    path.pop();
    visiting.delete(node);
    return undefined;
  };
  return walk(start);
}
