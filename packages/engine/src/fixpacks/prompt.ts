import type { Confidence, Coverage, Finding, TechDetection } from '@codelens/core';
import type { FixPack } from './grouping.ts';

/**
 * Fix Pack prompt generation.
 *
 * The prompt is the product's actual output, so it is written to be executed by
 * a capable coding agent working in the real repository. That imposes a specific
 * discipline:
 *
 *  - Tell the agent to READ the code before changing it. Our findings are
 *    static analysis; the repository is the authority.
 *  - Label every claim with its confidence, so the agent knows which items are
 *    confirmed and which it must first verify.
 *  - Permit a better fix. A prompt that forbids deviation produces a worse
 *    result when the real code differs from what the analyser inferred.
 *  - Require honest reporting back, including what was NOT done.
 *  - Never ask for a destructive operation, and never ask for a claim of
 *    security that cannot be substantiated.
 */

export type AgentFormat = 'claude_code' | 'codex' | 'generic';

export interface PromptContext {
  projectName: string;
  scanId: string;
  /** Commit the scan read, when repository history was available. */
  baselineCommit?: string;
  branch?: string;
  /** Content hash of the analysed file set — the real reproducibility anchor. */
  contentHash: string;
  tech: TechDetection[];
  routeCount: number;
  modelCount: number;
  coverage: Coverage;
  /** Test command detected in the project manifest, if any. */
  testCommand?: string;
  typecheckCommand?: string;
  lintCommand?: string;
  /** Total packs in this scan, for "pack N of M". */
  totalPacks: number;
}

const CONFIDENCE_LABEL: Record<Confidence, string> = {
  confirmed: 'CONFIRMED — the evidence is conclusive',
  strong: 'STRONGLY SUPPORTED — evidence is clear but verify the surrounding context',
  moderate: 'SUSPECTED — plausible from the evidence; confirm before changing behaviour',
  weak: 'UNCERTAIN — weak evidence; investigate first and close as a false positive if it does not hold',
};

const ROLE_BY_FAMILY: Record<string, string> = {
  'security-access-control': 'a senior application security engineer with authority over the access-control model',
  'security-injection': 'a senior application security engineer specialising in injection and input-handling defects',
  'security-secrets-config': 'a security-minded platform engineer responsible for secret handling and HTTP security configuration',
  'backend-reliability': 'a senior backend engineer responsible for API correctness and failure behaviour',
  'database-integrity': 'a senior backend engineer with database ownership, responsible for schema constraints and query efficiency',
  'frontend-functionality': 'a senior frontend engineer responsible for interface correctness, state handling, and accessibility',
  'performance-scalability': 'a performance engineer responsible for reducing avoidable work without changing behaviour',
  'ai-safety': 'an AI systems engineer responsible for prompt boundaries, output validation, and model cost control',
  maintainability: 'a senior engineer responsible for reducing the risk of future changes',
  'testing-regression': 'a senior engineer responsible for regression protection',
  'deployment-readiness': 'a DevOps engineer responsible for a safe deployment path',
};

function heading(text: string): string {
  return `\n## ${text}\n`;
}

function stackSummary(tech: TechDetection[]): string {
  const byKind = new Map<string, string[]>();
  for (const t of tech) {
    if (t.confidence < 0.7) continue;
    const list = byKind.get(t.kind) ?? [];
    list.push(t.version ? `${t.name} ${t.version}` : t.name);
    byKind.set(t.kind, list);
  }
  const order = ['language', 'frontend', 'backend', 'database', 'orm', 'ai', 'testing', 'build', 'infrastructure', 'ci', 'package_manager'];
  const lines: string[] = [];
  for (const kind of order) {
    const list = byKind.get(kind);
    if (!list?.length) continue;
    lines.push(`- **${kind.replace(/_/g, ' ')}**: ${list.join(', ')}`);
  }
  return lines.join('\n');
}

function findingBlock(f: Finding, index: number): string {
  const lines: string[] = [];
  lines.push(`### ${index}. ${f.id} — ${f.title}`);
  lines.push('');
  lines.push(`- **Severity**: ${f.severity}`);
  lines.push(`- **Confidence**: ${CONFIDENCE_LABEL[f.confidence]}`);
  lines.push(`- **Category**: ${f.category}`);
  lines.push(`- **Files**: ${f.files.map((p) => `\`${p}\``).join(', ')}`);
  if (f.references.length) lines.push(`- **References**: ${f.references.join('; ')}`);
  lines.push('');
  lines.push(`**What is wrong.** ${f.explanation}`);
  lines.push('');
  lines.push(`**Why it matters to a user.** ${f.userImpact}`);
  if (f.likelyRootCause) {
    lines.push('');
    lines.push(`**Likely root cause.** ${f.likelyRootCause}`);
  }

  lines.push('');
  lines.push('**Evidence.**');
  for (const e of f.evidence) {
    const loc = e.startLine ? `${e.file}:${e.startLine}` : e.file;
    lines.push(`- \`${loc}\`${e.symbol ? ` (in \`${e.symbol}\`)` : ''}${e.verified ? '' : '  _[could not be re-verified against the snapshot — treat with suspicion]_'}`);
    if (e.excerpt) {
      lines.push('  ```');
      lines.push(`  ${e.excerpt}`);
      lines.push('  ```');
    }
    if (e.note) lines.push(`  ${e.note}`);
  }

  if (f.trace && f.trace.steps.length > 0) {
    lines.push('');
    lines.push(`**Traced relationship** (${f.trace.kind}${f.trace.complete ? '' : ' — INCOMPLETE: one or more steps could not be resolved statically, so verify this chain yourself'}):`);
    f.trace.steps.forEach((s, i) => {
      const loc = s.line ? `${s.file}:${s.line}` : s.file;
      lines.push(`${i + 1}. \`${loc}\`${s.symbol ? ` (\`${s.symbol}\`)` : ''} — ${s.detail}`);
    });
  }

  if (f.downstreamConsequences.length) {
    lines.push('');
    lines.push('**Consequences to keep in mind while fixing.**');
    for (const c of f.downstreamConsequences) lines.push(`- ${c}`);
  }

  lines.push('');
  lines.push(`**Recommended remediation.** ${f.remediation}`);
  lines.push('');
  lines.push(`**Estimated effort.** ${f.effort}`);
  return lines.join('\n');
}

export function generateFixPackPrompt(
  pack: FixPack,
  ctx: PromptContext,
  format: AgentFormat,
): string {
  const findings = pack.findings.map((p) => p.finding);
  const role = ROLE_BY_FAMILY[pack.family] ?? 'a senior software engineer';
  const out: string[] = [];

  // ---- Title and provenance ----
  out.push(`# Fix Pack ${pack.ordinal} of ${ctx.totalPacks} — ${pack.title}`);
  out.push('');
  out.push(
    `_Generated by CodeLens AI from scan \`${ctx.scanId}\` of **${ctx.projectName}**` +
    (ctx.baselineCommit ? ` at commit \`${ctx.baselineCommit}\`` : '') +
    (ctx.branch ? ` on branch \`${ctx.branch}\`` : '') +
    `. Analysed file-set hash \`${ctx.contentHash.slice(0, 16)}\`._`,
  );
  out.push('');
  out.push(
    '> These findings come from static analysis of a snapshot. The repository is the authority: ' +
    'where the code contradicts a finding below, trust the code, say so in your report, and treat ' +
    'that finding as a false positive.',
  );

  // ---- A. Role and objective ----
  out.push(heading('A. Role and objective'));
  out.push(`You are ${role}.`);
  out.push('');
  out.push(`**Objective.** ${pack.objective}`);
  out.push('');
  out.push(
    `This pack covers ${findings.length} finding${findings.length === 1 ? '' : 's'} ` +
    `(${findings.map((f) => f.id).join(', ')}), highest priority ${pack.topPriority}, ` +
    `estimated aggregate effort ${pack.effort}.`,
  );
  if (pack.dependsOn.length > 0) {
    out.push('');
    out.push(
      `**Prerequisite.** Apply ${pack.dependsOn.map((d) => `\`${d}\``).join(' and ')} before this pack. ` +
      'Those packs change the behaviour this one builds on, so applying this one first risks conflicting edits ' +
      'and tests that assert behaviour about to be replaced.',
    );
  }

  // ---- B. Repository context ----
  out.push(heading('B. Repository context'));
  out.push('Detected stack:');
  out.push('');
  out.push(stackSummary(ctx.tech) || '- (no technologies were detected with sufficient confidence)');
  out.push('');
  out.push(
    `The scan indexed ${ctx.coverage.filesIndexed} file(s) and parsed ${ctx.coverage.filesParsed} of them ` +
    `(${(ctx.coverage.parseRatio * 100).toFixed(0)}% of source files), identifying ${ctx.routeCount} API route(s) ` +
    `and ${ctx.modelCount} data model(s).`,
  );
  if (ctx.coverage.languagesShallow.length > 0) {
    out.push('');
    out.push(
      `Languages analysed structurally but without a full AST: ${ctx.coverage.languagesShallow.join(', ')}. ` +
      'Findings in those files are shallower, so read them yourself before acting.',
    );
  }
  if (ctx.coverage.truncated) {
    out.push('');
    out.push(`**Incomplete coverage.** ${ctx.coverage.truncationNote ?? 'Some files were not analysed.'}`);
  }
  out.push('');
  out.push('Areas this pack touches:');
  out.push('');
  for (const file of pack.affectedFiles.slice(0, 25)) out.push(`- \`${file}\``);
  if (pack.affectedFiles.length > 25) out.push(`- …and ${pack.affectedFiles.length - 25} more`);
  if (pack.affectedFeatures.length > 0) {
    out.push('');
    out.push(`Features affected: ${pack.affectedFeatures.join(', ')}.`);
  }

  // ---- C. Identified problems ----
  out.push(heading('C. Identified problems'));
  out.push('| ID | Severity | Confidence | Problem | Primary file |');
  out.push('| --- | --- | --- | --- | --- |');
  for (const f of findings) {
    const primary = f.evidence[0];
    const loc = primary?.startLine ? `${primary.file}:${primary.startLine}` : (f.files[0] ?? '');
    out.push(`| ${f.id} | ${f.severity} | ${f.confidence} | ${f.title.replace(/\|/g, '\\|')} | \`${loc}\` |`);
  }
  out.push('');
  findings.forEach((f, i) => {
    out.push(findingBlock(f, i + 1));
    out.push('');
  });

  // ---- D. Required investigation ----
  out.push(heading('D. Required investigation (do this before editing anything)'));
  out.push('1. Read every file listed in section B, in full. Do not rely on the excerpts above — they are truncated.');
  out.push('2. For each finding, confirm the described condition still holds at the cited location. Line numbers may have moved.');
  out.push(
    '3. Establish how the project already solves this class of problem elsewhere, and follow that existing pattern ' +
    'rather than introducing a new one. Look for an existing helper, middleware, or utility before writing a new one.',
  );
  if (pack.family === 'security-access-control') {
    out.push('4. Trace the complete request path for each affected route: entry point → middleware → handler → data access.');
    out.push('5. Establish how the authenticated identity is obtained and what the ownership model is for each resource.');
    out.push('6. Identify every other handler that reads or writes the same resources, since they likely share the gap.');
  } else if (pack.family === 'backend-reliability') {
    out.push('4. For each contract finding, read BOTH ends: the consumer that reads the field and the handler that builds the response.');
    out.push('5. Establish which side is correct — whether the field should be added to the response or removed from the consumer.');
  } else if (pack.family === 'database-integrity') {
    out.push('4. Read the schema and the existing migrations, and establish how migrations are generated and applied in this project.');
    out.push('5. For each index you intend to add, confirm from the query sites which columns are actually filtered and in what order.');
  } else if (pack.family === 'testing-regression') {
    out.push('4. Read the existing tests and the test configuration, and follow their structure and helpers exactly.');
    out.push('5. Establish how the suite obtains a database or fixtures, so new tests use the same mechanism.');
  } else {
    out.push('4. Identify the call sites and consumers of each thing you intend to change, so you can assess the blast radius.');
  }
  out.push('');
  out.push('Report anything you find that contradicts a finding. A finding you disprove is a useful result, not a failure.');

  // ---- E. Remediation objectives ----
  out.push(heading('E. Exact remediation objectives'));
  out.push('Each item states the behaviour that must change. How you achieve it is your judgement.');
  out.push('');
  for (const f of findings) {
    out.push(`- **${f.id}**: ${f.remediation}`);
  }

  // ---- F. Engineering constraints ----
  out.push(heading('F. Engineering constraints'));
  out.push('- Preserve all existing intended functionality. No user-visible behaviour changes beyond those required above.');
  out.push('- Preserve the existing public API shape unless a finding explicitly requires changing it; if you must change it, say so prominently in your report.');
  out.push('- Maintain type safety. Do not introduce `any`, non-null assertions, or `@ts-ignore` to make a change compile.');
  out.push('- Enforce security boundaries server-side. A client-side check is not an access control.');
  out.push('- Match the surrounding code: its existing idioms, error-handling style, naming, and comment density.');
  out.push('- Keep the change set scoped to this pack. Do not refactor unrelated code, reformat untouched files, or upgrade dependencies.');
  out.push('- Do not add a new dependency unless a finding requires it; if you do, state what it is and why nothing already present suffices.');
  out.push('- Do not delete data, drop a column, run a destructive migration, or rewrite git history. Where a destructive step is genuinely required, describe it and stop.');
  out.push('- Do not weaken or delete an existing test to make it pass.');
  out.push('- Never commit a credential. If you encounter one, leave it in place and report it — rotation is the owner\'s decision.');

  // ---- G. Implementation strategy ----
  out.push(heading('G. Implementation strategy'));
  out.push('Suggested order, adjusted to what you find in the code:');
  out.push('');
  const ordered = [...pack.findings].sort((a, b) => a.priority.localeCompare(b.priority) || b.score - a.score);
  ordered.forEach((p, i) => {
    out.push(`${i + 1}. **${p.finding.id}** (${p.priority}) — ${p.rationale}`);
  });
  out.push('');
  out.push(
    'Where two findings touch the same function, fix them in one edit rather than two passes. ' +
    'Where a shared helper would remove a whole class of these problems, prefer it over repeating the same fix — ' +
    'but say so in your report so the change is reviewed as a pattern, not just a patch.',
  );
  out.push('');
  out.push('If the real code reveals a safer or simpler approach than the recommendation above, take it and explain why.');

  // ---- H. Verification ----
  out.push(heading('H. Verification'));
  out.push('Run these and report the actual output. Do not report a check you did not run.');
  out.push('');
  if (ctx.typecheckCommand) out.push(`- Type check: \`${ctx.typecheckCommand}\``);
  if (ctx.lintCommand) out.push(`- Lint: \`${ctx.lintCommand}\``);
  if (ctx.testCommand) out.push(`- Tests: \`${ctx.testCommand}\``);
  if (!ctx.testCommand && !ctx.typecheckCommand) {
    out.push('- No test or type-check command was detected in the project manifest. Establish how this project is checked and run that; if there is genuinely no way to verify, say so explicitly.');
  }
  out.push('');
  const allVerification = [...new Set(findings.flatMap((f) => f.verificationSteps))];
  if (allVerification.length > 0) {
    out.push('Finding-specific verification:');
    out.push('');
    for (const v of allVerification) out.push(`- ${v}`);
  }
  out.push('');
  out.push('Add a regression test for each behaviour you change, so a future change cannot silently undo this work.');

  // ---- I. Acceptance criteria ----
  out.push(heading('I. Acceptance criteria'));
  out.push('This pack is complete when all of the following are observably true:');
  out.push('');
  for (const f of findings) {
    out.push(`- ${f.id}: the condition described in section C no longer holds, verified by the steps in section H.`);
  }
  out.push('- Existing functionality is unchanged: the previously passing checks still pass.');
  out.push('- Type checking and linting are clean, or any remaining item is pre-existing and identified as such.');
  out.push('- Each changed behaviour has a test that fails without the fix and passes with it.');
  out.push('- No new credential, secret, or token appears anywhere in the diff.');
  if (pack.family === 'security-access-control') {
    out.push('- Every affected route rejects an unauthenticated caller, serves the legitimate owner, and refuses a non-owner.');
    out.push('- Authorisation is enforced on the server for every path, including any path that bypasses the normal client.');
  }

  // ---- J. Final report ----
  out.push(heading('J. Final report'));
  out.push('Finish with a report containing:');
  out.push('');
  out.push('1. Every file changed, and a one-line description of the change to each.');
  out.push('2. Each finding id, and whether it is fixed, partially fixed, or not fixed — with the reason for anything not fixed.');
  out.push('3. Each finding you concluded was a false positive, and the evidence that disproved it.');
  out.push('4. Every command you ran, with its real outcome. Quote failures rather than summarising them.');
  out.push('5. Tests added or changed, and what each asserts.');
  out.push('6. Anything you deliberately did not do, and why.');
  out.push('7. Residual risk a reviewer should look at, including anything you could not verify.');
  out.push('');
  out.push(
    '**Do not claim a security guarantee.** Report what you changed and what you verified. ' +
    'Do not state that tests pass unless you ran them and they passed.',
  );

  // ---- Format-specific tail ----
  if (format === 'claude_code') {
    out.push(heading('Working notes'));
    out.push('- Read the affected files before editing. Prefer targeted edits over rewriting a file.');
    out.push('- Work through the findings in the order given in section G, verifying as you go rather than at the end.');
    out.push('- If a change grows beyond this pack\'s scope, stop and report rather than widening it.');
  } else if (format === 'codex') {
    out.push(heading('Working notes'));
    out.push('- Inspect the repository before making changes; the sections above describe a snapshot, not the current tree.');
    out.push('- Keep each logical fix a separate, reviewable change where the repository\'s workflow allows it.');
    out.push('- Run the verification commands in section H and include their real output in your report.');
  }

  return out.join('\n');
}
