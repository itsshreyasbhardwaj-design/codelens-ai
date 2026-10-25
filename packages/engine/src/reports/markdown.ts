import type { Coverage, Feature, Finding, PrioritizedFinding, Scorecard, TechDetection } from '@codelens/core';
import type { RepoMap } from '../graph/repomap.ts';
import type { FixPack } from '../fixpacks/grouping.ts';
import type { ScanOutcome } from '../pipeline/orchestrator.ts';

/**
 * Markdown reports.
 *
 * Two audiences, two documents. The executive summary must be readable by a
 * non-technical founder without becoming vague or overstated; the technical
 * report must give an engineer everything needed to act. Both carry the same
 * limitations section, because a report that travels without its caveats is how
 * static analysis gets mistaken for proof.
 */

function severityCounts(findings: Finding[]): Record<string, number> {
  const out: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) out[f.severity] = (out[f.severity] ?? 0) + 1;
  return out;
}

function gradeLine(card: Scorecard | undefined): string {
  if (!card) return 'No score was produced because the scan did not complete.';
  if (card.overall === null) {
    return `**Overall: insufficient evidence.** Only ${(card.assessedWeight * 100).toFixed(0)}% of the assessment ` +
      `weight could be graded, which is below the ${(card.rules.minAssessedWeight * 100).toFixed(0)}% needed for an ` +
      `overall figure. Unassessed areas: ${card.unassessedDimensions.join(', ') || 'none'}.`;
  }
  return `**Overall: ${card.overall}/100 (${card.overallGrade}).** ` +
    `Graded from ${(card.assessedWeight * 100).toFixed(0)}% of the assessment weight.`;
}

function coverageSection(c: Coverage): string[] {
  const lines: string[] = [];
  lines.push('| Measure | Value |');
  lines.push('| --- | --- |');
  lines.push(`| Files indexed | ${c.filesIndexed} of ${c.filesTotal} |`);
  lines.push(`| Files parsed into an AST | ${c.filesParsed} |`);
  lines.push(`| Parse coverage of deep-support source | ${(c.parseRatio * 100).toFixed(0)}% |`);
  lines.push(`| Files excluded | ${c.filesSkipped} |`);
  lines.push(`| Deep analysis languages | ${c.languagesDeep.join(', ') || 'none'} |`);
  lines.push(`| Shallow analysis languages | ${c.languagesShallow.join(', ') || 'none'} |`);
  lines.push(`| Unsupported languages present | ${c.languagesUnsupported.join(', ') || 'none'} |`);
  lines.push(`| Analyzers run | ${c.analyzersRun.join(', ') || 'none'} |`);
  lines.push('');
  lines.push('Analysis layers actually completed:');
  lines.push('');
  lines.push(`- Deterministic static analysis: ${c.layers.static ? 'yes' : 'NO'}`);
  lines.push(`- Cross-file relationship analysis: ${c.layers.graph ? 'yes' : 'NO'}`);
  lines.push(`- AI semantic investigation: ${c.layers.ai ? 'yes' : 'no'}`);
  lines.push(`- Dynamic verification (builds/tests): ${c.layers.dynamic ? 'yes' : 'no'}`);
  if (c.analyzersSkipped.length > 0) {
    lines.push('');
    lines.push('Analyzers that did not run:');
    lines.push('');
    for (const s of c.analyzersSkipped) lines.push(`- \`${s.analyzer}\` — ${s.reason}`);
  }
  if (c.truncated) {
    lines.push('');
    lines.push(`**Coverage was truncated.** ${c.truncationNote ?? ''}`);
  }
  return lines;
}

const LIMITATIONS = `
## Limitations of this report

- This is static analysis of a snapshot. It **cannot prove** that the project is free of
  vulnerabilities or defects. A clean result means these checks found nothing, not that nothing
  is there.
- Severity describes what the issue would cost **if real**. Confidence describes how strong the
  evidence is. They are independent: read both. A critical finding marked *suspected* needs
  verification before action, not panic.
- No figure in this report is a measurement unless it says so. Where dynamic verification did
  not run, nothing here is runtime-verified: no timing, no throughput, no capacity, and no
  code-coverage percentage.
- Findings in languages marked shallow are structural and text-level only. Read those files
  yourself before acting.
- Files that could not be parsed are reported as unparsed, never as clean.
`.trim();

export function renderExecutiveSummary(outcome: ScanOutcome, projectName: string): string {
  const { findings, scorecard, coverage, map } = outcome;
  const counts = severityCounts(findings);
  const p0 = outcome.prioritized.filter((p) => p.priority === 'P0');
  const p1 = outcome.prioritized.filter((p) => p.priority === 'P1');
  const out: string[] = [];

  out.push(`# ${projectName} — Executive summary`);
  out.push('');
  out.push(`_CodeLens AI scan \`${outcome.scanId}\`${outcome.commitSha ? `, commit \`${outcome.commitSha.slice(0, 10)}\`` : ''}. Scan status: **${outcome.status}**._`);
  out.push('');

  // --- What this project is ---
  out.push('## What this project is');
  out.push('');
  if (map) {
    const languages = outcome.tech.filter((t) => t.kind === 'language').map((t) => t.name);
    const frameworks = outcome.tech.filter((t) => t.kind === 'frontend' || t.kind === 'backend').map((t) => t.name);
    const stores = outcome.tech.filter((t) => t.kind === 'database' || t.kind === 'orm').map((t) => t.name);
    out.push(
      `A ${frameworks.slice(0, 3).join(' / ') || 'software'} application written in ` +
      `${languages.slice(0, 3).join(' and ') || 'an undetected language'}, with ${map.routes.length} API endpoint(s) ` +
      `and ${map.models.length} data model(s)` +
      (stores.length ? `, storing data via ${stores.join(' and ')}` : '') + '.',
    );
    out.push('');
    out.push(`CodeLens identified ${map.features.length} distinct feature(s). Their implementation state:`);
    out.push('');
    const byStatus = new Map<string, number>();
    for (const f of map.features) byStatus.set(f.status, (byStatus.get(f.status) ?? 0) + 1);
    for (const [status, n] of [...byStatus].sort((a, b) => b[1] - a[1])) {
      out.push(`- ${n} ${status.replace(/_/g, ' ')}`);
    }
  } else {
    out.push('The project could not be mapped, so no description is available.');
  }

  // --- The headline ---
  out.push('');
  out.push('## Where it stands');
  out.push('');
  out.push(gradeLine(scorecard));
  out.push('');
  out.push(
    `${findings.length} finding(s) in total: ${counts.critical} critical, ${counts.high} high, ` +
    `${counts.medium} medium, ${counts.low} low.`,
  );
  out.push('');
  if (p0.length > 0) {
    out.push(`**${p0.length} issue(s) need attention before this ships.** These are confirmed, consequential, and in the critical path:`);
    out.push('');
    for (const p of p0) {
      out.push(`- **${p.finding.id} — ${p.finding.title}**`);
      out.push(`  ${p.finding.userImpact}`);
    }
  } else if (p1.length > 0) {
    out.push(
      `No issue met the bar for immediate release-blocking attention. ${p1.length} important correction(s) ` +
      'are recommended before this is relied on in production:',
    );
    out.push('');
    for (const p of p1.slice(0, 5)) out.push(`- **${p.finding.id} — ${p.finding.title}**`);
  } else {
    out.push('No critical or high-priority issues were found among the checks that ran. Read the coverage section below before treating that as reassurance.');
  }

  // --- Scorecard ---
  if (scorecard) {
    out.push('');
    out.push('## Assessment by area');
    out.push('');
    out.push('| Area | Score | Grade | Weight | Findings |');
    out.push('| --- | --- | --- | --- | --- |');
    for (const d of scorecard.dimensions) {
      const findingTotal = Object.values(d.findingCounts).reduce((a, b) => a + b, 0);
      out.push(
        `| ${d.dimension} | ${d.score === null ? '—' : d.score} | ${d.grade === 'insufficient_evidence' ? 'insufficient evidence' : d.grade} | ` +
        `${(d.weight * 100).toFixed(0)}% | ${findingTotal} |`,
      );
    }
    const ungraded = scorecard.dimensions.filter((d) => d.score === null);
    if (ungraded.length > 0) {
      out.push('');
      out.push('Areas that could not be graded, and why:');
      out.push('');
      for (const d of ungraded) out.push(`- **${d.dimension}**: ${d.reason}`);
    }
  }

  // --- What to do ---
  out.push('');
  out.push('## Recommended next action');
  out.push('');
  if (outcome.fixPacks.length > 0) {
    const first = outcome.fixPacks[0]!;
    out.push(
      `CodeLens grouped the findings into ${outcome.fixPacks.length} Fix Pack(s) — self-contained remediation briefs ` +
      'that can be handed to a coding agent or an engineer, in dependency order.',
    );
    out.push('');
    out.push(`Start with **Fix Pack ${first.ordinal}: ${first.title}** (${first.findings.length} finding(s), estimated effort ${first.effort}).`);
    out.push('');
    out.push('| # | Fix Pack | Findings | Priority | Effort | Prerequisites |');
    out.push('| --- | --- | --- | --- | --- | --- |');
    for (const p of outcome.fixPacks) {
      out.push(`| ${p.ordinal} | ${p.title} | ${p.findings.length} | ${p.topPriority} | ${p.effort} | ${p.dependsOn.join(', ') || 'none'} |`);
    }
  } else {
    out.push('No Fix Packs were produced, either because no actionable findings were reported or because the generated prompts did not pass validation.');
  }

  out.push('');
  out.push('## What was and was not examined');
  out.push('');
  out.push(...coverageSection(coverage));
  out.push('');
  out.push(LIMITATIONS);
  return out.join('\n');
}

export function renderTechnicalReport(outcome: ScanOutcome, projectName: string): string {
  const out: string[] = [];
  const { findings, map, coverage, scorecard } = outcome;

  out.push(`# ${projectName} — Technical diagnostic report`);
  out.push('');
  out.push(`_Scan \`${outcome.scanId}\`, status **${outcome.status}**${outcome.commitSha ? `, commit \`${outcome.commitSha}\`` : ''}._`);
  if (outcome.snapshot) out.push(`_Analysed file-set hash \`${outcome.snapshot.contentHash}\`._`);
  out.push('');

  // --- stage ledger ---
  out.push('## Scan execution');
  out.push('');
  out.push('| Stage | Status | Duration | Notes |');
  out.push('| --- | --- | --- | --- |');
  for (const s of outcome.stages) {
    const note = [s.message, ...s.warnings].filter(Boolean).join(' · ').replace(/\|/g, '\\|').slice(0, 220);
    out.push(`| ${s.name} | ${s.status} | ${s.durationMs !== undefined ? `${s.durationMs}ms` : '—'} | ${note || ''} |`);
  }

  out.push('');
  out.push('## Coverage');
  out.push('');
  out.push(...coverageSection(coverage));

  // --- technology ---
  out.push('');
  out.push('## Detected technology');
  out.push('');
  out.push('| Kind | Name | Version | Confidence | Analysis depth | Evidence |');
  out.push('| --- | --- | --- | --- | --- | --- |');
  for (const t of outcome.tech) {
    const ev = t.evidence[0];
    out.push(
      `| ${t.kind} | ${t.name} | ${t.version ?? '—'} | ${t.confidence.toFixed(2)} | ${t.analysisDepth} | ` +
      `${ev ? `\`${ev.file}${ev.startLine ? `:${ev.startLine}` : ''}\`` : '—'} |`,
    );
  }

  // --- architecture ---
  if (map) {
    out.push('');
    out.push('## Architecture');
    out.push('');
    out.push(`${map.components.length} component(s), ${map.relationships.length} relationship(s).`);
    out.push('');
    out.push('Relationships marked `inferred` come from naming or layout convention rather than from code, and should be treated as hypotheses.');
    out.push('');
    out.push('```mermaid');
    out.push(renderMermaid(map));
    out.push('```');

    out.push('');
    out.push('### API surface');
    out.push('');
    out.push('| Method | Path | Auth | Authorisation checks | Validation | Errors | Response shape | Source |');
    out.push('| --- | --- | --- | --- | --- | --- | --- | --- |');
    for (const r of map.routes) {
      out.push(
        `| ${r.method} | \`${r.path}\` | ${r.authRequired} | ${r.authorizationChecks.join('; ') || 'none detected'} | ` +
        `${r.validation} | ${r.errorHandling} | ${r.responseShape ? `\`${r.responseShape}\`` : '—'} | \`${r.file}:${r.line ?? '?'}\` |`,
      );
    }

    out.push('');
    out.push('### Data models');
    out.push('');
    out.push('| Model | Fields | Relations | Indexes | Ownership column | Source |');
    out.push('| --- | --- | --- | --- | --- | --- |');
    for (const m of map.models) {
      out.push(
        `| ${m.name} | ${m.fields.length} | ${m.relations.map((r) => r.to).join(', ') || '—'} | ` +
        `${m.indexes.join(', ') || 'none'} | ${m.ownershipField ?? '—'} | \`${m.file}\` |`,
      );
    }

    out.push('');
    out.push('### Environment variables');
    out.push('');
    out.push('| Name | Documented | Fallback | Read in |');
    out.push('| --- | --- | --- | --- |');
    for (const u of map.env.usages) {
      out.push(
        `| \`${u.name}\` | ${u.documented ? 'yes' : '**no**'} | ${u.hasFallback ? 'yes' : 'no'} | ` +
        `${u.readIn.map((r) => `\`${r.file}:${r.line}\``).join(', ')} |`,
      );
    }

    out.push('');
    out.push('### Feature inventory');
    out.push('');
    out.push(...renderFeatures(map.features));
  }

  // --- findings ---
  out.push('');
  out.push('## Findings');
  out.push('');
  if (findings.length === 0) {
    out.push('No findings were reported by the analyzers that ran. See the coverage section above for what that does and does not mean.');
  } else {
    out.push('| ID | Priority | Severity | Confidence | Status | Category | Title | Location |');
    out.push('| --- | --- | --- | --- | --- | --- | --- | --- |');
    for (const p of outcome.prioritized) {
      const f = p.finding;
      const ev = f.evidence[0];
      out.push(
        `| ${f.id} | ${p.priority} | ${f.severity} | ${f.confidence} | ${f.status.replace(/_/g, ' ')} | ${f.category} | ` +
        `${f.title.replace(/\|/g, '\\|')} | \`${ev?.file ?? f.files[0] ?? ''}${ev?.startLine ? `:${ev.startLine}` : ''}\` |`,
      );
    }
    out.push('');
    for (const p of outcome.prioritized) out.push(renderFindingDetail(p));
  }

  // --- refused findings ---
  if (outcome.rejectedFindings.length > 0) {
    out.push('');
    out.push('## Findings refused by the evidence gate');
    out.push('');
    out.push('These were produced by an analyzer but withheld because their evidence did not hold up. They are listed for transparency.');
    out.push('');
    for (const r of outcome.rejectedFindings) out.push(`- **${r.title}** — ${r.reason}`);
  }

  // --- AI layer ---
  if (outcome.aiReport) {
    out.push('');
    out.push('## AI semantic investigation');
    out.push('');
    if (outcome.aiReport.skippedReason) {
      out.push(`Not run: ${outcome.aiReport.skippedReason}`);
    } else {
      const u = outcome.aiReport.usage;
      out.push(
        `${outcome.aiReport.targetsCompleted} of ${outcome.aiReport.targetsAttempted} investigations completed using ` +
        `${u.provider}/${u.model} (${u.requests} request(s), ${u.tokensIn} tokens in, ${u.tokensOut} out).`,
      );
      if (outcome.aiReport.rejected.length > 0) {
        out.push('');
        out.push(`${outcome.aiReport.rejected.length} model finding(s) were rejected by evidence verification:`);
        out.push('');
        for (const r of outcome.aiReport.rejected) out.push(`- ${r.title ? `"${r.title}": ` : ''}${r.reason}`);
      }
    }
  }

  out.push('');
  out.push(LIMITATIONS);
  return out.join('\n');
}

function renderFeatures(features: Feature[]): string[] {
  const out: string[] = [];
  for (const f of features) {
    out.push(`#### ${f.name} — ${f.status.replace(/_/g, ' ')}`);
    out.push('');
    out.push(f.intendedFunction);
    out.push('');
    if (f.backendFiles.length) out.push(`- Backend: ${f.backendFiles.map((p) => `\`${p}\``).join(', ')}`);
    if (f.frontendFiles.length) out.push(`- Frontend: ${f.frontendFiles.map((p) => `\`${p}\``).join(', ')}`);
    if (f.databaseDeps.length) out.push(`- Data: ${f.databaseDeps.join(', ')}`);
    if (f.externalServices.length) out.push(`- External: ${f.externalServices.join(', ')}`);
    out.push(`- Authentication: ${f.authRequirement}`);
    out.push(`- Tests: ${f.tests.length ? f.tests.map((p) => `\`${p}\``).join(', ') : 'none found'}`);
    if (f.possibleDefects.length) {
      out.push('- Possible defects:');
      for (const d of f.possibleDefects) out.push(`  - ${d}`);
    }
    out.push('');
  }
  return out;
}

function renderFindingDetail(p: PrioritizedFinding): string {
  const f = p.finding;
  const out: string[] = [];
  out.push(`### ${f.id} — ${f.title}`);
  out.push('');
  out.push(
    `**${f.severity}** severity · **${f.confidence}** confidence · status **${f.status.replace(/_/g, ' ')}** · ` +
    `priority **${p.priority}** (score ${p.score}) · detected by **${f.detectionSource}** · effort **${f.effort}**`,
  );
  out.push('');
  out.push(`_Priority rationale: ${p.rationale}_`);
  out.push('');
  out.push(`**Technical explanation.** ${f.explanation}`);
  out.push('');
  out.push(`**User-facing impact.** ${f.userImpact}`);
  if (f.likelyRootCause) {
    out.push('');
    out.push(`**Likely root cause.** ${f.likelyRootCause}`);
  }
  if ((f.downstreamConsequences ?? []).length) {
    out.push('');
    out.push('**Downstream consequences.**');
    for (const c of f.downstreamConsequences ?? []) out.push(`- ${c}`);
  }
  out.push('');
  out.push('**Evidence.**');
  for (const e of f.evidence) {
    out.push(`- \`${e.file}${e.startLine ? `:${e.startLine}` : ''}\`${e.verified ? '' : ' _(unverified)_'}${e.note ? ` — ${e.note}` : ''}`);
    if (e.excerpt) out.push(`  \`\`\`\n  ${e.excerpt}\n  \`\`\``);
  }
  if (f.trace) {
    out.push('');
    out.push(`**Traced relationship** (${f.trace.kind}${f.trace.complete ? '' : ', incomplete'}):`);
    f.trace.steps.forEach((s, i) => {
      out.push(`${i + 1}. \`${s.file}${s.line ? `:${s.line}` : ''}\` — ${s.detail}`);
    });
  }
  out.push('');
  out.push(`**Remediation.** ${f.remediation}`);
  if (f.verificationSteps.length) {
    out.push('');
    out.push('**Verification.**');
    for (const v of f.verificationSteps) out.push(`- ${v}`);
  }
  if (f.references.length) {
    out.push('');
    out.push(`**References.** ${f.references.join('; ')}`);
  }
  if (f.affectedFeatures.length) {
    out.push('');
    out.push(`**Affected features.** ${f.affectedFeatures.join(', ')}`);
  }
  out.push('');
  return out.join('\n');
}

/** Mermaid diagram of the architecture, bounded so a large repository stays readable. */
export function renderMermaid(map: RepoMap, maxNodes = 40): string {
  const lines: string[] = ['graph TD'];
  const byKind = new Map<string, typeof map.components>();
  for (const c of map.components) {
    const list = byKind.get(c.kind) ?? [];
    list.push(c);
    byKind.set(c.kind, list);
  }

  // Keep the most connected components when bounding.
  const degree = new Map<string, number>();
  for (const r of map.relationships) {
    degree.set(r.from, (degree.get(r.from) ?? 0) + 1);
    degree.set(r.to, (degree.get(r.to) ?? 0) + 1);
  }
  const kept = [...map.components]
    .sort((a, b) => (degree.get(b.id) ?? 0) - (degree.get(a.id) ?? 0))
    .slice(0, maxNodes);
  const keptIds = new Set(kept.map((c) => c.id));

  const safeId = (id: string) => `n${Buffer.from(id).toString('hex').slice(0, 14)}`;
  const label = (name: string) => name.replace(/"/g, "'").slice(0, 44);

  const groups = new Map<string, typeof kept>();
  for (const c of kept) {
    const list = groups.get(c.kind) ?? [];
    list.push(c);
    groups.set(c.kind, list);
  }
  for (const [kind, list] of groups) {
    lines.push(`  subgraph ${kind.replace(/_/g, ' ')}`);
    for (const c of list) {
      const shape = c.kind === 'datastore' ? ['[(', ')]'] : c.kind === 'external_service' ? ['{{', '}}'] : ['["', '"]'];
      lines.push(`    ${safeId(c.id)}${shape[0]}${shape[0] === '["' ? '' : '"'}${label(c.name)}${shape[0] === '["' ? '' : '"'}${shape[1]}`);
    }
    lines.push('  end');
  }
  for (const r of map.relationships) {
    if (!keptIds.has(r.from) || !keptIds.has(r.to)) continue;
    const arrow = r.provenance === 'inferred' ? '-.->' : '-->';
    lines.push(`  ${safeId(r.from)} ${arrow}|${r.kind}| ${safeId(r.to)}`);
  }
  if (kept.length < map.components.length) {
    lines.push(`  note["${map.components.length - kept.length} further components omitted for readability"]`);
  }
  return lines.join('\n');
}

export function renderFixPackBundle(outcome: ScanOutcome, format: 'claude_code' | 'codex' | 'generic' = 'claude_code'): string {
  const out: string[] = [];
  out.push(`# Fix Pack bundle — scan ${outcome.scanId}`);
  out.push('');
  out.push(
    `${outcome.fixPacks.length} pack(s), in dependency order. Each is a self-contained brief: apply them one at a ` +
    'time, verify, and re-scan. Applying several at once makes the result impossible to attribute.',
  );
  out.push('');
  for (const pack of outcome.fixPacks) {
    const prompt = outcome.packPrompts.get(pack.key)?.[format];
    if (!prompt) continue;
    out.push('---');
    out.push('');
    out.push(prompt);
    out.push('');
    const validation = outcome.packValidations.get(pack.key);
    const warnings = validation?.issues.filter((i) => i.level === 'warning') ?? [];
    if (warnings.length > 0) {
      out.push('> **Validation warnings for this pack:**');
      for (const w of warnings) out.push(`> - ${w.check}: ${w.detail}`);
      out.push('');
    }
  }
  return out.join('\n');
}
