import type { Finding } from '@codelens/core';
import type { RepoMap } from '../graph/repomap.ts';
import { BudgetExceeded, ModelClient, ProviderDisabled } from './provider.ts';
import { ANALYSIS_SYSTEM_PROMPT, fenceUntrusted } from './safety.ts';
import { buildContext, renderContext, selectTargets, type InvestigationTarget } from './retrieval.ts';
import { AI_FINDING_SCHEMA, parseJsonResponse, verifyAiFindings, type RawAiFinding } from './verify.ts';

/**
 * Stage 8 — AI semantic investigation.
 *
 * Layer C adds reasoning over evidence that the deterministic layers retrieved.
 * It never replaces them, and it is bounded on every axis that could surprise an
 * operator: which questions are asked (chosen deterministically), how much
 * context each question gets, how many tokens the whole stage may spend, and
 * what is allowed through afterwards (only findings whose quoted line exists).
 */

export interface InvestigationReport {
  findings: Finding[];
  /** Set when the stage did not run; the UI shows this instead of implying it did. */
  skippedReason?: string;
  targetsAttempted: number;
  targetsCompleted: number;
  rejected: Array<{ reason: string; title?: string }>;
  warnings: string[];
  usage: { provider: string; model: string; tokensIn: number; tokensOut: number; requests: number };
}

export async function investigate(
  map: RepoMap,
  client: ModelClient,
  options: { maxTargets?: number; contextTokensPerTarget?: number } = {},
): Promise<InvestigationReport> {
  const unavailable = client.unavailableReason();
  if (unavailable) {
    return {
      findings: [],
      skippedReason: unavailable,
      targetsAttempted: 0,
      targetsCompleted: 0,
      rejected: [],
      warnings: [],
      usage: client.usage,
    };
  }

  const targets = selectTargets(map, options.maxTargets ?? 8);
  const contextBudget = options.contextTokensPerTarget ?? 6000;
  const findings: Finding[] = [];
  const rejected: InvestigationReport['rejected'] = [];
  const warnings: string[] = [];
  let completed = 0;

  for (const target of targets) {
    // Stop cleanly when the budget is nearly gone rather than failing mid-target.
    if (client.remaining < contextBudget + 1500) {
      warnings.push(
        `token budget nearly exhausted after ${completed} of ${targets.length} investigations; ` +
        `the remaining ${targets.length - completed} were not attempted`,
      );
      break;
    }

    try {
      const finding = await investigateOne(map, client, target, contextBudget);
      findings.push(...finding.accepted);
      rejected.push(...finding.rejected);
      completed++;
    } catch (e) {
      if (e instanceof BudgetExceeded) {
        warnings.push(e.message);
        break;
      }
      if (e instanceof ProviderDisabled) {
        return {
          findings, skippedReason: e.reason, targetsAttempted: targets.length,
          targetsCompleted: completed, rejected, warnings, usage: client.usage,
        };
      }
      // One failed investigation must not fail the stage.
      warnings.push(`investigation '${target.id}' failed: ${(e as Error).message}`);
    }
  }

  return {
    findings,
    targetsAttempted: targets.length,
    targetsCompleted: completed,
    rejected,
    warnings,
    usage: client.usage,
  };
}

async function investigateOne(
  map: RepoMap,
  client: ModelClient,
  target: InvestigationTarget,
  contextBudget: number,
): Promise<{ accepted: Finding[]; rejected: Array<{ reason: string; title?: string }> }> {
  const bundle = buildContext(map, target, contextBudget);
  if (bundle.excerpts.length === 0) {
    return { accepted: [], rejected: [{ reason: `no readable context could be assembled for '${target.id}'` }] };
  }

  const fenced = fenceUntrusted('source code', renderContext(bundle));

  const user =
    `## Question\n${target.question}\n\n` +
    `## Why this needs investigation\n${target.rationale}\n\n` +
    `## Code\n${fenced.text}\n\n` +
    `## Required output\n` +
    `Return JSON: { "findings": [ ... ] }. For each finding include ruleId (category-prefixed, one of ` +
    `security./reliability./performance./scalability./accessibility./quality./testing./devops./cost./ai.), ` +
    `title, severity, confidence (strong|moderate|weak), file, line, quotedLine (copied verbatim from the numbered ` +
    `source above, without the line-number prefix), explanation, userImpact, remediation.\n` +
    `Only cite files and lines present above. If the code does not support a finding, return an empty array — ` +
    `that is a valid and useful answer.`;

  const res = await client.complete({
    system: ANALYSIS_SYSTEM_PROMPT,
    user,
    schema: AI_FINDING_SCHEMA as unknown as Record<string, unknown>,
    maxOutputTokens: 2000,
    temperature: 0,
  });

  const parsed = parseJsonResponse<{ findings?: RawAiFinding[] }>(res.text);
  if (!parsed.ok) {
    return { accepted: [], rejected: [{ reason: `malformed model output for '${target.id}': ${parsed.error}` }] };
  }
  const raw = Array.isArray(parsed.value.findings) ? parsed.value.findings : [];

  const outcome = verifyAiFindings(raw, map);
  return {
    accepted: outcome.accepted,
    rejected: outcome.rejected.map((r) => ({ reason: r.reason, title: r.raw.title })),
  };
}
