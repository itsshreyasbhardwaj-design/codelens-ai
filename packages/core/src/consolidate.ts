import type { Confidence, Finding, FindingStatus } from './types.ts';

/**
 * Finding consolidation and evidence discipline.
 *
 * This is the gate that stops a plausible-sounding claim from being stored as a
 * fact. It runs over every finding regardless of which layer produced it, and
 * it can only ever downgrade confidence — never raise it.
 */

const CONFIDENCE_ORDER: Confidence[] = ['weak', 'moderate', 'strong', 'confirmed'];

function capConfidence(current: Confidence, ceiling: Confidence): Confidence {
  return CONFIDENCE_ORDER.indexOf(current) > CONFIDENCE_ORDER.indexOf(ceiling) ? ceiling : current;
}

/** Status implied by confidence, unless the analyzer already demanded runtime proof. */
export function deriveStatus(confidence: Confidence, requested?: FindingStatus): FindingStatus {
  if (requested === 'needs_runtime_verification' || requested === 'accepted_risk' ||
      requested === 'false_positive' || requested === 'resolved') {
    return requested;
  }
  switch (confidence) {
    case 'confirmed': return 'confirmed';
    case 'strong': return 'strongly_supported';
    default: return 'suspected';
  }
}

export interface DisciplineResult {
  kept: Finding[];
  /** Findings refused, with the reason. Surfaced in the scan report, not hidden. */
  rejected: Array<{ finding: Finding; reason: string }>;
  adjustments: Array<{ fingerprint: string; from: Confidence; to: Confidence; reason: string }>;
}

/**
 * Enforce the evidence rules:
 *  - a finding with no evidence at all is refused;
 *  - an AI-produced finding with no verified evidence is refused, because its
 *    only support is the model's own assertion;
 *  - no verified evidence from any source caps confidence at `moderate`;
 *  - an incomplete relationship trace caps confidence at `moderate`;
 *  - status is then re-derived from the final confidence.
 */
export function enforceEvidenceDiscipline(findings: Finding[]): DisciplineResult {
  const kept: Finding[] = [];
  const rejected: DisciplineResult['rejected'] = [];
  const adjustments: DisciplineResult['adjustments'] = [];

  for (const f of findings) {
    if (f.evidence.length === 0) {
      rejected.push({ finding: f, reason: 'no evidence attached' });
      continue;
    }
    const verified = f.evidence.filter((e) => e.verified);
    if (f.detectionSource === 'ai' && verified.length === 0) {
      rejected.push({
        finding: f,
        reason: 'AI-sourced finding whose cited evidence could not be verified against the snapshot',
      });
      continue;
    }

    let confidence = f.confidence;
    const before = confidence;
    const reasons: string[] = [];

    if (verified.length === 0) {
      confidence = capConfidence(confidence, 'moderate');
      reasons.push('no evidence excerpt could be verified against the snapshot');
    }
    if (f.trace && !f.trace.complete) {
      confidence = capConfidence(confidence, 'moderate');
      reasons.push('relationship trace is incomplete');
    }
    if (confidence !== before) {
      adjustments.push({ fingerprint: f.fingerprint, from: before, to: confidence, reason: reasons.join('; ') });
    }

    kept.push({ ...f, confidence, status: deriveStatus(confidence, f.status) });
  }
  return { kept, rejected, adjustments };
}

function mergeUnique(a: string[], b: string[]): string[] {
  return [...new Set([...a, ...b])];
}

/**
 * Collapse exact duplicates (same fingerprint) and cross-link near-duplicates
 * (same rule, overlapping files) so the explorer can group them.
 */
export function consolidateFindings(findings: Finding[]): Finding[] {
  const byFingerprint = new Map<string, Finding>();

  for (const f of findings) {
    const existing = byFingerprint.get(f.fingerprint);
    if (!existing) {
      byFingerprint.set(f.fingerprint, { ...f });
      continue;
    }
    // Same underlying problem found twice (e.g. a rule and the graph layer).
    // Keep the stronger confidence and union the supporting evidence.
    const strongerConfidence =
      CONFIDENCE_ORDER.indexOf(f.confidence) > CONFIDENCE_ORDER.indexOf(existing.confidence)
        ? f.confidence : existing.confidence;
    const seen = new Set(existing.evidence.map((e) => `${e.file}:${e.startLine}:${e.excerpt}`));
    const extraEvidence = f.evidence.filter((e) => !seen.has(`${e.file}:${e.startLine}:${e.excerpt}`));

    byFingerprint.set(f.fingerprint, {
      ...existing,
      confidence: strongerConfidence,
      status: deriveStatus(strongerConfidence, existing.status),
      // Corroboration from two independent layers is worth recording.
      detectionSource: existing.detectionSource === f.detectionSource ? existing.detectionSource : 'graph',
      files: mergeUnique(existing.files, f.files),
      evidence: [...existing.evidence, ...extraEvidence],
      references: mergeUnique(existing.references, f.references),
      relatedTests: mergeUnique(existing.relatedTests, f.relatedTests),
      verificationSteps: mergeUnique(existing.verificationSteps, f.verificationSteps),
      affectedFeatures: mergeUnique(existing.affectedFeatures, f.affectedFeatures),
      trace: existing.trace ?? f.trace,
    });
  }

  const out = [...byFingerprint.values()];

  // Cross-link siblings: same rule, overlapping files, different fingerprints.
  for (const a of out) {
    for (const b of out) {
      if (a.fingerprint === b.fingerprint) continue;
      if (a.ruleId !== b.ruleId) continue;
      if (!a.files.some((p) => b.files.includes(p))) continue;
      if (!a.relatedFindings.includes(b.fingerprint)) a.relatedFindings.push(b.fingerprint);
    }
  }
  return out;
}
