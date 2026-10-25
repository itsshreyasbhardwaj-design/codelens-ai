/**
 * Shared presentation helpers.
 *
 * Severity and confidence are formatted by different functions on purpose: the
 * UI must never merge them into one indicator, since that is exactly the
 * conflation the findings model exists to prevent.
 */

export const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'] as const;
export const CONFIDENCE_ORDER = ['confirmed', 'strong', 'moderate', 'weak'] as const;
export const PRIORITY_ORDER = ['P0', 'P1', 'P2', 'P3'] as const;

export function severityStyle(severity: string): { color: string; bg: string } {
  switch (severity) {
    case 'critical': return { color: 'var(--critical)', bg: 'var(--critical-soft)' };
    case 'high': return { color: 'var(--high)', bg: 'var(--high-soft)' };
    case 'medium': return { color: 'var(--medium)', bg: 'var(--medium-soft)' };
    case 'low': return { color: 'var(--low)', bg: 'var(--low-soft)' };
    default: return { color: 'var(--info)', bg: 'var(--info-soft)' };
  }
}

/** Plain-language gloss for a confidence level, shown next to the label. */
export const CONFIDENCE_MEANING: Record<string, string> = {
  confirmed: 'The evidence is conclusive.',
  strong: 'Evidence is clear; verify the surrounding context.',
  moderate: 'Plausible from the evidence; confirm before changing behaviour.',
  weak: 'Weak evidence; investigate before acting.',
};

export const STATUS_LABEL: Record<string, string> = {
  confirmed: 'Confirmed',
  strongly_supported: 'Strongly supported',
  suspected: 'Suspected',
  needs_runtime_verification: 'Needs runtime verification',
  resolved: 'Resolved',
  accepted_risk: 'Accepted risk',
  false_positive: 'False positive',
};

export const PRIORITY_MEANING: Record<string, string> = {
  P0: 'Immediate attention — confirmed, consequential, release-blocking.',
  P1: 'Important correction — high impact on reliability, access control, or operations.',
  P2: 'Quality improvement — performance, maintainability, accessibility, non-critical defects.',
  P3: 'Optional enhancement — lower impact refinements.',
};

export const FEATURE_STATUS_LABEL: Record<string, string> = {
  implemented_verified: 'Implemented and verified',
  implemented_unverified: 'Implemented but unverified',
  partially_implemented: 'Partially implemented',
  placeholder_or_mock: 'Placeholder or mock',
  broken_confirmed: 'Broken (confirmed)',
  unknown: 'Unknown',
};

export const DIMENSION_LABEL: Record<string, string> = {
  security: 'Security',
  reliability: 'Functional reliability',
  architecture: 'Architecture and maintainability',
  performance: 'Performance',
  scalability: 'Scalability',
  testing: 'Testing and QA',
  accessibility: 'Accessibility and UX',
  deployment: 'Deployment readiness',
};

export const CATEGORY_LABEL: Record<string, string> = {
  security: 'Security',
  reliability: 'Reliability',
  performance: 'Performance',
  scalability: 'Scalability',
  accessibility: 'Accessibility',
  quality: 'Code quality',
  testing: 'Testing',
  devops: 'DevOps',
  cost: 'Cost',
  ai_app: 'AI application',
  architecture: 'Architecture',
};

export const DETECTION_SOURCE_LABEL: Record<string, string> = {
  static: 'Deterministic static analysis',
  graph: 'Cross-file relationship analysis',
  ai: 'AI semantic investigation',
  dynamic: 'Dynamic verification',
  website: 'External website observation',
  external: 'Third-party tool',
};

export function gradeLabel(grade: string): string {
  return grade === 'insufficient_evidence' ? 'Insufficient evidence' : grade;
}

export function formatRelative(iso: string | undefined): string {
  if (!iso) return '—';
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return '—';
  const seconds = Math.round((Date.now() - then) / 1000);
  if (seconds < 60) return 'just now';
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes} minute${minutes === 1 ? '' : 's'} ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours} hour${hours === 1 ? '' : 's'} ago`;
  const days = Math.round(hours / 24);
  if (days < 30) return `${days} day${days === 1 ? '' : 's'} ago`;
  return new Date(iso).toLocaleDateString();
}

export function formatDuration(ms: number | undefined): string {
  if (ms === undefined) return '—';
  if (ms < 1000) return `${ms}ms`;
  return `${(ms / 1000).toFixed(1)}s`;
}

export function pluralize(n: number, singular: string, plural?: string): string {
  return `${n} ${n === 1 ? singular : plural ?? `${singular}s`}`;
}

export function locationOf(f: { files: string[]; evidence: Array<{ file: string; startLine?: number }> }): string {
  const ev = f.evidence[0];
  if (ev) return `${ev.file}${ev.startLine ? `:${ev.startLine}` : ''}`;
  return f.files[0] ?? '';
}
