import type { EffortBand, Finding } from '@codelens/core';
import type { PrioritizedFinding } from '@codelens/core';

/**
 * Fix Pack grouping.
 *
 * The objective is NOT one prompt per finding. It is a small number of coherent,
 * dependency-aware remediation units, each small enough that a coding agent can
 * complete it in one session and a human can review the result.
 *
 * Three rules shape the grouping:
 *  1. Findings that will be fixed by touching the same code belong together.
 *  2. Unrelated changes must not share a pack, because that produces a diff
 *     nobody can review.
 *  3. A pack that must be applied after another declares that dependency, so the
 *     roadmap is executable top to bottom.
 */

/** Maximum findings in one pack before it is split. Keeps a session reviewable. */
export const MAX_FINDINGS_PER_PACK = 8;

export interface PackFamily {
  key: string;
  title: string;
  /** Ordering intent: lower runs first. */
  rank: number;
  /** Pack families this one must follow. */
  dependsOn: string[];
  objective: string;
  /** Decide whether a finding belongs to this family. */
  claims(f: Finding): boolean;
}

const isAuthz = (f: Finding) =>
  f.ruleId.startsWith('security.authz.') ||
  f.ruleId.startsWith('security.auth.') ||
  f.ruleId.startsWith('security.webhook.');

const isSecretOrConfig = (f: Finding) =>
  f.ruleId.startsWith('security.secret.') ||
  f.ruleId.startsWith('security.config.') ||
  f.ruleId.startsWith('security.storage.');

const isInjectionClass = (f: Finding) =>
  f.ruleId.startsWith('security.injection.') ||
  f.ruleId.startsWith('security.xss.') ||
  f.ruleId.startsWith('security.ssrf.') ||
  f.ruleId.startsWith('security.upload.');

/**
 * Pack families, in dependency order.
 *
 * Authorisation comes first because other work assumes the access-control model
 * is correct: adding tests or refactoring queries on top of a broken
 * authorisation boundary bakes the flaw in.
 */
export const PACK_FAMILIES: PackFamily[] = [
  {
    key: 'security-access-control',
    title: 'Critical Security and Authorization',
    rank: 1,
    dependsOn: [],
    objective:
      'Close the authentication and authorisation gaps so that every request is attributed to a caller and every ' +
      'resource access is checked against that caller, without changing intended user flows.',
    claims: isAuthz,
  },
  {
    key: 'security-injection',
    title: 'Injection, Upload and Request-Forgery Hardening',
    rank: 2,
    dependsOn: ['security-access-control'],
    objective:
      'Remove the paths by which untrusted input is executed, rendered, or used to reach internal systems: ' +
      'parameterise queries, sanitise rendered markup, constrain outbound requests, and validate uploads.',
    claims: isInjectionClass,
  },
  {
    key: 'security-secrets-config',
    title: 'Secret Handling and Security Configuration',
    rank: 3,
    dependsOn: [],
    objective:
      'Move credentials out of the repository, make their absence fail loudly rather than silently falling back, ' +
      'and set the HTTP security headers that limit the blast radius of other defects.',
    claims: isSecretOrConfig,
  },
  {
    key: 'backend-reliability',
    title: 'Backend Reliability and API Contracts',
    rank: 4,
    dependsOn: ['security-access-control'],
    objective:
      'Make the API behave correctly at its edges: honour the response contracts clients depend on, handle absent ' +
      'and failing cases, make repeat deliveries safe, and order state changes so a failure cannot leave data wrong.',
    claims: (f) =>
      f.category === 'reliability' &&
      (f.ruleId.includes('contract') || f.ruleId.includes('idempot') || f.ruleId.includes('payment') ||
        f.ruleId.includes('null') || f.ruleId.includes('error') || f.ruleId.includes('async') ||
        f.ruleId.includes('rejection') || f.ruleId.includes('env') || f.ruleId.includes('integration') ||
        f.ruleId.includes('retry') || f.ruleId.includes('race')),
  },
  {
    key: 'database-integrity',
    title: 'Database Integrity and Query Efficiency',
    rank: 5,
    dependsOn: ['security-access-control'],
    objective:
      'Correct the data layer: add the constraints and indexes the access patterns require, bound unbounded reads, ' +
      'and remove the query patterns that multiply work per row.',
    claims: (f) =>
      f.ruleId.includes('index') || f.ruleId.includes('n_plus_one') || f.ruleId.includes('nplus') ||
      f.ruleId.includes('unbounded') || f.ruleId.includes('query') || f.ruleId.includes('migration') ||
      f.ruleId.includes('pagination') || f.ruleId.includes('over_fetch') || f.ruleId.includes('overfetch'),
  },
  {
    key: 'frontend-functionality',
    title: 'Frontend Functionality, State and Accessibility',
    rank: 6,
    dependsOn: ['backend-reliability'],
    objective:
      'Make the interface do what it appears to do and be usable by everyone: wire up controls that currently do ' +
      'nothing, handle pending and failed states, and give every control an accessible name.',
    claims: (f) =>
      f.category === 'accessibility' ||
      (f.category === 'reliability' && (f.ruleId.includes('dead_ui') || f.ruleId.includes('loading') || f.ruleId.includes('ui'))),
  },
  {
    key: 'performance-scalability',
    title: 'Performance and Scalability',
    rank: 7,
    dependsOn: ['database-integrity'],
    objective:
      'Reduce avoidable work per request and remove the structural barriers to running more than one instance, ' +
      'without changing behaviour.',
    claims: (f) => f.category === 'performance' || f.category === 'scalability' || f.category === 'cost',
  },
  {
    key: 'ai-safety',
    title: 'AI Integration Safety and Cost Control',
    rank: 8,
    dependsOn: ['security-access-control'],
    objective:
      'Separate untrusted user text from privileged instructions, validate model output before it is used, and ' +
      'bound the cost and failure modes of model calls.',
    claims: (f) => f.category === 'ai_app',
  },
  {
    key: 'maintainability',
    title: 'Maintainability and Dead Code',
    rank: 9,
    dependsOn: [],
    objective:
      'Remove the duplication and dead code that make future changes risky, in particular logic that has been ' +
      'copied and has already diverged between copies.',
    claims: (f) => f.category === 'quality' || f.category === 'architecture',
  },
  {
    key: 'testing-regression',
    title: 'Testing and Regression Protection',
    rank: 10,
    // Tests are written last so they assert the corrected behaviour, not the
    // behaviour being replaced.
    dependsOn: ['security-access-control', 'backend-reliability'],
    objective:
      'Add the regression tests that would have caught the defects in this report, prioritising the authorisation, ' +
      'payment, and webhook paths where a silent regression is most costly.',
    claims: (f) => f.category === 'testing',
  },
  {
    key: 'deployment-readiness',
    title: 'Deployment and Production Readiness',
    rank: 11,
    dependsOn: ['testing-regression'],
    objective:
      'Make the deployment path safe: run the checks before shipping, stop the container running as root, give the ' +
      'orchestrator a real health signal, and keep secrets out of build artefacts.',
    claims: (f) => f.category === 'devops',
  },
];

export interface FixPack {
  key: string;
  title: string;
  family: string;
  ordinal: number;
  objective: string;
  effort: EffortBand;
  dependsOn: string[];
  findings: PrioritizedFinding[];
  affectedFiles: string[];
  affectedFeatures: string[];
  /** Highest priority among the pack's findings, for ordering and display. */
  topPriority: string;
}

/** Aggregate effort: the pack is as big as its contents, capped at 'large'. */
function aggregateEffort(findings: PrioritizedFinding[]): EffortBand {
  const weights: Record<EffortBand, number> = { trivial: 1, small: 2, medium: 4, large: 8, unknown: 3 };
  const total = findings.reduce((s, f) => s + weights[f.finding.effort], 0);
  if (total <= 3) return 'trivial';
  if (total <= 8) return 'small';
  if (total <= 20) return 'medium';
  return 'large';
}

/**
 * Split an oversized family into reviewable packs.
 *
 * Splitting follows file clusters so each resulting pack still touches a
 * coherent area, rather than cutting an arbitrary list in half.
 */
function splitByFileCluster(findings: PrioritizedFinding[]): PrioritizedFinding[][] {
  if (findings.length <= MAX_FINDINGS_PER_PACK) return [findings];

  // Group by top-level directory of the primary file, then pack greedily.
  const groups = new Map<string, PrioritizedFinding[]>();
  for (const pf of findings) {
    const file = pf.finding.files[0] ?? '';
    const parts = file.split('/');
    const cluster = parts.length > 2 ? parts.slice(0, parts.length - 1).join('/') : parts[0] ?? 'root';
    const list = groups.get(cluster) ?? [];
    list.push(pf);
    groups.set(cluster, list);
  }

  const out: PrioritizedFinding[][] = [];
  let current: PrioritizedFinding[] = [];
  // Largest clusters first so a big coherent area gets its own pack.
  for (const list of [...groups.values()].sort((a, b) => b.length - a.length)) {
    if (list.length >= MAX_FINDINGS_PER_PACK) {
      for (let i = 0; i < list.length; i += MAX_FINDINGS_PER_PACK) {
        out.push(list.slice(i, i + MAX_FINDINGS_PER_PACK));
      }
      continue;
    }
    if (current.length + list.length > MAX_FINDINGS_PER_PACK) {
      out.push(current);
      current = [];
    }
    current.push(...list);
  }
  if (current.length > 0) out.push(current);
  return out;
}

/**
 * Build Fix Packs from prioritised findings.
 *
 * Only families with supporting findings produce a pack, so the number of packs
 * follows the audit rather than a fixed template. Informational findings are
 * excluded: a pack should contain work worth a session.
 */
export function buildFixPacks(prioritized: PrioritizedFinding[]): FixPack[] {
  const eligible = prioritized.filter(
    (p) =>
      p.finding.severity !== 'info' &&
      p.finding.status !== 'false_positive' &&
      p.finding.status !== 'resolved' &&
      p.finding.status !== 'accepted_risk',
  );

  const assigned = new Set<string>();
  const byFamily = new Map<string, PrioritizedFinding[]>();

  // First match wins, so a finding appears in exactly one pack.
  for (const family of [...PACK_FAMILIES].sort((a, b) => a.rank - b.rank)) {
    const claimed = eligible.filter(
      (p) => !assigned.has(p.finding.fingerprint) && family.claims(p.finding),
    );
    if (claimed.length === 0) continue;
    for (const c of claimed) assigned.add(c.finding.fingerprint);
    byFamily.set(family.key, claimed);
  }

  // Anything unclaimed still deserves a home rather than being dropped silently.
  const leftovers = eligible.filter((p) => !assigned.has(p.finding.fingerprint));
  if (leftovers.length > 0) {
    const existing = byFamily.get('maintainability') ?? [];
    byFamily.set('maintainability', [...existing, ...leftovers]);
  }

  const packs: FixPack[] = [];
  let ordinal = 0;

  for (const family of [...PACK_FAMILIES].sort((a, b) => a.rank - b.rank)) {
    const claimed = byFamily.get(family.key);
    if (!claimed || claimed.length === 0) continue;

    const chunks = splitByFileCluster(
      [...claimed].sort((a, b) => a.priority.localeCompare(b.priority) || b.score - a.score),
    );

    chunks.forEach((chunk, i) => {
      ordinal++;
      const key = chunks.length > 1 ? `${family.key}-${i + 1}` : family.key;
      const title = chunks.length > 1 ? `${family.title} (part ${i + 1} of ${chunks.length})` : family.title;

      // A split family's later parts follow its earlier parts.
      const dependsOn = [...family.dependsOn];
      if (i > 0) dependsOn.push(`${family.key}-${i}`);

      packs.push({
        key,
        title,
        family: family.key,
        ordinal,
        objective: family.objective,
        effort: aggregateEffort(chunk),
        dependsOn,
        findings: chunk,
        affectedFiles: [...new Set(chunk.flatMap((p) => p.finding.files))].sort(),
        affectedFeatures: [...new Set(chunk.flatMap((p) => p.finding.affectedFeatures))].sort(),
        topPriority: chunk.map((p) => p.priority).sort()[0] ?? 'P3',
      });
    });
  }

  // Drop declared dependencies on families that produced no pack, so a prompt
  // never tells an agent to wait for work that does not exist.
  const existingKeys = new Set(packs.map((p) => p.key));
  for (const pack of packs) {
    pack.dependsOn = pack.dependsOn.flatMap((dep) => {
      if (existingKeys.has(dep)) return [dep];
      // A split family is satisfied by its first part.
      const firstPart = `${dep}-1`;
      return existingKeys.has(firstPart) ? [firstPart] : [];
    });
  }

  return packs;
}
