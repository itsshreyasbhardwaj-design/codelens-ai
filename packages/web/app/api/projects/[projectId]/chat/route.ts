import { NextResponse } from 'next/server';
import { loadAiConfig, ModelClient } from '@codelens/engine/ai/provider.ts';
import { ANALYSIS_SYSTEM_PROMPT, fenceUntrusted } from '@codelens/engine/ai/safety.ts';
import { compareScans } from '@codelens/engine/reports/compare.ts';
import { loadScanSide } from '@codelens/engine/pipeline/persist.ts';
import {
  db, getProject, latestScan, listScans, scanComponents, scanFeatures, scanFindings,
  scanFixPacks, scanModels, scanRelationships, scanRoutes, scanTech,
  type EvidenceRow, type FindingRow, type RouteRow, type ScanRow,
} from '../../../../lib/store.ts';
import {
  FEATURE_STATUS_LABEL, formatRelative, pluralize, SEVERITY_ORDER,
} from '../../../../lib/format.ts';
// Type-only import: erased at compile time, so no client module is pulled into
// this server route. It keeps the wire shape defined in exactly one place.
import type {
  AnswerBlock, ChatAnswer, Citation, FindingRef,
} from '../../../../projects/[projectId]/chat/chat-panel.tsx';

/**
 * Repository-aware question answering.
 *
 * The AI layer is disabled by default, so this is built as a deterministic query
 * engine over the stored scan rather than as a chat wrapper around a model. Each
 * supported question is a real query against the tables the scan wrote, and
 * every answer carries the file:line evidence it was derived from. With no
 * provider configured the surface is fully functional; a configured model is
 * only ever allowed to rephrase an answer that has already been assembled.
 *
 * Prompt-injection posture: repository content — file excerpts, titles, README
 * text, code comments — is DATA, never instruction. If a model is used, the
 * system prompt is the fixed ANALYSIS_SYSTEM_PROMPT and the assembled answer is
 * wrapped with fenceUntrusted() before it is shown to the model. Nothing read
 * out of the repository can change the instructions, the facts, or the
 * citations: the citations are attached after the model has spoken, from the
 * store, and the model's output is used only as prose.
 */

export const dynamic = 'force-dynamic';

// ------------------------------------------------------------------- intents --

interface Intent {
  id: string;
  label: string;
  question: string;
  /**
   * Terms distinctive enough that one of them settles the question. "reliability"
   * belongs here; "risk" does not, because it appears in questions about every
   * category.
   */
  strong: string[];
  /** Supporting terms. Several are needed before they decide anything. */
  weak: string[];
}

/**
 * The catalogue of answerable questions. The chat page shows the same list as
 * suggestions; this array is what the matcher and the fallback reply use.
 */
const INTENTS: Intent[] = [
  {
    id: 'auth',
    label: 'How authentication works',
    question: 'How does authentication work in this project?',
    strong: ['authentication', 'authenticate', 'authenticated', 'authorisation', 'authorization',
      'auth', 'authz', 'login', 'log in', 'logged in', 'sign in', 'signin', 'jwt', 'password'],
    weak: ['session', 'sessions', 'token', 'tokens', 'permissions', 'access control', 'who can access'],
  },
  {
    id: 'architecture',
    label: 'Backend architecture',
    question: 'Explain the backend architecture.',
    strong: ['architecture', 'architectural', 'backend', 'back end', 'how is this built',
      'how is it built', 'how does this fit together'],
    weak: ['structure', 'structured', 'components', 'stack', 'layout', 'design', 'overview',
      'models', 'data model', 'built', 'shape'],
  },
  {
    id: 'untested-endpoints',
    label: 'Endpoints without tests',
    question: 'Which API endpoints lack tests?',
    strong: ['untested', 'lack tests', 'lacks tests', 'no tests', 'without tests', 'test coverage',
      'missing tests', 'not tested'],
    weak: ['endpoint', 'endpoints', 'route', 'routes', 'api', 'test', 'tests', 'tested', 'coverage'],
  },
  {
    id: 'reliability-risks',
    label: 'Reliability risks',
    question: 'What are the most significant reliability risks?',
    strong: ['reliability', 'reliable', 'data loss', 'data corruption'],
    weak: ['risk', 'risks', 'risky', 'fail', 'fails', 'failure', 'break', 'breaks', 'crash',
      'outage', 'stability', 'significant', 'robust', 'wrong'],
  },
  {
    id: 'coupling',
    label: 'Module coupling',
    question: 'Which modules are unnecessarily coupled?',
    strong: ['coupled', 'coupling', 'cohesion', 'tangled', 'spaghetti', 'entangled',
      'interdependent', 'too many dependencies'],
    weak: ['modules', 'module', 'dependencies', 'depends', 'depend', 'relationships', 'graph'],
  },
  {
    id: 'fix-first',
    label: 'What to fix first',
    question: 'What should I fix first?',
    strong: ['fix first', 'where do i start', 'where should i start', 'most important', 'urgent',
      'blocker', 'p0', 'what next', 'highest priority'],
    weak: ['first', 'priority', 'priorities', 'prioritise', 'prioritize', 'start', 'blocking',
      'next', 'fix', 'worst'],
  },
  {
    id: 'scan-diff',
    label: 'Change between the last two scans',
    question: 'What changed between the last two scans?',
    strong: ['last scan', 'previous scan', 'two scans', 'last two scans', 'scans', 'diff',
      'compare', 'compared', 'comparison', 'regressed', 'regression'],
    weak: ['changed', 'change', 'changes', 'since', 'progress', 'improved', 'worse', 'better'],
  },
  {
    id: 'incomplete-features',
    label: 'Incomplete features',
    question: 'Which features are incomplete?',
    strong: ['incomplete', 'unfinished', 'placeholder', 'not implemented', 'not finished',
      'half built', 'half finished'],
    weak: ['feature', 'features', 'mock', 'mocked', 'stub', 'stubbed', 'partially', 'partial',
      'todo', 'done'],
  },
];

const ANSWERABLE = INTENTS.map((i) => ({ id: i.id, question: i.question }));

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function hits(question: string, terms: string[]): number {
  let n = 0;
  for (const t of terms) {
    if (new RegExp(`\\b${escapeRe(t)}\\b`, 'i').test(question)) n++;
  }
  return n;
}

/**
 * Score the question against each intent and take the best.
 *
 * One distinctive term settles it; otherwise three supporting terms are needed.
 * Below that nothing is returned, and the handler says what it cannot answer
 * instead of picking the closest intent and guessing. Being conservative here is
 * deliberate: a confidently wrong answer about a codebase is worse than none.
 */
function matchIntent(question: string): Intent | undefined {
  const q = question.toLowerCase();
  let best: { intent: Intent; score: number } | undefined;
  for (const intent of INTENTS) {
    const strong = hits(q, intent.strong);
    const weak = hits(q, intent.weak);
    const score = strong * 5 + weak;
    const qualifies = strong > 0 || weak >= 3;
    if (!qualifies) continue;
    if (!best || score > best.score) best = { intent, score };
  }
  return best?.intent;
}

// ------------------------------------------------------------------ evidence --

function cite(e: EvidenceRow, label?: string): Citation {
  return {
    file: e.file,
    line: e.startLine,
    endLine: e.endLine,
    symbol: e.symbol,
    excerpt: e.excerpt,
    note: e.note,
    verified: e.verified,
    label,
  };
}

function routeCite(r: RouteRow): Citation {
  return {
    file: r.file,
    line: r.line,
    symbol: r.handlerSymbol,
    verified: true,
    label: `${r.method} ${r.path} handler`,
  };
}

/** Distinct citations, keeping the first occurrence of each file:line. */
function dedupe(citations: Citation[], limit = 12): Citation[] {
  const seen = new Set<string>();
  const out: Citation[] = [];
  for (const c of citations) {
    const key = `${c.file}:${c.line ?? ''}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(c);
    if (out.length >= limit) break;
  }
  return out;
}

function findingRef(f: FindingRow, citationLimit = 2): FindingRef {
  return {
    displayId: f.displayId,
    title: f.title,
    category: f.category,
    severity: f.severity,
    confidence: f.confidence,
    status: f.status,
    priority: f.priority,
    userImpact: f.userImpact,
    remediation: f.remediation,
    citations: f.evidence.length > 0
      ? dedupe(f.evidence.map((e) => cite(e, f.displayId)), citationLimit)
      : dedupe(f.files.map((file) => ({ file, verified: false, label: f.displayId })), citationLimit),
  };
}

function severityRank(s: string): number {
  const i = (SEVERITY_ORDER as readonly string[]).indexOf(s);
  return i === -1 ? SEVERITY_ORDER.length : i;
}

function bySeverityThenPriority(a: FindingRow, b: FindingRow): number {
  const d = severityRank(a.severity) - severityRank(b.severity);
  if (d !== 0) return d;
  return (a.priority ?? 'P9').localeCompare(b.priority ?? 'P9');
}

function countBy<T>(items: T[], key: (t: T) => string): Map<string, number> {
  const out = new Map<string, number>();
  for (const it of items) {
    const k = key(it);
    out.set(k, (out.get(k) ?? 0) + 1);
  }
  return out;
}

/**
 * What the scan did not look at. Attached to every answer, because an answer
 * drawn from a partial scan reads as complete unless it says otherwise.
 */
function coverageCaveats(scan: ScanRow): string[] {
  const out: string[] = [];
  const c = scan.coverage;
  if (!c) {
    out.push('This scan recorded no coverage summary, so what it examined cannot be stated.');
    return out;
  }
  if (c.analyzersSkipped.length > 0) {
    for (const s of c.analyzersSkipped) {
      out.push(`The '${s.analyzer}' analyzer did not run (${s.reason}), so nothing in that category was assessed.`);
    }
  }
  if (c.filesParsed < c.filesIndexed) {
    out.push(
      `${c.filesParsed} of ${c.filesIndexed} indexed files were parsed into a syntax tree ` +
      `(parse coverage ${(c.parseRatio * 100).toFixed(0)}% of deep-support source). The rest were ` +
      'read structurally or at text level only and must not be read as clean.',
    );
  }
  if (!c.layers.ai) {
    out.push('AI semantic investigation did not run for this scan, so no answer here comes from a model reading the code.');
  }
  if (!c.layers.dynamic) {
    out.push('Dynamic verification did not run: nothing here is a runtime measurement — no timing, throughput, or capacity.');
  }
  if (c.truncated) {
    out.push(`Coverage was truncated. ${c.truncationNote ?? 'The whole project was not read.'}`);
  }
  out.push('This is static analysis of one snapshot. It cannot prove that a problem is absent.');
  return out;
}

// --------------------------------------------------------- answer assembly --

interface Ctx {
  projectId: string;
  projectName: string;
  scan: ScanRow;
}

function authAnswer(ctx: Ctx): { summary: string; blocks: AnswerBlock[]; caveats: string[] } {
  const scanId = ctx.scan.id;
  const routes = scanRoutes(scanId);
  const findings = scanFindings(scanId);
  const models = scanModels(scanId);

  const required = routes.filter((r) => r.authRequired === 'required');
  const open = routes.filter((r) => r.authRequired === 'public');
  const unknown = routes.filter((r) => r.authRequired === 'unknown');

  const authFindings = findings
    .filter((f) =>
      /^security\.(auth|authz|secret)\./.test(f.ruleId)
      || /^testing\.authorization\./.test(f.ruleId)
      || /\bauth(?:entication|orisation|orization)?\b|\bsession\b|\btoken\b|\bpassword\b/i.test(f.title))
    .sort(bySeverityThenPriority);

  const blocks: AnswerBlock[] = [];

  blocks.push({
    heading: 'Every route, and what it requires',
    text:
      'This is the authentication requirement CodeLens resolved for each handler. '
      + '`public` means no authentication check was found on the path to the handler; '
      + '`unknown` means the path could not be resolved statically.',
    table: {
      caption: 'API routes with their resolved authentication requirement',
      head: ['Method', 'Path', 'Auth required', 'Authorisation checks', 'Validation', 'Source'],
      rows: routes.map((r) => [
        r.method,
        r.path,
        r.authRequired,
        r.authorizationChecks.length > 0 ? r.authorizationChecks.join('; ') : 'none detected',
        r.validation,
        `${r.file}${r.line ? `:${r.line}` : ''}`,
      ]),
    },
    citations: dedupe(routes.map(routeCite)),
  });

  if (authFindings.length > 0) {
    blocks.push({
      heading: `Findings that bear on authentication and authorisation (${authFindings.length})`,
      text:
        'Severity is what each issue would cost if it is real; confidence is how strong the evidence is. '
        + 'They are independent — read both.',
      findings: authFindings.slice(0, 10).map((f) => findingRef(f)),
    });
    if (authFindings.length > 10) {
      blocks.push({ text: `${authFindings.length - 10} further authentication-related finding(s) are on the Findings tab.` });
    }
  } else {
    blocks.push({
      heading: 'Findings that bear on authentication',
      text: 'No finding in this scan was attributed to authentication or authorisation. Read the coverage notes below before treating that as reassurance.',
    });
  }

  const ownership = models.filter((m) => m.ownershipField);
  blocks.push({
    heading: 'Files the answer is drawn from',
    bullets: [
      `${pluralize(routes.length, 'route handler')} across ${new Set(routes.map((r) => r.file)).size} file(s).`,
      ownership.length > 0
        ? `${pluralize(ownership.length, 'data model')} declare an ownership column (${ownership.map((m) => `${m.name}.${m.ownershipField}`).join(', ')}), which is what an object-level authorisation check would have to compare against.`
        : 'No data model in this scan declares an ownership column, so there is no stored field an object-level authorisation check could compare a caller against.',
    ],
    citations: dedupe([
      ...authFindings.flatMap((f) => f.evidence.map((e) => cite(e, f.displayId))),
      ...ownership.map((m) => ({ file: m.file, verified: true, label: `${m.name} model` })),
    ], 10),
  });

  const summary = required.length === 0
    ? `No route in this scan requires authentication. All ${pluralize(routes.length, 'route')} resolved to `
      + `${open.length} public and ${unknown.length} undetermined, and ${authFindings.length} finding(s) bear on authentication or authorisation.`
    : `Of ${pluralize(routes.length, 'route')}, ${required.length} ${required.length === 1 ? 'requires' : 'require'} `
      + `authentication, ${open.length} ${open.length === 1 ? 'is' : 'are'} reachable without it and ${unknown.length} `
      + `could not be resolved. ${authFindings.length} finding(s) bear on authentication or authorisation.`;

  return {
    summary,
    blocks,
    caveats: [
      'Authorisation enforced by a framework convention or by middleware that CodeLens does not model can be reported as missing. Trace the evidence before acting.',
      ...coverageCaveats(ctx.scan),
    ],
  };
}

function architectureAnswer(ctx: Ctx): { summary: string; blocks: AnswerBlock[]; caveats: string[] } {
  const scanId = ctx.scan.id;
  const components = scanComponents(scanId);
  const relationships = scanRelationships(scanId);
  const routes = scanRoutes(scanId);
  const models = scanModels(scanId);
  const features = scanFeatures(scanId);
  const tech = scanTech(scanId);

  const byKind = countBy(components, (c) => c.kind);
  const relByKind = countBy(relationships, (r) => r.kind);
  const inferred = relationships.filter((r) => r.provenance === 'inferred').length;

  const blocks: AnswerBlock[] = [];

  blocks.push({
    heading: 'Components',
    table: {
      caption: 'Architecture components by kind',
      head: ['Kind', 'Count', 'Examples'],
      rows: [...byKind.entries()].sort((a, b) => b[1] - a[1]).map(([kind, n]) => [
        kind.replace(/_/g, ' '),
        String(n),
        components.filter((c) => c.kind === kind).slice(0, 4).map((c) => c.name).join(', '),
      ]),
    },
    citations: dedupe(components
      .filter((c) => c.files.length > 0)
      .slice(0, 10)
      .map((c) => ({ file: c.files[0]!, verified: c.provenance === 'detected', label: `${c.name} (${c.kind.replace(/_/g, ' ')})` }))),
  });

  blocks.push({
    heading: 'Relationships',
    text: `${pluralize(relationships.length, 'relationship')} between components, of which ${inferred} `
      + 'came from naming or layout convention rather than from code and should be read as a hypothesis.',
    table: {
      caption: 'Component relationships by kind',
      head: ['Kind', 'Count', 'Detected', 'Inferred'],
      rows: [...relByKind.entries()].sort((a, b) => b[1] - a[1]).map(([kind, n]) => [
        kind,
        String(n),
        String(relationships.filter((r) => r.kind === kind && r.provenance === 'detected').length),
        String(relationships.filter((r) => r.kind === kind && r.provenance === 'inferred').length),
      ]),
    },
  });

  blocks.push({
    heading: 'API surface',
    table: {
      caption: 'Routes with authentication, validation and error handling',
      head: ['Method', 'Path', 'Auth', 'Validation', 'Errors', 'Source'],
      rows: routes.map((r) => [
        r.method, r.path, r.authRequired, r.validation, r.errorHandling,
        `${r.file}${r.line ? `:${r.line}` : ''}`,
      ]),
    },
    citations: dedupe(routes.map(routeCite), 10),
  });

  blocks.push({
    heading: 'Data models',
    table: {
      caption: 'Data models with field, relation and index counts',
      head: ['Model', 'Kind', 'Fields', 'Relations', 'Indexes', 'Ownership column', 'Source'],
      rows: models.map((m) => [
        m.name, m.kind.replace(/_/g, ' '), String(m.fields.length),
        m.relations.map((r) => r.to).join(', ') || '—',
        m.indexes.join(', ') || 'none',
        m.ownershipField ?? '—',
        m.file,
      ]),
    },
    citations: dedupe(models.map((m) => ({ file: m.file, verified: true, label: `${m.name} model` }))),
  });

  const platform = tech.filter((t) => t.kind !== 'language').slice(0, 8);
  blocks.push({
    heading: 'Detected technology',
    bullets: [
      `Languages with deep analysis support in this scan: ${ctx.scan.coverage?.languagesDeep.join(', ') || 'none recorded'}.`,
      `Languages analysed structurally only: ${ctx.scan.coverage?.languagesShallow.join(', ') || 'none recorded'}.`,
      platform.length > 0
        ? `Frameworks and services detected: ${platform.map((t) => `${t.name}${t.version ? ` ${t.version}` : ''} (${t.analysisDepth})`).join(', ')}.`
        : 'No framework or service was detected beyond the languages themselves.',
    ],
    citations: dedupe(tech.flatMap((t) => t.evidence.map((e) => cite(e, t.name))), 8),
  });

  const featureStatuses = countBy(features, (f) => f.status);
  const summary =
    `${pluralize(components.length, 'component')} and ${pluralize(relationships.length, 'relationship')} were mapped, `
    + `exposing ${pluralize(routes.length, 'API route')} over ${pluralize(models.length, 'data model')}, `
    + `grouped into ${pluralize(features.length, 'feature')} (`
    + [...featureStatuses.entries()].map(([s, n]) => `${n} ${(FEATURE_STATUS_LABEL[s] ?? s).toLowerCase()}`).join(', ')
    + ').';

  return {
    summary,
    blocks,
    caveats: [
      'The environment-variable map built during the scan is not persisted, so this answer says nothing about configuration the code reads at run time.',
      ...coverageCaveats(ctx.scan),
    ],
  };
}

function untestedEndpointsAnswer(ctx: Ctx): { summary: string; blocks: AnswerBlock[]; caveats: string[] } {
  const scanId = ctx.scan.id;
  const routes = scanRoutes(scanId);
  const features = scanFeatures(scanId);
  const findings = scanFindings(scanId);

  /** A route is covered when a feature that owns its handler file lists a test file. */
  const coverage = routes.map((r) => {
    const owning = features.filter((f) =>
      f.backendFiles.includes(r.file) || f.frontendFiles.includes(r.file));
    const tests = [...new Set(owning.flatMap((f) => f.tests))];
    return { route: r, owning, tests };
  });
  const uncovered = coverage.filter((c) => c.tests.length === 0);
  const covered = coverage.filter((c) => c.tests.length > 0);

  const testFindings = findings.filter((f) => f.category === 'testing').sort(bySeverityThenPriority);

  const blocks: AnswerBlock[] = [];

  blocks.push({
    heading: 'How this is decided',
    text:
      'A route counts as covered when a feature that owns its handler file lists at least one test file. '
      + 'That is a reference-level check over the stored feature inventory: CodeLens did not execute the '
      + 'test suite, so this is not a coverage measurement and a listed test may not exercise the route.',
  });

  blocks.push({
    heading: uncovered.length > 0 ? `Routes with no test file attached (${uncovered.length})` : 'Routes with no test file attached',
    table: uncovered.length > 0
      ? {
          caption: 'Routes for which no owning feature lists a test file',
          head: ['Method', 'Path', 'Auth', 'Owning feature', 'Source'],
          rows: uncovered.map((c) => [
            c.route.method, c.route.path, c.route.authRequired,
            c.owning.map((f) => f.name).join(', ') || 'not attributed to a feature',
            `${c.route.file}${c.route.line ? `:${c.route.line}` : ''}`,
          ]),
        }
      : undefined,
    text: uncovered.length === 0 ? 'Every route is owned by a feature that lists at least one test file.' : undefined,
    citations: dedupe(uncovered.map((c) => routeCite(c.route))),
  });

  if (covered.length > 0) {
    blocks.push({
      heading: `Routes with a test file attached (${covered.length})`,
      table: {
        caption: 'Routes whose owning feature lists a test file',
        head: ['Method', 'Path', 'Test files', 'Source'],
        rows: covered.map((c) => [
          c.route.method, c.route.path, c.tests.join(', '),
          `${c.route.file}${c.route.line ? `:${c.route.line}` : ''}`,
        ]),
      },
    });
  }

  if (testFindings.length > 0) {
    blocks.push({
      heading: `What the testing analyzer reported (${testFindings.length})`,
      findings: testFindings.slice(0, 6).map((f) => findingRef(f)),
    });
  }

  const summary = uncovered.length === 0
    ? `All ${pluralize(routes.length, 'route')} are owned by a feature that lists a test file.`
    : `${uncovered.length} of ${pluralize(routes.length, 'route')} have no test file attached through the feature `
      + `inventory${covered.length > 0 ? `, and ${covered.length} ${covered.length === 1 ? 'does' : 'do'}` : ''}. `
      + `The testing analyzer raised ${pluralize(testFindings.length, 'finding')}.`;

  return {
    summary,
    blocks,
    caveats: [
      'A test file being listed is not evidence that it asserts anything about the route. No test was executed during this scan.',
      ...coverageCaveats(ctx.scan),
    ],
  };
}

function reliabilityAnswer(ctx: Ctx): { summary: string; blocks: AnswerBlock[]; caveats: string[] } {
  const findings = scanFindings(ctx.scan.id);
  const reliability = findings.filter((f) => f.category === 'reliability').sort(bySeverityThenPriority);
  const bySeverity = countBy(reliability, (f) => f.severity);
  const top = reliability.filter((f) => f.severity === 'critical' || f.severity === 'high');
  const adjacent = findings
    .filter((f) => (f.category === 'performance' || f.category === 'scalability' || f.category === 'devops')
      && (f.severity === 'critical' || f.severity === 'high'))
    .sort(bySeverityThenPriority);

  const blocks: AnswerBlock[] = [];

  if (reliability.length === 0) {
    blocks.push({
      heading: 'Reliability findings',
      text: 'No finding in this scan was categorised as reliability. That is the absence of a report, not evidence of reliability.',
    });
  } else {
    blocks.push({
      heading: 'Reliability findings by severity',
      table: {
        caption: 'Count of reliability findings at each severity',
        head: ['Severity', 'Count'],
        rows: SEVERITY_ORDER.filter((s) => (bySeverity.get(s) ?? 0) > 0).map((s) => [s, String(bySeverity.get(s))]),
      },
    });
    blocks.push({
      heading: top.length > 0
        ? `The critical and high-severity ones (${top.length})`
        : 'Highest-severity reliability findings',
      text: top.length === 0
        ? 'No reliability finding is critical or high severity; the medium and low ones are on the Findings tab.'
        : 'Ordered by severity, then by the priority the engine assigned. Confidence is shown separately: a critical finding that is only suspected needs verification first.',
      findings: top.slice(0, 8).map((f) => findingRef(f)),
    });
  }

  if (adjacent.length > 0) {
    blocks.push({
      heading: `Adjacent risks in other categories (${adjacent.length})`,
      text: 'These are categorised as performance, scalability or DevOps rather than reliability, but at this severity they are failure modes too.',
      findings: adjacent.slice(0, 5).map((f) => findingRef(f)),
    });
  }

  const summary = reliability.length === 0
    ? 'This scan reported no reliability findings.'
    : `${pluralize(reliability.length, 'reliability finding')}: `
      + SEVERITY_ORDER.filter((s) => (bySeverity.get(s) ?? 0) > 0).map((s) => `${bySeverity.get(s)} ${s}`).join(', ')
      + `. ${top.length} of them are critical or high severity.`;

  return {
    summary,
    blocks,
    caveats: [
      '"Most significant" here means highest severity and priority as the engine scored them. It is not a measured failure rate: no load, fault injection or runtime observation took place.',
      ...coverageCaveats(ctx.scan),
    ],
  };
}

function couplingAnswer(ctx: Ctx): { summary: string; blocks: AnswerBlock[]; caveats: string[] } {
  const scanId = ctx.scan.id;
  const components = scanComponents(scanId);
  const relationships = scanRelationships(scanId);
  const byKey = new Map(components.map((c) => [c.key, c]));

  const degree = new Map<string, { in: number; out: number }>();
  for (const r of relationships) {
    const from = degree.get(r.from) ?? { in: 0, out: 0 };
    from.out++;
    degree.set(r.from, from);
    const to = degree.get(r.to) ?? { in: 0, out: 0 };
    to.in++;
    degree.set(r.to, to);
  }

  const ranked = [...degree.entries()]
    .map(([key, d]) => ({ key, ...d, total: d.in + d.out, component: byKey.get(key) }))
    .sort((a, b) => b.total - a.total || a.key.localeCompare(b.key));

  const blocks: AnswerBlock[] = [];

  blocks.push({
    heading: 'What this answer is, and is not',
    text:
      'CodeLens cannot judge whether a dependency is necessary — that is a design decision it has no '
      + 'access to. What it can report is relationship degree: how many edges each component sits on. '
      + 'A high degree is a place to look, not a verdict.',
  });

  if (ranked.length === 0) {
    blocks.push({
      heading: 'Relationship degree',
      text: 'No relationships were recorded between components in this scan, so no coupling can be reported.',
    });
  } else {
    blocks.push({
      heading: 'Components by relationship degree',
      table: {
        caption: 'Components ordered by the number of relationships they sit on',
        head: ['Component', 'Kind', 'Incoming', 'Outgoing', 'Total', 'Source'],
        rows: ranked.slice(0, 10).map((r) => [
          r.component?.name ?? r.key,
          (r.component?.kind ?? 'unknown').replace(/_/g, ' '),
          String(r.in), String(r.out), String(r.total),
          r.component?.files[0] ?? '—',
        ]),
      },
      citations: dedupe(ranked.slice(0, 8)
        .filter((r) => r.component?.files.length)
        .map((r) => ({
          file: r.component!.files[0]!,
          verified: r.component!.provenance === 'detected',
          label: `${r.component!.name}, degree ${r.total}`,
        }))),
    });

    const hottest = ranked[0]!;
    const edges = relationships.filter((r) => r.from === hottest.key || r.to === hottest.key);
    blocks.push({
      heading: `Every edge on ${hottest.component?.name ?? hottest.key}`,
      bullets: edges.map((e) => {
        const fromName = byKey.get(e.from)?.name ?? e.from;
        const toName = byKey.get(e.to)?.name ?? e.to;
        return `${fromName} ${e.kind} ${toName} — ${e.provenance === 'inferred' ? 'inferred from convention, treat as a hypothesis' : 'detected in code'}`;
      }),
      citations: dedupe(edges.flatMap((e) => e.evidence.map((ev) => cite(ev, `${byKey.get(e.from)?.name ?? e.from} → ${byKey.get(e.to)?.name ?? e.to}`))), 10),
    });

    const inferredEdges = relationships.filter((r) => r.provenance === 'inferred');
    if (inferredEdges.length > 0) {
      blocks.push({
        text: `${inferredEdges.length} of ${relationships.length} edges are inferred rather than detected, so part of this ranking rests on convention rather than on code.`,
      });
    }
  }

  const summary = ranked.length === 0
    ? 'No component relationships were recorded, so coupling cannot be assessed from this scan.'
    : `${pluralize(relationships.length, 'relationship')} across ${pluralize(components.length, 'component')}. `
      + `The most connected is ${ranked[0]!.component?.name ?? ranked[0]!.key} with ${ranked[0]!.total} edge(s) `
      + `(${ranked[0]!.in} in, ${ranked[0]!.out} out).`;

  return {
    summary,
    blocks,
    caveats: [
      'Dynamic imports, reflection and string-built references are not resolvable statically, so some real dependencies are missing from this graph entirely.',
      ...coverageCaveats(ctx.scan),
    ],
  };
}

function fixFirstAnswer(ctx: Ctx): { summary: string; blocks: AnswerBlock[]; caveats: string[] } {
  const scanId = ctx.scan.id;
  const findings = scanFindings(scanId);
  const packs = scanFixPacks(scanId);
  const p0 = findings.filter((f) => f.priority === 'P0');
  const p1 = findings.filter((f) => f.priority === 'P1');
  const first = packs[0];

  const blocks: AnswerBlock[] = [];

  if (p0.length > 0) {
    blocks.push({
      heading: `P0 — immediate attention (${p0.length})`,
      text: 'Confirmed, consequential and on the critical path. Severity and confidence are shown separately so an expensive-but-weakly-evidenced issue is not mistaken for a certainty.',
      findings: p0.slice(0, 8).map((f) => findingRef(f)),
    });
  } else {
    blocks.push({
      heading: 'P0 — immediate attention',
      text: 'No finding met the bar for immediate, release-blocking attention.',
    });
  }

  if (p1.length > 0) {
    blocks.push({
      heading: `P1 — important corrections (${p1.length})`,
      findings: p1.slice(0, 5).map((f) => findingRef(f)),
    });
    if (p1.length > 5) blocks.push({ text: `${p1.length - 5} further P1 finding(s) are on the Findings tab.` });
  }

  if (first) {
    const issues = first.validation.issues.filter((i) => i.level === 'error' || i.level === 'warning');
    blocks.push({
      heading: `Start with Fix Pack ${first.ordinal}: ${first.title}`,
      text: first.objective,
      bullets: [
        `Estimated effort: ${first.effort}.`,
        `Covers ${pluralize(first.findingIds.length, 'finding')}: ${first.findingIds.join(', ')}.`,
        first.dependsOn.length > 0 ? `Prerequisites: ${first.dependsOn.join(', ')}.` : 'No prerequisites.',
        first.validation.presentable
          ? `Passed prompt validation (${first.validation.checksRun.length} check(s) run).`
          : 'Did not pass prompt validation and is withheld from the bundle until it does.',
        ...issues.map((i) => `Validation ${i.level}: ${i.check} — ${i.detail}`),
      ],
    });
    blocks.push({
      heading: 'The full order',
      table: {
        caption: 'Fix Packs in dependency order',
        head: ['#', 'Fix Pack', 'Findings', 'Effort', 'Prerequisites'],
        rows: packs.map((p) => [
          String(p.ordinal), p.title, String(p.findingIds.length), p.effort,
          p.dependsOn.join(', ') || 'none',
        ]),
      },
    });
  } else {
    blocks.push({
      heading: 'Fix Packs',
      text: 'No Fix Pack was produced for this scan, either because no finding was actionable or because the generated prompts did not pass validation.',
    });
  }

  const summary = p0.length > 0
    ? `Fix the ${pluralize(p0.length, 'P0 finding')} first, then the ${pluralize(p1.length, 'P1 finding')}. `
      + (first ? `The engine's own order starts with Fix Pack ${first.ordinal}, "${first.title}".` : '')
    : p1.length > 0
      ? `Nothing is P0. Start with the ${pluralize(p1.length, 'P1 finding')}.`
        + (first ? ` The engine's order starts with Fix Pack ${first.ordinal}, "${first.title}".` : '')
      : 'No finding in this scan was prioritised above P2.';

  return {
    summary,
    blocks,
    caveats: [
      'Fix Packs are ordered by dependency, so applying them out of order can make a later pack inapplicable. Apply one, verify, then re-scan.',
      ...coverageCaveats(ctx.scan),
    ],
  };
}

function scanDiffAnswer(ctx: Ctx): { summary: string; blocks: AnswerBlock[]; caveats: string[] } {
  const scans = listScans(ctx.projectId).filter((s) => s.status === 'completed' || s.status === 'partial');
  if (scans.length < 2) {
    return {
      summary:
        `This project has ${pluralize(scans.length, 'comparable scan')}, so there is nothing to compare. `
        + 'A comparison needs two scans of the same project.',
      blocks: [{
        heading: 'What exists',
        bullets: scans.map((s) => `${s.id} — ${s.status}, ${formatRelative(s.queuedAt)}, ${pluralize(s.findings, 'finding')}.`),
      }],
      caveats: ['Scan the project again to produce a comparison. Comparing a scan with itself would report no change, which says nothing.'],
    };
  }

  const head = scans[0]!;
  const base = scans[1]!;
  const headSide = loadScanSide(db(), head.id);
  const baseSide = loadScanSide(db(), base.id);
  if (!headSide || !baseSide) {
    return {
      summary: 'Two scans exist, but one of them could not be loaded for comparison.',
      blocks: [],
      caveats: ['A scan with no persisted coverage cannot be compared, because absences could not be judged against coverage.'],
    };
  }

  const cmp = compareScans(baseSide, headSide);
  const d = cmp.coverageDelta;

  const blocks: AnswerBlock[] = [];

  blocks.push({
    heading: 'Counts',
    table: {
      caption: 'Finding changes between the two most recent scans',
      head: ['Change', 'Count', 'Meaning'],
      rows: [
        ['Verified resolved', String(cmp.resolved.length), 'Gone, and the newer scan covered the same ground'],
        ['Unverified absence', String(cmp.unverifiedAbsences.length), 'No longer reported, NOT confirmed fixed'],
        ['Still present', String(cmp.persistent.length), 'Reported by both scans'],
        ['Newly reported', String(cmp.introduced.length), 'Only in the newer scan'],
        ['Regressed', String(cmp.regressed.length), 'Resolved earlier, present again'],
        ['Severity changed', String(cmp.severityChanges.length), 'Same finding, different severity'],
      ],
    },
  });

  if (cmp.unverifiedAbsences.length > 0) {
    blocks.push({
      heading: `Unverified absences (${cmp.unverifiedAbsences.length}) — do not count these as progress`,
      text: 'These findings are no longer reported, but the newer scan did not cover the same ground, so their absence cannot be attributed to a fix.',
      bullets: cmp.unverifiedAbsences.slice(0, 10).map((c) => `${c.title} (${c.severity}) — ${c.caveat ?? 'coverage changed'}`),
    });
  }

  blocks.push({
    heading: `Verified resolved (${cmp.resolved.length})`,
    text: cmp.resolved.length === 0
      ? 'No finding could be verified as resolved between these two scans.'
      : 'Absent from the newer scan, and the newer scan looked at the same ground.',
    bullets: cmp.resolved.slice(0, 10).map((c) => `${c.title} (${c.severity})`),
  });

  if (cmp.introduced.length > 0) {
    blocks.push({
      heading: `Newly reported (${cmp.introduced.length})`,
      bullets: cmp.introduced.slice(0, 10).map((c) => `${c.title} (${c.severity})`),
    });
  }

  blocks.push({
    heading: 'Coverage delta',
    text: 'Coverage decides whether an absence counts as a fix, so it is reported alongside the counts.',
    table: {
      caption: 'Change in coverage between the two scans',
      head: ['Measure', 'Change'],
      rows: [
        ['Files indexed', d.filesIndexed >= 0 ? `+${d.filesIndexed}` : String(d.filesIndexed)],
        ['Files parsed', d.filesParsed >= 0 ? `+${d.filesParsed}` : String(d.filesParsed)],
        ['Parse ratio', `${d.parseRatio >= 0 ? '+' : ''}${(d.parseRatio * 100).toFixed(0)} pp`],
        ['Analyzers added', d.analyzersAdded.join(', ') || 'none'],
        ['Analyzers removed', d.analyzersRemoved.join(', ') || 'none'],
        ['Layers gained', d.layersGained.join(', ') || 'none'],
        ['Layers lost', d.layersLost.join(', ') || 'none'],
      ],
    },
  });

  if (cmp.scoreDelta) {
    blocks.push({
      heading: 'Overall score',
      text: cmp.scoreDelta.change === null
        ? (cmp.scoreDelta.note ?? 'No score change can be stated.')
        : `${cmp.scoreDelta.overallBefore} to ${cmp.scoreDelta.overallAfter} (${cmp.scoreDelta.change >= 0 ? '+' : ''}${cmp.scoreDelta.change}).`,
    });
  }

  return {
    summary: `Comparing ${base.id} (${formatRelative(base.queuedAt)}) with ${head.id} (${formatRelative(head.queuedAt)}). ${cmp.summary}`,
    blocks,
    caveats: [
      'A falling finding count is only progress when coverage held. The unverified absences above are listed separately for exactly that reason.',
      ...coverageCaveats(ctx.scan),
    ],
  };
}

function incompleteFeaturesAnswer(ctx: Ctx): { summary: string; blocks: AnswerBlock[]; caveats: string[] } {
  const features = scanFeatures(ctx.scan.id);
  const byStatus = countBy(features, (f) => f.status);
  const incomplete = features.filter((f) =>
    f.status === 'partially_implemented' || f.status === 'placeholder_or_mock'
    || f.status === 'broken_confirmed' || f.status === 'unknown');
  const unverified = features.filter((f) => f.status === 'implemented_unverified');

  const blocks: AnswerBlock[] = [];

  blocks.push({
    heading: 'Every feature by status',
    table: {
      caption: 'Feature inventory grouped by implementation status',
      head: ['Status', 'Count', 'Features'],
      rows: [...byStatus.entries()].sort((a, b) => b[1] - a[1]).map(([status, n]) => [
        FEATURE_STATUS_LABEL[status] ?? status,
        String(n),
        features.filter((f) => f.status === status).map((f) => f.name).join(', '),
      ]),
    },
  });

  if (incomplete.length > 0) {
    blocks.push({
      heading: `Features that are not fully implemented (${incomplete.length})`,
      bullets: incomplete.map((f) =>
        `${f.name} — ${FEATURE_STATUS_LABEL[f.status] ?? f.status}. ${f.intendedFunction}`
        + (f.possibleDefects.length > 0 ? ` Possible defects: ${f.possibleDefects.join('; ')}.` : '')),
      citations: dedupe(incomplete.flatMap((f) => [
        ...f.evidence.map((e) => cite(e, f.name)),
        ...f.backendFiles.map((file) => ({ file, verified: true, label: `${f.name} backend` })),
      ]), 12),
    });
  } else {
    blocks.push({
      heading: 'Features that are not fully implemented',
      text: 'No feature was recorded as partially implemented, placeholder, broken or unknown.',
    });
  }

  if (unverified.length > 0) {
    blocks.push({
      heading: `Implemented but unverified (${unverified.length})`,
      text:
        'These have an implementation but nothing proves it works: no test was found that exercises them, '
        + 'and dynamic verification did not run. "Unverified" is not the same as "incomplete", and it is '
        + 'not the same as "working" either.',
      bullets: unverified.map((f) =>
        `${f.name} — authentication ${f.authRequirement}; `
        + `${f.tests.length > 0 ? `tests: ${f.tests.join(', ')}` : 'no test file found'}`
        + `${f.possibleDefects.length > 0 ? `; possible defects: ${f.possibleDefects.join('; ')}` : ''}`),
      citations: dedupe(unverified.flatMap((f) => f.evidence.map((e) => cite(e, f.name))), 12),
    });
  }

  const summary = `${pluralize(features.length, 'feature')} were inventoried: `
    + [...byStatus.entries()].map(([s, n]) => `${n} ${(FEATURE_STATUS_LABEL[s] ?? s).toLowerCase()}`).join(', ')
    + `. ${incomplete.length} are recorded as not fully implemented.`;

  return {
    summary,
    blocks,
    caveats: [
      'Feature status is inferred from structure: which files exist, what they reference, and whether a test file was found. It is not a judgement on whether the feature behaves correctly.',
      ...coverageCaveats(ctx.scan),
    ],
  };
}

const BUILDERS: Record<string, (ctx: Ctx) => { summary: string; blocks: AnswerBlock[]; caveats: string[] }> = {
  auth: authAnswer,
  architecture: architectureAnswer,
  'untested-endpoints': untestedEndpointsAnswer,
  'reliability-risks': reliabilityAnswer,
  coupling: couplingAnswer,
  'fix-first': fixFirstAnswer,
  'scan-diff': scanDiffAnswer,
  'incomplete-features': incompleteFeaturesAnswer,
};

// ----------------------------------------------------------- model phrasing --

/** Flatten an assembled answer to plain text for the model to rephrase. */
function answerAsText(answer: ChatAnswer): string {
  const lines: string[] = [answer.summary];
  for (const b of answer.blocks) {
    if (b.heading) lines.push(`## ${b.heading}`);
    if (b.text) lines.push(b.text);
    for (const bullet of b.bullets ?? []) lines.push(`- ${bullet}`);
    if (b.table) {
      lines.push(b.table.head.join(' | '));
      for (const row of b.table.rows) lines.push(row.join(' | '));
    }
    for (const f of b.findings ?? []) {
      lines.push(`- ${f.displayId} ${f.title} [severity ${f.severity}, confidence ${f.confidence}, status ${f.status}]`);
      for (const c of f.citations) lines.push(`  evidence: ${c.file}${c.line ? `:${c.line}` : ''}`);
    }
    for (const c of b.citations ?? []) lines.push(`  evidence: ${c.file}${c.line ? `:${c.line}` : ''}`);
  }
  return lines.join('\n');
}

/**
 * Ask a configured model to phrase the assembled answer more fluently.
 *
 * The model is deliberately kept out of the facts. It receives the already
 * assembled answer as fenced untrusted data under the fixed analysis system
 * prompt, and only its prose is used: the blocks, findings and citations shown
 * to the user are the ones this route computed from the store. A model that is
 * successfully manipulated by repository text can therefore change the wording
 * and nothing else. Any failure leaves the deterministic answer in place.
 */
async function phrase(answer: ChatAnswer, question: string): Promise<{ summary?: string; note?: string }> {
  const client = new ModelClient(loadAiConfig());
  const unavailable = client.unavailableReason();
  if (unavailable) return {};

  const fenced = fenceUntrusted(
    'an answer assembled from a repository scan, together with the question that was asked',
    `QUESTION: ${question}\n\nASSEMBLED ANSWER:\n${answerAsText(answer)}`,
  );

  try {
    const res = await client.complete({
      system: ANALYSIS_SYSTEM_PROMPT,
      user:
        'Rewrite the summary of the assembled answer below as two or three plain sentences of British '
        + 'English technical prose. Use only facts that appear in the data region. Do not add findings, '
        + 'numbers, file paths or claims that are not there. Do not remove a stated caveat.\n\n'
        + `${fenced.text}\n\n`
        + 'Respond only with JSON of the form {"summary": "..."}.',
      schema: {
        type: 'object',
        properties: { summary: { type: 'string' } },
        required: ['summary'],
      },
      maxOutputTokens: 400,
    });
    const parsed = JSON.parse(res.text) as { summary?: unknown };
    if (typeof parsed.summary === 'string' && parsed.summary.trim().length > 0) {
      return { summary: parsed.summary.trim() };
    }
    return { note: 'A model is configured but returned no usable wording, so the composed answer is shown unchanged.' };
  } catch (e) {
    return {
      note: `A model is configured but could not be used for wording (${e instanceof Error ? e.message : String(e)}). `
        + 'The answer below is the composed one and is unaffected.',
    };
  }
}

// ----------------------------------------------------------------- handler --

export async function POST(request: Request, { params }: { params: Promise<{ projectId: string }> }) {
  const { projectId } = await params;

  let question = '';
  try {
    const body = (await request.json()) as { question?: unknown };
    if (typeof body.question === 'string') question = body.question.trim();
  } catch {
    return NextResponse.json({ error: 'the request body must be JSON of the form {"question": "..."}' }, { status: 400 });
  }
  if (question.length === 0) {
    return NextResponse.json({ error: 'a question is required' }, { status: 400 });
  }
  if (question.length > 600) {
    return NextResponse.json({ error: 'the question is too long; 600 characters is the limit' }, { status: 400 });
  }

  const project = getProject(projectId);
  if (!project) {
    return NextResponse.json({ error: `no project '${projectId}' in this organisation` }, { status: 404 });
  }
  const scan = latestScan(projectId);
  if (!scan) {
    return NextResponse.json({ error: `project '${projectId}' has no scan to answer from` }, { status: 409 });
  }

  const scanLabel = `scan ${scan.id.slice(0, 12)}… (${formatRelative(scan.queuedAt)})`;
  const intent = matchIntent(question);

  if (!intent) {
    const unmatched: ChatAnswer = {
      question,
      intent: 'none',
      intentLabel: 'No matching query',
      matched: false,
      scanId: scan.id,
      scanLabel,
      summary:
        'That question does not match any query this surface can answer from the stored scan, and it will '
        + 'not be guessed at. These are the questions it can answer:',
      blocks: [],
      caveats: [
        'Answers are assembled from the stored scan only. Where the scan holds no evidence, there is no answer to give.',
      ],
      composedBy: 'stored-evidence',
      answerable: ANSWERABLE,
    };
    return NextResponse.json(unmatched);
  }

  const built = BUILDERS[intent.id]!({ projectId, projectName: project.name, scan });

  const answer: ChatAnswer = {
    question,
    intent: intent.id,
    intentLabel: intent.label,
    matched: true,
    scanId: scan.id,
    scanLabel,
    summary: built.summary,
    blocks: built.blocks,
    caveats: built.caveats,
    composedBy: 'stored-evidence',
    answerable: ANSWERABLE,
  };

  const phrased = await phrase(answer, question);
  if (phrased.summary) {
    answer.summary = phrased.summary;
    answer.composedBy = 'model-phrased';
  }
  if (phrased.note) answer.modelNote = phrased.note;

  return NextResponse.json(answer);
}
