import type {
  ApiEndpoint, Confidence, Evidence, Finding, RelationshipTrace, Severity,
} from '@codelens/core';
import type { SourceFile } from '../ingest/normalize.ts';
import type { ParsedModule } from '../parse/types.ts';
import type { RepoMap } from '../graph/repomap.ts';
import type { Analyzer, AnalyzerContext } from './types.ts';
import { codeText } from './text.ts';

/**
 * Testing and QA audit — the TEST-GAP MATRIX.
 *
 * This analyzer never executes a test, so it has no coverage measurement and
 * must not imply one. Every quantity it reports is a count of things it could
 * read: how many test files exist, how many routes are named by a test, how
 * many protected routes have no negative-path test. A percentage would read as
 * a coverage figure, so none is produced. See docs/LIMITATIONS.md.
 *
 * Confidence discipline here:
 *   - a single-file observation (no failure assertion anywhere in the test
 *     corpus) is `strong` only because the corpus is small and fully read;
 *     if any test file could not be parsed, or if tests build paths
 *     dynamically, confidence drops to `moderate` and the note says why;
 *   - a correlation across files (route declared here, no test anywhere names
 *     it; CI deploys here, test script declared there) is `graph` with a trace;
 *   - nothing in this category is ever `confirmed`: a test harness can exercise
 *     a route through a value this analyzer cannot resolve statically, and
 *     claiming certainty about the absence of a test would be dishonest.
 *
 * Comments are stripped from every test file before matching. Without that, the
 * comment "no coverage of auth, payment, or the webhook handler" makes a test
 * file look as though it covers exactly those things.
 */

const REF = {
  busl: 'OWASP WSTG: Business Logic Testing (WSTG-BUSL)',
  errh: 'OWASP WSTG: Testing for Error Handling (WSTG-ERRH)',
  athz: 'OWASP WSTG: Testing for Authorization (WSTG-ATHZ)',
  asvsBuild: 'OWASP ASVS v4.0 §14.1 Build and Deploy',
  asvsArch: 'OWASP ASVS v4.0 §1 Architecture, Design and Threat Modelling',
  pyramid: 'Martin Fowler, bliki: TestPyramid (test level selection)',
  dora: 'DORA / Accelerate: continuous testing as a delivery capability',
} as const;

// ----------------------------------------------------------- flow classes ---

/**
 * Flow classes that make an untested route expensive rather than merely
 * untidy. These are framework-agnostic path and method shapes, not names taken
 * from any particular project.
 */
const FLOW_CLASSES: Array<{ label: string; tier: 1 | 2; re?: RegExp; methods?: string[] }> = [
  {
    label: 'authentication',
    tier: 1,
    re: /\b(login|signin|sign-in|logout|signout|sign-out|signup|sign-up|register|auth|oauth|sso|saml|session|sessions|token|tokens|refresh|credential|credentials|password|passwd|reset|forgot|verify|confirm|otp|mfa|2fa|magic)\b/i,
  },
  {
    label: 'authorisation',
    tier: 1,
    re: /\b(admin|administrator|internal|staff|moderator|superuser|root|impersonate|role|roles|permission|permissions|acl|policy|tenant|tenants|org|orgs|organisation|organization|member|members|invite|invites|grant|revoke)\b/i,
  },
  {
    label: 'payment',
    tier: 1,
    re: /\b(pay|pays|payment|payments|checkout|charge|charges|capture|billing|bill|invoice|invoices|subscription|subscriptions|plan|plans|refund|refunds|payout|payouts|wallet|transfer|transfers|transaction|transactions|order|orders|cart|carts|coupon|discount|price|pricing)\b/i,
  },
  { label: 'webhook', tier: 1, re: /webhook|\bhook\b|\bhooks\b|\bcallback\b|\bnotify\b|\bipn\b/i },
  {
    label: 'destructive',
    tier: 2,
    re: /\b(delete|destroy|remove|purge|wipe|drop|cancel|close|deactivate|disable|archive)\b/i,
    methods: ['DELETE'],
  },
  {
    label: 'data export',
    tier: 2,
    re: /\b(export|exports|download|downloads|report|reports|backup|backups|dump|csv|xlsx|pdf|bulk)\b/i,
  },
  {
    label: 'file upload',
    tier: 2,
    re: /\b(upload|uploads|attachment|attachments|media|file|files|image|images|avatar)\b/i,
  },
];

function flowsForRoute(r: ApiEndpoint): string[] {
  const out: string[] = [];
  for (const f of FLOW_CLASSES) {
    const byPath = f.re ? f.re.test(r.path) : false;
    const byMethod = f.methods ? f.methods.includes(r.method) : false;
    if (byPath || byMethod) out.push(f.label);
  }
  // A route the map reports as requiring authentication is an authorisation
  // flow regardless of what its path is called.
  if (r.authRequired === 'required' && !out.includes('authorisation')) out.push('authorisation');
  return out;
}

function tierOfRoute(r: ApiEndpoint): 1 | 2 | 3 {
  const flows = flowsForRoute(r);
  for (const f of FLOW_CLASSES) {
    if (f.tier === 1 && flows.includes(f.label)) return 1;
  }
  if (flows.length > 0) return 2;
  return ['POST', 'PUT', 'PATCH', 'DELETE'].includes(r.method) ? 2 : 3;
}

// ------------------------------------------------------------ test corpus ---

type TestLevel = 'unit' | 'integration' | 'end-to-end';

interface TestView {
  file: SourceFile;
  module?: ParsedModule;
  /** Comment-free, lower-cased text. The only haystack used for matching. */
  haystack: string;
  /** Repository paths this test file imports, when the specifier resolved. */
  importedPaths: Set<string>;
  /** A real line to cite as evidence. */
  anchorLine: number;
  level: TestLevel;
  parsed: boolean;
}

const TEST_DECL_RE =
  /(?:^|[^\w.])(?:test|it|describe|suite|context|scenario|bench)\s*[.(]|^\s*(?:def\s+test_|func\s+Test|public\s+void\s+test|\[Fact\]|\[Test\])/i;

const E2E_RE =
  /\b(playwright|puppeteer|cypress|selenium|webdriver|testcafe|nightwatch|appium|detox|browser\.|page\.goto|page\.click|chromedriver|capybara|visit\(|cy\.)\b/i;

const HTTP_HARNESS_RE =
  /\b(supertest|request\(app\)|testclient|httpx|aiohttp|msw|nock|fetch\(|axios\.|got\(|undici|rest-?assured|webtestclient|mockmvc|rack::test|hurl|newman)\b/i;

function buildTestViews(map: RepoMap): TestView[] {
  const views: TestView[] = [];
  for (const file of map.byRole('test')) {
    if (file.binary || file.text === null) continue;
    const module = map.modules.get(file.path);
    const stripped = codeText(file.text, file.language);
    const haystack = stripped.toLowerCase();

    const importedPaths = new Set<string>();
    for (const imp of module?.imports ?? []) {
      if (imp.resolvedPath) importedPaths.add(imp.resolvedPath);
    }

    // Cite the first test declaration rather than line 1, so the evidence shows
    // a reader what the test actually asserts.
    const lines = stripped.split('\n');
    let anchorLine = 1;
    for (let i = 0; i < lines.length; i++) {
      if (TEST_DECL_RE.test(lines[i]!)) { anchorLine = i + 1; break; }
      if (anchorLine === 1 && lines[i]!.trim().length > 0) anchorLine = i + 1;
    }

    const isE2e = E2E_RE.test(haystack) || /(^|\/)(e2e|cypress|playwright)\//.test(file.path) || /\.cy\.[cm]?[jt]sx?$/.test(file.path);
    const referencesHttp = HTTP_HARNESS_RE.test(haystack)
      || /(^|\/)(integration|it|api)\//.test(file.path)
      || /\.(?:int|integration)\.test\./.test(file.path)
      || [...importedPaths].some((p) => map.filesByPath.get(p)?.role === 'route');

    views.push({
      file,
      module,
      haystack,
      importedPaths,
      anchorLine,
      level: isE2e ? 'end-to-end' : referencesHttp ? 'integration' : 'unit',
      parsed: module?.parsed === true,
    });
  }
  return views;
}

/** Word-boundary search that tolerates identifier separators. */
function mentionsWord(haystack: string, word: string): boolean {
  const w = word.trim().toLowerCase();
  if (w.length < 3) return false;
  const escaped = w.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return new RegExp(`(?:^|[^a-z0-9])${escaped}(?:[^a-z0-9]|$)`).test(haystack);
}

/**
 * The static part of a route path, with dynamic segments dropped.
 * '/api/orders/[id]' -> '/api/orders'; '/users/:id/posts' -> '/users'.
 */
function staticPrefix(path: string): string {
  const parts = path.split('/');
  const kept: string[] = [];
  for (const p of parts) {
    if (p === '') { kept.push(p); continue; }
    if (/^[[:{<*]/.test(p) || /^\.{3}/.test(p) || /^<.*>$/.test(p)) break;
    kept.push(p);
  }
  const joined = kept.join('/');
  return joined.length > 1 ? joined.replace(/\/$/, '') : path;
}

interface Coverage {
  covered: boolean;
  /** How the reference was found, for the matrix and the trace. */
  via?: string;
  /** Test files that reference it. */
  tests: string[];
}

/**
 * Is this route referenced by any test file?
 *
 * Deliberately generous: a path mention, an import of the handler file, the
 * handler symbol name, or the name of a model the route queries all count. The
 * cost of a false "untested" claim is a reader losing trust in the matrix, so
 * every plausible reference is treated as coverage.
 */
function coverageForRoute(map: RepoMap, r: ApiEndpoint, views: TestView[]): Coverage {
  const tests: string[] = [];
  let via: string | undefined;

  const prefix = staticPrefix(r.path).toLowerCase();
  const fullPath = r.path.toLowerCase();
  const handler = r.handlerSymbol;
  // 'GET'/'POST' as a handler name is an HTTP verb, and every HTTP test
  // contains those words. Only a distinctive handler name is a signal.
  const usableHandler = handler && handler.length >= 4 && !/^(get|post|put|patch|delete|head|options|handler|default|index)$/i.test(handler)
    ? handler : undefined;

  const queriedModels = map.relationships
    .filter((rel) => rel.kind === 'queries' && rel.from === `api_route:${r.method} ${r.path}`)
    .map((rel) => rel.to.replace(/^datastore:/, ''));

  for (const v of views) {
    let hit: string | undefined;
    if (v.importedPaths.has(r.file)) hit = 'it imports the handler module';
    else if (fullPath.length > 1 && v.haystack.includes(fullPath)) hit = `it names the path ${r.path}`;
    else if (prefix.length > 1 && v.haystack.includes(prefix)) hit = `it names the path prefix ${prefix}`;
    else if (usableHandler && mentionsWord(v.haystack, usableHandler)) hit = `it names the handler ${usableHandler}`;
    else {
      const model = queriedModels.find((m) => mentionsWord(v.haystack, m));
      if (model) hit = `it names the ${model} model this route queries`;
    }
    if (hit) {
      tests.push(v.file.path);
      via ??= hit;
    }
  }

  // The feature inventory may already have decided a test meaningfully
  // exercises this feature; trust that rather than contradict it.
  if (tests.length === 0) {
    const feature = map.features.find((f) => f.backendFiles.includes(r.file) && f.status === 'implemented_verified');
    if (feature && feature.tests.length > 0) {
      return { covered: true, via: `the ${feature.name} feature is recorded as verified by ${feature.tests[0]}`, tests: feature.tests };
    }
  }

  return { covered: tests.length > 0, via, tests };
}

// ------------------------------------------------------ manifest scripts ----

interface ScriptRef {
  file: string;
  line: number;
  name: string;
  command: string;
}

const TEST_RUNNER_RE =
  /\b(jest|vitest|mocha|ava|karma|jasmine|tap\b|node\s+--test|node:test|pytest|unittest|tox|nox|rspec|minitest|phpunit|pest|go\s+test|cargo\s+test|dotnet\s+test|mvn[\w\s-]*\btest\b|gradle\w*\s+test|mix\s+test|ctest|rails\s+test|bundle\s+exec\s+rspec|playwright\s+test|cypress\s+run|testcafe)\b/i;

const TYPECHECK_RE = /\b(tsc\b|typecheck|type-check|mypy|pyright|flow\s+check|tsc\s+--noEmit)\b/i;

function lineMatching(text: string, re: RegExp): number | undefined {
  const lines = text.split('\n');
  for (let i = 0; i < lines.length; i++) if (re.test(lines[i]!)) return i + 1;
  return undefined;
}

/** Test scripts a project declares for itself, read from its manifests. */
function declaredTestScripts(map: RepoMap): ScriptRef[] {
  const out: ScriptRef[] = [];
  for (const file of map.byRole('manifest')) {
    if (!file.text) continue;
    if (file.path.endsWith('package.json')) {
      let scripts: Record<string, unknown> | undefined;
      try {
        const parsed = JSON.parse(file.text) as { scripts?: Record<string, unknown> };
        scripts = parsed.scripts;
      } catch {
        scripts = undefined;
      }
      for (const [name, value] of Object.entries(scripts ?? {})) {
        if (typeof value !== 'string') continue;
        const isTestName = /^(test|tests|spec|e2e|unit|integration|verify|check|ci)(:|$)/i.test(name);
        if (!isTestName && !TEST_RUNNER_RE.test(value)) continue;
        const line = lineMatching(file.text, new RegExp(`"${name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}"\\s*:`)) ?? 1;
        out.push({ file: file.path, line, name, command: value });
      }
      continue;
    }
    // Non-JSON manifests (pyproject.toml, Gemfile, pom.xml, Cargo.toml …):
    // a declared runner is enough to know the project intends to run tests.
    const stripped = codeText(file.text, file.language);
    const line = lineMatching(stripped, TEST_RUNNER_RE);
    if (line !== undefined) {
      out.push({ file: file.path, line, name: 'declared test runner', command: stripped.split('\n')[line - 1]!.trim().slice(0, 120) });
    }
  }
  return out;
}

// --------------------------------------------------------------- matrix -----

interface MatrixRow {
  method: string;
  path: string;
  flows: string[];
  tier: 1 | 2 | 3;
  covered: boolean;
  via?: string;
  file: string;
  line?: number;
  authRequired: ApiEndpoint['authRequired'];
}

function renderMatrix(rows: MatrixRow[]): string {
  if (rows.length === 0) return '  (no HTTP routes were reconstructed from this snapshot)';
  const width = Math.min(46, Math.max(...rows.map((r) => r.method.length + r.path.length + 1)));
  return rows
    .map((r) => {
      const left = `${r.method} ${r.path}`.padEnd(width);
      const state = r.covered ? 'covered  ' : 'UNCOVERED';
      const detail = r.covered
        ? (r.via ? ` — ${r.via}` : '')
        : r.flows.length > 0 ? ` — ${r.flows.join(', ')}` : '';
      return `  ${left}  ${state}${detail}`;
    })
    .join('\n');
}

// -------------------------------------------------------------- analyzer ----

export const testingAnalyzer: Analyzer = {
  id: 'testing',
  category: 'testing',
  description:
    'Test-gap matrix: which flows have tests, whether error and authorisation paths are exercised, and whether CI runs the suite before deploying.',

  precondition(map: RepoMap): string | undefined {
    const testFiles = map.byRole('test');
    const hasManifest = map.byRole('manifest').length > 0;
    const hasTestTooling = map.tech.some((t) => t.kind === 'testing');
    if (testFiles.length === 0 && !hasManifest && !hasTestTooling) {
      return 'no test files, no project manifest, and no test tooling were found, so a genuinely untested project cannot be distinguished from a partial snapshot of one';
    }
    const anyParsed = [...map.modules.values()].some((m) => m.parsed);
    if (!anyParsed && map.routes.length === 0 && map.models.length === 0) {
      return 'no source file in this snapshot could be parsed and no routes or data models were reconstructed, so there is nothing to compare tests against';
    }
    return undefined;
  },

  run(ctx: AnalyzerContext): Finding[] {
    const { map } = ctx;
    const views = buildTestViews(map);
    const scripts = declaredTestScripts(map);
    const findings: Finding[] = [];

    findings.push(...missingTestInfrastructure(ctx, views, scripts));
    findings.push(...untestedCriticalFlows(ctx, views));
    findings.push(...missingTestLevels(ctx, views));
    findings.push(...missingErrorPathTests(ctx, views));
    findings.push(...missingAuthorizationTests(ctx, views));
    findings.push(...testsThatDoNotExerciseTheFeature(ctx, views));
    findings.push(...ciDoesNotRunTests(ctx, views, scripts));

    return findings;
  },
};

// -------------------------------------------------- 1. no test harness ------

function missingTestInfrastructure(ctx: AnalyzerContext, views: TestView[], scripts: ScriptRef[]): Finding[] {
  const { map } = ctx;
  if (views.length > 0) return [];

  const routeCount = map.routes.length;
  const modelCount = map.models.length;
  const sourceCount = map.files.filter((f) => f.role === 'source' || f.role === 'route' || f.role === 'component').length;
  const testTech = map.tech.filter((t) => t.kind === 'testing');

  // Without either a declared intent to test or a non-trivial application
  // surface, "there are no tests" is an observation about the snapshot rather
  // than a defect in the project.
  if (scripts.length === 0 && testTech.length === 0 && routeCount === 0 && modelCount === 0) return [];

  const script = scripts[0];
  const evidence: Evidence[] = [];
  if (script) {
    evidence.push(map.evidenceLine(script.file, script.line,
      `the manifest declares the '${script.name}' script (\`${script.command}\`), but no file in the snapshot matches a test-file pattern`));
  }
  for (const t of testTech.slice(0, 1)) {
    const ev = t.evidence.find((e) => e.verified);
    if (ev) evidence.push({ ...ev, note: `${t.name} is installed as a dependency but no test file was found for it to run` });
  }
  if (evidence.length === 0) {
    const anchor = map.routes[0];
    if (anchor) {
      evidence.push(map.evidenceLine(anchor.file, anchor.line ?? 1,
        'an HTTP route with no test anywhere in the snapshot; no test file of any kind was found'));
    } else if (map.models[0]) {
      evidence.push(map.evidenceAt(map.models[0].file, map.models[0].name,
        'a persisted data model with no test anywhere in the snapshot'));
    }
  }
  if (evidence.length === 0 || !evidence.some((e) => e.verified)) return [];

  const declared = !!script || testTech.length > 0;
  const severity: Severity = routeCount > 0 || modelCount > 0 ? 'high' : 'medium';

  return [ctx.finding({
    ruleId: declared ? 'testing.infrastructure.declared_but_absent' : 'testing.infrastructure.missing',
    title: declared
      ? 'A test command is configured but there are no tests for it to run'
      : 'The project has no automated tests',
    severity,
    confidence: 'strong',
    detectionSource: declared ? 'graph' : 'static',
    files: [script?.file ?? evidence[0]!.file],
    evidence,
    trace: declared && script
      ? {
          kind: 'import',
          steps: [
            { file: script.file, line: script.line, detail: `manifest declares '${script.name}': ${script.command}` },
            { file: script.file, detail: `${map.files.length} files were indexed; none has a test role` },
            ...(testTech[0] ? [{ file: script.file, detail: `${testTech[0].name} is installed as a dependency` }] : []),
          ],
          complete: true,
        }
      : undefined,
    explanation:
      (declared
        ? `The project declares a way to run tests${script ? ` (\`${script.command}\`)` : ''}${testTech.length ? ` and installs ${testTech.map((t) => t.name).join(', ')}` : ''}, but no file in this snapshot matches a test-file pattern, so that command has nothing to execute. `
        : 'No file in this snapshot matches a test-file pattern for any supported language. ') +
      `The snapshot contains ${sourceCount} source file(s), ${routeCount} HTTP route(s) and ${modelCount} data model(s), all of which are therefore unverified by any automated check. ` +
      'No coverage tool was run and no coverage figure is available: this is the absence of test files, not a measured coverage number.',
    userImpact:
      'Every change ships without an automated check, so a regression is first observed by whoever uses the application next: a broken ' +
      'checkout, a failing login, or silently wrong data. Problems are found in production rather than before release, and the time to ' +
      'notice them depends on someone reporting them.',
    likelyRootCause: declared
      ? 'The test runner was installed and a script added at project setup, but no test was ever written against it.'
      : 'Tests were deferred during early development and never started.',
    downstreamConsequences: [
      'Refactoring is risky: there is no signal that behaviour was preserved.',
      'A CI pipeline cannot gate a release on a suite that does not exist.',
      'New contributors have no executable description of how the system is meant to behave.',
    ],
    remediation:
      'Start with the flows whose failure costs the most rather than with broad coverage: authentication, authorisation, payment or ' +
      'webhook handling, and anything that writes to the database. Write one test per flow that exercises it end to end through its ' +
      'public entry point, assert both the success and the rejection path, and wire the command into CI so it runs before deployment. ' +
      'Add a coverage tool if a number is wanted — until one runs, no coverage figure can honestly be reported.',
    effort: 'medium',
    relatedTests: [],
    verificationSteps: [
      script ? `Run \`${script.command}\` and confirm it discovers and executes at least one test.` : 'Run the project test command and confirm it executes at least one test.',
      'Confirm the new test fails when the behaviour it asserts is deliberately broken.',
      'Confirm the command is invoked by CI and that a failure blocks the deployment.',
    ],
    references: [REF.asvsArch, REF.pyramid],
  })];
}

// --------------------------------------- 2. untested critical flows ---------

function untestedCriticalFlows(ctx: AnalyzerContext, views: TestView[]): Finding[] {
  const { map } = ctx;
  if (map.routes.length === 0) return [];

  const rows: MatrixRow[] = map.routes.map((r) => {
    const cov = coverageForRoute(map, r, views);
    return {
      method: r.method,
      path: r.path,
      flows: flowsForRoute(r),
      tier: tierOfRoute(r),
      covered: cov.covered,
      via: cov.via,
      file: r.file,
      line: r.line,
      authRequired: r.authRequired,
    };
  });

  const uncovered = rows.filter((r) => !r.covered);
  if (uncovered.length === 0) return [];

  // Order the matrix so the expensive gaps are read first.
  const ordered = [...rows].sort((a, b) =>
    (a.covered === b.covered ? 0 : a.covered ? 1 : -1) || a.tier - b.tier || a.path.localeCompare(b.path));

  const tier1 = uncovered.filter((r) => r.tier === 1);
  const tier2 = uncovered.filter((r) => r.tier === 2);
  const tier1Labels = new Set(FLOW_CLASSES.filter((f) => f.tier === 1).map((f) => f.label));
  const worstFlows = [...new Set(tier1.flatMap((r) => r.flows))].filter((l) => tier1Labels.has(l));

  const severity: Severity = tier1.length > 0 ? 'critical' : tier2.length > 0 ? 'high' : 'medium';

  // A test harness that builds request paths dynamically is not resolvable
  // statically; the matrix would then understate coverage.
  const dynamicPaths = views.some((v) => /`[^`]*\/[^`]*\$\{/.test(v.file.text ?? ''));
  const unparsed = views.filter((v) => !v.parsed).map((v) => v.file.path);
  const confidence: Confidence = dynamicPaths || unparsed.length > 0 ? 'moderate' : 'strong';

  const evidence: Evidence[] = [];
  for (const r of ordered.filter((x) => !x.covered).slice(0, 5)) {
    evidence.push(map.evidenceLine(r.file, r.line ?? 1,
      `${r.method} ${r.path}${r.flows.length ? ` (${r.flows.join(', ')})` : ''} — no test file names this path, its handler, or a model it queries`));
  }
  for (const v of views.slice(0, 2)) {
    evidence.push(map.evidenceLine(v.file.path, v.anchorLine,
      `${v.level} test; comments stripped before matching, so a comment naming a route does not count as coverage`));
  }
  if (!evidence.some((e) => e.verified)) return [];

  const matrix = renderMatrix(ordered);
  const testList = views.length === 0
    ? 'There are no test files at all.'
    : `Test files read: ${views.map((v) => `${v.file.path} (${v.level})`).join(', ')}.`;

  const trace: RelationshipTrace = {
    kind: 'import',
    steps: [
      ...ordered.filter((r) => !r.covered).slice(0, 3).map((r) => ({
        file: r.file, line: r.line, detail: `${r.method} ${r.path} declared${r.flows.length ? ` — ${r.flows.join(', ')} flow` : ''}`,
      })),
      ...views.slice(0, 2).map((v) => ({
        file: v.file.path, line: v.anchorLine,
        detail: `test module read: imports ${[...v.importedPaths].join(', ') || 'nothing inside the project'}`,
      })),
      {
        file: ordered.find((r) => !r.covered)!.file,
        detail: `no test module references this route's path, handler symbol, handler file, or queried model${dynamicPaths ? '; one test builds paths by interpolation, which cannot be resolved statically' : ''}`,
      },
    ],
    complete: !dynamicPaths && unparsed.length === 0,
  };

  return [ctx.finding({
    ruleId: 'testing.coverage.untested_critical_flows',
    title: tier1.length > 0
      ? `${tier1.length} route(s) on critical flows have no test: ${worstFlows.join(', ')}`
      : `${uncovered.length} of ${rows.length} routes are not referenced by any test`,
    severity,
    confidence,
    detectionSource: 'graph',
    files: [...new Set(ordered.filter((r) => !r.covered).map((r) => r.file))].slice(0, 10),
    evidence,
    trace,
    explanation:
      'TEST-GAP MATRIX — every reconstructed HTTP route against whether any test file references it:\n\n' +
      `${matrix}\n\n` +
      `Counts: ${uncovered.length} of ${rows.length} route(s) are referenced by no test; of those, ${tier1.length} sit on a ` +
      `critical flow (authentication, authorisation, payment, or webhook handling) and ${tier2.length} change state or move data. ` +
      `${testList}\n\n` +
      'A route counts as referenced when a test file names its path or path prefix, imports its handler module, names a distinctive ' +
      'handler symbol, or names a data model that route queries. Comments are stripped before matching. ' +
      'No coverage tool was executed, so these are counts of static test references and not a code-coverage measurement; a reference ' +
      'is also weaker than real coverage, since naming a path does not prove the test asserts anything useful about it.',
    userImpact: tier1.length > 0
      ? 'A regression in one of these flows reaches users directly and silently: a sign-in that stops working, an order that can be read ' +
        'by the wrong account, a payment that is taken but never recorded, or a provider callback that is dropped. Nothing in the build ' +
        'would fail first — the first signal is a customer complaint or a reconciliation mismatch.'
      : 'A regression in these routes is not caught before release, so users encounter it first and the team learns about it from reports ' +
        'rather than from a failing build.',
    likelyRootCause:
      'Tests were written for the code that was easy to call directly — pure helper functions — rather than for the request paths that ' +
      'carry the risk, because the latter need a harness that can issue requests and seed data.',
    downstreamConsequences: [
      'Changes to shared helpers (session handling, database access) cannot be verified against the routes that depend on them.',
      'Each deployment carries the full regression risk of every untested flow, so the cost of releasing does not fall as the suite grows.',
      'Security fixes in these handlers have no regression test, so the same defect can return unnoticed.',
    ],
    remediation:
      'Add one test per uncovered critical flow, in the order the matrix lists them, exercising the route through its HTTP entry point ' +
      'rather than by calling internal helpers: issue the request with the framework\'s test client (or a local server plus an HTTP ' +
      'client), seed the data the handler expects, and assert the response status, the response body, and the resulting database state. ' +
      'For a payment or provider callback, also assert the handler is idempotent when the same event arrives twice. Keep each test ' +
      'independent of the others so a failure names one flow. Treat the matrix as a checklist and keep it in the repository so a new ' +
      'route without a test is visible in review.',
    effort: 'large',
    relatedTests: views.map((v) => v.file.path),
    verificationSteps: [
      'Run the suite and confirm a test now exists for each flow the matrix marks UNCOVERED.',
      'Break one handler deliberately (return the wrong status, skip the ownership filter) and confirm its new test fails.',
      'Re-run this analyser and confirm the matrix shows those routes as covered.',
      'For each covered row, confirm the test asserts behaviour rather than merely importing the module.',
    ],
    references: [REF.busl, REF.asvsArch, REF.pyramid],
  })];
}

// ----------------------------------------- 3. unit / integration / e2e ------

function missingTestLevels(ctx: AnalyzerContext, views: TestView[]): Finding[] {
  const { map } = ctx;
  if (views.length === 0) return [];
  if (map.routes.length === 0) return [];

  const levels = new Set(views.map((v) => v.level));
  if (levels.has('integration') || levels.has('end-to-end')) return [];

  const anchor = views[0]!;
  const evidence: Evidence[] = [
    map.evidenceLine(anchor.file.path, anchor.anchorLine,
      'the only kind of test present: it calls a function directly and does not issue a request to any route'),
  ];
  const firstRoute = map.routes[0]!;
  evidence.push(map.evidenceLine(firstRoute.file, firstRoute.line ?? 1,
    `${map.routes.length} HTTP route(s) exist, and no test file uses an HTTP test client, a browser driver, or imports a route module`));
  if (!evidence.some((e) => e.verified)) return [];

  const unparsed = views.filter((v) => !v.parsed).length;

  return [ctx.finding({
    ruleId: 'testing.levels.no_integration_or_end_to_end',
    title: views.length === 1
      ? 'The only test file is a unit test; no integration or end-to-end test exists'
      : `All ${views.length} test files are unit tests; no integration or end-to-end test exists`,
    severity: 'medium',
    confidence: unparsed > 0 ? 'moderate' : 'strong',
    detectionSource: 'static',
    files: [anchor.file.path, firstRoute.file],
    evidence,
    explanation:
      `This project exposes ${map.routes.length} HTTP route(s) and ${map.models.length} data model(s), but every test file reads as a ` +
      'unit test: none imports a route module, uses an HTTP test client (supertest, the framework test client, httpx, MockMvc, Rack::Test ' +
      'or similar), or drives a browser (Playwright, Cypress, Selenium). ' +
      `Test files and the level each was classified as: ${views.map((v) => `${v.file.path} → ${v.level}`).join(', ')}. ` +
      'The consequence is structural rather than a matter of quantity: the layers where request parsing, middleware, session resolution, ' +
      'serialisation and database behaviour meet have no test that can observe them, because unit tests call past them. ' +
      'This is a statement about which test levels exist, not a coverage measurement — no coverage tool was run.',
    userImpact:
      'Defects that only appear when the parts are assembled — a route that is registered at the wrong path, middleware that does not run, ' +
      'a response field renamed on one side only, a query that fails against the real schema — are not caught by the suite and are first ' +
      'experienced by users as a broken page or an error response.',
    likelyRootCause:
      'Unit tests need no harness, so they get written first; an integration test needs a way to start the application and seed data, ' +
      'and that setup cost postpones it indefinitely.',
    downstreamConsequences: [
      'Mocked boundaries in unit tests can drift from the real interface without any test failing.',
      'Without a request-level test there is no natural place to assert status codes, headers, or authorisation behaviour.',
      'End-to-end regressions are only discovered by manual checking before each release, which does not scale.',
    ],
    remediation:
      'Add one integration test that starts the application the way the framework intends for tests (Next.js route handlers can be invoked ' +
      'with a constructed Request; Express can be driven with supertest; FastAPI and Django ship test clients) and asserts a full ' +
      'request-to-response cycle against a disposable database. Build the fixture and seeding helpers once, then grow the suite a flow at ' +
      'a time, starting with the rows the test-gap matrix marks uncovered. Add a small end-to-end test for the one journey that must never ' +
      'break — typically sign-in followed by the primary action — and keep the number of such tests low so they stay fast and reliable.',
    effort: 'large',
    relatedTests: views.map((v) => v.file.path),
    verificationSteps: [
      'Run the new integration test and confirm it fails when the route is renamed or unregistered.',
      'Confirm the test runs against a disposable database and leaves no state behind.',
      'Confirm the suite still completes quickly enough to run on every change.',
    ],
    references: [REF.pyramid, 'Google Testing Blog: Test Sizes (small, medium, large)'],
  })];
}

// ------------------------------------------- 4. no error-path assertions ----

const ERROR_ASSERTION_RE = new RegExp([
  'tothrow', 'tothrowerror', 'assert\\.throws', 'assert\\.rejects', 'assertthrows',
  'rejects', 'rejected', 'refus', 'pytest\\.raises', 'assertraises', 'expect_?error',
  'shouldraise', 'shouldthrow', 'willthrow', 'xunit', 'expectexception',
  '\\bthrows?\\b', '\\bthrown\\b', '\\bcatch\\b', '\\.catch\\(', '\\btry\\b',
  '\\berror\\b', '\\berrors\\b', '\\bexception\\b', '\\bfailure\\b', '\\bfails?\\b',
  '\\bfailed\\b', '\\binvalid\\b', '\\bmalformed\\b', '\\bunauthori[sz]ed\\b',
  '\\bunauthenticated\\b', '\\bforbidden\\b', '\\bnot[ _-]?found\\b',
  '\\bbad[ _-]?request\\b', '\\bconflict\\b', '\\btimeout\\b', '\\bretry\\b',
  '\\brollback\\b', '\\bdenied\\b', '\\breject\\b',
  'status[^a-z0-9]{0,4}(4\\d\\d|5\\d\\d)', 'statuscode[^a-z0-9]{0,4}(4\\d\\d|5\\d\\d)',
  '\\b(400|401|402|403|404|405|409|410|422|429|500|502|503|504)\\b',
].join('|'), 'i');

function missingErrorPathTests(ctx: AnalyzerContext, views: TestView[]): Finding[] {
  const { map } = ctx;
  if (views.length === 0) return [];

  // Only meaningful where there are error paths worth asserting on.
  const throwsSomewhere = [...map.modules.values()].some(
    (m) => m.parsed && (m.hasTryCatch || m.symbols.some((s) => /\bthrow\b/.test(s.text))),
  );
  if (map.routes.length === 0 && !throwsSomewhere) return [];

  const withAssertion = views.filter((v) => ERROR_ASSERTION_RE.test(v.haystack));
  if (withAssertion.length > 0) return [];

  const anchor = views[0]!;
  const evidence: Evidence[] = [
    map.evidenceLine(anchor.file.path, anchor.anchorLine,
      'the test corpus asserts only on success values: no rejection, thrown error, or 4xx/5xx status is asserted anywhere'),
  ];
  // Route extraction reports 'partial' as well as the three values the shared
  // type declares, so compare as a string rather than narrow it away.
  const errorRoute = map.routes.find((r) => r.errorHandling === 'absent')
    ?? map.routes.find((r) => String(r.errorHandling) === 'partial')
    ?? map.routes[0];
  if (errorRoute) {
    evidence.push(map.evidenceLine(errorRoute.file, errorRoute.line ?? 1,
      `this handler's error handling is reported as '${errorRoute.errorHandling}' and no test exercises its failure path`));
  }
  if (!evidence.some((e) => e.verified)) return [];

  const unparsed = views.filter((v) => !v.parsed).length;
  const absentHandling = map.routes.filter((r) => r.errorHandling === 'absent').length;

  return [ctx.finding({
    ruleId: 'testing.error_paths.no_failure_assertions',
    title: 'No test asserts a failure, rejection, or error response',
    severity: absentHandling > 0 ? 'high' : 'medium',
    confidence: unparsed > 0 ? 'moderate' : 'strong',
    detectionSource: 'static',
    files: [anchor.file.path],
    evidence,
    explanation:
      `All ${views.length} test file(s) assert only on the happy path. None contains a thrown-error assertion ` +
      '(`toThrow`, `assert.throws`, `pytest.raises`, `assertRaises` and equivalents), a rejected-promise assertion, an assertion on a ' +
      '4xx or 5xx status, or a test whose name describes a failure. ' +
      (absentHandling > 0
        ? `At the same time, ${absentHandling} route handler(s) are reported as having no error handling at all, so their behaviour when a dependency fails is both unimplemented and unverified. `
        : '') +
      'Error handling is the part of a system least exercised by manual use and most likely to be wrong, because it only runs when ' +
      'something else has already gone wrong. Untested error paths commonly return a 200 with an empty body, leak an internal stack ' +
      'trace, or leave a half-finished write behind.',
    userImpact:
      'When something goes wrong — invalid input, an expired session, a database or payment provider that is unavailable — the user sees ' +
      'whatever the untested path happens to do: a blank screen, a spinner that never resolves, a technical error page, or worst of all a ' +
      'success message for an action that did not complete.',
    likelyRootCause:
      'Tests were written to confirm the feature works, which is the case the author had in mind; the failure cases were never enumerated.',
    downstreamConsequences: [
      'Error responses can change shape without any test noticing, breaking clients that depend on them.',
      'Partial writes on a failed request go undetected until data is found to be inconsistent.',
      'Retry and timeout behaviour cannot be changed with any confidence.',
    ],
    remediation:
      'For each flow already under test, add its failure cases as explicit tests: invalid or missing input, an absent or expired session, ' +
      'a resource that does not exist, a duplicate submission, and an unavailable dependency (inject a failure at the boundary rather ' +
      'than waiting for a real outage). Assert the status code, the error body shape, and that no partial write survives. Assert that ' +
      'internal details — stack traces, SQL, provider payloads — are not returned to the caller.',
    effort: 'medium',
    relatedTests: views.map((v) => v.file.path),
    verificationSteps: [
      'Run the suite and confirm at least one test fails when an error path is changed to return 200.',
      'Confirm a test covers an unavailable dependency, by injecting the failure rather than by disabling the service.',
      'Confirm the asserted error responses contain no internal diagnostics.',
    ],
    references: [REF.errh, 'CWE-391 Unchecked Error Condition'],
  })];
}

// -------------------------------------- 5. no authorisation-negative tests --

const AUTHZ_NEGATIVE_RE = new RegExp([
  '\\b(401|403)\\b', 'unauthori[sz]ed', 'unauthenticated', 'forbidden',
  'without[ _-]?(?:a[ _-]?)?(?:token|session|auth|credential|credentials|login|cookie)',
  'no[ _-]?(?:token|session|auth|credential|credentials|cookie)',
  'missing[ _-]?(?:token|session|auth|credential|credentials|header)',
  'invalid[ _-]?(?:token|session|credential|credentials|signature)',
  'expired[ _-]?(?:token|session)',
  '(?:wrong|other|another|different|second)[ _-]?(?:user|account|tenant|owner|org)',
  'non[ _-]?owner', 'not[ _-]?the[ _-]?owner', 'cross[ _-]?(?:account|tenant|user)',
  'anonymous', 'logged[ _-]?out', 'signed[ _-]?out', 'guest',
  'requires[ _-]?(?:auth|authentication|login|a[ _-]?session)',
  'denies', 'denied', 'access[ _-]?control', 'permission[ _-]?denied',
  'escalat', 'impersonat',
].join('|'), 'i');

function missingAuthorizationTests(ctx: AnalyzerContext, views: TestView[]): Finding[] {
  const { map } = ctx;

  const protectedRoutes = map.routes.filter(
    (r) => r.authRequired === 'required' || r.authorizationChecks.length > 0,
  );
  if (protectedRoutes.length === 0) return [];

  const withNegative = views.filter((v) => AUTHZ_NEGATIVE_RE.test(v.haystack));
  if (withNegative.length > 0) return [];

  const ownershipModels = new Set(
    map.models.filter((m) => m.ownershipField).map((m) => m.name),
  );

  const evidence: Evidence[] = [];
  for (const r of protectedRoutes.slice(0, 4)) {
    evidence.push(map.evidenceLine(r.file, r.line ?? 1,
      `${r.method} ${r.path} requires an authenticated caller, and no test issues an unauthenticated or wrong-user request against it`));
  }
  for (const v of views.slice(0, 1)) {
    evidence.push(map.evidenceLine(v.file.path, v.anchorLine,
      'no test file in the project asserts a 401 or 403, or exercises a request as the wrong user'));
  }
  if (!evidence.some((e) => e.verified)) return [];

  const unparsed = views.filter((v) => !v.parsed).length;
  const matrix = protectedRoutes
    .map((r) => {
      const models = map.relationships
        .filter((rel) => rel.kind === 'queries' && rel.from === `api_route:${r.method} ${r.path}`)
        .map((rel) => rel.to.replace(/^datastore:/, ''));
      const owned = models.filter((m) => ownershipModels.has(m));
      return `  ${`${r.method} ${r.path}`.padEnd(34)}  no unauthenticated test, no wrong-user test` +
        (owned.length ? ` (queries ${owned.join(', ')}, which has an ownership column)` : '');
    })
    .join('\n');

  const otherRoutes = map.routes.length - protectedRoutes.length;

  return [ctx.finding({
    ruleId: 'testing.authorization.no_negative_tests',
    title: `No test exercises an unauthenticated or wrong-user request against ${protectedRoutes.length} protected route(s)`,
    severity: 'high',
    confidence: unparsed > 0 ? 'moderate' : 'strong',
    detectionSource: 'graph',
    files: [...new Set(protectedRoutes.map((r) => r.file))].slice(0, 8),
    evidence,
    trace: {
      kind: 'route_authorization',
      steps: [
        ...protectedRoutes.slice(0, 3).map((r) => ({
          file: r.file, line: r.line, symbol: r.handlerSymbol,
          detail: `${r.method} ${r.path} resolves a session, so an unauthenticated caller must be rejected`,
        })),
        ...views.slice(0, 2).map((v) => ({
          file: v.file.path, line: v.anchorLine,
          detail: 'test module read in full (comments stripped): contains no 401/403 assertion and no wrong-user request',
        })),
        {
          file: protectedRoutes[0]!.file,
          detail: 'the rejection branch of every protected route is therefore unverified by the suite',
        },
      ],
      complete: unparsed === 0,
    },
    explanation:
      'AUTHORISATION TEST MATRIX — routes the map reports as requiring an authenticated caller:\n\n' +
      `${matrix}\n\n` +
      'Authorisation is the one behaviour whose correctness is defined entirely by what it refuses, so a suite that only tests ' +
      'authorised callers tests the half that cannot fail safely. No test file asserts a 401 or 403 status, issues a request with no or ' +
      'an invalid session, or repeats a request as a second user. ' +
      (otherRoutes > 0
        ? `A further ${otherRoutes} route(s) are reported as public or of unknown auth status and are not counted here; whether they should require authentication is a question for the security findings, not this one. `
        : '') +
      'These are counts of assertions found in the test corpus, not a coverage measurement.',
    userImpact:
      'If an access check is removed or weakened — by a refactor, a middleware change, or a new code path added alongside the old one — ' +
      'nothing in the build fails. One user reading or deleting another user\'s records, or an anonymous caller reaching a protected ' +
      'endpoint, would ship unnoticed, and the first evidence would be a data-exposure report.',
    likelyRootCause:
      'Tests were written from the authenticated user\'s point of view, where a session already exists, so the rejection branch was never ' +
      'given a test of its own.',
    downstreamConsequences: [
      'Any security fix in these handlers has no regression test, so the same gap can reappear.',
      'Middleware changes that silently stop matching a route produce no failing test.',
      'Where the data model has an owner column, a missing ownership filter is invisible to a single-user test suite.',
    ],
    remediation:
      'For each protected route add three tests: no credentials (expect 401), valid credentials for a user who does not own the resource ' +
      '(expect 403, or 404 where existence itself should not be confirmed), and the owner (expect success). Seed two distinct users in the ' +
      'fixture so the wrong-user case is expressible at all, and assert on the response body as well as the status so an empty 200 cannot ' +
      'pass. Where authorisation is enforced by middleware, assert it through the HTTP layer rather than by calling the handler directly, ' +
      'so the test fails if the middleware stops matching.',
    effort: 'medium',
    relatedTests: views.map((v) => v.file.path),
    verificationSteps: [
      'Run the suite, then remove an authentication check from one handler and confirm a test fails.',
      'Confirm the wrong-user test fails if the ownership filter is removed from the query.',
      'Confirm the fixture creates at least two users, so cross-user access is actually exercised.',
    ],
    references: [REF.athz, 'OWASP ASVS v4.0 §4 Access Control Verification Requirements', 'CWE-862 Missing Authorization'],
  })];
}

// -------------------------------- 6. test present, feature not exercised ----

function testsThatDoNotExerciseTheFeature(ctx: AnalyzerContext, views: TestView[]): Finding[] {
  const { map } = ctx;
  const out: Finding[] = [];
  if (views.length === 0) return out;

  for (const feature of map.features) {
    // The feature inventory records exactly this case: a test imports the
    // feature's code, but names none of its routes or models.
    if (feature.tests.length === 0) continue;
    if (feature.status === 'implemented_verified') continue;
    if (feature.status === 'placeholder_or_mock') continue;

    const featureFiles = new Set([...feature.frontendFiles, ...feature.backendFiles]);
    const evidence: Evidence[] = [];
    const steps: RelationshipTrace['steps'] = [];

    for (const testPath of feature.tests.slice(0, 2)) {
      const view = views.find((v) => v.file.path === testPath);
      const mod = map.modules.get(testPath);
      const imp = mod?.imports.find((i) => i.resolvedPath && featureFiles.has(i.resolvedPath));
      const line = imp?.line ?? view?.anchorLine ?? 1;
      evidence.push(map.evidenceLine(testPath, line,
        `this test imports the ${feature.name} implementation but exercises none of its routes or models`));
      steps.push({ file: testPath, line, detail: `test imports ${imp?.resolvedPath ?? 'this feature\'s code'}` });
    }

    const route = map.routes.find((r) => feature.backendFiles.includes(r.file));
    if (route) {
      evidence.push(map.evidenceLine(route.file, route.line ?? 1,
        `${route.method} ${route.path} belongs to this feature and is named by no test`));
      steps.push({ file: route.file, line: route.line, detail: `${route.method} ${route.path} is part of the ${feature.name} feature and is not named by the test` });
    } else if (feature.databaseDeps.length > 0) {
      const model = map.models.find((m) => feature.databaseDeps.includes(m.name));
      if (model) {
        evidence.push(map.evidenceAt(model.file, model.name,
          `the ${model.name} model backs this feature and is named by no test`));
        steps.push({ file: model.file, detail: `${model.name} backs this feature and is not named by the test` });
      }
    }

    if (!evidence.some((e) => e.verified)) continue;
    const detail = feature.possibleDefects.find((d) => /not covered|does not exercise/i.test(d));

    out.push(ctx.finding({
      ruleId: 'testing.coverage.test_does_not_exercise_feature',
      title: `The ${feature.name} feature has a test that does not exercise it`,
      severity: 'medium',
      confidence: 'strong',
      detectionSource: 'graph',
      files: [...new Set([...feature.tests.slice(0, 2), ...feature.backendFiles, ...feature.frontendFiles])].slice(0, 6),
      evidence,
      trace: { kind: 'import', steps, complete: true },
      affectedFeatures: [feature.name],
      explanation:
        `${feature.tests.length} test file(s) import code belonging to the ${feature.name} feature ` +
        `(${feature.tests.join(', ')}), but none of them names any of its routes` +
        (feature.databaseDeps.length ? `, nor the ${feature.databaseDeps.join('/')} model(s) it depends on` : '') +
        '. What the test exercises is a helper that the feature happens to share, not the feature itself. ' +
        (detail ? `The feature inventory records the same observation: "${detail}". ` : '') +
        'This is the most misleading shape a test gap can take, because the file-level signal — a test exists and imports this code — ' +
        'looks like coverage in any tool that counts files touched, while the behaviour users depend on is unverified. ' +
        'No coverage tool was run here; this is a comparison of what the test names against what the feature contains.',
      userImpact:
        `The ${feature.name} feature can break without any test failing. A reviewer looking for test coverage sees an existing test ` +
        'file and reasonably assumes the feature is protected, so the gap is less likely to be found than if there were no test at all.',
      likelyRootCause:
        'A single pure helper was easy to test in isolation, and the test was written for it rather than for the behaviour that calls it.',
      downstreamConsequences: [
        'Reported test counts and file-touch metrics overstate how much of this feature is verified.',
        'A regression in the feature\'s route or query path produces a green build.',
      ],
      remediation:
        `Keep the helper test — it is cheap and correct — and add a test that exercises the ${feature.name} feature through its own entry ` +
        'point: call the route with a request, assert the status and body, and assert the resulting state of the records it writes. ' +
        'Where the feature spans a page and an API route, assert the contract between them (the field names the page reads) so a rename on ' +
        'one side fails the suite.',
      effort: 'small',
      relatedTests: feature.tests,
      verificationSteps: [
        `Break the ${feature.name} feature\'s route or query deliberately and confirm a test now fails.`,
        'Confirm the new test names the route path or model, so the gap does not reopen silently.',
      ],
      references: [REF.busl, REF.pyramid],
    }));
  }
  return out;
}

// --------------------------------------------- 7. CI does not run tests -----

const CI_DEPLOY_RE = new RegExp([
  '\\bdeploy\\b', '\\bdeploys\\b', '\\bdeployment\\b', '\\brelease\\b', '\\bpublish\\b',
  '\\bpromote\\b', '\\brollout\\b', '\\bvercel\\b', '\\bnetlify\\b', '\\bflyctl\\b',
  '\\bheroku\\b', '\\bkubectl\\b', '\\bhelm\\b', 'terraform\\s+apply', '\\bserverless\\b',
  '\\bcdk\\s+deploy\\b', 'aws\\s+s3\\s+sync', 'aws\\s+ecs', 'gcloud\\s+run\\s+deploy',
  'az\\s+webapp', 'docker\\s+push', 'npm\\s+publish', 'gh\\s+release', 'eas\\s+submit',
  'ansible-playbook', 'cap\\s+production',
].join('|'), 'i');

const CI_TEST_STEP_RE = new RegExp([
  '(?:npm|pnpm|yarn|bun|npx)\\s+(?:run\\s+)?(?:test|tests|spec|e2e|unit|integration|verify|ci:test)\\b',
  '(?:npm|pnpm|yarn|bun)\\s+(?:run\\s+)?(?:jest|vitest|mocha|ava|playwright|cypress)\\b',
  '\\bjest\\b', '\\bvitest\\b', '\\bmocha\\b', '\\bpytest\\b', '\\btox\\b', '\\bnox\\b',
  '\\brspec\\b', '\\bphpunit\\b', '\\bpest\\b', 'go\\s+test', 'cargo\\s+test',
  'dotnet\\s+test', 'mvn[\\w\\s-]*\\btest\\b', 'gradle\\w*\\s+test', 'mix\\s+test',
  'make\\s+test', 'node\\s+--test', 'rails\\s+test', 'bundle\\s+exec\\s+rspec',
  'playwright\\s+test', 'cypress\\s+run', 'ctest',
].join('|'), 'i');

const CI_TYPECHECK_RE = new RegExp([
  '(?:npm|pnpm|yarn|bun|npx)\\s+(?:run\\s+)?(?:typecheck|type-check|tsc|check)\\b',
  '\\btsc\\b', '\\bmypy\\b', '\\bpyright\\b', 'flow\\s+check',
].join('|'), 'i');

/**
 * The line of the step that performs the deployment, preferred over the
 * workflow's own `name:` so the evidence shows a reader the actual command.
 */
function deployStepLine(stripped: string): number | undefined {
  const lines = stripped.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const l = lines[i]!;
    if (/^\s+.*\b(?:run|uses|script|command|entrypoint)\s*:/.test(l) && CI_DEPLOY_RE.test(l)) return i + 1;
  }
  for (let i = 0; i < lines.length; i++) {
    const l = lines[i]!;
    if (/^\s+/.test(l) && CI_DEPLOY_RE.test(l)) return i + 1;
  }
  return lineMatching(stripped, CI_DEPLOY_RE);
}

const CI_DELEGATION_RE = /uses:\s*\.?\/?\.github\/workflows\/|workflow_call|workflow_run|\bneeds:/i;

function ciDoesNotRunTests(ctx: AnalyzerContext, views: TestView[], scripts: ScriptRef[]): Finding[] {
  const { map } = ctx;
  const ciFiles = map.byRole('ci').filter((f) => f.text !== null && !f.binary);
  if (ciFiles.length === 0) return [];
  // With neither tests nor a test command there is nothing for CI to run; the
  // infrastructure finding covers that case instead.
  if (views.length === 0 && scripts.length === 0) return [];

  interface CiView {
    file: SourceFile;
    stripped: string;
    deployLine?: number;
    testLine?: number;
    typecheckLine?: number;
    delegates: boolean;
  }

  const ciViews: CiView[] = ciFiles.map((f) => {
    const stripped = codeText(f.text, f.language);
    return {
      file: f,
      stripped,
      deployLine: deployStepLine(stripped),
      testLine: lineMatching(stripped, CI_TEST_STEP_RE),
      typecheckLine: lineMatching(stripped, CI_TYPECHECK_RE),
      delegates: CI_DELEGATION_RE.test(stripped),
    };
  });

  const out: Finding[] = [];
  const elsewhere = ciViews.filter((c) => c.testLine !== undefined);

  for (const ci of ciViews) {
    if (ci.deployLine === undefined) continue;   // not a deploying pipeline
    if (ci.testLine !== undefined) continue;     // it does run tests

    const testScript = scripts.find((s) => /^(test|tests)(:|$)/i.test(s.name)) ?? scripts[0];
    const evidence: Evidence[] = [
      map.evidenceLine(ci.file.path, ci.deployLine,
        'this workflow deploys; comments are stripped before matching, so a comment mentioning tests does not count as a test step'),
    ];
    if (testScript) {
      evidence.push(map.evidenceLine(testScript.file, testScript.line,
        `the project declares '${testScript.name}' (\`${testScript.command}\`), which this workflow never invokes`));
    }
    for (const v of views.slice(0, 1)) {
      evidence.push(map.evidenceLine(v.file.path, v.anchorLine,
        'an existing test that the deployment pipeline does not run'));
    }
    if (!evidence.some((e) => e.verified)) continue;

    const runsTypecheckOnly = ci.typecheckLine !== undefined;
    const testedElsewhere = elsewhere.filter((c) => c.file.path !== ci.file.path);

    const severity: Severity =
      testedElsewhere.length > 0 ? 'medium' : runsTypecheckOnly ? 'medium' : 'high';
    const confidence: Confidence = ci.delegates ? 'moderate' : 'strong';

    const steps: RelationshipTrace['steps'] = [
      { file: ci.file.path, line: ci.deployLine, detail: `workflow step deploys: ${ci.stripped.split('\n')[ci.deployLine - 1]!.trim().slice(0, 120)}` },
    ];
    if (testScript) {
      steps.push({ file: testScript.file, line: testScript.line, detail: `'${testScript.name}' script defined: ${testScript.command}` });
    }
    for (const v of views.slice(0, 1)) {
      steps.push({ file: v.file.path, line: v.anchorLine, detail: 'test file that exists and is never executed by this pipeline' });
    }
    steps.push({
      file: ci.file.path,
      detail: ci.delegates
        ? 'no step in this workflow runs a test command; it references another workflow or a job dependency that could not be resolved from this snapshot'
        : 'no step in this workflow runs a test or typecheck command before the deployment step',
    });

    out.push(ctx.finding({
      ruleId: 'testing.ci.deploys_without_running_tests',
      title: `${ci.file.path} deploys without running the test suite`,
      severity,
      confidence,
      detectionSource: 'graph',
      files: [ci.file.path, ...(testScript ? [testScript.file] : [])],
      evidence,
      trace: { kind: 'call', steps, complete: !ci.delegates },
      explanation:
        `${ci.file.path} contains a deployment step (line ${ci.deployLine}), and no step in the same workflow runs a test command` +
        (runsTypecheckOnly ? `; it does run a type check (line ${ci.typecheckLine})` : ' or a type check') +
        '. ' +
        (testScript
          ? `The project declares '${testScript.name}' (\`${testScript.command}\`) in ${testScript.file}, and ${views.length} test file(s) exist, so there is a suite available that this pipeline simply does not invoke. `
          : `${views.length} test file(s) exist, so there is a suite available that this pipeline does not invoke. `) +
        (testedElsewhere.length > 0
          ? `Tests do run in ${testedElsewhere.map((c) => c.file.path).join(', ')}, but that is a separate workflow: unless this one is gated on it, a red suite does not stop a deployment. `
          : 'No CI workflow in this snapshot runs tests at all. ') +
        (ci.delegates
          ? 'This workflow references another workflow or declares a job dependency that could not be resolved from the snapshot, so a test step may exist outside what was read — confirm before acting. '
          : '') +
        'Comments were stripped before matching: a comment describing tests does not make a pipeline run them. ' +
        'This finding is about the pipeline\'s test gate specifically; broader pipeline concerns such as rollback and environment ' +
        'promotion belong to the deployment findings.',
      userImpact:
        'A change that breaks a tested behaviour reaches production anyway, because nothing between merging and deploying can reject it. ' +
        'Users meet the regression before anyone on the team does, and recovery depends on noticing and reverting by hand.',
      likelyRootCause:
        'The deployment workflow was written to get the application released, and the test gate was expected to be added later or assumed ' +
        'to be covered by a separate pipeline.',
      downstreamConsequences: [
        'The existing suite provides no release protection, so the effort spent writing it is not repaid.',
        'A failing test can stay red indefinitely without blocking anything, which erodes trust in the suite.',
        'There is no recorded build in which the deployed commit passed its tests.',
      ],
      remediation:
        `Add a step that runs the suite${testScript ? ` (\`${testScript.command}\`)` : ''} before the deployment step in this workflow, and ` +
        'make the deployment depend on it so a non-zero exit stops the release. If the suite already runs in a separate workflow, gate ' +
        'this one on that workflow\'s result (a `needs:` dependency on a job in the same workflow, or a required status check on the ' +
        'protected branch) rather than relying on it running in parallel. Add the type check to the same gate, and do not mark the test ' +
        'step `continue-on-error`, which reintroduces the gap quietly.',
      effort: 'small',
      relatedTests: views.map((v) => v.file.path),
      verificationSteps: [
        'Push a commit with a deliberately failing test and confirm the pipeline stops before the deployment step.',
        'Confirm the deployment job reports the test job as a dependency, not merely as a parallel job.',
        'Confirm the test step runs on the same commit that is deployed.',
      ],
      references: [REF.asvsBuild, REF.dora],
    }));
  }
  return out;
}
