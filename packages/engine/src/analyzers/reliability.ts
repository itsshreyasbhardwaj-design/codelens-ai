import type {
  ApiEndpoint, Confidence, DataModel, Evidence, Finding, RelationshipTrace, Severity,
} from '@codelens/core';
import type { RepoMap } from '../graph/repomap.ts';
import type { JsxElement, ParsedModule, SymbolInfo } from '../parse/types.ts';
import type { Analyzer, AnalyzerContext } from './types.ts';
import { codeText } from './text.ts';

/**
 * Functional reliability audit: the paths that break at runtime rather than the
 * ones an attacker reaches.
 *
 * Confidence discipline in this analyzer:
 *   - a pattern match alone is `moderate`;
 *   - a pattern plus a traced relationship across files (a declared response
 *     type against the shape a handler actually returns, a write against the
 *     schema that should constrain it, a module against its importers) is
 *     `strong`;
 *   - nothing here is `confirmed`, because every rule in this file infers
 *     runtime behaviour from a snapshot, and a reflective call, a dynamic
 *     import, or a framework convention we do not model can always be the
 *     explanation. Where that is likely rather than merely possible, the
 *     finding says so and the trace is marked incomplete so the discipline gate
 *     caps it.
 *
 * Real timing is never asserted. The one rule whose claim depends on two
 * requests actually interleaving is reported as
 * `needs_runtime_verification`, because a snapshot cannot show a race
 * happening — only that nothing prevents it.
 */

// ---------------------------------------------------------------------------
// Shared text and lookup helpers (inlined deliberately: sibling analyzers are
// being written concurrently, so this file owns everything it needs).
// ---------------------------------------------------------------------------

interface FileLines {
  /** Raw lines, 0-indexed array for 1-indexed line numbers. */
  raw: string[];
  /** Comment-free lines, line numbers preserved. */
  code: string[];
}

interface Ctx {
  ctx: AnalyzerContext;
  map: RepoMap;
  lines: Map<string, FileLines>;
  /** Paths already reported as dead integrations, so later rules do not pile on. */
  deadIntegrations: Set<string>;
  /** True when the project resolves modules in ways this map cannot follow. */
  hasDynamicResolution: boolean;
}

function linesOf(c: Ctx, path: string): FileLines {
  const hit = c.lines.get(path);
  if (hit) return hit;
  const f = c.map.filesByPath.get(path);
  const text = f?.text ?? null;
  const value: FileLines = {
    raw: text ? text.split('\n') : [],
    code: codeText(text, f?.language).split('\n'),
  };
  c.lines.set(path, value);
  return value;
}

function codeAt(fl: FileLines, line: number): string {
  return fl.code[line - 1] ?? '';
}

/** Comment-free text of an inclusive line range. */
function codeRange(fl: FileLines, from: number, to: number): string {
  if (to < from) return '';
  return fl.code.slice(Math.max(0, from - 1), to).join('\n');
}

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function bracketBalance(line: string): number {
  let n = 0;
  for (const ch of line) {
    if (ch === '(' || ch === '[' || ch === '{') n++;
    else if (ch === ')' || ch === ']' || ch === '}') n--;
  }
  return n;
}

/**
 * The full text of a statement starting at `line`, following method-chain
 * continuation lines.
 *
 * A promise chain is almost always written across several lines, so looking at
 * the start line alone would report every chain as missing its `.catch`.
 */
function statementTextAt(fl: FileLines, line: number, maxLines = 24): string {
  let text = codeAt(fl, line);
  let balance = bracketBalance(text);
  for (let i = line + 1; i < line + maxLines && i <= fl.code.length; i++) {
    const next = codeAt(fl, i);
    const trimmed = next.trim();
    const continues = balance > 0 || trimmed.startsWith('.') || trimmed.startsWith('?.');
    if (!continues) break;
    text += `\n${next}`;
    balance += bracketBalance(next);
    if (balance <= 0 && /[;)]\s*$/.test(trimmed)) break;
  }
  return text;
}

function symbolNamed(mod: ParsedModule, name: string): SymbolInfo | undefined {
  return mod.symbols.find((s) => s.name === name && s.kind !== 'interface' && s.kind !== 'type');
}

function enclosingSymbol(mod: ParsedModule, line: number): SymbolInfo | undefined {
  const containing = mod.symbols.filter(
    (s) => s.startLine <= line && s.endLine >= line && (s.kind === 'function' || s.kind === 'arrow' || s.kind === 'method'),
  );
  // The innermost function wins.
  return containing.sort((a, b) => (b.startLine - a.startLine))[0];
}

function handlerOf(map: RepoMap, route: ApiEndpoint): SymbolInfo | undefined {
  const mod = map.modules.get(route.file);
  if (!mod) return undefined;
  return mod.symbols.find((s) => s.name === route.handlerSymbol && s.kind !== 'interface')
    ?? (route.line !== undefined
      ? mod.symbols.find((s) => s.startLine <= route.line! && s.endLine >= route.line!)
      : undefined);
}

function callsIn(mod: ParsedModule, from: number, to: number): ParsedModule['calls'] {
  return mod.calls.filter((c) => c.line >= from && c.line <= to);
}

function basenameOf(path: string): string {
  return path.slice(path.lastIndexOf('/') + 1);
}

function dirnameOf(path: string): string {
  const i = path.lastIndexOf('/');
  return i === -1 ? '' : path.slice(0, i);
}

const TEST_PATH_RE = /(?:^|\/)(?:tests?|__tests__|spec|e2e|cypress|fixtures?|mocks?|__mocks__)\//i;
const TEST_FILE_RE = /\.(?:test|spec)\.[cm]?[jt]sx?$/i;

function isTestPath(path: string): boolean {
  return TEST_PATH_RE.test(path) || TEST_FILE_RE.test(path);
}

/** Next.js app-router special files and page modules. */
const NEXT_SPECIAL_RE = /(?:^|\/)(?:page|layout|template|loading|error|global-error|not-found|default|route|middleware|instrumentation|sitemap|robots|opengraph-image|icon|manifest)\.[cm]?[jt]sx?$/;

/**
 * Entry points: a module the runtime loads directly is not "unused" merely
 * because nothing in the repository imports it.
 */
function isEntryPointLike(c: Ctx, path: string): boolean {
  const base = basenameOf(path);
  const stem = base.replace(/\.[cm]?[jt]sx?$/, '');
  if (['index', 'main', 'app', 'server', 'cli', 'bin', 'entry', 'worker', 'handler', 'mod', 'setup', '__init__'].includes(stem)) return true;
  if (NEXT_SPECIAL_RE.test(path)) return true;
  if (/\.(?:config|conf|setup|d)\.[cm]?[jt]sx?$/.test(base)) return true;
  if (/(?:^|\/)(?:scripts?|bin|migrations?|seeds?|prisma|public|\.github)\//.test(path)) return true;
  // Named in the manifest: main, module, exports, bin, or a script command.
  const manifest = c.map.files.find((f) => f.path === 'package.json' || /\/package\.json$/.test(f.path));
  if (manifest?.text && manifest.text.includes(stem) && new RegExp(`['"][^'"]*${escapeRe(stem)}(?:\\.[cm]?[jt]sx?)?['"]`).test(manifest.text)) {
    return true;
  }
  return false;
}

/**
 * True when any other module's source names this file in a module specifier.
 *
 * `export { x } from './y'` is recorded as an export, not an import, so a
 * barrel re-export does not reach `map.importers`. Checking the raw specifier
 * text closes that gap, and errs towards staying silent.
 */
function referencedBySpecifier(c: Ctx, path: string): boolean {
  const stem = basenameOf(path).replace(/\.[cm]?[jt]sx?$/, '');
  if (!stem) return true;
  const re = new RegExp(`from\\s*['"\`][^'"\`]*${escapeRe(stem)}['"\`]|import\\s*\\(\\s*['"\`][^'"\`]*${escapeRe(stem)}['"\`]|require\\s*\\(\\s*['"\`][^'"\`]*${escapeRe(stem)}['"\`]`);
  for (const other of c.map.modules.values()) {
    if (other.path === path) continue;
    const text = c.map.filesByPath.get(other.path)?.text;
    if (text && re.test(text)) return true;
  }
  return false;
}

function nonTestImporters(map: RepoMap, path: string): string[] {
  return (map.importers.get(path) ?? []).filter((p) => !isTestPath(p));
}

/** A model whose ORM accessor name matches, tolerating plural accessors. */
function modelFor(models: DataModel[], accessor: string): DataModel | undefined {
  const key = accessor.toLowerCase();
  return models.find((m) => m.name.toLowerCase() === key)
    ?? models.find((m) => `${m.name.toLowerCase()}s` === key)
    ?? models.find((m) => m.name.toLowerCase() === key.replace(/s$/, ''))
    ?? models.find((m) => m.name.toLowerCase().replace(/[_-]/g, '') === key.replace(/[_-]/g, ''));
}

function hasUnique(model: DataModel, column: string): boolean {
  const lower = column.toLowerCase();
  if (model.fields.some((f) => f.name.toLowerCase() === lower && f.unique)) return true;
  // Indexes are stored as 'a' or 'a+b' for compound definitions.
  return model.indexes.some((idx) => idx.toLowerCase() === lower);
}

// ---------------------------------------------------------------------------
// Analyzer
// ---------------------------------------------------------------------------

export const reliabilityAnalyzer: Analyzer = {
  id: 'reliability',
  category: 'reliability',
  description:
    'Broken code paths: frontend/backend contract breaks, unhandled async work, missing null and error handling, '
    + 'webhook idempotency, payment-state ordering, dead UI actions, unused integrations, and undocumented configuration.',

  precondition(map: RepoMap): string | undefined {
    const analysable = map.files.filter((f) => f.parsed && !f.generated && !f.vendored).length;
    if (analysable === 0) {
      return 'no file in this snapshot produced an AST, so no code path could be followed';
    }
    return undefined;
  },

  run(ctx: AnalyzerContext): Finding[] {
    const map = ctx.map;
    const c: Ctx = {
      ctx,
      map,
      lines: new Map(),
      deadIntegrations: new Set(),
      hasDynamicResolution: detectDynamicResolution(map),
    };

    const findings: Finding[] = [];

    // The flagship first: it is the finding no single file reveals.
    findings.push(...frontendBackendContractBreaks(c));
    findings.push(...unhandledPromiseChains(c));
    findings.push(...floatingPromises(c));
    findings.push(...uncheckedNullDereferences(c));
    findings.push(...nonIdempotentWebhooks(c));
    findings.push(...paymentStateOrdering(c));
    findings.push(...nonAtomicReadModifyWrite(c));
    findings.push(...deadUiActions(c));
    findings.push(...incompleteForms(c));
    findings.push(...unusedIntegrations(c));
    findings.push(...externalCallsWithoutTimeout(c));
    findings.push(...unreachableServers(c));
    findings.push(...routesWithoutErrorHandling(c));
    findings.push(...missingLoadingAndErrorStates(c));
    findings.push(...undocumentedEnvVars(c));

    return findings;
  },
};

/** True when the project resolves modules in ways the import graph cannot follow. */
function detectDynamicResolution(map: RepoMap): boolean {
  for (const mod of map.modules.values()) {
    const text = map.filesByPath.get(mod.path)?.text;
    if (!text) continue;
    if (/\bimport\s*\(\s*[^'"`)]/.test(text)) return true;
    if (/\brequire\s*\(\s*[^'"`)]/.test(text)) return true;
    if (/\brequire\.context\s*\(|\bglob(?:Sync)?\s*\(|importAll|readdirSync\s*\([^)]*\)\s*\.\s*map/.test(text)) return true;
  }
  return false;
}

// ------------------------------------------------- 1. contract breaks (flagship) ---

const RESPONSE_LITERAL_RE =
  /(?:NextResponse|Response|res|reply|response|ctx\.body|c)\s*\.\s*json\s*\(\s*\{|\bjsonify\s*\(\s*\{|\bJSONResponse\s*\(\s*(?:content\s*=\s*)?\{|\bres\.send\s*\(\s*\{/;

const RESPONSE_CALL_RE = /(?:^|\.)(?:json|send|jsonify|JSONResponse)$/;

const FETCH_LEAVES = new Set(['fetch', 'get', 'post', 'put', 'patch', 'delete', 'request', 'head']);

/** Properties that come from JavaScript itself, never from a response body. */
const INTRINSIC_PROPS = new Set([
  'length', 'map', 'filter', 'forEach', 'reduce', 'find', 'some', 'every', 'slice', 'join',
  'toString', 'valueOf', 'constructor', 'then', 'catch', 'finally', 'hasOwnProperty',
  'push', 'pop', 'concat', 'includes', 'indexOf', 'keys', 'values', 'entries', 'sort',
]);

interface DeclaredShape {
  typeName: string;
  line: number;
  keys: string[];
  /** Source of the declaration, used to spot optional members. */
  text: string;
}

function declaredShapesIn(mod: ParsedModule): DeclaredShape[] {
  const out: DeclaredShape[] = [];
  for (const lit of mod.objectLiterals) {
    if (!lit.inSymbol || lit.keys.length === 0) continue;
    const sym = mod.symbols.find(
      (s) => s.name === lit.inSymbol && (s.kind === 'interface' || s.kind === 'type') && s.startLine === lit.line,
    );
    if (!sym) continue;
    out.push({ typeName: sym.name, line: lit.line, keys: lit.keys, text: sym.text });
  }
  return out;
}

function isOptionalMember(shape: DeclaredShape, key: string): boolean {
  return new RegExp(`(?:^|[\\s;,{(])${escapeRe(key)}\\s*\\?\\s*:`).test(shape.text);
}

/** Literal URL of a client call, with interpolation holes preserved. */
function literalUrlOf(arg: string): string | undefined {
  const trimmed = arg.trim();
  const m = /^['"`]([^'"`]*)['"`]$/.exec(trimmed) ?? /^`([\s\S]*)`$/.exec(trimmed);
  const value = m?.[1];
  if (!value) return undefined;
  if (!value.startsWith('/') && !/^https?:\/\//.test(value)) return undefined;
  return value.replace(/^https?:\/\/[^/]+/, '') || '/';
}

function methodOfClientCall(callee: string, args: string[]): string | undefined {
  const leaf = callee.split('.').pop() ?? '';
  if (leaf !== 'fetch' && leaf !== 'request' && FETCH_LEAVES.has(leaf)) return leaf.toUpperCase();
  const options = args.slice(1).join(' ');
  const m = /\bmethod\s*:\s*['"`](\w+)['"`]/i.exec(options);
  if (m) return m[1]!.toUpperCase();
  return 'GET';
}

function routesMatching(map: RepoMap, url: string): ApiEndpoint[] {
  const clean = (url.split('?')[0] ?? '').replace(/\/$/, '') || '/';
  const parts = clean.split('/');
  return map.routes.filter((r) => {
    const rp = r.path.split('/');
    if (rp.length !== parts.length) return false;
    return rp.every((seg, i) => {
      const u = parts[i] ?? '';
      if (/^\[.*\]$/.test(seg) || seg.startsWith(':') || seg.startsWith('{') || seg === '*') return true;
      if (u.includes('${') || u === '*') return true;
      return seg === u;
    });
  });
}

function frontendBackendContractBreaks(c: Ctx): Finding[] {
  const { ctx, map } = c;
  const out: Finding[] = [];

  for (const mod of map.modules.values()) {
    if (!mod.parsed || isTestPath(mod.path)) continue;
    // A route file is the backend end, not the frontend end.
    if (map.routes.some((r) => r.file === mod.path)) continue;

    const shapes = declaredShapesIn(mod);
    if (shapes.length === 0) continue;

    for (const call of mod.calls) {
      const leaf = call.callee.split('.').pop() ?? '';
      if (!FETCH_LEAVES.has(leaf)) continue;
      const url = literalUrlOf(call.args[0] ?? '');
      if (!url) continue;

      const candidates = routesMatching(map, url);
      if (candidates.length === 0) continue;

      const method = methodOfClientCall(call.callee, call.args);
      const byMethod = candidates.filter((r) => r.method === method || r.method === 'ANY');
      // When the method cannot be pinned to exactly one handler the trace is
      // incomplete, and the gate caps the finding at `moderate`.
      const route = byMethod.length === 1 ? byMethod[0]! : candidates.length === 1 ? candidates[0]! : undefined;
      if (!route) continue;
      const methodResolved = byMethod.length === 1;

      if (!route.responseShape) continue;
      const sent = new Set(route.responseShape.split(',').map((k) => k.trim()).filter(Boolean));
      if (sent.size === 0) continue;

      const handler = handlerOf(map, route);
      if (!handler) continue;
      const handlerCode = codeText(handler.text);
      // A spread means the recorded shape is incomplete by construction, so a
      // missing key proves nothing.
      if (/\{\s*\.\.\.|,\s*\.\.\.|\*\*\w/.test(handlerCode)) continue;
      // The shape must come from an inline literal handed to the response, not
      // from the widest-object-literal fallback, which is often a query arg.
      if (!RESPONSE_LITERAL_RE.test(handlerCode)) continue;

      for (const shape of shapes) {
        const declared = new Set(shape.keys);
        const sharedWithRoute = shape.keys.filter((k) => sent.has(k));
        // The type must plausibly describe this response before its extra
        // members can be called a contract break.
        if (sharedWithRoute.length < 2) continue;

        // Which local object holds the parsed response: the one whose reads
        // line up with both the declared type and what the route sends.
        const byRoot = new Map<string, Array<{ property: string; line: number }>>();
        for (const access of mod.memberAccesses) {
          if (INTRINSIC_PROPS.has(access.property)) continue;
          const list = byRoot.get(access.object) ?? [];
          list.push({ property: access.property, line: access.line });
          byRoot.set(access.object, list);
        }

        for (const [root, accesses] of byRoot) {
          const props = [...new Set(accesses.map((a) => a.property))];
          const inDeclared = props.filter((p) => declared.has(p));
          if (inDeclared.length < 2) continue;
          if (!props.some((p) => sent.has(p))) continue;
          // An identifier that is an imported binding is not the response.
          if (mod.imports.some((imp) => imp.names.includes(root))) continue;

          const missing = inDeclared.filter((p) => !sent.has(p) && !isOptionalMember(shape, p));
          if (missing.length === 0) continue;

          const responseCall = callsIn(map.modules.get(route.file)!, handler.startLine, handler.endLine)
            .filter((rc) => RESPONSE_CALL_RE.test(rc.callee))
            .map((rc) => ({
              line: rc.line,
              score: sharedWithRoute.filter((k) => (rc.args[0] ?? '').includes(k)).length,
            }))
            .sort((a, b) => b.score - a.score)[0];
          const responseLine = responseCall && responseCall.score > 0 ? responseCall.line : (route.line ?? handler.startLine);

          for (const field of missing) {
            // If the handler mentions the name at all, it may be assembled by a
            // path the shape extraction cannot see. Stay silent.
            if (new RegExp(`\\b${escapeRe(field)}\\b`).test(handlerCode)) continue;

            const readLine = accesses.find((a) => a.property === field)!.line;
            const fl = linesOf(c, mod.path);
            // An optional read (`order?.field`) still renders nothing, but the
            // author has signalled that absence is expected.
            if (new RegExp(`${escapeRe(root)}\\s*\\?\\s*\\.\\s*${escapeRe(field)}`).test(codeAt(fl, readLine))) continue;

            const evidence: Evidence[] = [
              map.evidenceLine(mod.path, readLine,
                `the frontend reads ${root}.${field} from the response of ${route.method} ${route.path}`),
              map.evidenceLine(mod.path, shape.line,
                `${shape.typeName} declares ${field} as a non-optional member of that response`),
              map.evidenceLine(route.file, responseLine,
                `the handler responds with { ${route.responseShape} } — ${field} is not among the keys`),
              map.evidenceLine(mod.path, call.line,
                `client call that fetches ${route.method} ${route.path}`),
            ];

            const trace: RelationshipTrace = {
              kind: 'frontend_backend_contract',
              steps: [
                { file: mod.path, symbol: shape.typeName, line: shape.line, detail: `declares the response as { ${shape.keys.join(', ')} }` },
                { file: mod.path, symbol: enclosingSymbol(mod, call.line)?.name, line: call.line, detail: `calls ${route.method} ${route.path}` },
                { file: mod.path, symbol: enclosingSymbol(mod, readLine)?.name, line: readLine, detail: `reads ${root}.${field} from the parsed response` },
                { file: route.file, symbol: route.handlerSymbol, line: responseLine, detail: `handler returns { ${route.responseShape} }, without ${field}` },
              ],
              complete: methodResolved,
            };

            const confidence: Confidence = methodResolved ? 'strong' : 'moderate';

            out.push(ctx.finding({
              ruleId: 'reliability.contract.response_field_missing',
              title: `${basenameOf(mod.path)} reads ${field}, which ${route.method} ${route.path} never sends`,
              severity: 'high',
              confidence,
              detectionSource: 'graph',
              files: [mod.path, route.file],
              symbol: shape.typeName,
              evidence,
              trace,
              explanation:
                `${mod.path} declares the response of ${route.method} ${route.path} as ${shape.typeName}, which includes `
                + `a required member \`${field}\`, and reads \`${root}.${field}\` at line ${readLine}. The handler in ${route.file} `
                + `responds with an object literal whose keys are { ${route.responseShape} }. \`${field}\` is never serialised, so at `
                + `runtime the property is \`undefined\` — the declared type says otherwise, and because the type is a compile-time `
                + `assertion about data that crosses a network boundary, the compiler cannot catch the disagreement. `
                + `No single file shows this: the declaration and the read are in the component, the omission is in the handler.`,
              userImpact:
                `Wherever ${field} is shown, the user sees an empty space, the literal text "undefined", or a blank field, `
                + 'depending on how it is rendered. Nothing fails loudly: the page renders, the request succeeds, and the '
                + 'information the user came for is simply absent. If the value feeds a calculation or a comparison instead of '
                + 'being displayed, the result is wrong rather than missing.',
              likelyRootCause:
                'The response type was written from the intended shape of the feature, or copied from the data model, rather than '
                + 'from what the handler actually returns — or the handler was later narrowed and the consumer was not updated.',
              downstreamConsequences: [
                `Every other consumer of ${shape.typeName} inherits the same wrong assumption.`,
                'TypeScript reports no error, so the build and the type-check both pass.',
                `Adding ${field} to the handler is a response-shape change, and any client caching the old shape must be considered.`,
              ],
              remediation:
                `Decide which end is correct. If the field belongs in the response, add it to the handler's returned object and `
                + `make sure the query actually selects it. If it does not, remove it from ${shape.typeName} and from the render path, `
                + 'and let the compiler point at every consumer. To stop the pair drifting again, derive one end from the other: '
                + 'generate the client type from the handler (or from a shared schema validated at the boundary) instead of declaring '
                + 'it twice by hand, and parse the response against that schema so a missing field fails at the boundary rather than '
                + 'silently rendering as undefined.',
              effort: 'small',
              verificationSteps: [
                `Call ${route.method} ${route.path} directly and inspect the JSON body for a \`${field}\` key.`,
                `Render the component against that real response and confirm ${field} displays a value.`,
                `Add a test that asserts the handler's response contains every required member of ${shape.typeName}.`,
              ],
              references: [
                'CWE-1288 Improper Validation of Consistency within Input',
                'OpenAPI / typed-contract generation as the standard remedy for duplicated response types',
              ],
            }));
          }
        }
      }
    }
  }
  return dedupe(out);
}

// ------------------------------------------------------ 2. unhandled chains ---

function unhandledPromiseChains(c: Ctx): Finding[] {
  const { ctx, map } = c;
  const out: Finding[] = [];
  const globalHandler = hasGlobalRejectionHandler(map);

  for (const mod of map.modules.values()) {
    if (!mod.parsed || isTestPath(mod.path)) continue;
    const fl = linesOf(c, mod.path);

    const byLine = new Map<number, { callee: string; args: string[] }>();
    for (const call of mod.calls) {
      if (!/(?:^|\.)then$/.test(call.callee)) continue;
      const existing = byLine.get(call.line);
      const depth = (call.callee.match(/\.then/g) ?? []).length;
      const existingDepth = existing ? (existing.callee.match(/\.then/g) ?? []).length : -1;
      if (depth >= existingDepth) byLine.set(call.line, { callee: call.callee, args: call.args });
    }

    for (const [line, chain] of byLine) {
      // A rejection handler anywhere in the chain, in either form.
      if (/\.(?:catch|finally)\b/.test(chain.callee)) continue;
      if (chain.args.length >= 2) continue;

      const statement = statementTextAt(fl, line);
      if (/\.\s*catch\s*\(|\.\s*finally\s*\(/.test(statement)) continue;

      // Only a bare expression statement loses the rejection. Returned,
      // awaited, or assigned chains hand it to someone who may handle it.
      const head = codeAt(fl, line).trim();
      const root = (chain.callee.split('.')[0] ?? '').replace(/\(\)$/, '');
      if (!root) continue;
      if (!new RegExp(`^${escapeRe(root)}\\b`).test(head)) continue;
      if (/^\s*(?:return|await|yield|void|export|throw)\b/.test(head)) continue;

      const symbol = enclosingSymbol(mod, line);
      const confidence: Confidence = globalHandler ? 'moderate' : 'strong';
      const inComponent = mod.jsx.length > 0;

      out.push(ctx.finding({
        ruleId: 'reliability.async.unhandled_promise_chain',
        title: `Promise chain with no rejection handler in ${basenameOf(mod.path)}`,
        severity: inComponent ? 'medium' : 'high',
        confidence,
        files: [mod.path],
        symbol: symbol?.name,
        evidence: [
          map.evidenceLine(mod.path, line, 'promise chain started here has no .catch() and no second then() argument'),
        ],
        explanation:
          `The chain starting at ${mod.path}:${line} attaches success handlers with .then() but never attaches a rejection `
          + 'handler, and the chain is a bare expression statement, so the promise is not returned, awaited, or assigned either. '
          + 'If the request fails — a network error, a non-JSON body, a 500 — the rejection has nowhere to go. It surfaces as an '
          + '`unhandledrejection` event in the browser, or as an unhandled rejection in Node, where recent versions terminate the '
          + 'process by default. The success handlers simply never run.'
          + (globalHandler
            ? ' This project registers a global unhandled-rejection handler, which may log the failure; it cannot repair the state '
              + 'the chain left half-initialised, so the user-visible outcome is unchanged.'
            : ''),
        userImpact:
          inComponent
            ? 'On failure the component never leaves its initial state: the user sees an empty panel, a spinner that never stops, '
              + 'or stale content, with no error message and nothing to retry. The interface looks like it is still loading '
              + 'forever, so the usual response is to reload and try again, which fails the same way.'
            : 'On failure the work silently does not happen, and in Node the unhandled rejection can take the process down, '
              + 'turning one failed request into an outage for every request in flight.',
        likelyRootCause:
          'The chain was written against the success path. A `.catch()` is easy to omit because nothing warns about it and the '
          + 'happy path works in development, where the request rarely fails.',
        downstreamConsequences: [
          'The failure is invisible to monitoring unless a global handler reports it.',
          'Any state the chain was supposed to set keeps its initial value, so later code reads it as empty rather than failed.',
        ],
        remediation:
          'Attach a rejection handler that puts the UI or the caller into an explicit error state rather than leaving it in the '
          + 'loading state: `.catch((err) => { report(err); setError(err); })`, and distinguish "loading", "loaded", and "failed" '
          + 'so the render path can tell them apart. Check `response.ok` before parsing, because a 4xx or 5xx does not reject a '
          + 'fetch promise. In new code prefer `await` inside `try/catch`, which makes an unhandled path a visible omission.',
        effort: 'trivial',
        verificationSteps: [
          'Block or fail the request (offline mode, or a route that returns 500) and confirm the UI shows an error state rather than staying blank.',
          'Confirm no `unhandledrejection` is logged in the browser console during that failure.',
          'Add a test that makes the request reject and asserts the error state is reached.',
        ],
        references: [
          'CWE-391 Unchecked Error Condition',
          'MDN: Promise rejection handling — unhandledrejection',
        ],
      }));
    }
  }
  return out;
}

function hasGlobalRejectionHandler(map: RepoMap): boolean {
  for (const f of map.files) {
    if (!f.text) continue;
    if (/unhandledrejection|unhandledRejection/.test(f.text)) return true;
  }
  return false;
}

// ----------------------------------------------------- 3. floating promises ---

const ASYNC_IO_CALLEE_RE =
  /(?:^|\.)(?:fetch|findMany|findUnique|findFirst|create|createMany|update|updateMany|upsert|delete|deleteMany|save|insert|execute|executemany|writeFile|readFile|appendFile|sendMail|sendEmail|publish|enqueue|dispatchEvent)$/;

function floatingPromises(c: Ctx): Finding[] {
  const { ctx, map } = c;
  const out: Finding[] = [];

  for (const mod of map.modules.values()) {
    if (!mod.parsed || isTestPath(mod.path)) continue;
    const fl = linesOf(c, mod.path);

    for (const call of mod.calls) {
      if (call.awaited) continue;
      const leaf = call.callee.split('.').pop() ?? '';
      if (leaf === 'then' || leaf === 'catch' || leaf === 'finally') continue;

      // Why we believe this call returns a promise.
      const localAsync = mod.symbols.find((s) => s.name === call.callee && s.async);
      const importedAsync = !localAsync ? importedAsyncSymbol(map, mod, call.callee) : undefined;
      const patternAsync = ASYNC_IO_CALLEE_RE.test(call.callee);
      if (!localAsync && !importedAsync && !patternAsync) continue;

      const head = codeAt(fl, call.line).trim();
      const root = call.callee.split('.')[0] ?? '';
      if (!root || !new RegExp(`^${escapeRe(root)}\\b`).test(head)) continue;
      if (/^\s*(?:return|await|yield|void|export|throw)\b/.test(head)) continue;

      const statement = statementTextAt(fl, call.line);
      if (/\.\s*(?:then|catch|finally)\s*\(/.test(statement)) continue;

      const symbol = enclosingSymbol(mod, call.line);
      const source = localAsync
        ? `${call.callee} is declared \`async\` in this module`
        : importedAsync
          ? `${call.callee} is declared \`async\` in ${importedAsync}`
          : `${call.callee} is an asynchronous I/O call`;
      const confidence: Confidence = localAsync || importedAsync ? 'strong' : 'moderate';

      out.push(ctx.finding({
        ruleId: 'reliability.async.floating_promise',
        title: `${call.callee}() is called without await and its result is discarded`,
        severity: 'medium',
        confidence,
        files: [mod.path],
        symbol: symbol?.name,
        evidence: [map.evidenceLine(mod.path, call.line, `${source}; the returned promise is neither awaited, returned, nor handled`)],
        explanation:
          `${mod.path}:${call.line} calls ${call.callee}() as a statement and throws the returned promise away. `
          + `${source}, so the work it starts is still in flight when the surrounding function continues. Two things follow: the `
          + 'code after this line runs before the operation completes, and if the operation rejects there is no handler, which '
          + 'surfaces as an unhandled rejection rather than an error anyone can act on.',
        userImpact:
          'The user is told the action succeeded before it has actually finished, and if it fails they are never told at all. '
          + 'In a request handler the response can be sent — and the process torn down or the serverless invocation frozen — '
          + 'before the operation lands, so the write silently does not happen some fraction of the time.',
        likelyRootCause:
          'An `await` was omitted, often because the call was treated as fire-and-forget, or because the function was made '
          + 'asynchronous after this call site was written.',
        downstreamConsequences: [
          'Ordering guarantees the surrounding code appears to have do not hold.',
          'In a serverless runtime the work may be abandoned when the response is returned.',
        ],
        remediation:
          'Await the call, or return its promise so the caller can. If it is genuinely meant to be fire-and-forget, make that '
          + 'explicit and safe: attach a rejection handler that reports the failure, and in a serverless runtime hand the work to '
          + 'the platform\'s background mechanism (for example a queue, or `waitUntil`) so it is guaranteed to run to completion. '
          + 'Enabling a no-floating-promises lint rule stops the next one reaching the repository.',
        effort: 'trivial',
        verificationSteps: [
          'Confirm the surrounding function waits for the operation before returning or responding.',
          'Make the operation fail and confirm the failure is reported rather than becoming an unhandled rejection.',
        ],
        references: ['CWE-703 Improper Check or Handling of Exceptional Conditions'],
      }));
    }
  }
  return out;
}

/** The module an imported symbol comes from, when that symbol is async there. */
function importedAsyncSymbol(map: RepoMap, mod: ParsedModule, callee: string): string | undefined {
  const name = callee.split('.')[0] ?? '';
  const imp = mod.imports.find((i) => i.resolvedPath && i.names.includes(name));
  if (!imp?.resolvedPath) return undefined;
  const target = map.modules.get(imp.resolvedPath);
  const sym = target?.symbols.find((s) => s.name === name && s.async);
  return sym ? imp.resolvedPath : undefined;
}

// -------------------------------------------- 4. unchecked null dereference ---

/**
 * Finders whose documented contract is "the row or null".
 *
 * `findFirstOrThrow`, `findUniqueOrThrow`, and friends are deliberately absent:
 * they throw, which is a handled path.
 */
const NULLABLE_FINDER_RE = /^(?:\w+\.)*\w+\.(findUnique|findFirst|findOne|findById|findByPk|maybeSingle|queryOne|getOne)$/;

const NULLABLE_ORMS = ['Prisma', 'Mongoose', 'Sequelize', 'TypeORM', 'Drizzle', 'Supabase'];

function uncheckedNullDereferences(c: Ctx): Finding[] {
  const { ctx, map } = c;
  const out: Finding[] = [];
  const ormKnown = NULLABLE_ORMS.some((o) => map.hasTech(o));

  for (const mod of map.modules.values()) {
    if (!mod.parsed || isTestPath(mod.path)) continue;
    const fl = linesOf(c, mod.path);

    for (const call of mod.calls) {
      const m = NULLABLE_FINDER_RE.exec(call.callee);
      if (!m) continue;

      // The binding this result was assigned to.
      const binding = mod.symbols.find(
        (s) => (s.kind === 'const' || s.kind === 'arrow') && s.startLine === call.line,
      );
      if (!binding) continue;
      const name = binding.name;

      const derefs = mod.memberAccesses
        .filter((a) => a.object === name && a.line > binding.endLine)
        .sort((a, b) => a.line - b.line);
      if (derefs.length === 0) continue;
      const first = derefs[0]!;

      // Everything between the binding and the first dereference is where a
      // guard would live.
      const between = codeRange(fl, binding.startLine, first.line - 1);
      const derefLine = codeAt(fl, first.line);
      if (hasNullGuard(between, name)) continue;
      // An explicit `?.` or `!` is the author handling or asserting it.
      if (new RegExp(`${escapeRe(name)}\\s*(?:\\?\\s*\\.|!\\s*\\.)`).test(derefLine)) continue;
      if (hasNullGuard(derefLine, name)) continue;

      const route = map.routes.find(
        (r) => r.file === mod.path && r.line !== undefined && handlerRangeContains(map, r, call.line),
      );
      const guarded = mod.hasTryCatch;
      const severity: Severity = route && !guarded ? 'high' : guarded ? 'medium' : 'high';
      const confidence: Confidence = ormKnown ? 'strong' : 'moderate';

      out.push(ctx.finding({
        ruleId: 'reliability.null.unchecked_dereference',
        title: `\`${name}\` from ${call.callee}() is dereferenced without a null check`,
        severity,
        confidence,
        files: [mod.path],
        symbol: binding.name,
        evidence: [
          map.evidenceLine(mod.path, call.line, `${call.callee}() resolves to the row or null`),
          map.evidenceLine(mod.path, first.line, `\`${name}.${first.property}\` is read with no check that \`${name}\` exists`),
        ],
        trace: {
          kind: 'call',
          steps: [
            { file: mod.path, symbol: enclosingSymbol(mod, call.line)?.name, line: call.line, detail: `${name} assigned from ${call.callee}(), which returns null when no row matches` },
            { file: mod.path, symbol: enclosingSymbol(mod, first.line)?.name, line: first.line, detail: `${name}.${first.property} read with no intervening null check` },
          ],
          complete: true,
        },
        explanation:
          `${call.callee}() returns the matching row or null — that is its contract, not an edge case. At ${mod.path}:${call.line} `
          + `the result is bound to \`${name}\`, and at line ${first.line} \`${name}.${first.property}\` is read with nothing in between `
          + `that tests whether \`${name}\` exists. When the identifier does not match a row — a deleted record, a stale link, a `
          + `mistyped or guessed id — the read throws "Cannot read properties of null".`
          + (route
            ? ` This sits in the ${route.method} ${route.path} handler, so the failure is a request failure.`
            : ''),
        userImpact:
          route
            ? 'A request for a record that does not exist returns a 500 instead of a 404. The user sees a generic failure page or '
              + 'an error toast that suggests the application is broken rather than that the thing they asked for is not there, '
              + 'and retrying never helps. Operationally the same bad link produces a stream of server errors that drown real '
              + 'incidents in the logs.'
            : 'The operation crashes instead of reporting that the record is missing, so the user sees a hard failure rather than '
              + 'a clear "not found".',
        likelyRootCause:
          'The lookup was written for the case where the record exists, which is the only case exercised by hand during development.',
        downstreamConsequences: [
          'The distinction between "missing" and "broken" is lost in both the response and the logs.',
          'Error-rate alerting fires on ordinary user behaviour, which trains the team to ignore it.',
        ],
        remediation:
          `Test for null immediately after the lookup and return the correct outcome — a 404 response, a "not found" state, or `
          + `whatever the surrounding code means by absence — before any property is read. Where the ORM offers a throwing variant `
          + `(for example \`findUniqueOrThrow\`) that is caught centrally and mapped to a 404, that is equally good. Narrowing the `
          + `type at the boundary, rather than reaching for \`?.\` or \`!\` at each use, keeps the compiler on your side for every `
          + `later read of \`${name}\`.`,
        effort: 'trivial',
        verificationSteps: [
          'Request the record with an id that does not exist and confirm the response is a 404 (or the equivalent) with no stack trace.',
          'Confirm the server logs no exception for that request.',
          'Add a test for the missing-record case alongside the existing happy-path test.',
        ],
        references: ['CWE-476 NULL Pointer Dereference', 'CWE-754 Improper Check for Unusual or Exceptional Conditions'],
      }));
    }
  }
  return out;
}

function hasNullGuard(text: string, name: string): boolean {
  const n = escapeRe(name);
  const patterns = [
    new RegExp(`if\\s*\\(\\s*!\\s*${n}\\b`),
    new RegExp(`if\\s*\\(\\s*${n}\\s*(?:===?|!==?)\\s*(?:null|undefined)`),
    new RegExp(`if\\s*\\(\\s*(?:null|undefined)\\s*(?:===?|!==?)\\s*${n}\\b`),
    new RegExp(`if\\s*\\(\\s*${n}\\s*\\)`),
    new RegExp(`${n}\\s*(?:\\?\\?|\\|\\||&&)`),
    new RegExp(`${n}\\s*\\?[^.:]`),
    new RegExp(`(?:assert|invariant|ensure|require|guard|notFound|abort|raise_for_status)\\s*\\(\\s*!?\\s*${n}\\b`),
    new RegExp(`${n}\\s+is\\s+(?:not\\s+)?None`),
    new RegExp(`if\\s+not\\s+${n}\\b`),
  ];
  return patterns.some((re) => re.test(text));
}

function handlerRangeContains(map: RepoMap, route: ApiEndpoint, line: number): boolean {
  const handler = handlerOf(map, route);
  return !!handler && handler.startLine <= line && handler.endLine >= line;
}

// ------------------------------------------------- 5. webhook idempotency ---

const EVENT_WRITE_RE = /^(?:\w+\.)*(\w+)\.(create|createMany|insert|save|add)$/;
const EXISTENCE_CHECK_RE = /(?:^|\.)(?:findUnique|findFirst|findOne|count|exists|get|has)$/;
const EVENT_ID_COLUMN_RE =
  /^(?:event|external|provider|delivery|message|request|webhook|stripe|paypal|razorpay|idempotency|idempotence|dedupe|dedup)_?(?:id|key|token|uuid)$/i;

function isWebhookRoute(route: ApiEndpoint): boolean {
  return /webhook|web_hook|callback\/|\/hooks?(?:\/|$)/i.test(route.path) || /webhook/i.test(route.file);
}

function nonIdempotentWebhooks(c: Ctx): Finding[] {
  const { ctx, map } = c;
  const out: Finding[] = [];

  for (const route of map.routes) {
    if (!isWebhookRoute(route)) continue;
    const mod = map.modules.get(route.file);
    const handler = handlerOf(map, route);
    if (!mod || !handler) continue;
    const handlerCode = codeText(handler.text);

    // A write the provider can deliver twice.
    for (const call of callsIn(mod, handler.startLine, handler.endLine)) {
      const m = EVENT_WRITE_RE.exec(call.callee);
      if (!m) continue;
      const accessor = m[1]!;
      const model = modelFor(map.models, accessor);
      if (!model) continue;

      const args = call.args.join(' ');
      const columns = [...new Set([...args.matchAll(/(\w+)\s*:/g)].map((x) => x[1]!))];
      const eventIdColumn = columns.find((col) => EVENT_ID_COLUMN_RE.test(col));
      if (!eventIdColumn) continue;

      // Guards that make a replay harmless.
      if (hasUnique(model, eventIdColumn)) continue;
      if (/\bupsert\b|onConflict|ON\s+CONFLICT|skipDuplicates|ignoreDuplicates|INSERT\s+IGNORE/i.test(handlerCode)) continue;
      const checkedFirst = callsIn(mod, handler.startLine, call.line - 1).some(
        (prev) => EXISTENCE_CHECK_RE.test(prev.callee)
          && (prev.callee.toLowerCase().includes(accessor.toLowerCase())
            || prev.args.join(' ').includes(eventIdColumn)),
      );
      if (checkedFirst) continue;

      // Any state change in the same handler is what a replay would repeat.
      const stateWrites = callsIn(mod, handler.startLine, handler.endLine)
        .filter((w) => /^(?:\w+\.)*\w+\.(update|updateMany|upsert|increment|decrement|delete|deleteMany)$/.test(w.callee))
        .map((w) => ({ callee: w.callee, line: w.line }));

      const evidence: Evidence[] = [
        map.evidenceLine(route.file, call.line,
          `the provider's event id is written here with no uniqueness check before the write`),
        // The schema column is located by its declaration text, not a line number.
        map.evidenceAt(model.file, eventIdColumn,
          `${model.name}.${eventIdColumn} carries no unique constraint, so the database will accept the same event twice`),
      ];
      for (const w of stateWrites.slice(0, 2)) {
        evidence.push(map.evidenceLine(route.file, w.line, `${w.callee}() in the same handler is repeated on a replayed delivery`));
      }

      out.push(ctx.finding({
        ruleId: 'reliability.webhook.non_idempotent',
        title: `${route.method} ${route.path} processes a replayed delivery twice`,
        severity: stateWrites.length > 0 ? 'high' : 'medium',
        confidence: 'strong',
        detectionSource: 'graph',
        files: [route.file, model.file],
        symbol: route.handlerSymbol,
        evidence,
        trace: {
          kind: 'webhook_idempotency',
          steps: [
            { file: route.file, symbol: route.handlerSymbol, line: route.line, detail: `${route.method} ${route.path} receives provider deliveries` },
            ...stateWrites.slice(0, 2).map((w) => ({
              file: route.file, symbol: route.handlerSymbol, line: w.line,
              detail: `changes state via ${w.callee}() before recording the event`,
            })),
            { file: route.file, symbol: route.handlerSymbol, line: call.line, detail: `records the delivery with ${call.callee}(), without first checking whether ${eventIdColumn} has been seen` },
            { file: model.file, detail: `${model.name}.${eventIdColumn} has no unique index: indexes present are [${model.indexes.join(', ') || 'none'}]` },
          ],
          complete: true,
        },
        explanation:
          `Webhook providers guarantee at-least-once delivery, not exactly-once: a delivery is retried whenever the response is `
          + `slow, non-2xx, or lost, and the same event id arrives again. This handler records the delivery with `
          + `${call.callee}() and nothing makes that record unique — there is no read of ${model.name} by ${eventIdColumn} before `
          + `the write, and the schema puts no unique constraint on the column (declared indexes: `
          + `${model.indexes.join(', ') || 'none'}). The duplicate insert therefore succeeds`
          + (stateWrites.length > 0
            ? `, and every state change in the handler (${stateWrites.map((w) => w.callee).join(', ')}) runs a second time.`
            : '.')
          + ' Neither file shows the problem alone: the handler looks like it is recording events, and the schema looks like an '
          + 'ordinary table.',
        userImpact:
          stateWrites.length > 0
            ? 'A customer can be charged, credited, or fulfilled twice for one real event — the duplicate looks exactly like a '
              + 'legitimate second event, so it is not caught until someone reconciles the books or the customer complains. '
              + 'Refunds and goodwill follow, and the ledger disagrees with the provider\'s.'
            : 'The same event is recorded more than once, so counts, exports, and anything derived from the event log overstate '
              + 'what actually happened.',
        likelyRootCause:
          'The handler was written against a single successful delivery. Retries only appear in production, under exactly the '
          + 'conditions (timeouts, deploys, provider incidents) that make them hardest to notice.',
        downstreamConsequences: [
          'Retries cluster during incidents and deploys, so duplicates arrive precisely when the team is already busy.',
          'Reconciliation against the provider becomes manual, because the local record no longer maps one-to-one onto their events.',
          'Any downstream consumer of these rows (emails, analytics, accounting) multiplies the error.',
        ],
        remediation:
          `Make the delivery record the idempotency key. Add a unique constraint on ${model.name}.${eventIdColumn} and insert it `
          + `*before* doing any work, treating a unique-violation as "already processed" and returning 2xx immediately. Where the `
          + `ORM supports it, a single conditional insert (\`create\` caught on unique violation, or \`upsert\`/\`ON CONFLICT DO `
          + `NOTHING\`) is enough. Run the insert and the state change in one transaction so a crash between them cannot leave the `
          + `event recorded but the work undone. Verifying the provider's signature is a separate and equally necessary control.`,
        effort: 'medium',
        verificationSteps: [
          'Add the unique constraint by migration and confirm it applies on a copy of production data (existing duplicates must be resolved first).',
          'Replay one real delivery twice against a test environment and confirm the second is acknowledged with 2xx and changes nothing.',
          'Add a test that posts the same event id twice and asserts exactly one state change.',
          'Check the provider dashboard for deliveries that were retried, and reconcile any that were processed more than once.',
        ],
        references: [
          'CWE-837 Improper Enforcement of a Single, Unique Action',
          'Stripe: Webhooks — handle duplicate events',
        ],
      }));
    }
  }
  return dedupe(out);
}

// ----------------------------------------------- 6. payment-state ordering ---

const PAID_STATE_RE =
  /\b(?:status|state|payment_?status|order_?status|fulfillment_?status|paid|is_?paid|fulfilled|completed?)\s*[:=]\s*(?:true|['"`](?:paid|complete|completed|success|succeeded|fulfilled|confirmed|settled|active|captured)\b)/i;

const OUTCOME_READ_RE =
  /\b\w+\s*\??\.\s*(?:type|status|state|outcome|paid|payment_?status|payment_?intent|result|succeeded|failure_?code|failure_?message|last_?payment_?error)\b/;

const OUTCOME_LITERAL_RE =
  /['"`][\w.\-]*(?:fail|failed|declin|cancel|canceled|cancelled|expire|expired|refund|succeed|succeeded|payment_intent|charge)[\w.\-]*['"`]/i;

const PAYMENT_CONTEXT_RE =
  /stripe|paypal|razorpay|braintree|adyen|square|checkout|payment|charge|invoice|subscription|billing|refund|payout/i;

function paymentStateOrdering(c: Ctx): Finding[] {
  const { ctx, map } = c;
  const out: Finding[] = [];

  for (const route of map.routes) {
    const mod = map.modules.get(route.file);
    const handler = handlerOf(map, route);
    if (!mod || !handler) continue;
    const handlerCode = codeText(handler.text);
    if (!PAYMENT_CONTEXT_RE.test(`${route.path} ${route.file} ${handlerCode}`)) continue;

    const fl = linesOf(c, route.file);

    // The line that marks the record settled.
    let stateLine: number | undefined;
    let stateCall: string | undefined;
    for (const call of callsIn(mod, handler.startLine, handler.endLine)) {
      if (!/^(?:\w+\.)*\w+\.(update|updateMany|upsert|save|update_one|findOneAndUpdate)$/.test(call.callee)) continue;
      if (!PAID_STATE_RE.test(call.args.join(' '))) continue;
      // Prefer the exact line the state is written on, not the call line.
      let exact = call.line;
      for (let i = call.line; i <= Math.min(call.line + 12, handler.endLine); i++) {
        if (PAID_STATE_RE.test(codeAt(fl, i))) { exact = i; break; }
      }
      if (stateLine === undefined || exact < stateLine) { stateLine = exact; stateCall = call.callee; }
    }
    if (stateLine === undefined) continue;

    // The first line that examines the provider's outcome.
    let outcomeLine: number | undefined;
    for (let i = handler.startLine; i <= handler.endLine; i++) {
      const line = codeAt(fl, i);
      if (!/\b(?:if|elif|else\s+if|switch|match)\b/.test(line) && !/\?\s*[^:]*:/.test(line)) continue;
      if (!OUTCOME_READ_RE.test(line) && !OUTCOME_LITERAL_RE.test(line)) continue;
      outcomeLine = i;
      break;
    }
    if (outcomeLine === undefined || outcomeLine <= stateLine) continue;

    out.push(ctx.finding({
      ruleId: 'reliability.payment.state_before_outcome',
      title: `${route.method} ${route.path} marks the record settled before reading the payment outcome`,
      severity: 'critical',
      confidence: 'strong',
      files: [route.file],
      symbol: route.handlerSymbol,
      evidence: [
        map.evidenceLine(route.file, stateLine, 'the record is marked settled here, unconditionally'),
        map.evidenceLine(route.file, outcomeLine, 'the provider\'s outcome is only examined here, after the write above'),
      ],
      trace: {
        kind: 'call',
        steps: [
          { file: route.file, symbol: route.handlerSymbol, line: stateLine, detail: `${stateCall ?? 'state write'} sets the settled state with no condition on the outcome` },
          { file: route.file, symbol: route.handlerSymbol, line: outcomeLine, detail: 'the success/failure branch is evaluated after the state has already been written' },
        ],
        complete: true,
      },
      explanation:
        `In the ${route.method} ${route.path} handler the record is marked settled at line ${stateLine}, and the provider's `
        + `outcome field is not examined until line ${outcomeLine}. The write is therefore unconditional: it runs for a failed `
        + `charge, a cancelled payment, a dispute, and a test event exactly as it runs for a successful one. The branch below can `
        + `log the failure or alert on it, but the state it would need to prevent has already been committed, and nothing in this `
        + `handler reverses it.`,
      userImpact:
        'An order whose payment failed is treated as paid: it is fulfilled, shipped, or unlocked, and the customer receives goods '
        + 'or access that was never paid for. The mirror case is just as bad — a customer whose payment genuinely succeeded cannot '
        + 'be distinguished from one whose did not, so support has no reliable answer, and the business discovers the gap through '
        + 'reconciliation rather than through the application.',
      likelyRootCause:
        'The handler was written for the success event and later extended with a failure branch, which was appended to the end of '
        + 'the function instead of placed before the state change.',
      downstreamConsequences: [
        'Revenue reported by the application diverges from the provider\'s settlement records.',
        'Fulfilment, entitlement, and email flows triggered by the settled state all fire on failed payments.',
        'Correcting the data later requires matching every affected record against the provider by hand.',
      ],
      remediation:
        'Read the outcome first and make the state change conditional on it. Branch on the event type or the payment status at the '
        + 'top of the handler, return early for anything that is not a confirmed success, and only then write the settled state — '
        + 'ideally in the same transaction as the idempotency record, so a crash cannot settle a record without logging why. Treat '
        + 'unknown or new event types as "do nothing" rather than as success, and let the provider retry what you did not handle.',
      effort: 'small',
      verificationSteps: [
        'Send a failure event (the provider\'s test mode can generate a declined charge) and confirm the record is not marked settled.',
        'Send a success event and confirm it is.',
        'Send an event type the handler does not recognise and confirm nothing changes.',
        'Query for records in the settled state whose provider payment is not successful, to size any damage already done.',
      ],
      references: [
        'CWE-840 Business Logic Errors',
        'CWE-696 Incorrect Behavior Order',
      ],
    }));
  }
  return out;
}

// --------------------------------------------- 7. non-atomic read-modify-write ---

const READ_FOR_WRITE_RE = /^(?:\w+\.)*(\w+)\.(findUnique|findFirst|findOne|findById|findByPk|count|aggregate)$/;
const WRITE_RE = /^(?:\w+\.)*(\w+)\.(update|updateMany|upsert|delete|deleteMany|create|save|increment|decrement)$/;
const TRANSACTION_RE =
  /\$transaction|\.transaction\s*\(|withTransaction|BEGIN\b|FOR\s+UPDATE|SERIALIZABLE|atomic\s*\(|select_for_update|session\.begin/i;

function nonAtomicReadModifyWrite(c: Ctx): Finding[] {
  const { ctx, map } = c;
  const out: Finding[] = [];

  for (const route of map.routes) {
    const mod = map.modules.get(route.file);
    const handler = handlerOf(map, route);
    if (!mod || !handler) continue;
    const handlerCode = codeText(handler.text);
    if (TRANSACTION_RE.test(handlerCode)) continue;

    const calls = callsIn(mod, handler.startLine, handler.endLine);
    for (const read of calls) {
      const rm = READ_FOR_WRITE_RE.exec(read.callee);
      if (!rm) continue;
      const accessor = rm[1]!;
      const model = modelFor(map.models, accessor);
      if (!model) continue;

      const write = calls.find((w) => {
        if (w.line <= read.line) return false;
        const wm = WRITE_RE.exec(w.callee);
        return !!wm && wm[1]!.toLowerCase() === accessor.toLowerCase();
      });
      if (!write) continue;

      // The write must depend on what was read, or there is no lost update.
      const binding = mod.symbols.find((s) => s.kind === 'const' && s.startLine === read.line);
      const writeArgs = write.args.join(' ');
      const dependent = !!binding && new RegExp(`\\b${escapeRe(binding.name)}\\b`).test(writeArgs);
      if (!dependent) continue;

      out.push(ctx.finding({
        ruleId: 'reliability.concurrency.non_atomic_update',
        title: `${route.method} ${route.path} reads ${model.name} and writes it back without a transaction`,
        severity: 'medium',
        confidence: 'moderate',
        status: 'needs_runtime_verification',
        files: [route.file],
        symbol: route.handlerSymbol,
        evidence: [
          map.evidenceLine(route.file, read.line, `${read.callee}() reads the current ${model.name} row`),
          map.evidenceLine(route.file, write.line, `${write.callee}() writes back a value derived from that read`),
        ],
        trace: {
          kind: 'call',
          steps: [
            { file: route.file, symbol: route.handlerSymbol, line: read.line, detail: `reads ${model.name} with ${read.callee}()` },
            { file: route.file, symbol: route.handlerSymbol, line: write.line, detail: `writes the derived value with ${write.callee}(), outside any transaction` },
          ],
          complete: true,
        },
        explanation:
          `The handler reads a ${model.name} row at line ${read.line} and writes a value derived from it at line ${write.line}, with `
          + 'no transaction, row lock, or conditional update between the two. Two requests that interleave between the read and the '
          + 'write both act on the same starting value, and the second write overwrites the first. Whether this actually happens '
          + 'depends on real concurrency, which a snapshot cannot show — this finding reports that nothing prevents it, not that it '
          + 'has occurred, and is marked for runtime verification for exactly that reason.',
        userImpact:
          'Under concurrent use one of the two changes silently disappears. Both users are told their action succeeded, and only '
          + 'one of them was. Where the value is a balance, a stock level, or a counter, the stored number ends up higher or lower '
          + 'than the real one, and the discrepancy is only noticed later.',
        likelyRootCause:
          'Read-then-write is the natural way to express the change, and single-user testing never interleaves two requests.',
        downstreamConsequences: [
          'The error compounds: each lost update moves the stored value further from the truth.',
          'Reproducing it requires concurrent load, so it tends to be dismissed as a data-entry mistake.',
        ],
        remediation:
          'Make the update atomic rather than computed in application code. Prefer a single conditional or relative statement the '
          + 'database evaluates (an `increment`/`decrement`, or an update whose WHERE clause includes the value or version you read). '
          + 'Where the logic genuinely needs several statements, wrap them in one transaction and take a row lock, or add an optimistic '
          + 'version column and retry on conflict. Confirm the chosen isolation level actually provides what the code assumes.',
        effort: 'medium',
        verificationSteps: [
          'Issue two concurrent requests that both modify the same row and assert the final value reflects both changes.',
          'Confirm the database isolation level in use, and that the update is expressed as a single atomic statement or runs under a lock.',
        ],
        references: ['CWE-362 Concurrent Execution using Shared Resource with Improper Synchronization', 'CWE-567 Unsynchronized Access to Shared Data'],
      }));
      break; // One finding per handler is enough to prompt the fix.
    }
  }
  return out;
}

// -------------------------------------------------------- 8. dead UI actions ---

const ACTION_ATTRS = ['onClick', 'onSubmit', 'onPress', 'onDoubleClick', 'onClickCapture'];
const INTERACTIVE_TAG_RE = /^(?:button|a|form|input|select|summary)$/;
const INTERACTIVE_COMPONENT_RE = /(?:Button|Link|Pressable|Touchable|MenuItem|Tab|Chip|Card|Submit|Anchor|Cta|CTA|Action)/;
const TRANSACTIONAL_RE = /pay|checkout|buy|purchase|order|subscribe|submit|save|send|delete|remove|confirm|book|apply|upload|publish|transfer|withdraw/i;

function isInteractive(el: JsxElement): boolean {
  if (INTERACTIVE_TAG_RE.test(el.tag)) return true;
  return /^[A-Z]/.test(el.tag) && INTERACTIVE_COMPONENT_RE.test(el.tag);
}

/** Identifier a handler attribute refers to, when it is a bare reference. */
function handlerIdentifier(value: string): string | undefined {
  const m = /^\{\s*([A-Za-z_$][\w$]*)\s*\}$/.exec(value.trim());
  return m?.[1];
}

/**
 * The body of a function, excluding its own declaration.
 *
 * `const handle = () => {}` contains an `=`, so testing the whole declaration
 * for an assignment would class every arrow-function handler as doing work.
 */
function functionBodyOf(source: string): string {
  const code = codeText(source);
  const arrow = code.indexOf('=>');
  if (arrow !== -1) return code.slice(arrow + 2);
  const brace = code.indexOf('{');
  return brace === -1 ? '' : code.slice(brace);
}

/** True when a body changes state or dispatches, so it is not inert. */
function bodyChangesState(source: string): boolean {
  const body = functionBodyOf(source);
  return /[^=!<>+\-*/%&|^]=[^=]|\+\+|--|\bdispatch\b|\bset[A-Z]\w*\s*\(|\bthrow\b|\breturn\s+\S/.test(body);
}

/** True when an inline arrow body is empty or only a comment. */
function isEmptyInlineHandler(value: string): boolean {
  const body = codeText(value.trim().replace(/^\{/, '').replace(/\}$/, ''));
  return /^(?:async\s*)?(?:\(\s*[^)]*\)|[A-Za-z_$][\w$]*)\s*=>\s*\{\s*\}$/.test(body.trim())
    || /^(?:async\s*)?function\s*\([^)]*\)\s*\{\s*\}$/.test(body.trim());
}

function deadUiActions(c: Ctx): Finding[] {
  const { ctx, map } = c;
  const out: Finding[] = [];

  for (const mod of map.modules.values()) {
    if (!mod.parsed || mod.jsx.length === 0 || isTestPath(mod.path)) continue;

    for (const el of mod.jsx) {
      if (!isInteractive(el)) continue;
      for (const attr of el.attrs) {
        if (!ACTION_ATTRS.includes(attr.name) || !attr.expression || !attr.value) continue;

        const label = (el.text ?? '').trim();
        let detail: string;
        let handlerName: string | undefined;
        let handlerFile = mod.path;
        let handlerLine = el.line;
        let evidenceNote: string;
        let crossFile = false;

        const identifier = handlerIdentifier(attr.value);
        if (identifier) {
          const local = symbolNamed(mod, identifier);
          if (local) {
            const bodyCalls = callsIn(mod, local.startLine, local.endLine);
            if (bodyCalls.length > 0 || bodyChangesState(local.text)) continue;
            handlerName = identifier;
            handlerLine = local.startLine;
            const todo = /\bTODO\b|\bFIXME\b|\bXXX\b|not implemented|unimplemented/i.test(local.text);
            detail = todo
              ? 'its body contains only a TODO comment'
              : 'its body performs no call and changes no state';
            evidenceNote = `${identifier} is wired to ${attr.name} but ${detail}`;
          } else {
            // The handler may be imported: follow it, or stay silent.
            const imp = mod.imports.find((i) => i.resolvedPath && i.names.includes(identifier));
            const target = imp?.resolvedPath ? map.modules.get(imp.resolvedPath) : undefined;
            const remote = target ? symbolNamed(target, identifier) : undefined;
            if (!target || !remote) continue;
            const bodyCalls = callsIn(target, remote.startLine, remote.endLine);
            if (bodyCalls.length > 0 || bodyChangesState(remote.text)) continue;
            handlerName = identifier;
            handlerFile = target.path;
            handlerLine = remote.startLine;
            crossFile = true;
            detail = 'its body performs no call and changes no state';
            evidenceNote = `${identifier}, imported from ${target.path}, ${detail}`;
          }
        } else if (isEmptyInlineHandler(attr.value)) {
          detail = 'the inline handler body is empty';
          evidenceNote = `${attr.name} is bound to an empty inline function`;
        } else {
          continue;
        }

        const transactional = TRANSACTIONAL_RE.test(`${label} ${handlerName ?? ''} ${basenameOf(mod.path)}`);
        const files = crossFile ? [mod.path, handlerFile] : [mod.path];

        out.push(ctx.finding({
          ruleId: 'reliability.ui.dead_action',
          title: `${el.tag}${label ? ` "${label}"` : ''} in ${basenameOf(mod.path)} is wired to a handler that does nothing`,
          severity: transactional ? 'high' : 'medium',
          confidence: 'strong',
          detectionSource: crossFile ? 'graph' : 'static',
          files,
          symbol: handlerName,
          evidence: [
            map.evidenceLine(mod.path, el.line, evidenceNote),
            ...(handlerFile !== mod.path || handlerLine !== el.line
              ? [map.evidenceLine(handlerFile, handlerLine, `handler declared here: ${detail}`)]
              : []),
          ],
          trace: {
            kind: 'dead_ui_action',
            steps: [
              { file: mod.path, line: el.line, detail: `<${el.tag}> declares ${attr.name}=${attr.value}` },
              { file: handlerFile, symbol: handlerName, line: handlerLine, detail },
            ],
            complete: true,
          },
          explanation:
            `An interactive <${el.tag}>${label ? ` labelled "${label}"` : ''} in ${mod.path} binds ${attr.name}, so it is `
            + `rendered as something the user can press, and the browser will happily dispatch the event. The handler it points at `
            + `${detail}: there is no call, no state change, and no navigation anywhere in its body. The control is therefore `
            + `decorative. Because the element looks and behaves like an enabled control — it is not disabled, and it carries no `
            + `"coming soon" affordance — nothing distinguishes it from one that works.`,
          userImpact:
            transactional
              ? 'The user presses what looks like the primary action — paying, submitting, saving — and nothing happens. No '
                + 'confirmation, no error, no change. Most people press it again, then assume the site is broken and leave; the '
                + 'ones who persist contact support about a transaction that was never attempted. For a checkout control this is '
                + 'the difference between a completed sale and an abandoned one, with no trace in any log.'
              : 'The user presses the control and nothing happens, with no feedback explaining why. The feature appears to exist '
                + 'and appears to be broken, which erodes trust in the parts that do work.',
          likelyRootCause:
            'The interface was built before the behaviour behind it, and the placeholder handler was never replaced. Nothing in a '
            + 'type-check or a build fails when a handler is empty.',
          downstreamConsequences: [
            'The feature inventory and the interface both claim a capability the code does not provide.',
            'Analytics records the click, so the funnel shows intent without any corresponding completion.',
          ],
          remediation:
            'Either implement the action or stop advertising it. If the backing work is not ready, remove the control, or render it '
            + 'disabled with an explanation, so the interface tells the truth about what is available. When it is implemented, make '
            + 'the handler report its own failure: show a pending state while it runs, and an error state if it fails, rather than '
            + 'returning the control silently to its resting state. An end-to-end test that presses the control and asserts the '
            + 'resulting request or state change keeps it honest.',
          effort: transactional ? 'medium' : 'small',
          verificationSteps: [
            `Press the control in a browser with the network panel open and confirm the expected request is made.`,
            'Confirm the interface shows a pending state while the action runs and an explicit error state when it fails.',
            'Add an end-to-end test that presses the control and asserts the observable outcome.',
          ],
          references: ['CWE-1164 Irrelevant Code', 'WCAG 2.1 — controls must behave as their role implies'],
        }));
      }
    }
  }
  return dedupe(out);
}

// ------------------------------------------------------ 9. form completeness ---

function incompleteForms(c: Ctx): Finding[] {
  const { ctx, map } = c;
  const out: Finding[] = [];

  for (const mod of map.modules.values()) {
    if (!mod.parsed || mod.jsx.length === 0 || isTestPath(mod.path)) continue;

    for (const el of mod.jsx) {
      if (el.tag !== 'form') continue;
      const attrNames = el.attrs.map((a) => a.name);
      const onSubmit = el.attrs.find((a) => a.name === 'onSubmit');
      const action = el.attrs.find((a) => a.name === 'action');

      // A form with no submit path at all.
      if (!onSubmit && !action) {
        out.push(ctx.finding({
          ruleId: 'reliability.form.no_submit_handler',
          title: `<form> in ${basenameOf(mod.path)} has neither an onSubmit handler nor an action`,
          severity: 'medium',
          confidence: 'strong',
          files: [mod.path],
          symbol: enclosingSymbol(mod, el.line)?.name,
          evidence: [map.evidenceLine(mod.path, el.line, `form declares ${attrNames.length ? attrNames.join(', ') : 'no attributes'}; no submit path`)],
          explanation:
            `The <form> at ${mod.path}:${el.line} declares neither \`onSubmit\` nor \`action\`. Submitting it — by pressing a submit `
            + 'button or pressing Enter in a field — triggers the browser default, which is a GET request to the current URL with the '
            + 'field values appended as query parameters. In a single-page application that reloads the route and discards component '
            + 'state, so the entered data is lost and nothing is sent anywhere the application reads.',
          userImpact:
            'The user fills in the form, submits it, and watches the page reload empty. Their input is gone, nothing was saved, and '
            + 'the only visible clue is a changed address bar. Sensitive values typed into the form also end up in the URL, in '
            + 'browser history, and in any proxy or server log along the way.',
          likelyRootCause: 'The markup was written before the submit behaviour, or the handler was attached to the button rather than the form.',
          downstreamConsequences: [
            'Field values may be recorded in URLs, browser history, and access logs.',
            'Pressing Enter in any field triggers the same loss, which is easy to miss when only the button is tested.',
          ],
          remediation:
            'Attach an `onSubmit` handler to the form itself (not only a click handler to the button), call `preventDefault()`, '
            + 'validate, and submit the data explicitly. Where a server action or a real `action` endpoint is intended, set it so the '
            + 'browser default becomes the correct behaviour rather than an accident.',
          effort: 'small',
          verificationSteps: [
            'Fill the form, press Enter in a text field, and confirm the data is submitted and the page does not reload.',
            'Confirm no field value appears in the address bar after submission.',
          ],
          references: ['CWE-598 Use of GET Request Method With Sensitive Query Strings'],
        }));
        continue;
      }

      // An onSubmit handler that never prevents the default navigation.
      if (onSubmit && onSubmit.expression && onSubmit.value) {
        const identifier = handlerIdentifier(onSubmit.value);
        const sym = identifier ? symbolNamed(mod, identifier) : undefined;
        const body = sym ? codeText(sym.text) : codeText(onSubmit.value);
        if (/preventDefault|\bserver\s*action|useActionState|formAction/i.test(body)) continue;
        // A server-rendered form with a real action does not need it.
        if (action) continue;
        if (!sym && !/=>/.test(body)) continue;

        out.push(ctx.finding({
          ruleId: 'reliability.form.missing_prevent_default',
          title: `Form submit handler in ${basenameOf(mod.path)} never prevents the browser default`,
          severity: 'medium',
          confidence: sym ? 'strong' : 'moderate',
          files: [mod.path],
          symbol: identifier ?? enclosingSymbol(mod, el.line)?.name,
          evidence: [
            map.evidenceLine(mod.path, el.line, 'form submit handler bound here'),
            ...(sym ? [map.evidenceLine(mod.path, sym.startLine, 'handler body contains no preventDefault() call')] : []),
          ],
          explanation:
            `The submit handler bound at ${mod.path}:${el.line} does not call \`preventDefault()\`, and the form has no \`action\`. `
            + 'The handler runs, and then the browser performs its default submission as well: a GET to the current URL that reloads '
            + 'the page. Whatever the handler started — a fetch, a state update — is interrupted by the navigation, so the outcome '
            + 'depends on a race between the two.',
          userImpact:
            'Submitting appears to work intermittently. Sometimes the request completes before the reload and sometimes it does not, '
            + 'so the user cannot tell whether their data was saved, and duplicate or missing submissions both occur.',
          likelyRootCause: 'The handler was written as if it were the only consequence of submitting the form.',
          downstreamConsequences: [
            'The behaviour varies with network speed, which makes it look like an intermittent backend fault.',
            'Field values can be exposed in the URL by the default submission.',
          ],
          remediation:
            'Call `event.preventDefault()` as the first statement of the handler, then perform the submission and drive an explicit '
            + 'pending and error state from it. Where the framework offers a server action or an action-state hook, use that instead '
            + 'of a hand-rolled handler: it owns the default behaviour for you.',
          effort: 'trivial',
          verificationSteps: [
            'Submit the form and confirm the page does not reload and the request completes.',
            'Throttle the network, submit again, and confirm the result is the same.',
          ],
          references: ['CWE-703 Improper Check or Handling of Exceptional Conditions'],
        }));
      }
    }
  }
  return out;
}

// ---------------------------------------------------- 10. unused integrations ---

const EXTERNAL_IO_CALLEE_RE = /^(?:fetch|axios|got|ky|superagent|XMLHttpRequest|urlopen|requests)$|(?:^|\.)(?:fetch|request)$/;
const IO_SDK_PACKAGE_RE =
  /^(?:stripe|openai|nodemailer|resend|postmark|mailgun[-.]?js|@sendgrid\/mail|twilio|@aws-sdk\/|@anthropic-ai\/sdk|firebase(?:-admin)?$|@supabase\/|algoliasearch|meilisearch|@slack\/|@sentry\/|pusher|ioredis|redis$|@upstash\/|mysql2|mongodb|pg$|node-fetch|undici|got$|axios$)/;

function unusedIntegrations(c: Ctx): Finding[] {
  const { ctx, map } = c;
  const out: Finding[] = [];

  for (const mod of map.modules.values()) {
    if (!mod.parsed || isTestPath(mod.path)) continue;
    const file = map.filesByPath.get(mod.path);
    if (!file || file.generated || file.vendored) continue;
    if (file.role === 'test' || file.role === 'config' || file.role === 'manifest' || file.role === 'migration'
      || file.role === 'schema' || file.role === 'ci' || file.role === 'infrastructure' || file.role === 'documentation') continue;
    // A UI module is rendered, not imported for its side effect. An unrendered
    // component is a different problem, and this rule would describe it wrongly.
    if (file.role === 'component' || mod.jsx.length > 0) continue;
    if (map.routes.some((r) => r.file === mod.path)) continue;
    if (isEntryPointLike(c, mod.path)) continue;
    if (mod.exports.length === 0) continue;

    // Anything imported anywhere is not a dead integration.
    if ((map.importers.get(mod.path) ?? []).length > 0) continue;
    if (referencedBySpecifier(c, mod.path)) continue;

    // Which exported symbols actually reach an external system.
    const sdkNames = new Set<string>();
    for (const imp of mod.imports) {
      if (imp.external && IO_SDK_PACKAGE_RE.test(imp.specifier)) {
        for (const n of imp.names) if (n !== '*' && n !== 'default') sdkNames.add(n);
        // A default or namespace import is used under the local binding name,
        // which the parser does not record; fall back to the call-pattern test.
      }
    }

    const ioSymbols: Array<{ name: string; line: number; callee: string }> = [];
    for (const sym of mod.symbols) {
      if (!sym.exported) continue;
      if (sym.kind === 'interface' || sym.kind === 'type' || sym.kind === 'enum') continue;
      for (const call of callsIn(mod, sym.startLine, sym.endLine)) {
        const root = call.callee.split('.')[0] ?? '';
        const isIo = EXTERNAL_IO_CALLEE_RE.test(call.callee) || sdkNames.has(root);
        if (!isIo) continue;
        ioSymbols.push({ name: sym.name, line: call.line, callee: call.callee });
        break;
      }
    }
    if (ioSymbols.length === 0) continue;

    c.deadIntegrations.add(mod.path);
    const confidence: Confidence = c.hasDynamicResolution ? 'moderate' : 'strong';
    const names = ioSymbols.map((s) => s.name);
    const declLine = mod.symbols.find((s) => s.name === names[0])?.startLine ?? ioSymbols[0]!.line;

    out.push(ctx.finding({
      ruleId: 'reliability.integration.unused',
      title: `${names.join(', ')} performs external I/O but nothing in the repository calls it`,
      severity: 'medium',
      confidence,
      detectionSource: 'graph',
      files: [mod.path],
      symbol: names[0],
      evidence: [
        map.evidenceLine(mod.path, ioSymbols[0]!.line,
          `${ioSymbols[0]!.callee}() reaches an external system from exported ${ioSymbols[0]!.name}`),
        map.evidenceLine(mod.path, declLine,
          `${names[0]} is exported here, and no module in the snapshot imports this file`),
      ],
      trace: {
        kind: 'unused_integration',
        steps: [
          { file: mod.path, symbol: names[0], line: ioSymbols[0]!.line, detail: `exported ${names[0]} calls ${ioSymbols[0]!.callee}()` },
          { file: mod.path, detail: 'the import graph records no module that imports this file, and no module names it in a specifier' },
        ],
        complete: !c.hasDynamicResolution,
      },
      explanation:
        `${mod.path} exports ${names.join(', ')}, which reaches an external system (${ioSymbols[0]!.callee}). The import graph `
        + 'records no module anywhere in the snapshot that imports this file, and no other source file names it in a module '
        + 'specifier, so the code is never reached. The integration exists, compiles, and is dead: the side effect it was written '
        + 'to produce never happens.'
        + (c.hasDynamicResolution
          ? ' This project resolves some modules dynamically, which this map cannot follow, so confirm the module is not loaded '
            + 'by a path the import graph does not record.'
          : ''),
      userImpact:
        'Whatever this integration was supposed to do for the user does not happen, and nothing fails to say so. If it sends a '
        + 'confirmation, a receipt, or a notification, the user completes their action and then waits for a message that will '
        + 'never arrive — the most common conclusion being that the action itself did not work. Support hears about it long '
        + 'before monitoring does, because there is no error to monitor.',
      likelyRootCause:
        'The integration was built ahead of the call site, or the call site was removed or refactored away and the module was left '
        + 'behind.',
      downstreamConsequences: [
        'The feature inventory and the roadmap both count this as delivered.',
        'The dependency, its credentials, and its configuration are still carried, reviewed, and rotated for no benefit.',
      ],
      remediation:
        `Decide whether the integration is wanted. If it is, call it from the place in the flow it belongs to — typically right `
        + `after the state change it reports on, inside the same transaction boundary or a queued job so a failure is retried `
        + `rather than lost — and add a test that asserts the call happens. If it is not, delete the module and remove the `
        + `dependency and configuration it needs, so nobody else assumes it is live.`,
      effort: 'small',
      verificationSteps: [
        'Search the repository (including dynamic imports and configuration) for any reference to the module, to confirm it is genuinely unreferenced.',
        'If it should be live: perform the triggering action end to end and confirm the external system receives the call.',
        'Add a test asserting the integration is invoked for that flow.',
      ],
      references: ['CWE-561 Dead Code', 'CWE-1164 Irrelevant Code'],
    }));
  }
  return out;
}

// --------------------------------------------- 11. external calls without timeout ---

function externalCallsWithoutTimeout(c: Ctx): Finding[] {
  const { ctx, map } = c;
  const out: Finding[] = [];

  for (const mod of map.modules.values()) {
    if (!mod.parsed || isTestPath(mod.path)) continue;
    // A module already reported as dead does not need a second finding.
    if (c.deadIntegrations.has(mod.path)) continue;
    const moduleText = codeText(map.filesByPath.get(mod.path)?.text ?? null, mod.language);
    if (/retry|backoff|p-retry|axios-?retry|circuit|bulkhead/i.test(moduleText)) continue;

    const reported = new Set<number>();
    for (const call of mod.calls) {
      const leaf = call.callee.split('.').pop() ?? '';
      if (leaf !== 'fetch' && !/^(?:axios|got|ky)$/.test(call.callee.split('.')[0] ?? '')) continue;
      const first = call.args[0] ?? '';
      if (!/^['"`]https?:\/\//.test(first.trim())) continue;
      const options = call.args.join(' ');
      if (/\bsignal\b|\btimeout\b|AbortSignal|AbortController|deadline/i.test(options)) continue;
      if (reported.has(call.line)) continue;
      reported.add(call.line);

      const host = /^['"`](https?:\/\/[^/'"`]+)/.exec(first.trim())?.[1] ?? 'an external service';

      out.push(ctx.finding({
        ruleId: 'reliability.http.no_timeout',
        title: `Outbound call to ${host} has no timeout and no retry policy`,
        severity: 'low',
        confidence: 'moderate',
        files: [mod.path],
        symbol: call.inSymbol,
        evidence: [map.evidenceLine(mod.path, call.line, 'no signal, timeout, or AbortController passed to this request')],
        explanation:
          `The request at ${mod.path}:${call.line} calls ${host} with no abort signal or timeout in its options, and the module `
          + 'contains no retry or circuit-breaker logic. The platform default for an outbound request is long — minutes, in some '
          + 'runtimes, and effectively unbounded once a connection is established and the peer simply stops responding. A caller '
          + 'waiting on this request holds its own resources (a request slot, a connection, a serverless invocation) for the whole '
          + 'of that time. This is a structural observation: no actual latency was measured.',
        userImpact:
          'When the external service is slow rather than down, the user\'s request hangs instead of failing, and they wait with no '
          + 'feedback until something further up gives up. Under load the waiting requests pile up and the application becomes '
          + 'unresponsive for everyone, not only for the people using the feature that depends on this call.',
        likelyRootCause: 'The default behaviour was accepted because the dependency is fast and reliable in development.',
        downstreamConsequences: [
          'A slow dependency becomes an outage of this application rather than a degraded feature.',
          'Serverless cost and concurrency limits are consumed by requests that are only waiting.',
        ],
        remediation:
          'Set an explicit deadline on the request (an `AbortSignal` with a timeout, or the client\'s own timeout option) chosen from '
          + 'what the caller can actually wait for. Decide what happens when it expires: retry a bounded number of times with jitter '
          + 'for idempotent requests, and fail fast with a clear message for the rest. Where the dependency is not essential to the '
          + 'response, move it out of the request path entirely, into a queued job.',
        effort: 'small',
        verificationSteps: [
          'Point the call at an endpoint that never responds and confirm it aborts within the configured deadline.',
          'Confirm the surrounding code handles the abort as a failure rather than treating it as an empty result.',
        ],
        references: ['CWE-1088 Synchronous Access of Remote Resource without Timeout', 'CWE-400 Uncontrolled Resource Consumption'],
      }));
    }
  }
  return out;
}

// -------------------------------------------------- 12. unreachable servers ---

const SERVER_CONSTRUCT_RE = /^(?:express|Fastify|fastify|Koa|Hapi|createServer|polka|restify)$|^new\s+(?:Koa|Hapi)$/;

function unreachableServers(c: Ctx): Finding[] {
  const { ctx, map } = c;
  const out: Finding[] = [];

  // A listen call anywhere in the project means some server is started; only
  // the absence of any listen makes an in-repo server definitively unreachable.
  const listensAnywhere = [...map.modules.values()].some((m) =>
    m.calls.some((call) => /(?:^|\.)(?:listen|serve|run|start)$/.test(call.callee)));

  for (const mod of map.modules.values()) {
    if (!mod.parsed || isTestPath(mod.path)) continue;
    const constructs = mod.calls.find((call) => SERVER_CONSTRUCT_RE.test(call.callee));
    if (!constructs) continue;
    const routesHere = map.routes.filter((r) => r.file === mod.path);
    if (routesHere.length === 0) continue;
    if (listensAnywhere) continue;
    if (nonTestImporters(map, mod.path).length > 0) continue;
    if (isEntryPointLike(c, mod.path)) continue;

    const testOnly = (map.importers.get(mod.path) ?? []).length > 0;

    out.push(ctx.finding({
      ruleId: 'reliability.deadcode.unreachable_server',
      title: `${routesHere.length} route(s) in ${basenameOf(mod.path)} are registered on a server that is never started`,
      severity: 'medium',
      confidence: 'moderate',
      detectionSource: 'graph',
      files: [mod.path],
      symbol: constructs.inSymbol,
      evidence: [
        map.evidenceLine(mod.path, constructs.line, `${constructs.callee}() creates a server here`),
        map.evidenceLine(mod.path, routesHere[0]!.line ?? constructs.line,
          `${routesHere[0]!.method} ${routesHere[0]!.path} is registered on it`),
      ],
      trace: {
        kind: 'unused_integration',
        steps: [
          { file: mod.path, line: constructs.line, detail: `${constructs.callee}() constructs a server` },
          ...routesHere.slice(0, 3).map((r) => ({ file: mod.path, line: r.line, detail: `registers ${r.method} ${r.path}` })),
          {
            file: mod.path,
            detail: testOnly
              ? 'no listen/serve call exists anywhere in the snapshot, and the only importers are tests'
              : 'no listen/serve call exists anywhere in the snapshot, and no module imports this file',
          },
        ],
        complete: false,
      },
      explanation:
        `${mod.path} constructs a server with ${constructs.callee}() and registers `
        + `${routesHere.map((r) => `${r.method} ${r.path}`).join(', ')} on it, but nothing in the snapshot calls listen (or an `
        + `equivalent), and `
        + (testOnly
          ? 'the only modules importing this file are tests. '
          : 'no module imports this file. ')
        + 'As far as this snapshot shows, these routes are never served. The trace is marked incomplete deliberately: a '
        + 'serverless adapter, a process manager, or a deployment configuration outside the repository can mount an exported app '
        + 'without any listen call appearing in the source, so this needs confirming against how the application is actually '
        + 'deployed before the code is removed.',
      userImpact:
        'Any client built against these endpoints receives a 404 rather than a response, and the behaviour they implement is '
        + 'unavailable. If the routes were superseded by handlers elsewhere, the risk runs the other way: this file is still '
        + 'maintained and reviewed, and a fix applied here does not reach the code that actually serves traffic.',
      likelyRootCause:
        'The server predates a migration to another framework or to serverless handlers, and was left in place rather than removed.',
      downstreamConsequences: [
        'Security and dependency review spend effort on code that does not run.',
        'A fix applied in this file silently has no effect in production.',
        'Tests covering it report coverage of behaviour no user can reach.',
      ],
      remediation:
        'Confirm against the deployment configuration whether this app is mounted anywhere. If it is, record that entry point in '
        + 'the repository (a start script, or an adapter module that imports it) so it is visible to anyone reading the code. If it '
        + 'is not, delete the module along with the dependencies and tests that exist only for it, after checking whether any route '
        + 'here implements behaviour the live surface still lacks.',
      effort: 'small',
      verificationSteps: [
        'Grep the deployment configuration, process manager, and start scripts for a reference to this module.',
        'Request one of these paths against the deployed application and confirm the response is a 404.',
        'If the module is to be removed, confirm no live route depends on anything it exports.',
      ],
      references: ['CWE-561 Dead Code'],
    }));
  }
  return out;
}

// ------------------------------------------- 13. routes without error handling ---

function routesWithoutErrorHandling(c: Ctx): Finding[] {
  const { ctx, map } = c;
  const out: Finding[] = [];
  const byFile = new Map<string, ApiEndpoint[]>();

  for (const route of map.routes) {
    if (route.errorHandling !== 'absent') continue;
    const mod = map.modules.get(route.file);
    const handler = handlerOf(map, route);
    if (!mod || !handler) continue;
    if (mod.hasTryCatch) continue;

    const component = `api_route:${route.method} ${route.path}`;
    const queries = map.relationships.some((rel) => rel.kind === 'queries' && rel.from === component);
    const externalCall = map.relationships.some((rel) => rel.kind === 'calls' && rel.from === component && rel.to.startsWith('external_service:'));
    const handlerCalls = callsIn(mod, handler.startLine, handler.endLine);
    const awaitsIo = handlerCalls.some((call) => call.awaited);
    const writes = ['POST', 'PUT', 'PATCH', 'DELETE'].includes(route.method);

    // Only report where an unhandled failure is actually reachable and costly.
    if (!(writes && (queries || awaitsIo)) && !externalCall) continue;

    const list = byFile.get(route.file) ?? [];
    list.push(route);
    byFile.set(route.file, list);
  }

  for (const [file, routes] of byFile) {
    const names = routes.map((r) => `${r.method} ${r.path}`);
    out.push(ctx.finding({
      ruleId: 'reliability.error_handling.route_unprotected',
      title: `${names.join(', ')} performs I/O with no error handling`,
      severity: 'medium',
      confidence: 'strong',
      files: [file],
      symbol: routes[0]!.handlerSymbol,
      evidence: routes.map((r) => map.evidenceLine(file, r.line ?? 1,
        `${r.method} ${r.path} handler contains no try/catch and no .catch()`)),
      explanation:
        `${names.join(', ')} in ${file} awaits I/O — a database call, a file write, or an external request — and the handler `
        + 'contains no try/catch and no rejection handler. When that I/O fails, and it will (a dropped connection, a constraint '
        + 'violation, a timeout, a provider incident), the rejection propagates out of the handler. The framework turns it into a '
        + 'generic 500 with no application-specific body, no structured log line identifying which operation failed, and no partial '
        + 'cleanup of anything the handler had already changed.',
      userImpact:
        'The user gets an unexplained failure for something that may be entirely recoverable — a value that needs correcting, a '
        + 'duplicate that already exists, a dependency that is briefly unavailable. Because the response cannot distinguish those '
        + 'cases, the interface cannot tell the user whether to fix their input, retry, or wait, so the usual outcome is an '
        + 'abandoned task and a support request. For a write that partly completed, the user is left not knowing what state their '
        + 'data is in.',
      likelyRootCause:
        'The handler was written for the success path. Nothing in the type system or the build requires a failure path, and the '
        + 'framework\'s default 500 makes the omission invisible until it is examined.',
      downstreamConsequences: [
        'Failures are indistinguishable in the logs, so the first step of every investigation is reproducing the request.',
        'A write that fails halfway leaves the record in an intermediate state that no later code expects.',
        'Error-rate metrics cannot separate client mistakes from dependency failures.',
      ],
      remediation:
        'Wrap the I/O in try/catch (or a shared handler wrapper, which keeps every route consistent). In the catch: log with enough '
        + 'context to identify the operation and the record, map known failures onto honest status codes (400 for bad input, 404 for '
        + 'missing, 409 for a conflict, 503 for an unavailable dependency), and return a body the interface can act on. Keep internal '
        + 'details out of the response while putting them in the log. Where a handler performs several writes, run them in one '
        + 'transaction so a failure cannot leave the record half-updated.',
      effort: 'small',
      verificationSteps: [
        'Force the I/O to fail (stop the database, revoke a permission, point the dependency at a dead host) and confirm the response carries an appropriate status and a usable message.',
        'Confirm the failure appears in the logs with the operation and record identified.',
        'For multi-write handlers, confirm a mid-way failure leaves no partially applied change.',
      ],
      references: ['CWE-391 Unchecked Error Condition', 'CWE-755 Improper Handling of Exceptional Conditions'],
    }));
  }
  return out;
}

// --------------------------------------- 14. missing loading and error states ---

const NEXT_PAGE_RE = /(?:^|\/)app\/(?:.*\/)?page\.[cm]?[jt]sx?$/;

function missingLoadingAndErrorStates(c: Ctx): Finding[] {
  const { ctx, map } = c;
  if (!map.hasTech('Next.js')) return [];
  const out: Finding[] = [];
  const paths = new Set(map.files.map((f) => f.path));

  for (const mod of map.modules.values()) {
    if (!mod.parsed || !NEXT_PAGE_RE.test(mod.path) || isTestPath(mod.path)) continue;
    if (mod.hasTryCatch) continue;

    const awaited = mod.calls.find((call) => call.awaited);
    if (!awaited) continue;

    const moduleText = codeText(map.filesByPath.get(mod.path)?.text ?? null, mod.language);
    const hasSuspense = /<Suspense\b/.test(moduleText);
    const hasInlineErrorState = /\berror\b[^\n]{0,40}(?:\?|&&|\bthen\b)|ErrorBoundary/i.test(moduleText);

    // Walk up to the app root looking for the conventional boundary files.
    const missing: string[] = [];
    let errorFile: string | undefined;
    let loadingFile: string | undefined;
    let dir = dirnameOf(mod.path);
    for (;;) {
      for (const base of ['error.tsx', 'error.jsx', 'error.js', 'global-error.tsx', 'global-error.jsx']) {
        if (!errorFile && paths.has(dir ? `${dir}/${base}` : base)) errorFile = `${dir}/${base}`;
      }
      for (const base of ['loading.tsx', 'loading.jsx', 'loading.js']) {
        if (!loadingFile && paths.has(dir ? `${dir}/${base}` : base)) loadingFile = `${dir}/${base}`;
      }
      if (/(?:^|\/)app$/.test(dir) || dir === '') break;
      const parent = dirnameOf(dir);
      if (parent === dir) break;
      dir = parent;
    }
    if (!errorFile && !hasInlineErrorState) missing.push('error');
    if (!loadingFile && !hasSuspense) missing.push('loading');
    if (missing.length === 0) continue;

    out.push(ctx.finding({
      ruleId: 'reliability.ui.missing_async_states',
      title: `${basenameOf(dirnameOf(mod.path)) || 'root'} page awaits data with no ${missing.join(' or ')} state`,
      severity: 'medium',
      confidence: 'strong',
      detectionSource: 'graph',
      files: [mod.path],
      symbol: enclosingSymbol(mod, awaited.line)?.name,
      evidence: [
        map.evidenceLine(mod.path, awaited.line, `${awaited.callee}() is awaited while rendering this page`),
        map.evidenceLine(mod.path, enclosingSymbol(mod, awaited.line)?.startLine ?? awaited.line,
          `no try/catch in this component, and no ${missing.join('/')} boundary file in this route segment or any ancestor up to app/`),
      ],
      trace: {
        kind: 'import',
        steps: [
          { file: mod.path, line: awaited.line, detail: `page awaits ${awaited.callee}() during render` },
          { file: mod.path, detail: `no ${missing.join(' or ')} boundary found in this segment or its ancestors` },
        ],
        complete: true,
      },
      explanation:
        `${mod.path} awaits ${awaited.callee}() while rendering, and the route segment it belongs to declares no `
        + `${missing.join(' or ')} boundary — no such file exists in this directory or in any ancestor up to the app root — and the `
        + 'module itself contains no try/catch'
        + (missing.includes('loading') ? ' and no Suspense boundary' : '')
        + '. In the App Router these files *are* the mechanism for the two states: without `error.tsx` a thrown error escapes to the '
        + 'nearest boundary above, and with none present the framework falls back to its own generic error screen; without '
        + '`loading.tsx` or a Suspense boundary the segment has no fallback, so navigation waits for the data before anything renders.',
      userImpact:
        (missing.includes('loading')
          ? 'While the data loads the user sees nothing happen: the old page stays on screen or the browser simply appears to hang, '
            + 'with no indication that their navigation registered. On a slow connection this reads as an unresponsive application, '
            + 'and the usual response is to press the link again. '
          : '')
        + (missing.includes('error')
          ? 'If the query fails the user is dropped onto a generic framework error page with no explanation, no retry, and no way '
            + 'back into the product other than the browser\'s back button.'
          : ''),
      likelyRootCause:
        'The page was built against a fast, always-succeeding local database, where neither state is ever visible.',
      downstreamConsequences: [
        'A single failing query takes out the whole route segment rather than degrading one part of the page.',
        'Perceived performance is governed by the slowest query on the page, because nothing renders until it completes.',
      ],
      remediation:
        'Add the boundary files the framework expects for this segment: an `error.tsx` that explains what failed and offers a retry '
        + '(it receives a `reset` function for exactly that), and a `loading.tsx` — or a Suspense boundary around the slow part — so '
        + 'the shell renders immediately. Where only part of the page depends on slow data, wrap that part alone, so the rest is '
        + 'usable while it loads. Put a boundary at the app root as well, as the last line of defence for segments that have none.',
      effort: 'small',
      verificationSteps: [
        'Make the data call throw and confirm the page shows your error UI with a working retry, not the framework default.',
        'Delay the data call and confirm a loading state appears immediately on navigation.',
        'Confirm the boundary covers the whole segment, including nested routes beneath it.',
      ],
      references: ['CWE-755 Improper Handling of Exceptional Conditions', 'Next.js App Router: error and loading conventions'],
    }));
  }
  return out;
}

// ------------------------------------------------- 15. undocumented env vars ---

/**
 * Names the platform supplies. Treating these as undocumented would bury the
 * variables that actually need writing down.
 */
const PLATFORM_ENV_RE =
  /^(?:NODE_ENV|NODE_OPTIONS|PORT|HOST|HOSTNAME|PWD|HOME|PATH|TZ|LANG|LC_[A-Z_]+|TERM|SHELL|USER|TMPDIR|CI|DEBUG|FORCE_COLOR|NO_COLOR|npm_.*|NEXT_RUNTIME|NEXT_PHASE|__NEXT_.*|VERCEL(?:_.*)?|NETLIFY(?:_.*)?|RAILWAY_.*|RENDER(?:_.*)?|FLY_.*|HEROKU_.*|DYNO|AWS_LAMBDA_.*|AWS_EXECUTION_ENV|GITHUB_.*|GITLAB_CI|K_SERVICE|FUNCTION_TARGET|PYTHONPATH|VIRTUAL_ENV)$/;

function undocumentedEnvVars(c: Ctx): Finding[] {
  const { ctx, map } = c;
  const out: Finding[] = [];

  const undocumented = map.env.usages.filter(
    (u) => !u.documented && !PLATFORM_ENV_RE.test(u.name) && u.readIn.length > 0,
  );
  if (undocumented.length === 0) return out;

  const template = map.env.templateFiles[0];

  // With no template at all, one finding about the missing template is honest;
  // one finding per variable would be noise about the same omission.
  if (!template) {
    const names = undocumented.map((u) => u.name);
    const fatal = undocumented.filter((u) => !u.hasFallback);
    const firstRead = undocumented[0]!.readIn[0]!;
    out.push(ctx.finding({
      ruleId: 'reliability.config.env_template_missing',
      title: `${names.length} environment variable(s) are read with no example or template file to document them`,
      severity: fatal.length > 0 ? 'medium' : 'low',
      confidence: 'strong',
      detectionSource: 'graph',
      files: [...new Set(undocumented.flatMap((u) => u.readIn.map((r) => r.file)))].slice(0, 10),
      evidence: undocumented.slice(0, 6).map((u) =>
        map.evidenceLine(u.readIn[0]!.file, u.readIn[0]!.line,
          `${u.name} is read here${u.hasFallback ? ' (a fallback is supplied)' : ' with no fallback'}`)),
      trace: {
        kind: 'env_var',
        steps: [
          { file: firstRead.file, line: firstRead.line, detail: `reads ${names.slice(0, 6).join(', ')} from the environment` },
          { file: firstRead.file, detail: 'no .env.example, .env.sample, or .env.template file exists in the snapshot to list them' },
        ],
        complete: true,
      },
      explanation:
        `The code reads ${names.length} environment variable(s) — ${names.slice(0, 8).join(', ')}`
        + `${names.length > 8 ? ', …' : ''} — and the repository contains no template file (.env.example, .env.sample, .env.template) `
        + 'listing them. The required configuration of this application therefore exists only inside the source, spread across the '
        + 'places each value happens to be read. Anyone setting up a new environment has to discover the list by reading the code or '
        + 'by watching the application fail'
        + (fatal.length > 0
          ? `, and ${fatal.length} of these have no fallback, so absence is fatal rather than merely degrading.`
          : '.'),
      userImpact:
        'A deployment that is missing one of these starts successfully and then fails the first time the value is needed — often '
        + 'mid-request, for one feature, long after the deploy looked healthy. Users meet the failure before the operator does.',
      likelyRootCause: 'Variables were added one at a time as features needed them, and no single place was kept in step.',
      downstreamConsequences: [
        'Onboarding and environment setup depend on tacit knowledge.',
        'A variable renamed in code leaves no record of what the old deployments were configured with.',
      ],
      remediation:
        'Add a committed .env.example listing every name with an empty or clearly fake value and a one-line comment saying what it '
        + 'is for, and keep it in review scope so a new variable cannot merge without being listed. Then validate configuration once '
        + 'at startup — parse the whole environment against a schema and exit with a message naming every missing variable — so a '
        + 'misconfigured deployment fails immediately and visibly instead of at first use.',
      effort: 'small',
      verificationSteps: [
        'Start the application with an empty environment and confirm it refuses to start with a message naming each missing variable.',
        'Confirm every name read in the code appears in the template file.',
      ],
      references: ['CWE-1188 Insecure Default Initialization of Resource', 'Twelve-Factor App: Config'],
    }));
    return out;
  }

  for (const usage of undocumented) {
    const read = usage.readIn[0]!;
    const mod = map.modules.get(read.file);
    const moduleScope = !!mod && !enclosingSymbol(mod, read.line);
    const severity: Severity = usage.hasFallback ? 'low' : moduleScope ? 'high' : 'medium';

    out.push(ctx.finding({
      ruleId: 'reliability.config.env_undocumented',
      title: `${usage.name} is read from the environment but is not listed in ${basenameOf(template)}`,
      severity,
      confidence: 'strong',
      detectionSource: 'graph',
      files: [...new Set([...usage.readIn.map((r) => r.file), template])],
      symbol: usage.name,
      evidence: [
        map.evidenceLine(read.file, read.line,
          `${usage.name} is read here${usage.hasFallback ? ', with a fallback' : ', with no fallback'}`),
        map.evidenceLine(template, 1, `${basenameOf(template)} documents the required configuration but does not list ${usage.name}`),
      ],
      trace: {
        kind: 'env_var',
        steps: [
          ...usage.readIn.slice(0, 3).map((r) => ({ file: r.file, line: r.line, detail: `${usage.name} read here` })),
          { file: template, detail: `${usage.name} is absent from the documented names in this template` },
        ],
        complete: true,
      },
      explanation:
        `${usage.name} is read at ${read.file}:${read.line}`
        + (usage.readIn.length > 1 ? ` and in ${usage.readIn.length - 1} other place(s)` : '')
        + `, but ${template} — which this project uses to declare its required configuration — does not list it. The repository `
        + 'therefore describes a configuration surface narrower than the one the code depends on, and the only record of the '
        + 'variable is the line that reads it.'
        + (usage.hasFallback
          ? ` A fallback is supplied, so absence does not break the application outright: it runs with the default instead, which `
            + `means a deployment that was meant to override this value silently does not, and the difference shows up as behaviour `
            + `rather than as an error.`
          : ` No fallback is supplied${moduleScope ? ', and the read happens at module scope, so the module evaluates to an undefined value as soon as it is imported' : ''}. `
            + `When the variable is absent the value is \`undefined\` and the first code to use it fails.`),
      userImpact:
        usage.hasFallback
          ? 'An environment where this was never set behaves as if the default were intended — a wrong timeout, the wrong list of '
            + 'privileged users, the wrong limit. Nothing errors, so the misconfiguration is only noticed when someone questions '
            + 'the behaviour, which can be long after it started affecting users.'
          : 'A deployment missing this variable fails the moment the value is first needed. Because the process starts cleanly, '
            + 'the failure reaches users as a broken feature or an error page before anyone sees it in a deploy log.',
      likelyRootCause: `The variable was added to the code and to the deployed environment, but ${basenameOf(template)} was not updated.`,
      downstreamConsequences: [
        'A new environment, a local checkout, or a CI job is configured from an incomplete list.',
        usage.hasFallback
          ? 'The fallback hides the omission, so the gap can persist across many deployments.'
          : 'The failure appears at first use rather than at startup, which makes it look like an application bug.',
      ],
      remediation:
        `Add ${usage.name} to ${basenameOf(template)} with an empty or clearly fake value and a comment stating what it controls and `
        + `what a safe default is. Then validate it at startup rather than at first use: parse the environment against a schema when `
        + `the process boots and fail with a message naming the missing variable`
        + (usage.hasFallback
          ? `. Keep the fallback only if running with the default is genuinely correct; if it is not, removing it converts a silent `
            + `misconfiguration into a loud one, which is the behaviour you want.`
          : '.'),
      effort: 'trivial',
      verificationSteps: [
        `Confirm ${usage.name} now appears in ${basenameOf(template)}.`,
        `Start the application without ${usage.name} set and confirm the outcome is the intended one — a clear startup failure, or a documented default.`,
        'Confirm every deployed environment has a value for it.',
      ],
      references: ['CWE-1188 Insecure Default Initialization of Resource', 'Twelve-Factor App: Config'],
    }));
  }
  return out;
}

// ---------------------------------------------------------------------------

/** Drop findings that repeat an earlier one's fingerprint. */
function dedupe(findings: Finding[]): Finding[] {
  const seen = new Set<string>();
  return findings.filter((f) => {
    if (seen.has(f.fingerprint)) return false;
    seen.add(f.fingerprint);
    return true;
  });
}
