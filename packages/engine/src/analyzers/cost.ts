import type { ApiEndpoint, Confidence, DataModel, Evidence, Finding, Severity } from '@codelens/core';
import type { RepoMap } from '../graph/repomap.ts';
import type { CallRef, ParsedModule, SymbolInfo } from '../parse/types.ts';
import type { Analyzer, AnalyzerContext } from './types.ts';
import { codeText } from './text.ts';

/**
 * Cost and infrastructure efficiency.
 *
 * The hard rule for this analyzer: it has no billing data and no usage data, so
 * it never produces a monetary figure, a per-request price, a monthly total, or
 * a percentage saving. Every finding describes a *structural* cost risk — work
 * or storage the code buys without a ceiling — and names the measurement that
 * would quantify it (a provider usage dashboard, token accounting per request,
 * row counts, a connection count at the database). Magnitude depends on traffic
 * and data volume, which a snapshot cannot see.
 *
 * Confidence discipline, matching the rest of the suite:
 *   - a pattern match alone is `moderate`;
 *   - a pattern plus a traced relationship (a manifest entry tied to an import
 *     site, a call tied to a declared model, an argument correlated against the
 *     handler's member accesses) is `strong`;
 *   - nothing here reaches `confirmed`, because every claim in this category is
 *     a claim about waste, and whether work is wasted depends on intent that
 *     source code does not state.
 *
 * The angle is deliberately money and resource waste, not latency: the
 * performance analyzer owns query shape and response time. Where the two look
 * at the same line, this analyzer's claim is about what is paid for per call —
 * tokens bought, bytes moved, rows stored, services run twice.
 */

const REF = {
  costPillar: 'AWS Well-Architected Framework — Cost Optimization Pillar (match supply to demand; measure before optimising)',
  cweLimits: 'CWE-770 Allocation of Resources Without Limits or Throttling',
  cweResource: 'CWE-400 Uncontrolled Resource Consumption',
  cweExcessQuery: 'CWE-1049 Excessive Data Query Operations in a Large Data Table',
  cweLoopResource: 'CWE-1050 Excessive Platform Resource Consumption within a Loop',
  owaspResource: 'OWASP API Security Top 10 — API4:2023 Unrestricted Resource Consumption',
  owaspLlmConsumption: 'OWASP Top 10 for LLM Applications — LLM10 Unbounded Consumption',
  dataMinimisation: 'Data minimisation: fetch only the fields the caller needs',
  notMeasured: 'docs/LIMITATIONS.md — this scan has no billing or usage data, so no cost figure is produced',
} as const;

// --------------------------------------------------------------- patterns ---

/** Packages whose use implies metered, per-token model inference. */
const AI_SDK_EXACT = new Set([
  'openai', 'anthropic', 'ai', 'cohere-ai', 'cohere', 'mistralai', 'groq-sdk', 'groq',
  'replicate', 'together-ai', 'ollama', 'langchain', 'llamaindex', 'litellm',
  'google-generativeai', 'vertexai', 'openai-edge',
]);

/** Package prefixes with the same meaning (scoped SDKs and their submodules). */
const AI_SDK_PREFIXES = [
  '@anthropic-ai/', '@google/generative-ai', '@google/genai', '@google-cloud/aiplatform',
  '@ai-sdk/', '@langchain/', '@mistralai/', '@huggingface/inference',
  '@aws-sdk/client-bedrock-runtime', '@azure/openai', 'openai/', 'anthropic/',
];

/**
 * Callees that are unambiguously a model request: the dotted shape belongs to a
 * provider SDK and to nothing else a project is likely to call.
 */
const MODEL_CALL_UNAMBIGUOUS = [
  /(?:^|\.)chat\.completions\.create$/,
  /(?:^|\.)completions\.create$/,
  /(?:^|\.)responses\.create$/,
  /(?:^|\.)chat\.complete$/,
  /(?:^|\.)createChatCompletion$/,
  /(?:^|\.)createCompletion$/,
  /(?:^|\.)generateContent(?:Stream)?$/,
  /(?:^|\.)generate_content$/,
];

/**
 * Callees that are a model request *only* when the receiver resolves to a
 * provider client. `messages.create` is also how several ORMs write a row to a
 * `messages` table, so the receiver check is what keeps this from firing on a
 * database write.
 */
const MODEL_CALL_NEEDS_RECEIVER = [
  /(?:^|\.)messages\.(?:create|stream)$/,
  /(?:^|\.)createMessage$/,
  /(?:^|\.)invoke$/,
  /(?:^|\.)predict$/,
  /(?:^|\.)stream$/,
];

/** Bare function calls that are a model request when imported from an AI SDK. */
const MODEL_CALL_IMPORTED_NAMES = new Set([
  'generateText', 'streamText', 'generateObject', 'streamObject',
  'textGeneration', 'chatCompletion', 'complete', 'completion',
]);

/**
 * Callees whose own arguments are where an output ceiling is configured. A
 * LangChain `chain.invoke()` is excluded: its cap lives on the model
 * constructor, so reading its arguments would say nothing either way.
 */
const CAP_IN_ARGUMENTS = [
  /(?:^|\.)chat\.completions\.create$/,
  /(?:^|\.)completions\.create$/,
  /(?:^|\.)responses\.create$/,
  /(?:^|\.)chat\.complete$/,
  /(?:^|\.)createChatCompletion$/,
  /(?:^|\.)createCompletion$/,
  /(?:^|\.)generateContent(?:Stream)?$/,
  /(?:^|\.)generate_content$/,
  /(?:^|\.)messages\.(?:create|stream)$/,
  /(?:^|\.)createMessage$/,
];

/** Every spelling of an output ceiling across the major provider SDKs. */
const OUTPUT_CAP_RE =
  /\b(?:max_tokens|maxTokens|max_output_tokens|maxOutputTokens|max_completion_tokens|maxCompletionTokens|max_new_tokens|maxNewTokens|max_tokens_to_sample|maxTokensToSample|maxOutputTokenCount|max_length|maxLength)\b/;

/**
 * Hosts that bill per token. A model served from localhost or through Ollama is
 * deliberately absent: local inference costs compute the project already pays
 * for, so an uncapped local call is a performance question, not a spend one.
 */
const PROVIDER_HOST_RE =
  /\b(?:api\.openai\.com|api\.anthropic\.com|api\.cohere\.(?:ai|com)|generativelanguage\.googleapis\.com|[\w.-]+\.openai\.azure\.com|api\.mistral\.ai|api\.groq\.com|api\.together\.(?:xyz|ai)|api\.replicate\.com|api\.perplexity\.ai|api\.deepseek\.com|api\.x\.ai|api-inference\.huggingface\.co|bedrock-runtime\.[\w-]+\.amazonaws\.com|api\.fireworks\.ai|openrouter\.ai)\b/;

/** Provider endpoints that are billed but have no output-length parameter. */
const NON_COMPLETION_PATH_RE =
  /\/(?:embeddings|moderations|files|images|audio|batches|fine_tuning|assistants)\b/;

/** The request body is written inline at the call site, so it can be judged. */
const INLINE_REQUEST_BODY_RE = /\b(?:model|messages|prompt|contents|system|input)\s*:/;

/** Calls that put a request on the network. */
const NETWORK_LEAVES = new Set(['fetch', 'post', 'put', 'request', 'send']);

/** Reading, recording, or counting token consumption anywhere. */
const USAGE_ACCOUNTING_RE =
  /\b(?:usage|usageMetadata|usage_metadata|total_tokens|totalTokens|prompt_tokens|promptTokens|completion_tokens|completionTokens|input_tokens|inputTokens|output_tokens|outputTokens|tokenCount|token_count|countTokens|count_tokens|tiktoken|tokensUsed|tokens_used|token_usage|promptCost|costCents|cost_cents|llmCost|llm_cost)\b/;

/** A table or model that exists to record usage, spend, or quota. */
const METERING_MODEL_RE = /(?:usage|token|credit|quota|billing|invoice|meter|spend)/i;

/** Reads that return a whole collection unless an explicit ceiling is given. */
const COLLECTION_READ_LEAVES = new Set([
  'findMany', 'findAll', 'find', 'scan', 'selectAll', 'getAll', 'listAll', 'all',
]);

/** Arguments that bound a read: a ceiling, a page, or a filter. */
const ROW_CEILING_KEYS = new Set([
  'take', 'limit', 'first', 'last', 'top', 'perPage', 'per_page', 'pageSize', 'page_size',
  'cursor', 'after', 'before', 'skip', 'offset', 'page', 'maxResults', 'max_results', 'count', 'size',
]);
const PROJECTION_KEYS = new Set([
  'select', 'attributes', 'columns', 'fields', 'projection', 'omit', 'returning',
]);
const FILTER_KEYS = new Set([
  'where', 'filter', 'query', 'criteria', 'match', 'conditions',
]);
const RELATION_OBJECT_KEYS = new Set(['include', 'with']);
const RELATION_LIST_KEYS = new Set(['relations', 'populate', 'joins', 'joinedload']);

/** Writes that add a row. */
const INSERT_LEAVES = new Set([
  'create', 'createMany', 'insert', 'insertMany', 'insertOne', 'save', 'add', 'bulkCreate', 'upsert', 'put',
]);
/** Calls that remove rows — the absence of any of these is the retention signal. */
const DELETE_LEAVES = new Set([
  'delete', 'deleteMany', 'deleteOne', 'destroy', 'remove', 'removeMany', 'truncate',
  'drop', 'prune', 'purge', 'clear', 'expire', 'archive',
]);

/** A table whose rows accumulate with traffic rather than with the domain. */
const ACCUMULATING_NAME_RE =
  /(?:log|event|audit|history|session|metric|trace|span|analytic|telemetry|notification|activity|snapshot|request|webhook|job|queue|import|export|upload|attempt|impression|click|view)/i;

const TIMESTAMP_FIELD_RE =
  /^(?:created_?at|inserted_?at|updated_?at|occurred_?at|received_?at|logged_?at|recorded_?at|timestamp|time|date|ts)$/i;

/** Retention handled somewhere this analyzer can see, or by the datastore. */
const RETENTION_SIGNAL_RE =
  /\b(?:ttl|TTL|expireAfterSeconds|expires_?at|expiresAt|retention|retentionDays|prune|purge|archive|archival|vacuum|pg_cron|partman|cron|rollup|downsample)\b/;

/** Reads of a file's whole contents, which become prompt tokens if interpolated. */
const BULK_FILE_READ_LEAVES = new Set([
  'readFile', 'readFileSync', 'readdir', 'readdirSync', 'glob', 'globSync', 'read_text', 'load',
]);

// ---------------------------------------------------------------- helpers ---

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function lastSegment(callee: string): string {
  const parts = callee.replace(/\(\)/g, '').split('.');
  return parts[parts.length - 1] ?? '';
}

function calleeSegments(callee: string): string[] {
  return callee.replace(/\(\)/g, '').replace(/\[\]/g, '').split('.').filter(Boolean);
}

/**
 * Loose name comparison for schema-vs-code naming drift: a Prisma model `Order`
 * is called as `prisma.order`, a relation field `orders` points at model
 * `Order`, and a SQL table may be `orders`.
 */
function sameEntity(a: string, b: string): boolean {
  const norm = (s: string) => s.toLowerCase().replace(/[^a-z0-9]/g, '').replace(/(?:ies|es|s)$/, '');
  return norm(a) === norm(b) && norm(a).length > 0;
}

/**
 * A comment-free view of a file, with line starts, so text matching never hits
 * a commented-out call and never reads a `DEFECT:` note as code. Cached per
 * path because several rules need the same view.
 */
interface CodeView {
  text: string;
  lineStarts: number[];
}

function buildView(text: string): CodeView {
  const lineStarts: number[] = [0];
  for (let i = 0; i < text.length; i++) {
    if (text[i] === '\n') lineStarts.push(i + 1);
  }
  return { text, lineStarts };
}

function viewFor(map: RepoMap, path: string, cache: Map<string, CodeView | undefined>): CodeView | undefined {
  if (cache.has(path)) return cache.get(path);
  const file = map.filesByPath.get(path);
  const view = file?.text ? buildView(codeText(file.text, file.language)) : undefined;
  cache.set(path, view);
  return view;
}

function linesOf(view: CodeView, startLine: number, endLine: number): string {
  const start = view.lineStarts[startLine - 1];
  if (start === undefined) return '';
  const end = view.lineStarts[endLine] ?? view.text.length;
  return view.text.slice(start, end);
}

/** Source text from `open` (an opening bracket) to its match, exclusive. */
function balancedSlice(text: string, open: number): string | undefined {
  let depth = 0;
  let quote: string | undefined;
  const limit = Math.min(text.length, open + 20000);
  for (let i = open; i < limit; i++) {
    const ch = text[i]!;
    if (quote !== undefined) {
      if (ch === '\\') { i++; continue; }
      if (ch === quote) quote = undefined;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === '`') { quote = ch; continue; }
    if (ch === '(' || ch === '[' || ch === '{') { depth++; continue; }
    if (ch === ')' || ch === ']' || ch === '}') {
      depth--;
      if (depth === 0) return text.slice(open + 1, i);
    }
  }
  return undefined;
}

/**
 * The argument list of a call, read from the comment-stripped source rather
 * than from the parser's capped `args`.
 *
 * This matters for correctness, not neatness: the parser caps each argument at
 * 200 characters, so an option object with the ceiling written after that point
 * would look like an option object with no ceiling. Claiming a missing cap on a
 * truncated string would be a false positive by construction.
 */
function argumentText(view: CodeView, call: CallRef): string | undefined {
  const start = view.lineStarts[call.line - 1];
  if (start === undefined) return undefined;
  const window = view.text.slice(start, start + 4000);
  const leaf = lastSegment(call.callee);
  let at = leaf ? window.indexOf(leaf) : 0;
  if (at === -1) at = 0;
  const open = window.indexOf('(', at + leaf.length);
  if (open === -1) return undefined;
  return balancedSlice(view.text, start + open);
}

/** Top-level `key: value` pairs of an object-literal body, depth- and quote-aware. */
function topLevelEntries(body: string): Array<{ key: string; value: string }> {
  const out: Array<{ key: string; value: string }> = [];
  let depth = 0;
  let quote: string | undefined;
  let quoteStart = -1;
  let current = '';
  let key: string | undefined;
  let valueStart = 0;

  for (let i = 0; i < body.length; i++) {
    const ch = body[i]!;
    if (quote !== undefined) {
      if (ch === '\\') { i++; continue; }
      if (ch === quote) {
        if (depth === 0 && key === undefined) current = body.slice(quoteStart + 1, i);
        quote = undefined;
      }
      continue;
    }
    if (ch === '"' || ch === "'" || ch === '`') { quote = ch; quoteStart = i; continue; }
    if (ch === '(' || ch === '[' || ch === '{') { depth++; continue; }
    if (ch === ')' || ch === ']' || ch === '}') { depth--; continue; }
    if (depth !== 0) continue;
    if (ch === ':' && key === undefined) {
      const candidate = current.trim();
      if (/^[A-Za-z_$][\w$]*$/.test(candidate)) { key = candidate; valueStart = i + 1; }
      current = '';
      continue;
    }
    if (ch === ',') {
      if (key !== undefined) { out.push({ key, value: body.slice(valueStart, i).trim() }); key = undefined; }
      current = '';
      continue;
    }
    if (key === undefined) current += ch;
  }
  if (key !== undefined) out.push({ key, value: body.slice(valueStart).trim() });
  return out;
}

/** The first argument when it is an object literal, else undefined. */
function optionsBody(argText: string | undefined): string | undefined {
  if (argText === undefined) return undefined;
  const open = argText.indexOf('{');
  if (open === -1) return undefined;
  // Reject a leading identifier argument: `create(params, { ... })` style options
  // are still readable, but `create(params)` is not, and guessing is worse than
  // staying silent.
  const before = argText.slice(0, open);
  if (/[\w$]/.test(before.replace(/[\s,(]/g, ''))) return undefined;
  return balancedSlice(argText, open);
}

/**
 * The innermost *function* a line sits in.
 *
 * Deliberately not the innermost symbol of any kind: a multi-line
 * `const x = await query({...})` is itself a symbol, and treating it as the
 * enclosing scope would hide everything the function does with the result —
 * which is exactly what the over-fetch rule has to read before it claims a
 * value is unused.
 */
function enclosingFunction(mod: ParsedModule, line: number): SymbolInfo | undefined {
  let best: SymbolInfo | undefined;
  for (const s of mod.symbols) {
    if (s.kind !== 'function' && s.kind !== 'arrow' && s.kind !== 'method') continue;
    if (s.startLine <= line && s.endLine >= line) {
      if (!best || s.endLine - s.startLine < best.endLine - best.startLine) best = s;
    }
  }
  return best;
}

/** The identifier a call's result is assigned to, read from the source line. */
function assignedNameAt(view: CodeView, line: number): string | undefined {
  const text = linesOf(view, line, line);
  const m = /(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=/.exec(text);
  return m?.[1];
}

function modelFor(map: RepoMap, name: string | undefined): DataModel | undefined {
  if (!name) return undefined;
  return map.models.find((m) => sameEntity(m.name, name));
}

/** The model a dotted data call addresses: `prisma.order.findMany` -> Order. */
function modelForCall(map: RepoMap, call: CallRef): DataModel | undefined {
  const segs = calleeSegments(call.callee);
  if (segs.length < 2) return undefined;
  const receiver = segs[segs.length - 2];
  return modelFor(map, receiver) ?? (segs.length === 2 ? modelFor(map, segs[0]) : undefined);
}

/** Evidence, dropped unless it resolves against the snapshot. */
function verifiedOnly(items: Array<Evidence | undefined>): Evidence[] {
  return items.filter((e): e is Evidence => !!e && e.verified);
}

/** The declaration line of a model, for cross-file evidence. */
function modelEvidence(map: RepoMap, model: DataModel, note: string): Evidence | undefined {
  const needles = [
    `model ${model.name}`,
    `class ${model.name}`,
    `CREATE TABLE ${model.name}`,
    `CREATE TABLE "${model.name}"`,
    `CREATE TABLE IF NOT EXISTS ${model.name}`,
    model.name,
  ];
  for (const needle of needles) {
    const e = map.evidenceAt(model.file, needle, note);
    if (e.verified) return e;
  }
  return undefined;
}

function featureless(map: RepoMap, path: string): boolean {
  const role = map.filesByPath.get(path)?.role;
  return role === 'test' || role === 'documentation' || role === 'generated'
    || role === 'vendored' || role === 'asset';
}

/** Parsed source modules worth reasoning about: excludes tests and fixtures. */
function productionModules(map: RepoMap): ParsedModule[] {
  return [...map.modules.values()].filter((m) => m.parsed && !featureless(map, m.path));
}

// --------------------------------------------------------- AI call surface ---

interface ModelCall {
  mod: ParsedModule;
  call: CallRef;
  /** `sdk` for a provider client call, `http` for a direct call to a provider URL. */
  kind: 'sdk' | 'http';
  /** True when the receiver was resolved to a provider client. */
  receiverResolved: boolean;
}

function isAiSpecifier(spec: string): boolean {
  if (AI_SDK_EXACT.has(spec)) return true;
  return AI_SDK_PREFIXES.some((p) => spec === p.replace(/\/$/, '') || spec.startsWith(p));
}

/** Modules that import a provider SDK directly. */
function directAiModules(map: RepoMap): Set<string> {
  const out = new Set<string>();
  for (const mod of map.modules.values()) {
    if (!mod.parsed) continue;
    if (mod.imports.some((i) => i.external && isAiSpecifier(i.specifier))) out.add(mod.path);
  }
  return out;
}

/**
 * Identifier roots in this module that hold a provider client.
 *
 * Three ways a root qualifies: it is a name imported from a provider SDK, it is
 * a local binding constructed from such a name, or it is re-exported by a
 * project module that imports a provider SDK (one hop, which covers the common
 * `lib/ai.ts` wrapper).
 */
function aiClientRoots(map: RepoMap, mod: ParsedModule, aiModules: Set<string>): Set<string> {
  const roots = new Set<string>();
  const sdkNames = new Set<string>();

  for (const imp of mod.imports) {
    if (imp.external && isAiSpecifier(imp.specifier)) {
      for (const n of imp.names) {
        if (n === '*' || n === 'default') continue;
        sdkNames.add(n);
        roots.add(n);
      }
      // A default import is bound to a name the parser records as 'default';
      // recover it from the import line itself.
      if (imp.names.includes('default')) {
        const line = map.filesByPath.get(mod.path)?.text?.split('\n')[imp.line - 1] ?? '';
        const m = /import\s+(?:type\s+)?([A-Za-z_$][\w$]*)/.exec(line);
        if (m?.[1]) { sdkNames.add(m[1]); roots.add(m[1]); }
      }
    }
    if (!imp.external && imp.resolvedPath && aiModules.has(imp.resolvedPath)) {
      for (const n of imp.names) if (n !== '*' && n !== 'default') roots.add(n);
    }
  }

  if (sdkNames.size > 0) {
    const nameRe = new RegExp(`\\b(?:new\\s+)?(?:${[...sdkNames].map(escapeRe).join('|')})\\s*[.(]`);
    for (const sym of mod.symbols) {
      if (sym.kind !== 'const' && sym.kind !== 'arrow' && sym.kind !== 'function') continue;
      if (nameRe.test(sym.text)) roots.add(sym.name);
    }
  }
  return roots;
}

/**
 * Every call in the project that spends provider tokens.
 *
 * The gate is the module's own imports: a dotted shape such as
 * `chat.completions.create` is only read as a model request in a module that
 * imports a provider SDK (directly, or through a project module that does). A
 * callee segment matching a declared data model is rejected outright, so a
 * write to a `messages` table is never counted as inference.
 */
function modelCalls(
  map: RepoMap,
  aiModules: Set<string>,
  views: Map<string, CodeView | undefined>,
): ModelCall[] {
  const out: ModelCall[] = [];

  // A direct HTTP call to a provider endpoint is metered inference just as much
  // as an SDK call, and plenty of projects skip the SDK. The URL in the
  // arguments is the evidence, so this pass needs no import gate — but the
  // request body must be written inline, or there is nothing to judge.
  for (const mod of productionModules(map)) {
    const view = viewFor(map, mod.path, views);
    if (!view) continue;
    for (const call of mod.calls) {
      if (!NETWORK_LEAVES.has(lastSegment(call.callee))) continue;
      const argText = argumentText(view, call);
      if (!argText || !PROVIDER_HOST_RE.test(argText)) continue;
      if (NON_COMPLETION_PATH_RE.test(argText)) continue;
      if (!INLINE_REQUEST_BODY_RE.test(argText)) continue;
      out.push({ mod, call, kind: 'http', receiverResolved: true });
    }
  }

  for (const mod of productionModules(map)) {
    const importsAi = mod.imports.some(
      (i) => (i.external && isAiSpecifier(i.specifier))
        || (!i.external && !!i.resolvedPath && aiModules.has(i.resolvedPath)),
    );
    if (!importsAi) continue;

    const roots = aiClientRoots(map, mod, aiModules);
    const importedNames = new Set<string>();
    for (const imp of mod.imports) {
      if (imp.external && isAiSpecifier(imp.specifier)) {
        for (const n of imp.names) if (MODEL_CALL_IMPORTED_NAMES.has(n)) importedNames.add(n);
      }
    }

    for (const call of mod.calls) {
      const segs = calleeSegments(call.callee);
      // A declared model in the callee chain means this is a datastore call.
      if (segs.some((s) => map.models.some((m) => sameEntity(m.name, s)))) continue;

      const root = segs[0];
      const receiverResolved = !!root && (roots.has(root)
        // `this.openai.chat…` cannot be resolved to a declaration, but the
        // segment itself names a provider inside a module that imports one.
        || segs.some((s) => /^(?:openai|anthropic|claude|gemini|genai|bedrock|groq|mistral|cohere|llm|model)$/i.test(s)));

      if (segs.length === 1 && importedNames.has(segs[0]!)) {
        out.push({ mod, call, kind: 'sdk', receiverResolved: true });
        continue;
      }
      if (MODEL_CALL_UNAMBIGUOUS.some((re) => re.test(call.callee))) {
        out.push({ mod, call, kind: 'sdk', receiverResolved });
        continue;
      }
      if (receiverResolved && MODEL_CALL_NEEDS_RECEIVER.some((re) => re.test(call.callee))) {
        out.push({ mod, call, kind: 'sdk', receiverResolved: true });
      }
    }
  }
  return out;
}

/** The route whose handler contains a line, when the file serves traffic. */
function routeFor(map: RepoMap, path: string, line: number): ApiEndpoint | undefined {
  const candidates = map.routes.filter((r) => r.file === path);
  if (candidates.length === 0) return undefined;
  const mod = map.modules.get(path);
  if (mod?.parsed) {
    const sym = enclosingFunction(mod, line);
    if (sym) {
      const exact = candidates.find((r) => r.handlerSymbol === sym.name);
      if (exact) return exact;
    }
  }
  return candidates[0];
}

// ---------------------------------------------------------------- analyzer ---

export const costAnalyzer: Analyzer = {
  id: 'cost',
  category: 'cost',
  description:
    'Structural cost risk: uncapped model requests, token accounting, over-fetching, duplicated services, and storage that grows without a bound. No monetary figure is produced — this scan has no billing data.',

  precondition(map: RepoMap): string | undefined {
    const parsed = [...map.modules.values()].filter((m) => m.parsed).length;
    const manifests = map.byRole('manifest').length;
    if (parsed === 0 && manifests === 0) {
      return 'no source file could be parsed and no dependency manifest was found, so there is nothing to assess for cost';
    }
    return undefined;
  },

  run(ctx: AnalyzerContext): Finding[] {
    const { map } = ctx;
    const views = new Map<string, CodeView | undefined>();
    const aiModules = directAiModules(map);
    const calls = modelCalls(map, aiModules);

    const findings: Finding[] = [];
    findings.push(...uncappedModelOutput(ctx, calls, views));
    findings.push(...modelCallPerItem(ctx, calls, views));
    findings.push(...unboundedPromptContext(ctx, calls, views));
    findings.push(...noUsageAccounting(ctx, calls));
    const overfetched = relationsFetchedButUnused(ctx, views);
    findings.push(...overfetched.findings);
    findings.push(...wholeTableAllColumns(ctx, views, overfetched.claimed));
    findings.push(...storageWithoutRetention(ctx, views));
    findings.push(...duplicateCapabilities(ctx));
    findings.push(...duplicateDataAccessLayers(ctx));

    return findings;
  },
};

// ------------------------------------------------- AI: no output ceiling ---

/**
 * A model request with no ceiling on output length.
 *
 * Output tokens are the billed quantity the caller does not control: the model
 * decides how long the reply is, so the cost of one request is open-ended. The
 * check reads the call's real argument text (not the parser's capped copy) and
 * accepts any provider spelling of the ceiling. A call whose options arrive as
 * a variable is skipped rather than guessed at — the cap may well be in that
 * variable.
 */
function uncappedModelOutput(
  ctx: AnalyzerContext,
  calls: ModelCall[],
  views: Map<string, CodeView | undefined>,
): Finding[] {
  const { map } = ctx;
  const out: Finding[] = [];

  for (const { mod, call, receiverResolved } of calls) {
    if (!CAP_IN_ARGUMENTS.some((re) => re.test(call.callee))) continue;
    const view = viewFor(map, mod.path, views);
    if (!view) continue;

    const body = optionsBody(argumentText(view, call));
    if (body === undefined) continue;          // options not readable: stay silent
    if (OUTPUT_CAP_RE.test(body)) continue;    // a ceiling is set

    const route = routeFor(map, mod.path, call.line);
    const reachableAnonymously = !!route && route.authRequired !== 'required';
    const streaming = /\bstream\s*:\s*true\b/.test(body) || /stream$/i.test(lastSegment(call.callee));

    const evidence = verifiedOnly([
      map.evidenceLine(mod.path, call.line,
        'model request with no max output ceiling in its options, so reply length — and the tokens billed for it — is set by the model'),
      route
        ? map.evidenceLine(route.file, route.line ?? call.line,
          `reachable over HTTP as ${route.method} ${route.path}${reachableAnonymously ? ' with no authentication required' : ''}`)
        : undefined,
    ]);
    if (evidence.length === 0) continue;

    const severity: Severity = reachableAnonymously ? 'high' : 'medium';
    const confidence: Confidence = receiverResolved ? 'strong' : 'moderate';

    out.push(ctx.finding({
      ruleId: 'cost.ai.output_not_capped',
      title: `${call.callee}() requests inference with no output token ceiling`,
      severity,
      confidence,
      status: 'needs_runtime_verification',
      detectionSource: route ? 'graph' : 'static',
      files: route && route.file !== mod.path ? [mod.path, route.file] : [mod.path],
      symbol: call.inSymbol,
      evidence,
      trace: route
        ? {
          kind: 'call',
          steps: [
            { file: route.file, line: route.line, symbol: route.handlerSymbol, detail: `${route.method} ${route.path} handler entered` },
            { file: mod.path, line: call.line, symbol: call.inSymbol, detail: `${call.callee}() called with no output ceiling in its options` },
            { file: mod.path, line: call.line, detail: reachableAnonymously
              ? 'no authentication gate was resolved on this route, so an anonymous caller can drive the request volume'
              : 'the route requires a session, so request volume is bounded by the authenticated population' },
          ],
          complete: receiverResolved,
        }
        : undefined,
      explanation:
        `The options passed to ${call.callee}() contain no output ceiling — no max_tokens, max_output_tokens, or equivalent for this provider. ` +
        'Output tokens are billed per token and their number is decided by the model, not by this code, so the cost of a single request has no upper bound in the source. ' +
        (streaming ? 'The response is streamed, which changes when the tokens arrive but not how many are paid for. ' : '') +
        (reachableAnonymously
          ? 'The call sits behind an HTTP route on which no authentication gate was resolved, so the number of requests is also not bounded by anything in this code. '
          : '') +
        'How much this costs depends on traffic and on the distribution of reply lengths, neither of which a snapshot can see.',
      userImpact: reachableAnonymously
        ? 'Spend tracks whatever volume arrives at this endpoint. In the pattern users notice, a burst of traffic — organic or hostile — exhausts the provider budget or trips a rate limit, and the feature then fails for everyone until the next billing window or a manual limit increase.'
        : 'An unusually long reply costs an unusually large amount and takes an unusually long time to produce; the user sees a slow answer, and the bill carries the rest.',
      likelyRootCause:
        'The call was written to the provider quickstart, which omits the ceiling so the example works for any prompt.',
      downstreamConsequences: [
        'Spend cannot be forecast from the code: the per-request cost is a property of model output, not of a configured limit.',
        'A prompt that induces a long reply — repetition, an injected instruction to continue, a large document — multiplies the cost of one request.',
        'Without a ceiling there is no natural place to attach a per-user or per-tenant budget later.',
      ],
      remediation:
        'Set an explicit output ceiling on every model request, chosen from what the feature actually renders rather than from the model maximum, and treat truncation as a handled case in the response path. ' +
        'Keep the ceiling in one place (a shared request helper or a config constant) so no new call site can be added without one. ' +
        'Add a per-user or per-tenant request budget alongside it, and a server-side rate limit on the route, so the number of requests is bounded as well as the size of each one.',
      effort: 'small',
      verificationSteps: [
        'Send a prompt that invites a very long answer and confirm the response is truncated at the configured ceiling rather than running on.',
        'Read the token counts for that request in the provider usage dashboard — that measurement, not this report, is what quantifies the cost per request.',
        'Confirm the feature degrades acceptably when a reply is truncated (a visible "shortened" state, not a parse error).',
        reachableAnonymously
          ? 'Confirm an unauthenticated caller is rate limited on this route before the provider limit is reached.'
          : 'Confirm a single authenticated session cannot issue unbounded concurrent requests.',
      ],
      references: [REF.owaspLlmConsumption, REF.cweLimits, REF.costPillar, REF.notMeasured],
    }));
  }
  return out;
}

// --------------------------------------------------- AI: per-item requests ---

/**
 * A model request issued once per element.
 *
 * The loop flag is AST-derived: the parser sets it from the enclosing
 * for/while/forEach/map node, so a request inside `items.map(...)` counts even
 * though it is written as a callback. The cost claim is multiplicative — N
 * elements buy N requests — and N is a property of the data, so the magnitude
 * is explicitly left unquantified.
 */
function modelCallPerItem(
  ctx: AnalyzerContext,
  calls: ModelCall[],
  views: Map<string, CodeView | undefined>,
): Finding[] {
  const { map } = ctx;
  const out: Finding[] = [];

  for (const { mod, call, receiverResolved } of calls) {
    if (!call.insideLoop) continue;
    const view = viewFor(map, mod.path, views);
    if (!view) continue;

    const body = optionsBody(argumentText(view, call));
    const capped = body !== undefined && OUTPUT_CAP_RE.test(body);
    const route = routeFor(map, mod.path, call.line);

    const evidence = verifiedOnly([
      map.evidenceLine(mod.path, call.line,
        'inference requested inside a loop body, so one request is bought per element'),
    ]);
    if (evidence.length === 0) continue;

    out.push(ctx.finding({
      ruleId: 'cost.ai.request_per_item',
      title: `${call.callee}() issues one model request per element`,
      severity: 'high',
      confidence: receiverResolved ? 'strong' : 'moderate',
      status: 'needs_runtime_verification',
      files: [mod.path],
      symbol: call.inSymbol,
      evidence,
      explanation:
        `${call.callee}() is called inside a loop, so the number of billed requests equals the number of elements iterated. ` +
        'Provider pricing is per request and per token, so both the request count and the total token count scale with the collection — and the collection size is a property of the data, which this scan cannot read. ' +
        (capped
          ? 'Each individual request does carry an output ceiling, which bounds the cost of one request but not the number of them. '
          : 'No output ceiling was found on the request either, so neither the count nor the size of the responses is bounded. ') +
        (route ? `The loop runs inside the ${route.method} ${route.path} handler, so it repeats per inbound request as well. ` : ''),
      userImpact:
        'The feature gets slower and more expensive in proportion to how much data the user is working with, and the first person to hit a large collection is the one who discovers the provider rate limit — at which point the operation fails part-way through, having already been paid for.',
      likelyRootCause:
        'A per-item prompt was the simplest way to express the task, and the batch form of the same request was not available when it was written.',
      downstreamConsequences: [
        'Provider rate limits are reached by collection size rather than by user count, so the failure appears without a traffic increase.',
        'A partial failure mid-loop leaves work half-done and already billed, so a retry pays for the completed items again unless results are persisted.',
      ],
      remediation:
        'Replace the per-element request with a single request that handles the whole batch where the provider supports it, or with a batch/offline endpoint where throughput matters more than latency. ' +
        'Where per-element requests are unavoidable: bound the number processed in one operation, cache by a content key so repeated elements are not re-sent, persist each result as it arrives so a retry resumes rather than restarts, and keep an output ceiling on every request.',
      effort: 'medium',
      verificationSteps: [
        'Count the provider requests issued for one operation over a collection of a realistic size, then compare that count against the usage dashboard for the same window.',
        'Confirm the batched form returns results equivalent to the per-element form on a held-out sample before switching.',
        'Confirm a retry after a mid-loop failure does not re-send elements that already succeeded.',
      ],
      references: [REF.cweLoopResource, REF.owaspLlmConsumption, REF.costPillar, REF.notMeasured],
    }));
  }
  return out;
}

// ------------------------------------------------- AI: unbounded context ---

/**
 * A prompt assembled from a whole collection or a whole file.
 *
 * The conjunction is what makes this reportable: a bulk producer (a read with
 * no row ceiling, or a whole-file read) in the same function, its result bound
 * to a name, and that name interpolated into the arguments of a model request.
 * Input tokens are billed, so the prompt grows — and the bill with it — as the
 * underlying data grows.
 */
function unboundedPromptContext(
  ctx: AnalyzerContext,
  calls: ModelCall[],
  views: Map<string, CodeView | undefined>,
): Finding[] {
  const { map } = ctx;
  const out: Finding[] = [];

  for (const { mod, call, receiverResolved } of calls) {
    const view = viewFor(map, mod.path, views);
    if (!view) continue;
    const argText = argumentText(view, call);
    if (!argText) continue;

    const sym = enclosingFunction(mod, call.line);
    if (!sym) continue;

    for (const producer of mod.calls) {
      if (producer.line < sym.startLine || producer.line > sym.endLine) continue;
      if (producer.line >= call.line) continue;

      const leaf = lastSegment(producer.callee);
      const isCollectionRead = COLLECTION_READ_LEAVES.has(leaf);
      const isFileRead = BULK_FILE_READ_LEAVES.has(leaf);
      if (!isCollectionRead && !isFileRead) continue;

      if (isCollectionRead) {
        const body = optionsBody(argumentText(view, producer)) ?? '';
        const keys = topLevelEntries(body).map((e) => e.key);
        if (keys.some((k) => ROW_CEILING_KEYS.has(k))) continue; // bounded read
      }

      const name = assignedNameAt(view, producer.line);
      if (!name) continue;
      if (!new RegExp(`\\b${escapeRe(name)}\\b`).test(argText)) continue;

      const model = isCollectionRead ? modelForCall(map, producer) : undefined;
      const evidence = verifiedOnly([
        map.evidenceLine(mod.path, call.line,
          `prompt interpolates '${name}', which holds ${isFileRead ? 'the whole contents of a file' : 'every row the read above returned'}`),
        map.evidenceLine(mod.path, producer.line,
          isFileRead
            ? 'whole-file read with no size bound'
            : 'collection read with no row ceiling, so the size of this value is set by the data'),
        model ? modelEvidence(map, model, `the ${model.name} table supplies the interpolated value, and its row count grows with use`) : undefined,
      ]);
      if (evidence.length === 0) continue;

      out.push(ctx.finding({
        ruleId: 'cost.ai.unbounded_prompt_context',
        title: `Prompt for ${call.callee}() is built from an unbounded ${isFileRead ? 'file read' : 'collection read'}`,
        severity: 'high',
        confidence: receiverResolved && !!model ? 'strong' : 'moderate',
        status: 'needs_runtime_verification',
        detectionSource: model ? 'graph' : 'static',
        files: model ? [mod.path, model.file] : [mod.path],
        symbol: call.inSymbol,
        evidence,
        trace: {
          kind: 'call',
          steps: [
            { file: mod.path, line: producer.line, symbol: sym.name, detail: `${producer.callee}() returns an unbounded amount of data into '${name}'` },
            ...(model ? [{ file: model.file, detail: `'${name}' holds ${model.name} rows; the table has no ceiling in this query` }] : []),
            { file: mod.path, line: call.line, symbol: call.inSymbol, detail: `'${name}' is interpolated into the ${call.callee}() request, becoming billed input tokens` },
          ],
          complete: !!model || isFileRead,
        },
        explanation:
          `The value passed into ${call.callee}() includes '${name}', which is produced by ${producer.callee}() with no bound on how much it returns. ` +
          'Input tokens are billed, so the price of each request is a function of how much data that read happens to return on the day it runs, and the request will eventually exceed the model context window as well. ' +
          (model ? `The data comes from ${model.name}, whose row count grows with use. ` : '') +
          'No size figure is given here because the amount of data is a property of the deployment, not of the code.',
        userImpact:
          'The feature works on a small data set and then, with no code change, becomes slow and expensive and finally fails with a context-length error once the underlying data crosses a threshold — a failure that arrives suddenly and affects everyone using the feature.',
        likelyRootCause: 'Passing the whole data set was the quickest way to give the model enough context, and no selection step was added.',
        downstreamConsequences: [
          'Cost per request rises as the data grows, with no code change to attribute it to.',
          'Once the context window is exceeded the request fails outright rather than degrading.',
          'Prompt caching cannot help much, because the context differs on every call.',
        ],
        remediation:
          'Select the context instead of passing everything: retrieve the few records or passages relevant to the request (a filtered query, a ranked retrieval step, or an embedding search), bound both the number of items and their total length, and count the tokens of the assembled prompt before sending it so an over-large context is rejected or trimmed deterministically. ' +
          'Where the whole data set genuinely must be summarised, do it incrementally and cache the intermediate summaries rather than re-sending the raw data per request.',
        effort: 'medium',
        verificationSteps: [
          'Count the tokens of the assembled prompt against a realistically large data set and confirm the count is bounded by the code, not by the data.',
          'Confirm answer quality on a held-out sample is preserved after switching from the whole data set to the selected context.',
          'Compare per-request input tokens before and after in the provider usage dashboard — that comparison is the measurement this report cannot make.',
        ],
        references: [REF.owaspLlmConsumption, REF.cweLimits, REF.costPillar, REF.notMeasured],
      }));
      break; // one finding per model call
    }
  }
  return out;
}

// --------------------------------------------------- AI: usage accounting ---

/**
 * Metered inference with no token accounting anywhere in the project.
 *
 * This is an absence claim, so it is stated as one: the analyzer looked for any
 * read of a provider usage field, any token counting, and any model or table
 * that records consumption, and found none in the code it could parse. Spend
 * that is not attributed cannot be controlled, forecast, or billed on.
 */
function noUsageAccounting(ctx: AnalyzerContext, calls: ModelCall[]): Finding[] {
  const { map } = ctx;
  if (calls.length === 0) return [];

  const parsedModules = productionModules(map);
  for (const mod of parsedModules) {
    const file = map.filesByPath.get(mod.path);
    const text = codeText(file?.text ?? null, file?.language);
    if (USAGE_ACCOUNTING_RE.test(text)) return [];
  }
  if (map.models.some((m) => METERING_MODEL_RE.test(m.name))) return [];

  const unparsed = [...map.modules.values()].filter((m) => !m.parsed).length;
  const first = calls[0]!;
  const evidence = verifiedOnly([
    map.evidenceLine(first.mod.path, first.call.line,
      'billed model request; the response is consumed without reading the usage or token counts it returns'),
    ...calls.slice(1, 4).map(({ mod, call }) =>
      map.evidenceLine(mod.path, call.line, 'further billed model request with no usage accounting')),
  ]);
  if (evidence.length === 0) return [];

  const files = [...new Set(calls.map((c) => c.mod.path))];

  return [ctx.finding({
    ruleId: 'cost.ai.no_usage_accounting',
    title: `Metered model requests are issued from ${files.length} file${files.length === 1 ? '' : 's'} with no token accounting anywhere in the project`,
    severity: 'medium',
    confidence: 'moderate',
    detectionSource: 'graph',
    files,
    symbol: first.call.inSymbol,
    evidence,
    trace: {
      kind: 'unused_integration',
      steps: [
        ...calls.slice(0, 4).map(({ mod, call }) => ({
          file: mod.path, line: call.line, symbol: call.inSymbol,
          detail: `${call.callee}() spends provider tokens here`,
        })),
        { file: first.mod.path, detail: 'no usage, prompt_tokens, completion_tokens, or token-counting read appears in any module that could be parsed' },
        { file: first.mod.path, detail: 'no model or table records consumption, credits, or quota' },
      ],
      complete: unparsed === 0,
    },
    explanation:
      `${calls.length} model request${calls.length === 1 ? '' : 's'} in this project spend${calls.length === 1 ? 's' : ''} provider tokens, and nothing in the code records how many. ` +
      'Provider responses carry usage counts, and none of them is read, stored, or attributed to a user, tenant, or feature. ' +
      'The consequence is not a slower application but a blind one: spend can only be seen in aggregate on the provider invoice, after it has happened, with no way to say which feature or which caller caused it.' +
      (unparsed > 0
        ? ` Note that ${unparsed} module${unparsed === 1 ? '' : 's'} could not be parsed, so metering could exist there — confirm before acting.`
        : ''),
    userImpact:
      'When spend runs ahead of expectations the only available remedy is coarse: disable the feature or raise the budget, because there is no per-user or per-feature breakdown to act on. Users of a heavily-used feature are as likely to lose it as the users who caused the cost.',
    likelyRootCause: 'The integration was built to work first, and accounting was left for when the cost became visible.',
    downstreamConsequences: [
      'Abuse of an AI feature is indistinguishable from popularity until the invoice arrives.',
      'Per-user or per-plan limits cannot be enforced, because nothing counts what a user has consumed.',
      'A model or prompt change cannot be evaluated on cost, only on output quality.',
    ],
    remediation:
      'Read the usage counts the provider returns on every request and record them with the identity that caused them — user or tenant, feature, model, and prompt version — in a usage table or your metrics backend. ' +
      'Count the input tokens before sending, so an over-large prompt can be refused rather than discovered on the invoice. ' +
      'Then set budgets against those recorded counts (per user, per tenant, per day) and alert on the rate rather than the total, so a runaway is caught in minutes instead of at the end of the billing period.',
    effort: 'medium',
    verificationSteps: [
      'Issue one request and confirm a usage record is written with the token counts and the caller identity.',
      'Reconcile the sum of recorded tokens for a day against the provider usage dashboard for the same day; they should agree within rounding.',
      'Confirm a caller who exceeds their budget is refused before the provider is called.',
    ],
    references: [REF.owaspLlmConsumption, REF.costPillar, REF.notMeasured],
  })];
}

// ----------------------------------------------------------- over-fetching ---

/**
 * A relation pulled into a query that the handler never reads.
 *
 * Both halves are required. First, the query asks for a relation by name
 * (Prisma/Drizzle `include`/`with`, TypeORM `relations`, Mongoose `populate`)
 * and that name is not a scalar column of the declared model, so it is a join
 * that returns rows. Second, the function that issued the query never touches
 * that property and never hands the result anywhere this analyzer cannot see —
 * so the extra rows are fetched, serialised, and dropped.
 *
 * The escape check is the false-positive control: if the result is returned, or
 * passed to another function, the relation may be used out of view, and no
 * finding is produced.
 */
function relationsFetchedButUnused(
  ctx: AnalyzerContext,
  views: Map<string, CodeView | undefined>,
): { findings: Finding[]; claimed: Set<string> } {
  const { map } = ctx;
  const out: Finding[] = [];
  const claimed = new Set<string>();

  for (const mod of productionModules(map)) {
    const view = viewFor(map, mod.path, views);
    if (!view) continue;

    for (const call of mod.calls) {
      const model = modelForCall(map, call);
      if (!model) continue;

      const body = optionsBody(argumentText(view, call));
      if (body === undefined) continue;
      const entries = topLevelEntries(body);

      const requested: string[] = [];
      for (const { key, value } of entries) {
        if (RELATION_OBJECT_KEYS.has(key)) {
          for (const inner of topLevelEntries(balancedSlice(value, Math.max(0, value.indexOf('{'))) ?? '')) {
            if (!/^(?:false|undefined|null)$/.test(inner.value)) requested.push(inner.key);
          }
        } else if (RELATION_LIST_KEYS.has(key)) {
          for (const m of value.matchAll(/['"`]([A-Za-z_$][\w$.]*)['"`]/g)) requested.push(m[1]!);
        }
      }
      if (requested.length === 0) continue;

      // Only names that are not scalar columns of the model are joins.
      const relations = requested.filter((name) => !model.fields.some((f) => f.name === name));
      if (relations.length === 0) continue;

      const sym = enclosingFunction(mod, call.line);
      if (!sym) continue;
      const region = linesOf(view, sym.startLine, sym.endLine);
      const resultName = assignedNameAt(view, call.line);

      // Does the result leave this function?
      let escapes = false;
      if (resultName) {
        const word = new RegExp(`\\b${escapeRe(resultName)}\\b`);
        for (const other of mod.calls) {
          if (other === call) continue;
          if (other.line < sym.startLine || other.line > sym.endLine) continue;
          if (other.callee.startsWith(`${resultName}.`)) continue; // a method on the result
          if (other.args.some((a) => word.test(a))) { escapes = true; break; }
        }
        if (!escapes) {
          for (const line of region.split('\n')) {
            if (/\breturn\b/.test(line) && word.test(line)) { escapes = true; break; }
          }
        }
      } else {
        escapes = true; // result not bound to a name: it is being used inline
      }
      if (escapes) continue;

      const unused = relations.filter((name) => {
        const accessed = new RegExp(`\\.\\s*${escapeRe(name)}\\b`).test(region);
        const destructured = new RegExp(`\\{[^}]*\\b${escapeRe(name)}\\b[^}]*\\}\\s*=`).test(region);
        return !accessed && !destructured;
      });
      if (unused.length === 0) continue;

      const relatedModels = unused
        .map((name) => model.relations.find((r) => sameEntity(r.to, name)))
        .filter((r): r is NonNullable<typeof r> => !!r);
      const relatedModel = relatedModels.length > 0 ? modelFor(map, relatedModels[0]!.to) : undefined;
      const collectionRead = COLLECTION_READ_LEAVES.has(lastSegment(call.callee));
      const bounded = entries.some((e) => ROW_CEILING_KEYS.has(e.key));

      const evidence = verifiedOnly([
        map.evidenceLine(mod.path, call.line,
          `the query asks for ${unused.map((r) => `'${r}'`).join(', ')}; the handler never reads ${unused.length === 1 ? 'it' : 'them'}`),
        modelEvidence(map, model, `${unused.map((r) => `'${r}'`).join(', ')} ${unused.length === 1 ? 'is' : 'are'} a relation on ${model.name}, not a column, so each one is a join that returns rows`),
        relatedModel
          ? modelEvidence(map, relatedModel, `the joined ${relatedModel.name} rows are transferred and discarded`)
          : undefined,
      ]);
      if (evidence.length === 0) continue;

      claimed.add(`${mod.path}:${call.line}`);
      const severity: Severity = collectionRead && !bounded ? 'medium' : 'low';

      out.push(ctx.finding({
        ruleId: 'cost.data.unused_relation_fetched',
        title: `${call.callee}() fetches ${model.name} relation${unused.length === 1 ? '' : 's'} ${unused.map((r) => `'${r}'`).join(', ')} that the handler never reads`,
        severity,
        confidence: 'strong',
        status: 'needs_runtime_verification',
        detectionSource: 'graph',
        files: [...new Set([mod.path, model.file, ...(relatedModel ? [relatedModel.file] : [])])],
        symbol: call.inSymbol,
        evidence,
        trace: {
          kind: 'call',
          steps: [
            { file: mod.path, line: call.line, symbol: call.inSymbol, detail: `${call.callee}() requests the ${unused.join(', ')} relation${unused.length === 1 ? '' : 's'} of ${model.name}` },
            { file: model.file, detail: `${unused.join(', ')} ${unused.length === 1 ? 'is' : 'are'} declared as a relation on ${model.name}, so the database joins and returns those rows` },
            { file: mod.path, line: sym.startLine, symbol: sym.name, detail: `the result is bound to '${resultName}' and never leaves this function` },
            { file: mod.path, line: sym.startLine, symbol: sym.name, detail: `no member access or destructuring of ${unused.join(', ')} appears anywhere in the function body` },
          ],
          complete: true,
        },
        explanation:
          `${call.callee}() asks the database for the ${unused.join(', ')} relation of ${model.name}, and the function that issued the query never reads it. ` +
          (collectionRead && !bounded
            ? `The read has no row ceiling either, so the join runs for every ${model.name} row: the database does the work, the rows cross the network into the application process, and they are then discarded. `
            : 'The joined rows cross the network into the application process and are then discarded. ') +
          'This is paid for three times over — in database read units and I/O, in data transfer between the database and the application, and in the memory and deserialisation cost of rows nothing uses. ' +
          'How much that amounts to depends on how many related rows exist per parent, which is a property of the data and not visible here.',
        userImpact:
          'The request is slower and heavier than the result it produces, and it gets worse as the related data grows — so the feature degrades for everyone as the busiest accounts accumulate history, long before anyone changes the code.',
        likelyRootCause:
          'The relation was needed by an earlier version of the handler, or was added speculatively when the query was written, and nothing removed it when the code around it changed.',
        downstreamConsequences: [
          'The join competes for database resources with queries that do need the data, so the cost is not confined to this endpoint.',
          'Rows the handler never uses still travel across the network, and egress is billed on most managed databases.',
          'The real memory and I/O cost of this endpoint is invisible in the code, because the data it loads is not the data it returns.',
        ],
        remediation:
          `Remove ${unused.map((r) => `'${r}'`).join(', ')} from the query. ` +
          'Where the handler only needs a derived value such as a count, ask the database for that value — a relation count or an aggregate — rather than for the rows themselves. ' +
          'Project the specific columns the handler reads instead of whole records, and add a row ceiling to the read so the per-call cost is bounded by the code rather than by the data.',
        effort: 'trivial',
        verificationSteps: [
          'Remove the relation from the query and confirm the response body is byte-for-byte unchanged.',
          'Compare the rows read and the bytes returned for this query before and after, using the database\'s own statistics — that comparison is the measurement that quantifies the saving.',
          'Confirm no other caller depended on the relation being present (the result does not leave this function today, so this should hold).',
        ],
        references: [REF.cweExcessQuery, REF.dataMinimisation, REF.costPillar, REF.notMeasured],
      }));
    }
  }
  return { findings: out, claimed };
}

/**
 * A read of every row and every column of a table.
 *
 * Narrow on purpose: no filter, no row ceiling, and no column projection, on a
 * call whose receiver resolves to a declared model. A filtered read is left to
 * the performance analyzer's query-shape rules; what is reported here is a
 * query whose cost is the whole table, every time it runs, including columns
 * the caller may never read.
 */
function wholeTableAllColumns(
  ctx: AnalyzerContext,
  views: Map<string, CodeView | undefined>,
  claimed: Set<string>,
): Finding[] {
  const { map } = ctx;
  const out: Finding[] = [];

  for (const mod of productionModules(map)) {
    const view = viewFor(map, mod.path, views);
    if (!view) continue;

    for (const call of mod.calls) {
      if (claimed.has(`${mod.path}:${call.line}`)) continue;
      const leaf = lastSegment(call.callee);
      if (!COLLECTION_READ_LEAVES.has(leaf)) continue;

      const model = modelForCall(map, call);
      if (!model) continue;

      const argText = argumentText(view, call);
      if (argText === undefined) continue;
      // An argument that is not a readable object literal could be anything.
      const body = argText.trim() === '' ? '' : optionsBody(argText);
      if (body === undefined) continue;

      const keys = topLevelEntries(body).map((e) => e.key);
      if (keys.some((k) => FILTER_KEYS.has(k))) continue;      // filtered read
      if (keys.some((k) => ROW_CEILING_KEYS.has(k))) continue; // bounded read
      if (keys.some((k) => PROJECTION_KEYS.has(k))) continue;  // projected columns
      // A bare non-empty argument is probably a filter (`find({ status: 'x' })`).
      if (body.trim() !== '' && keys.length > 0) continue;

      const sym = enclosingFunction(mod, call.line);
      const columnCount = model.fields.length;
      const wideColumns = model.fields
        .filter((f) => /text|json|jsonb|blob|bytes|binary|xml|clob/i.test(f.type ?? ''))
        .map((f) => f.name);

      const evidence = verifiedOnly([
        map.evidenceLine(mod.path, call.line,
          'read with no filter, no row ceiling, and no column projection: every row and every column of the table'),
        modelEvidence(map, model, `${model.name} declares ${columnCount} column${columnCount === 1 ? '' : 's'}; all of them are transferred by this query`),
      ]);
      if (evidence.length === 0) continue;

      const exported = !!sym && sym.exported;
      const callers = exported ? (map.importers.get(mod.path) ?? []) : [];

      out.push(ctx.finding({
        ruleId: 'cost.data.whole_table_all_columns',
        title: `${call.callee}() reads every row and every column of ${model.name}`,
        severity: 'medium',
        confidence: 'strong',
        status: 'needs_runtime_verification',
        detectionSource: 'graph',
        files: [mod.path, model.file],
        symbol: call.inSymbol ?? sym?.name,
        evidence,
        trace: {
          kind: 'call',
          steps: [
            { file: mod.path, line: call.line, symbol: sym?.name, detail: `${call.callee}() called with no filter, ceiling, or projection` },
            { file: model.file, detail: `${model.name} has ${columnCount} declared column${columnCount === 1 ? '' : 's'}, so each returned row carries all of them` },
            ...(callers.length > 0
              ? [{ file: callers[0]!, detail: `${callers.length} module${callers.length === 1 ? '' : 's'} import this module, so the read is reachable from ${callers.length === 1 ? 'that caller' : 'those callers'}` }]
              : []),
          ],
          complete: true,
        },
        explanation:
          `${call.callee}() places no bound of any kind on what it retrieves: no filter to narrow the rows, no take/limit to cap them, and no column selection to narrow each row. ` +
          `Every ${model.name} row and all ${columnCount} of its columns are read, transferred, and deserialised on every call. ` +
          (wideColumns.length > 0
            ? `That includes ${wideColumns.join(', ')}, whose declared type can hold a large value per row, so the bytes moved are not proportional to the row count alone. `
            : '') +
          'The billed quantities here are database read units and I/O, data transfer out of the database, and the application memory needed to hold the result. ' +
          'All three scale with the table, and the table size is a property of the deployment that this scan cannot see — so no figure is given.',
        userImpact:
          'The feature behind this read is fast on a small table and gets steadily slower and more memory-hungry as the table fills, until it times out. Because the cost is shared — the same database, the same process memory — the slowdown is felt by users of other features too, not only this one.',
        likelyRootCause: 'The helper was written when the table was known to be small, so no bound was needed; the bound was never added as the data grew.',
        downstreamConsequences: [
          'Cost grows with the table rather than with usage, so it rises even while traffic is flat.',
          'Adding a column to the model silently increases the cost of every call to this helper.',
          'Most managed databases bill data transfer, so rows the caller never inspects are still paid for.',
        ],
        remediation:
          'Give the query a ceiling and a projection: select only the columns the callers read, and add an explicit row limit with paging (a limit with a sane default and a hard maximum, plus a cursor) so the per-call cost is set by the code. ' +
          (exported
            ? 'Because this is an exported helper, change the signature to require the bound rather than defaulting to unbounded, so a new caller cannot reintroduce the whole-table read. '
            : '') +
          'Where a whole-table pass is genuinely required (an export, a migration), stream it in cursor-based batches so memory stays flat, and run it off the request path.',
        effort: 'small',
        verificationSteps: [
          'Seed the table to a realistically large row count and confirm the returned row count is capped by the query rather than by the data.',
          'Record the rows read and bytes returned for this query from the database\'s own statistics before and after the change — that is the measurement that quantifies the saving.',
          'Confirm every caller still receives the fields it uses after the projection is narrowed.',
        ],
        references: [REF.cweExcessQuery, REF.dataMinimisation, REF.owaspResource, REF.notMeasured],
      }));
    }
  }
  return out;
}

// --------------------------------------------------------------- storage ---

/**
 * A table that accumulates rows with traffic and has no path that removes them.
 *
 * Four conditions together: the model's name says it records events rather than
 * domain state, it carries a creation timestamp (so rows are a time series),
 * something in the code inserts into it, and nothing in the code — or in any
 * configuration this analyzer can read — deletes, expires, prunes, or archives
 * it. Storage and backup are billed by volume, and a table like this grows
 * monotonically for as long as the application runs.
 */
function storageWithoutRetention(
  ctx: AnalyzerContext,
  views: Map<string, CodeView | undefined>,
): Finding[] {
  const { map } = ctx;
  const out: Finding[] = [];

  // A retention mechanism anywhere in the project suppresses the whole rule:
  // one scheduled prune usually covers every append-only table.
  for (const file of map.files) {
    if (file.binary || !file.text) continue;
    if (featureless(map, file.path)) continue;
    const role = file.role;
    const relevant = role === 'source' || role === 'route' || role === 'component'
      || role === 'config' || role === 'infrastructure' || role === 'ci'
      || role === 'schema' || role === 'migration' || role === 'manifest';
    if (!relevant) continue;
    if (RETENTION_SIGNAL_RE.test(codeText(file.text, file.language))) return [];
  }

  for (const model of map.models) {
    if (model.kind !== 'orm_model' && model.kind !== 'sql_table') continue;
    if (!ACCUMULATING_NAME_RE.test(model.name)) continue;
    if (!model.fields.some((f) => TIMESTAMP_FIELD_RE.test(f.name))) continue;

    const inserts: Array<{ mod: ParsedModule; call: CallRef }> = [];
    let removed = false;
    let reads = 0;

    for (const mod of productionModules(map)) {
      for (const call of mod.calls) {
        if (modelForCall(map, call) !== model) continue;
        const leaf = lastSegment(call.callee);
        if (INSERT_LEAVES.has(leaf)) inserts.push({ mod, call });
        else if (DELETE_LEAVES.has(leaf)) removed = true;
        else reads++;
      }
      // Raw SQL that removes rows from this table counts too.
      const view = viewFor(map, mod.path, views);
      if (view && new RegExp(`(?:DELETE\\s+FROM|TRUNCATE(?:\\s+TABLE)?)\\s+["'\`]?${escapeRe(model.name)}`, 'i').test(view.text)) {
        removed = true;
      }
    }
    if (inserts.length === 0 || removed) continue;

    const first = inserts[0]!;
    const evidence = verifiedOnly([
      map.evidenceLine(first.mod.path, first.call.line,
        'rows are appended here; no call anywhere in the project deletes, expires, or archives this table'),
      modelEvidence(map, model, `${model.name} records events over time and declares no expiry or retention field`),
    ]);
    if (evidence.length === 0) continue;

    out.push(ctx.finding({
      ruleId: 'cost.storage.no_retention_policy',
      title: `${model.name} accumulates rows with traffic and nothing in the project removes them`,
      severity: 'low',
      confidence: 'moderate',
      status: 'needs_runtime_verification',
      detectionSource: 'graph',
      files: [...new Set([model.file, ...inserts.map((i) => i.mod.path)])],
      evidence,
      trace: {
        kind: 'data_policy',
        steps: [
          { file: model.file, detail: `${model.name} is an append-only record of events, keyed by time` },
          ...inserts.slice(0, 3).map(({ mod, call }) => ({
            file: mod.path, line: call.line, symbol: call.inSymbol,
            detail: `${call.callee}() inserts a row per occurrence`,
          })),
          { file: model.file, detail: 'no delete, truncate, expiry, TTL, or archival path for this table exists in the code or configuration read by this scan' },
        ],
        complete: true,
      },
      explanation:
        `${model.name} gains a row every time the code path above runs, and no code path in this project ever removes one. ` +
        (reads === 0
          ? 'No read of this table appears anywhere either, so the rows are written, stored, and backed up without being used. '
          : '') +
        'Storage and backup are billed by volume, and backups multiply whatever the table holds, so this grows monotonically for as long as the application runs. ' +
        'Retention could be enforced outside this repository — a database-side job, a provider policy, a partition schedule — which this scan cannot see; that is why this is reported as a gap to confirm rather than as a fact.',
      userImpact:
        'Nothing is visible to users at first. The effects arrive indirectly and together: backups and restores take longer, queries that touch the table slow down as it grows, and the storage line on the bill rises without any change in traffic.',
      likelyRootCause: 'The table was added to record something useful, and no one owned the question of how long the records should live.',
      downstreamConsequences: [
        'Restore time grows with the table, so recovery gets slower as a side effect of an unrelated feature.',
        'Personal data kept indefinitely becomes a compliance question as well as a cost one.',
        'Index maintenance and autovacuum work grow with the table, taxing queries that do not touch it.',
      ],
      remediation:
        'Decide a retention period for this table and enforce it in code you can see: a scheduled job that deletes or archives rows past the cut-off, with a bounded batch size so the delete itself cannot overload the database. ' +
        'Where the data has analytic value beyond the retention period, roll it up into aggregates and keep those rather than the raw rows, or move the raw rows to cheaper object storage. ' +
        'Add the retention period to the model documentation so the next table of this kind starts with one.',
      effort: 'small',
      verificationSteps: [
        'Measure the current row count and on-disk size of the table, and the rate at which both grow over a week — that measurement is what sizes the problem.',
        'Confirm the retention job removes rows past the cut-off and that its batches do not hold long transactions.',
        'Confirm nothing depends on rows older than the retention period before the first run.',
      ],
      references: [REF.cweResource, REF.costPillar, REF.notMeasured],
    }));
  }
  return out;
}

// ----------------------------------------------------- duplicate services ---

interface Provider {
  label: string;
  packages: string[];
}

interface CapabilityGroup {
  capability: string;
  providers: Provider[];
  /** What is actually paid twice when both are shipped. */
  cost: string;
}

/**
 * Capabilities where shipping two implementations is duplication rather than
 * composition. Deliberately conservative: families that routinely coexist for
 * good reasons (payment providers, model providers, CSS tooling, bundlers that
 * appear as tool dependencies) are not listed, because a rule that fires on a
 * sound choice costs more trust than it saves money.
 */
const CAPABILITY_GROUPS: CapabilityGroup[] = [
  {
    capability: 'HTTP client',
    cost: 'two request/retry/timeout implementations to configure and keep consistent, and both in the shipped bundle',
    providers: [
      { label: 'axios', packages: ['axios'] },
      { label: 'got', packages: ['got'] },
      { label: 'node-fetch', packages: ['node-fetch'] },
      { label: 'superagent', packages: ['superagent'] },
      { label: 'request', packages: ['request'] },
      { label: 'ky', packages: ['ky'] },
      { label: 'undici', packages: ['undici'] },
      { label: 'cross-fetch', packages: ['cross-fetch', 'isomorphic-fetch'] },
    ],
  },
  {
    capability: 'object-relational mapper',
    cost: 'two schema definitions, two migration stories, and two connection pools against the same database',
    providers: [
      { label: 'Prisma', packages: ['prisma', '@prisma/client'] },
      { label: 'TypeORM', packages: ['typeorm'] },
      { label: 'Sequelize', packages: ['sequelize'] },
      { label: 'Drizzle ORM', packages: ['drizzle-orm'] },
      { label: 'Mongoose', packages: ['mongoose'] },
      { label: 'MikroORM', packages: ['@mikro-orm/core'] },
      { label: 'Objection', packages: ['objection'] },
    ],
  },
  {
    capability: 'date and time library',
    cost: 'two parsing and formatting implementations, two sets of locale and timezone data in the bundle',
    providers: [
      { label: 'Moment.js', packages: ['moment', 'moment-timezone'] },
      { label: 'Day.js', packages: ['dayjs'] },
      { label: 'date-fns', packages: ['date-fns', 'date-fns-tz'] },
      { label: 'Luxon', packages: ['luxon'] },
    ],
  },
  {
    capability: 'client state manager',
    cost: 'two stores, two sets of conventions, and two copies of state that can disagree',
    providers: [
      { label: 'Redux', packages: ['redux', '@reduxjs/toolkit'] },
      { label: 'Zustand', packages: ['zustand'] },
      { label: 'Jotai', packages: ['jotai'] },
      { label: 'Recoil', packages: ['recoil'] },
      { label: 'MobX', packages: ['mobx', 'mobx-react', 'mobx-react-lite'] },
      { label: 'Valtio', packages: ['valtio'] },
    ],
  },
  {
    capability: 'server-state cache',
    cost: 'two caches with independent keys and invalidation, so the same data is fetched twice',
    providers: [
      { label: 'TanStack Query', packages: ['@tanstack/react-query', 'react-query'] },
      { label: 'SWR', packages: ['swr'] },
      { label: 'Apollo Client', packages: ['@apollo/client', 'apollo-client'] },
      { label: 'urql', packages: ['urql', '@urql/core'] },
    ],
  },
  {
    capability: 'test runner',
    cost: 'two runners to install, configure, and run in CI, and two sets of tests that can be forgotten separately',
    providers: [
      { label: 'Jest', packages: ['jest'] },
      { label: 'Vitest', packages: ['vitest'] },
      { label: 'Mocha', packages: ['mocha'] },
      { label: 'AVA', packages: ['ava'] },
      { label: 'Jasmine', packages: ['jasmine'] },
      { label: 'Tape', packages: ['tape'] },
    ],
  },
  {
    capability: 'schema validation library',
    cost: 'two schema languages describing the same shapes, which drift apart',
    providers: [
      { label: 'Zod', packages: ['zod'] },
      { label: 'Yup', packages: ['yup'] },
      { label: 'Joi', packages: ['joi', '@hapi/joi'] },
      { label: 'Superstruct', packages: ['superstruct'] },
      { label: 'Valibot', packages: ['valibot'] },
      { label: 'class-validator', packages: ['class-validator'] },
    ],
  },
  {
    capability: 'application logger',
    cost: 'two log formats and two transports, so log ingestion is billed on output nothing can query uniformly',
    providers: [
      { label: 'Winston', packages: ['winston'] },
      { label: 'Pino', packages: ['pino'] },
      { label: 'Bunyan', packages: ['bunyan'] },
      { label: 'log4js', packages: ['log4js'] },
      { label: 'loglevel', packages: ['loglevel'] },
    ],
  },
  {
    capability: 'UI component library',
    cost: 'two component libraries and two theming systems in the shipped bundle',
    providers: [
      { label: 'MUI', packages: ['@mui/material'] },
      { label: 'Ant Design', packages: ['antd'] },
      { label: 'Chakra UI', packages: ['@chakra-ui/react'] },
      { label: 'Mantine', packages: ['@mantine/core'] },
      { label: 'React Bootstrap', packages: ['react-bootstrap'] },
    ],
  },
  {
    capability: 'email delivery client',
    cost: 'two delivery integrations to configure, monitor, and keep reputable',
    providers: [
      { label: 'Nodemailer', packages: ['nodemailer'] },
      { label: 'SendGrid', packages: ['@sendgrid/mail'] },
      { label: 'Resend', packages: ['resend'] },
      { label: 'Postmark', packages: ['postmark'] },
      { label: 'Mailgun', packages: ['mailgun.js', 'mailgun-js'] },
    ],
  },
];

/** Declared dependency names, by manifest path. */
function declaredDependencies(map: RepoMap): Map<string, Set<string>> {
  const out = new Map<string, Set<string>>();
  for (const file of map.byRole('manifest')) {
    if (!file.text) continue;
    const names = new Set<string>();
    if (file.path.endsWith('package.json')) {
      try {
        const json = JSON.parse(file.text) as Record<string, unknown>;
        for (const section of ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies']) {
          const deps = json[section];
          if (deps && typeof deps === 'object') for (const k of Object.keys(deps)) names.add(k);
        }
      } catch {
        // A malformed manifest is not something to guess about.
        continue;
      }
    } else {
      // requirements.txt / pyproject-style lines: `name==1.2`, `name = "^1.2"`.
      for (const raw of file.text.split('\n')) {
        const m = /^\s*["']?([A-Za-z0-9._-]+)["']?\s*(?:[=<>~!]=|==|=|>=|\s*=\s*["'])/.exec(raw);
        if (m?.[1]) names.add(m[1].toLowerCase());
      }
    }
    if (names.size > 0) out.set(file.path, names);
  }
  return out;
}

/** Modules that import a package, by package name. */
function importSites(map: RepoMap, pkg: string): Array<{ path: string; line: number }> {
  const sites: Array<{ path: string; line: number }> = [];
  for (const mod of map.modules.values()) {
    if (!mod.parsed) continue;
    for (const imp of mod.imports) {
      if (!imp.external) continue;
      if (imp.specifier === pkg || imp.specifier.startsWith(`${pkg}/`)) {
        sites.push({ path: mod.path, line: imp.line });
      }
    }
  }
  return sites;
}

/**
 * Two packages that do the same job, both declared and both imported.
 *
 * Declaration alone is not enough: a dependency nothing imports is a different
 * problem (unused weight), and reporting it as duplication would be wrong. The
 * import sites are what turn this into a traced, cross-file claim.
 */
function duplicateCapabilities(ctx: AnalyzerContext): Finding[] {
  const { map } = ctx;
  const manifests = declaredDependencies(map);
  if (manifests.size === 0) return [];
  const out: Finding[] = [];

  for (const group of CAPABILITY_GROUPS) {
    for (const [manifestPath, declared] of manifests) {
      const present: Array<{ provider: Provider; pkg: string; sites: Array<{ path: string; line: number }> }> = [];

      for (const provider of group.providers) {
        const pkg = provider.packages.find((p) => declared.has(p) || declared.has(p.toLowerCase()));
        if (!pkg) continue;
        const sites = provider.packages.flatMap((p) => importSites(map, p));
        if (sites.length === 0) continue;
        present.push({ provider, pkg, sites });
      }
      if (present.length < 2) continue;

      const evidence = verifiedOnly([
        ...present.map(({ pkg }) => map.evidenceAt(manifestPath, `"${pkg}"`, `${group.capability} declared as a dependency`)),
        ...present.map(({ provider, sites }) =>
          map.evidenceLine(sites[0]!.path, sites[0]!.line, `${provider.label} is imported here, so it is in use rather than merely declared`)),
      ]);
      if (evidence.length === 0) continue;

      const labels = present.map((p) => p.provider.label);
      const files = [...new Set([manifestPath, ...present.map((p) => p.sites[0]!.path)])];

      out.push(ctx.finding({
        ruleId: 'cost.infra.duplicate_capability',
        title: `${labels.join(' and ')} both provide the project's ${group.capability}`,
        severity: 'low',
        confidence: 'strong',
        detectionSource: 'graph',
        files,
        evidence,
        trace: {
          kind: 'import',
          steps: [
            ...present.map(({ provider, pkg }) => ({ file: manifestPath, detail: `${provider.label} declared as '${pkg}'` })),
            ...present.flatMap(({ provider, sites }) => sites.slice(0, 2).map((s) => ({
              file: s.path, line: s.line, detail: `${provider.label} imported here`,
            }))),
          ],
          complete: true,
        },
        explanation:
          `This project ships ${labels.length} ${group.capability}s — ${labels.join(' and ')} — and imports all of them, so both are in the dependency tree and both are exercised at runtime. ` +
          `What is paid for twice is ${group.cost}. ` +
          'The duplication may be a migration that stopped half-way, or two features written by different hands at different times. ' +
          'This scan can see that both are present and used; it cannot see whether that was deliberate, so treat it as a question to answer rather than a defect to fix blindly.',
        userImpact:
          `Behaviour diverges where the two implementations disagree — different retry, timeout, formatting, or caching defaults for the same kind of operation — so users meet inconsistent behaviour in different parts of the product, and a fix applied to one path leaves the other unchanged.`,
        likelyRootCause: 'An incomplete migration, or a second choice made locally without noticing the first.',
        downstreamConsequences: [
          'Every cross-cutting change to this capability has to be made twice, and one of the two is eventually forgotten.',
          'Both libraries must be kept patched, doubling the upgrade and vulnerability surface for one capability.',
          'Where the capability ships to the browser, both copies are downloaded and parsed by every visitor.',
        ],
        remediation:
          `Pick one ${group.capability} deliberately, write down why, and migrate the remaining call sites to it; then remove the other from the manifest so it cannot creep back. ` +
          'Where both must stay for a period, confine the one being retired to a single module so the boundary is visible and the remaining work is countable. ' +
          'Add a dependency check to CI that fails when a second implementation of this capability is introduced.',
        effort: present.length > 2 ? 'large' : 'medium',
        verificationSteps: [
          'List the import sites of the library being retired and confirm the count reaches zero.',
          'Confirm the retired package is gone from the manifest and the lockfile, and that the install size and bundle size both fall — that measurement is the saving.',
          'Confirm the behaviour that differed between the two (timeouts, retries, formatting) is explicit in the one that remains, rather than inherited by accident.',
        ],
        references: [REF.costPillar],
      }));
    }
  }
  return out;
}

const ORM_PROVIDERS: Provider[] = [
  { label: 'Prisma', packages: ['prisma', '@prisma/client'] },
  { label: 'TypeORM', packages: ['typeorm'] },
  { label: 'Sequelize', packages: ['sequelize'] },
  { label: 'Drizzle ORM', packages: ['drizzle-orm'] },
  { label: 'Mongoose', packages: ['mongoose'] },
  { label: 'Knex', packages: ['knex'] },
];

const DRIVER_PROVIDERS: Provider[] = [
  { label: 'node-postgres', packages: ['pg'] },
  { label: 'postgres.js', packages: ['postgres'] },
  { label: 'mysql2', packages: ['mysql2'] },
  { label: 'mysql', packages: ['mysql'] },
  { label: 'better-sqlite3', packages: ['better-sqlite3'] },
  { label: 'sqlite3', packages: ['sqlite3'] },
  { label: 'mongodb', packages: ['mongodb'] },
];

/** Query-shaped calls whose receiver is a binding constructed from `pkg`. */
function driverQuerySites(map: RepoMap, pkg: string): Array<{ path: string; line: number; callee: string }> {
  const sites: Array<{ path: string; line: number; callee: string }> = [];
  for (const mod of map.modules.values()) {
    if (!mod.parsed) continue;
    const names = new Set<string>();
    for (const imp of mod.imports) {
      if (!imp.external) continue;
      if (imp.specifier !== pkg && !imp.specifier.startsWith(`${pkg}/`)) continue;
      for (const n of imp.names) if (n !== '*' && n !== 'default') names.add(n);
    }
    if (names.size === 0) continue;

    const ctorRe = new RegExp(`\\b(?:new\\s+)?(?:${[...names].map(escapeRe).join('|')})\\s*[(<]`);
    const roots = new Set<string>();
    for (const sym of mod.symbols) {
      if (ctorRe.test(sym.text)) roots.add(sym.name);
    }
    if (roots.size === 0) continue;

    for (const call of mod.calls) {
      const segs = calleeSegments(call.callee);
      if (segs.length < 2 || !roots.has(segs[0]!)) continue;
      if (!/^(?:query|execute|unsafe|raw|end|connect|exec|run|get|all|prepare)$/.test(segs[segs.length - 1]!)) continue;
      if (segs[segs.length - 1] === 'end' || segs[segs.length - 1] === 'connect') continue;
      sites.push({ path: mod.path, line: call.line, callee: call.callee });
    }
  }
  return sites;
}

/** Query sites that go through an ORM client. */
function ormQuerySites(map: RepoMap): Array<{ path: string; line: number; callee: string }> {
  const sites: Array<{ path: string; line: number; callee: string }> = [];
  for (const mod of map.modules.values()) {
    if (!mod.parsed) continue;
    for (const call of mod.calls) {
      if (!modelForCall(map, call)) continue;
      const leaf = lastSegment(call.callee);
      if (!COLLECTION_READ_LEAVES.has(leaf) && !INSERT_LEAVES.has(leaf)
        && !/^(?:findUnique|findFirst|findOne|findByPk|update|updateMany|count|aggregate|groupBy)$/.test(leaf)) continue;
      sites.push({ path: mod.path, line: call.line, callee: call.callee });
    }
  }
  return sites;
}

/**
 * An ORM and a raw driver both used to query the same database.
 *
 * Reported separately from the duplicate-capability rule, and at lower
 * confidence, because the two are not strictly interchangeable: a raw driver
 * alongside an ORM is a reasonable escape hatch for a query the ORM cannot
 * express. What makes it a cost finding is the pair of independent connection
 * pools that come with it, each sized and billed on its own.
 */
function duplicateDataAccessLayers(ctx: AnalyzerContext): Finding[] {
  const { map } = ctx;
  const manifests = declaredDependencies(map);
  if (manifests.size === 0) return [];
  const out: Finding[] = [];

  for (const [manifestPath, declared] of manifests) {
    const orm = ORM_PROVIDERS
      .map((p) => ({ p, pkg: p.packages.find((n) => declared.has(n)) }))
      .find((x) => !!x.pkg);
    const driver = DRIVER_PROVIDERS
      .map((p) => ({ p, pkg: p.packages.find((n) => declared.has(n)) }))
      .find((x) => !!x.pkg);
    if (!orm?.pkg || !driver?.pkg) continue;

    const ormSites = ormQuerySites(map);
    const driverSites = driverQuerySites(map, driver.pkg);
    if (ormSites.length === 0 || driverSites.length === 0) continue;

    const evidence = verifiedOnly([
      map.evidenceLine(driverSites[0]!.path, driverSites[0]!.line,
        `${driver.p.label} is used to query directly, with its own connection pool`),
      map.evidenceLine(ormSites[0]!.path, ormSites[0]!.line,
        `${orm.p.label} queries the same database through its own client`),
      map.evidenceAt(manifestPath, `"${driver.pkg}"`, `${driver.p.label} declared alongside ${orm.p.label}`),
      map.evidenceAt(manifestPath, `"${orm.pkg}"`, `${orm.p.label} declared alongside ${driver.p.label}`),
    ]);
    if (evidence.length === 0) continue;

    const files = [...new Set([manifestPath, driverSites[0]!.path, ormSites[0]!.path])];

    out.push(ctx.finding({
      ruleId: 'cost.infra.duplicate_capability',
      title: `${orm.p.label} and ${driver.p.label} are two independent database access paths`,
      severity: 'low',
      confidence: 'moderate',
      detectionSource: 'graph',
      files,
      evidence,
      trace: {
        kind: 'import',
        steps: [
          { file: manifestPath, detail: `${orm.p.label} ('${orm.pkg}') and ${driver.p.label} ('${driver.pkg}') are both declared` },
          { file: ormSites[0]!.path, line: ormSites[0]!.line, detail: `${ormSites.length} quer${ormSites.length === 1 ? 'y goes' : 'ies go'} through ${orm.p.label}` },
          { file: driverSites[0]!.path, line: driverSites[0]!.line, detail: `${driverSites.length} quer${driverSites.length === 1 ? 'y goes' : 'ies go'} through ${driver.p.label} directly` },
          { file: driverSites[0]!.path, detail: 'each client maintains its own connection pool, so the two are additive against the database connection limit' },
        ],
        complete: true,
      },
      explanation:
        `The project queries its database two ways: through ${orm.p.label} and directly through ${driver.p.label}. ` +
        'Each client maintains its own connection pool, so a process that loads both holds two sets of connections — and connections are a bounded, billed resource on every managed database, charged for whether or not they are carrying queries. ' +
        'The second pool is also constructed when its module is imported, so a process pays for it even on request paths that only use the other one. ' +
        `A raw driver alongside an ORM is legitimate where a query cannot be expressed in ${orm.p.label}; this is reported so the choice is a decision rather than an accident.`,
      userImpact:
        'The symptom appears under load rather than in normal use: the two pools together exhaust the database connection limit, and requests then fail to acquire a connection — including requests to features that had nothing to do with the heavy path.',
      likelyRootCause: 'A query the ORM could not express, or an older access layer that was never retired after the ORM was introduced.',
      downstreamConsequences: [
        'Connection limits must be reasoned about across two pools, so the safe ceiling per instance is easy to get wrong.',
        'Raw-driver queries bypass the ORM\'s generated types and its query logging, so they are invisible to the tooling used to review the rest of the data layer.',
        'Two access layers mean two places to apply a schema change.',
      ],
      remediation:
        `Decide which access path owns normal queries — in most projects that is ${orm.p.label} — and express the remaining raw queries through its own escape hatch for parameterised SQL, so one pool serves the process. ` +
        'If the raw driver must stay, construct it lazily rather than at module load, give both pools explicit bounds whose sum fits inside the database connection limit with headroom for migrations and admin sessions, and keep its use confined to one module.',
      effort: 'medium',
      verificationSteps: [
        'Count the connections the application holds at the database under normal load and confirm the total matches the pools you intend to run.',
        'Confirm the sum of the configured pool maxima, times the number of instances, is below the database connection limit.',
        'Confirm the queries moved off the raw driver return identical results, including types and null handling.',
      ],
      references: [REF.costPillar, REF.cweResource],
    }));
  }
  return out;
}
