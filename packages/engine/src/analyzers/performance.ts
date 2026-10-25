import type { ApiEndpoint, DataModel, Evidence, Finding, Severity } from '@codelens/core';
import type { RepoMap } from '../graph/repomap.ts';
import type { CallRef, ParsedModule, SymbolInfo } from '../parse/types.ts';
import type { Analyzer, AnalyzerContext } from './types.ts';
import { codeText } from './text.ts';

/**
 * Performance audit.
 *
 * This module measures nothing. Everything below is a *static risk*: a shape in
 * the code that makes work grow with data or with request volume. So no finding
 * here states a latency, a throughput, a payload size, or a proportion — those
 * would be fabricated. Where the size of the effect can only be settled by
 * running something, the finding says which measurement would settle it and
 * carries `needs_runtime_verification`.
 *
 * Confidence discipline:
 *   - a pattern match alone is `moderate`;
 *   - a pattern plus a traced cross-file relationship (a query site correlated
 *     with the model definition, a rendered collection correlated with the
 *     query that produced it) is `strong`;
 *   - nothing here is `confirmed`, because every one of these shapes has a
 *     legitimate variant: a loop over three rows, a table that will never grow,
 *     a list the product deliberately shows in full. Structure is visible;
 *     cost is not.
 *
 * Resolution is deliberately conservative. A database call is only treated as
 * one when its receiver resolves to a model in `map.models` or to a binding
 * assigned from a database client, because `results.find(...)` and
 * `cache.get(...)` are ordinary array and Map operations and reporting them
 * would make the whole report untrustworthy.
 */

const REF = {
  loopResource: 'CWE-1050 Excessive Platform Resource Consumption within a Loop',
  excessAccess: 'CWE-1073 Non-SQL Invokable Control Element with Excessive Number of Data Resource Accesses',
  excessQuery: 'CWE-1049 Excessive Data Query Operations in a Large Data Table',
  noThrottle: 'CWE-770 Allocation of Resources Without Limits or Throttling',
  amplification: 'CWE-405 Asymmetric Resource Consumption (Amplification)',
  excessiveIteration: 'CWE-834 Excessive Iteration',
  apiConsumption: 'OWASP API Security Top 10: API4 Unrestricted Resource Consumption',
  notMeasured: 'docs/LIMITATIONS.md — this scan does not measure runtime behaviour',
} as const;

// --------------------------------------------------------------- helpers ---

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** Dotted callee split into segments, with call artefacts removed. */
function calleeSegments(callee: string): string[] {
  return callee.replace(/\(\)/g, '').split('.').filter((s) => s.length > 0);
}

/** Read operations whose names no array or Map has, so they identify a data layer. */
const ORM_ONLY_READS = new Set([
  'findMany', 'findAll', 'findFirst', 'findFirstOrThrow', 'findUnique', 'findUniqueOrThrow',
  'findOne', 'findOneBy', 'findOneOrFail', 'findBy', 'findAndCountAll', 'findByPk',
  'getMany', 'getOne', 'getRawMany', 'getRawOne', 'createQueryBuilder',
  'aggregate', 'groupBy', 'queryRaw', 'executeRaw', '$queryRaw', '$queryRawUnsafe',
  '$transaction', 'scan', 'getItem', 'batchGet', 'fetchAll', 'fetchone', 'fetchall',
]);

/** Read operations that are also ordinary collection methods: these need a resolved receiver. */
const AMBIGUOUS_READS = new Set([
  'find', 'query', 'select', 'execute', 'exec', 'first', 'count', 'all', 'toArray', 'stream', 'raw',
]);

/** Write operations, kept apart because parallelising or caching a write is not safe advice. */
const WRITE_LEAVES = new Set([
  'create', 'createMany', 'insert', 'insertMany', 'insertOne', 'update', 'updateMany',
  'updateOne', 'upsert', 'delete', 'deleteMany', 'deleteOne', 'destroy', 'save', 'remove',
  'bulkCreate', 'increment', 'decrement', 'executeRaw', '$executeRaw', '$executeRawUnsafe',
  'put', 'putItem', 'add', 'set', 'push', 'drop', 'truncate',
]);

/** Write operations no array or Map has, so the name alone identifies a data layer. */
const ORM_ONLY_WRITES = new Set([
  'createMany', 'updateMany', 'deleteMany', 'upsert', 'bulkCreate', 'insertMany', 'insertOne',
  'updateOne', 'deleteOne', 'putItem', 'executeRaw', '$executeRaw', '$executeRawUnsafe',
]);

/** Reads that can only come back with at most one row, so a row bound is implicit. */
const SINGLE_ROW_READS = new Set([
  'findUnique', 'findUniqueOrThrow', 'findFirst', 'findFirstOrThrow', 'findOne', 'findOneBy',
  'findOneOrFail', 'findByPk', 'getOne', 'getRawOne', 'getItem', 'fetchone', 'first', 'count',
  'aggregate', 'groupBy',
]);

/** Reads that return a collection, so an absent row bound is an absent ceiling. */
const COLLECTION_READS = new Set([
  'findMany', 'findAll', 'findAndCountAll', 'findBy', 'getMany', 'getRawMany', 'find', 'select',
  'scan', 'query', 'all', 'toArray', 'fetchAll', 'fetchall', 'batchGet',
]);

/** Receiver names conventionally bound to a data layer, used only for ambiguous leaves. */
const CONVENTIONAL_DB_ROOTS = new Set([
  'prisma', 'db', 'database', 'pool', 'pg', 'knex', 'sequelize', 'supabase', 'mongo', 'mongoose',
  'dynamo', 'dynamodb', 'drizzle', 'datasource', 'dataSource', 'repo', 'repository', 'em',
  'entityManager', 'queryRunner', 'conn', 'connection', 'collection', 'kysely', 'sql', 'orm',
]);

const DB_CLIENT_CTOR_RE =
  /\b(?:new\s+PrismaClient|PrismaClient\s*\(|new\s+Pool|createPool|new\s+Sequelize|new\s+MongoClient|new\s+Kysely|new\s+DataSource|getRepository|getManager|createConnection|createPool|knex\s*\(|drizzle\s*\(|postgres\s*\(|neon\s*\(|createPgClient|mongoose\.(?:connect|createConnection|model)|createClient\s*\(\s*\{?\s*(?:connectionString|url|host|database))/;

/** Names in this module bound to a database client. */
function dbBindingsIn(mod: ParsedModule): Set<string> {
  const out = new Set<string>();
  for (const sym of mod.symbols) {
    if (sym.kind !== 'const' && sym.kind !== 'class' && sym.kind !== 'arrow') continue;
    if (DB_CLIENT_CTOR_RE.test(sym.text)) out.add(sym.name);
  }
  return out;
}

/**
 * Database bindings visible in this module: ones declared here, plus ones
 * imported from a module that declares them. The single import hop matters:
 * almost every project keeps `const prisma = new PrismaClient()` in one file
 * and imports it everywhere else, so without the hop nothing resolves.
 */
function dbRootsFor(map: RepoMap, mod: ParsedModule, cache: Map<string, Set<string>>): Set<string> {
  const own = cache.get(mod.path) ?? dbBindingsIn(mod);
  cache.set(mod.path, own);
  const roots = new Set(own);
  for (const imp of mod.imports) {
    if (!imp.resolvedPath) continue;
    const target = map.modules.get(imp.resolvedPath);
    if (!target?.parsed) continue;
    let exported = cache.get(target.path);
    if (!exported) {
      exported = dbBindingsIn(target);
      cache.set(target.path, exported);
    }
    for (const name of imp.names) {
      if (exported.has(name)) roots.add(name);
      if (name === '*' || name === 'default') for (const e of exported) roots.add(e);
    }
  }
  return roots;
}

function resolveModel(map: RepoMap, name: string | undefined): DataModel | undefined {
  if (!name) return undefined;
  const lower = name.toLowerCase();
  return map.models.find((m) => {
    const mn = m.name.toLowerCase();
    return mn === lower || `${mn}s` === lower || `${mn}es` === lower || mn === lower.replace(/s$/, '');
  });
}

/**
 * A row ceiling present in the call's arguments or chained onto the callee.
 *
 * The trailing alternation matters: `findMany({ where, take })` passes the bound
 * as a shorthand property, and a rule that only recognised `take:` would report
 * a correctly bounded query as unbounded.
 */
const ROW_BOUND_ARG_RE =
  /\b(?:take|limit|first|last|perPage|per_page|pageSize|page_size|maxResults|max_results|maxItems|top|rowCount|batchSize|batch_size|chunkSize)\s*(?::|=|,|\}|$)/;
const ROW_BOUND_CHAIN_RE = /\.(?:take|limit|first|top|paginate|slice|head)$/;
const SQL_BOUND_RE = /\bLIMIT\s+(?:\d|[:$?@])|\bTOP\s*\(?\s*\d|\bFETCH\s+(?:FIRST|NEXT)\b|\bROWNUM\b/i;
const SQL_SELECT_RE = /\bSELECT\b[\s\S]*\bFROM\b/i;
const SQL_AGGREGATE_ONLY_RE = /\bSELECT\s+(?:DISTINCT\s+)?(?:COUNT|SUM|AVG|MIN|MAX)\s*\(/i;

const SCOPE_KINDS = new Set(['function', 'arrow', 'method', 'class']);

/**
 * The enclosing *scope* for a line: the tightest function-like symbol around it.
 *
 * A multi-line `const` binding is not a scope. Treating one as a scope hides the
 * loop header that sits above it, which silently turns a bounded loop into an
 * unknown one, so declarations are only used as a last resort.
 */
function enclosingSymbol(mod: ParsedModule, line: number): SymbolInfo | undefined {
  let best: SymbolInfo | undefined;
  let fallback: SymbolInfo | undefined;
  for (const s of mod.symbols) {
    if (s.startLine > line || s.endLine < line) continue;
    if (SCOPE_KINDS.has(s.kind)) {
      if (!best || s.endLine - s.startLine < best.endLine - best.startLine) best = s;
    } else if (s.endLine > s.startLine) {
      if (!fallback || s.endLine - s.startLine < fallback.endLine - fallback.startLine) fallback = s;
    }
  }
  return best ?? fallback;
}

/**
 * The call's own source text, re-read from the snapshot and balanced on parens.
 *
 * The parser caps each argument at a couple of hundred characters, which is
 * plenty for most rules but not for query options: `findMany({ where: {…}, take,
 * include: {…} })` loses its `take` to the cap, and a rule reading only the
 * captured arguments would report a correctly bounded query as unbounded. So
 * boundedness is decided against the real source.
 */
function callSourceText(
  map: RepoMap, mod: ParsedModule, call: CallRef, lineCache: Map<string, string[]>,
): string | undefined {
  let lines = lineCache.get(mod.path);
  if (!lines) {
    const file = map.filesByPath.get(mod.path);
    if (!file?.text) return undefined;
    lines = file.text.split('\n');
    lineCache.set(mod.path, lines);
  }
  const startIdx = call.line - 1;
  if (startIdx < 0 || startIdx >= lines.length) return undefined;

  const window = codeText(lines.slice(startIdx, startIdx + 80).join('\n'), mod.language);
  const leaf = calleeSegments(call.callee).pop() ?? '';
  const leafAt = leaf ? window.indexOf(leaf) : -1;
  const open = window.indexOf('(', leafAt === -1 ? 0 : leafAt);
  if (open === -1) return undefined;

  let depth = 0;
  for (let i = open; i < window.length && i - open < 6000; i++) {
    const ch = window[i];
    if (ch === '(') depth++;
    else if (ch === ')') {
      depth--;
      if (depth === 0) return window.slice(open, i + 1);
    }
  }
  return window.slice(open, Math.min(window.length, open + 6000));
}

/** Raw statement text for a call whose argument is an identifier holding SQL. */
function sqlTextFor(mod: ParsedModule, call: CallRef): string | undefined {
  const inline = call.args.find((a) => SQL_SELECT_RE.test(a));
  if (inline) return inline;
  const ident = /^([A-Za-z_$][\w$]*)$/.exec((call.args[0] ?? '').trim())?.[1];
  if (!ident) return undefined;
  const sym = mod.symbols.find((s) => s.name === ident && s.kind === 'const' && SQL_SELECT_RE.test(s.text));
  return sym?.text;
}

/**
 * Field names a `where` clause filters on, restricted to real columns of the model.
 *
 * Only a `where` at the top level of the options object counts. A `where` nested
 * inside an `include` belongs to the related model, and attributing its columns
 * to this one would invent index recommendations for the wrong table.
 */
function whereFieldsFor(argText: string, model: DataModel | undefined): { fields: string[]; block?: string } {
  if (!model) return { fields: [] };
  const open = topLevelWhereBrace(argText);
  if (open === undefined) return { fields: [] };
  let depth = 0;
  let end = -1;
  for (let i = open; i < argText.length; i++) {
    if (argText[i] === '{') depth++;
    else if (argText[i] === '}') { depth--; if (depth === 0) { end = i; break; } }
  }
  const block = argText.slice(open + 1, end === -1 ? argText.length : end);

  const modelNames = new Set<string>();
  const fieldTypes = new Map<string, string>();
  for (const f of model.fields) fieldTypes.set(f.name.toLowerCase(), f.type ?? '');
  for (const r of model.relations) modelNames.add(r.to.toLowerCase());

  const keys = new Set<string>();
  collectObjectKeys(block, keys);

  const out: string[] = [];
  for (const key of keys) {
    const type = fieldTypes.get(key.toLowerCase());
    if (type === undefined) continue; // an operator, or a field of a nested relation
    // A relation field is a join, not a column that an index on this table serves.
    if (modelNames.has(type.replace(/\[\]$/, '').toLowerCase())) continue;
    const field = model.fields.find((f) => f.name.toLowerCase() === key.toLowerCase())!;
    if (!out.includes(field.name)) out.push(field.name);
  }
  return { fields: out, block };
}

/**
 * Every property name in an object literal, at any depth.
 *
 * Shorthand properties have to be collected as well as `key: value` pairs:
 * `where: { queue, status: 'pending' }` filters on `queue`, and missing it would
 * hide the fact that an existing index already covers the predicate — which
 * would turn a correctly indexed query into a fabricated "missing index".
 */
function collectObjectKeys(block: string, out: Set<string>, depth = 0): void {
  if (depth > 6) return;
  for (const segment of splitTopLevel(block, ',')) {
    const colon = topLevelIndexOf(segment, ':');
    if (colon === -1) {
      const bare = segment.trim();
      if (/^[A-Za-z_$][\w$]*$/.test(bare)) out.add(bare);
      continue;
    }
    const key = segment.slice(0, colon).trim().replace(/^['"`]|['"`]$/g, '');
    if (/^[A-Za-z_$][\w$]*$/.test(key)) out.add(key);
    const value = segment.slice(colon + 1);
    const open = value.search(/[{[]/);
    if (open === -1) continue;
    let level = 0;
    for (let i = open; i < value.length; i++) {
      const ch = value[i];
      if (ch === '{' || ch === '[') level++;
      else if (ch === '}' || ch === ']') {
        level--;
        if (level === 0) { collectObjectKeys(value.slice(open + 1, i), out, depth + 1); break; }
      }
    }
  }
}

/** Split on a separator that sits outside braces, brackets, parens, and quotes. */
function splitTopLevel(text: string, separator: string): string[] {
  const parts: string[] = [];
  let depth = 0;
  let quote: string | undefined;
  let start = 0;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i]!;
    if (quote) {
      if (ch === '\\') i++;
      else if (ch === quote) quote = undefined;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === '`') { quote = ch; continue; }
    if (ch === '{' || ch === '[' || ch === '(') depth++;
    else if (ch === '}' || ch === ']' || ch === ')') depth--;
    else if (ch === separator && depth === 0) { parts.push(text.slice(start, i)); start = i + 1; }
  }
  parts.push(text.slice(start));
  return parts;
}

/** Index of the first separator outside braces, brackets, parens, and quotes. */
function topLevelIndexOf(text: string, separator: string): number {
  let depth = 0;
  let quote: string | undefined;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i]!;
    if (quote) {
      if (ch === '\\') i++;
      else if (ch === quote) quote = undefined;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === '`') { quote = ch; continue; }
    if (ch === '{' || ch === '[' || ch === '(') depth++;
    else if (ch === '}' || ch === ']' || ch === ')') depth--;
    else if (ch === separator && depth === 0) return i;
  }
  return -1;
}

/** Index of the brace opening a `where` object at the top level of the options literal. */
function topLevelWhereBrace(text: string): number | undefined {
  const objStart = text.indexOf('{');
  if (objStart === -1) return undefined;
  let depth = 0;
  for (let i = objStart; i < text.length; i++) {
    const ch = text[i];
    if (ch === '{' || ch === '[' || ch === '(') { depth++; continue; }
    if (ch === '}' || ch === ']' || ch === ')') { depth--; if (depth === 0) break; continue; }
    if (depth !== 1 || ch !== 'w') continue;
    const m = /^where\s*:\s*\{/.exec(text.slice(i));
    if (!m) continue;
    if (i > objStart && /[\w$.]/.test(text[i - 1] ?? '')) continue;
    return text.indexOf('{', i + 5);
  }
  return undefined;
}

const LOW_CARDINALITY_NAMES =
  /^(?:status|state|type|kind|role|conclusion|category|level|severity|visibility|provider|mode|stage|phase|tier|gender|locale|currency|plan|tag|flag|priority)$/i;
const BOOLEAN_NAME_RE = /^(?:is|has|can|should|allow|enable|disable)[A-Z_]|^(?:enabled|disabled|active|inactive|deleted|archived|demo|public|private|verified|published|draft|done|completed|read|seen|hidden|locked|flaky)$/;
const BOOLEAN_TYPE_RE = /^(?:boolean|bool|bit|tinyint)/i;

/**
 * Columns an index is unlikely to help, so recommending one would be weak advice.
 *
 * A boolean or an enum-shaped status splits the table into a handful of buckets;
 * the planner will usually scan anyway, and the right answer is a composite
 * index led by a selective column, which this rule cannot choose for the reader.
 */
function isLowCardinality(model: DataModel, field: string): boolean {
  const def = model.fields.find((f) => f.name === field);
  if (def?.type && BOOLEAN_TYPE_RE.test(def.type.replace(/\[\]$/, ''))) return true;
  return LOW_CARDINALITY_NAMES.test(field) || BOOLEAN_NAME_RE.test(field);
}

/** True when the predicate on this field is a text search, which a B-tree index does not serve. */
function usesTextSearchOperator(whereBlock: string, field: string): boolean {
  const m = new RegExp(`\\b${escapeRe(field)}\\s*:\\s*\\{([^{}]{0,200})\\}`).exec(whereBlock);
  if (!m) return false;
  return /\b(?:contains|startsWith|endsWith|search|mode|like|ilike|regex|matches)\b/i.test(m[1]!);
}

/** True when an index on `field` would serve a filter on it. */
function indexCovers(model: DataModel, field: string): boolean {
  const target = field.toLowerCase();
  return model.indexes.some((idx) => {
    const cols = idx.split('+').map((c) => c.trim().toLowerCase());
    // A composite index only serves a filter on its leading column.
    return cols[0] === target;
  });
}

interface DataCall {
  mod: ParsedModule;
  call: CallRef;
  kind: 'db_read' | 'db_write' | 'network';
  leaf: string;
  model?: DataModel;
  /** A row ceiling is present. */
  bounded: boolean;
  /** This read can return more than one row. */
  collection: boolean;
  whereFields: string[];
  /** Raw SQL statement text, when the statement was resolvable. */
  sql?: string;
  /** Source text of the `where` clause, when one was present. */
  whereBlock?: string;
}

/**
 * Test, fixture, and example code is excluded from this analyzer.
 *
 * An unbounded query in a test is the test doing its job. Reporting it costs a
 * reader attention and teaches them to discount the category.
 */
function isTestOrFixturePath(path: string): boolean {
  return /(?:^|\/)(?:tests?|__tests__|__mocks__|spec|specs|e2e|cypress|playwright|fixtures?|examples?|samples?|mocks?|benchmarks?|stories)\//i.test(path)
    || /\.(?:test|spec|stories|bench)\.[cm]?[jt]sx?$/i.test(path)
    || /_test\.py$|^test_|\/test_/.test(path);
}

/**
 * Code that does not run while serving users: seeders, migrations, one-off
 * scripts, demo data. A loop of writes is what a seeder *is*, so the query-shape
 * rules in this module would only produce noise there.
 */
function isOfflineToolingPath(path: string): boolean {
  return /(?:^|\/)(?:seeds?|seeders?|migrations?|scripts?|tools?|bin|demo|devtools|codegen|generators?)\//i.test(path)
    || /(?:^|\/)(?:seed|seeder|seed-data|migrate|generate)[-.\w]*\.[cm]?[jt]sx?$/i.test(path);
}

const NETWORK_ROOTS = new Set([
  'axios', 'got', 'ky', 'superagent', 'http', 'https', 'httpClient', 'apiClient', 'request', 'undici',
]);
const NETWORK_LEAVES = new Set(['get', 'post', 'put', 'patch', 'delete', 'head', 'request', 'send', 'fetch']);

function isNetworkCall(callee: string): boolean {
  const segs = calleeSegments(callee);
  const leaf = segs[segs.length - 1] ?? '';
  const root = segs[0] ?? '';
  if (root === 'fetch' || leaf === 'fetch') return true;
  if (NETWORK_ROOTS.has(root) && NETWORK_LEAVES.has(leaf)) return true;
  return false;
}

/**
 * Classify every call in the repository once.
 *
 * Request-object methods (`req.json`, `request.formData`) are excluded
 * explicitly: they read the inbound body, they are not remote work, and
 * treating them as such would make almost every handler look like it issues
 * serial remote calls.
 */
function collectDataCalls(map: RepoMap): DataCall[] {
  const out: DataCall[] = [];
  const bindingCache = new Map<string, Set<string>>();
  const lineCache = new Map<string, string[]>();

  for (const mod of map.modules.values()) {
    if (!mod.parsed) continue;
    const role = map.filesByPath.get(mod.path)?.role;
    if (isTestOrFixturePath(mod.path) || role === 'test') continue;
    if (isOfflineToolingPath(mod.path) || role === 'migration') continue;
    const dbRoots = dbRootsFor(map, mod, bindingCache);

    for (const call of mod.calls) {
      const segs = calleeSegments(call.callee);
      if (segs.length === 0) continue;
      const leaf = segs[segs.length - 1]!;
      const root = segs[0]!;
      if (/^(?:req|request|res|response|reply|ctx|context|event|socket)$/i.test(root)) continue;

      const receiver = segs.length >= 2 ? segs[segs.length - 2]! : undefined;
      const model = resolveModel(map, receiver) ?? (segs.length === 2 ? resolveModel(map, root) : undefined);
      const rootIsDb = dbRoots.has(root) || CONVENTIONAL_DB_ROOTS.has(root);

      // A name that only a data layer has is enough on its own. A name that
      // arrays and Maps also have (`find`, `get`, `all`, `create`, `set`) needs a
      // receiver that resolves to a database binding: `job.steps.find(...)`
      // resolves to a model called Step but is an ordinary array search, and
      // reporting it as a query would be plainly wrong.
      let kind: DataCall['kind'] | undefined;
      if (ORM_ONLY_READS.has(leaf)) kind = 'db_read';
      else if (ORM_ONLY_WRITES.has(leaf) && (model !== undefined || rootIsDb)) kind = 'db_write';
      else if (AMBIGUOUS_READS.has(leaf) && rootIsDb) kind = 'db_read';
      else if (WRITE_LEAVES.has(leaf) && rootIsDb) kind = 'db_write';
      else if (isNetworkCall(call.callee)) kind = 'network';
      if (!kind) continue;

      // Prefer the real source of the call over the parser's capped arguments.
      const source = callSourceText(map, mod, call, lineCache);
      const argText = source && source.length > 0 ? source : call.args.join(' ');
      const sql = kind === 'db_read' ? sqlTextFor(mod, call) : undefined;
      const sqlBounded = sql ? SQL_BOUND_RE.test(sql) || SQL_AGGREGATE_ONLY_RE.test(sql) : false;
      const bounded =
        SINGLE_ROW_READS.has(leaf)
        || ROW_BOUND_ARG_RE.test(argText)
        || ROW_BOUND_CHAIN_RE.test(call.callee)
        || sqlBounded;

      const where = whereFieldsFor(argText, model);
      out.push({
        mod, call, kind, leaf, model,
        bounded,
        collection: COLLECTION_READS.has(leaf) && !SINGLE_ROW_READS.has(leaf),
        whereFields: where.fields,
        whereBlock: where.block,
        sql,
      });
    }
  }
  return out;
}

interface LoopContext {
  /** Reads naturally in prose, e.g. "a for loop" or "a forEach callback". */
  phrase: string;
  /** The loop collects promises and hands them to Promise.all, so iterations overlap. */
  concurrent: boolean;
  /** The loop iterates a short inline array literal, so the element count is fixed and small. */
  boundedLiteral: boolean;
}

const UNKNOWN_LOOP: LoopContext = { phrase: 'a loop', concurrent: false, boundedLiteral: false };

/**
 * The loop construct immediately enclosing a line, read from the source above it.
 *
 * `boundedLiteral` matters more than it looks: `for (const c of ['python3', 'python'])`
 * is a loop, but its element count is two and will stay two, so per-iteration cost
 * is not a scaling problem and reporting it would be a false positive.
 */
function loopKindAbove(mod: ParsedModule, sym: SymbolInfo, line: number): LoopContext {
  const lines = codeText(sym.text, mod.language).split('\n');
  const offset = Math.min(Math.max(line - sym.startLine, 0), lines.length - 1);
  for (let i = offset; i >= 0; i--) {
    const text = lines[i] ?? '';
    const bounded = iteratesShortLiteral(text);
    if (/\bfor\s+await\s*\(/.test(text)) return { phrase: 'a for-await loop', concurrent: false, boundedLiteral: bounded };
    if (/\bfor\s*\(/.test(text)) return { phrase: 'a for loop', concurrent: false, boundedLiteral: bounded };
    if (/\bwhile\s*\(/.test(text)) return { phrase: 'a while loop', concurrent: false, boundedLiteral: false };
    const m = /\.\s*(forEach|map|flatMap|filter|reduce)\s*\(/.exec(text);
    if (m) {
      const windowText = lines.slice(Math.max(i - 2, 0), i + 1).join(' ');
      return {
        phrase: `a ${m[1]} callback`,
        concurrent: /Promise\.all|Promise\.allSettled/.test(windowText),
        boundedLiteral: bounded || /\[[^[\]]{0,120}\]\s*\.\s*(?:forEach|map|flatMap)/.test(text),
      };
    }
  }
  return UNKNOWN_LOOP;
}

/**
 * Where the loop's elements came from.
 *
 * `bounded` means the loop iterates a query result that already has a row
 * ceiling, so the per-element work is capped by that ceiling: a worker that
 * claims a batch with `take: n` and then updates each row is not an N+1 problem.
 * `unbounded` means N is the size of a table. `unknown` covers everything else —
 * a payload, a fixed registry, a computed array — where N is real but its scale
 * cannot be established from the source.
 */
function loopSourceKind(
  mod: ParsedModule, sym: SymbolInfo, line: number, dataCalls: DataCall[],
): 'bounded' | 'unbounded' | 'unknown' {
  const lines = codeText(sym.text, mod.language).split('\n');
  const offset = Math.min(Math.max(line - sym.startLine, 0), lines.length - 1);
  let iterated: string | undefined;
  for (let i = offset; i >= 0 && iterated === undefined; i--) {
    const text = lines[i] ?? '';
    iterated = /\b(?:of|in)\s+([A-Za-z_$][\w$]*)\s*\)/.exec(text)?.[1]
      ?? /\b([A-Za-z_$][\w$]*)\s*\.\s*(?:forEach|map|flatMap)\s*\(/.exec(text)?.[1];
  }
  if (!iterated) return 'unknown';
  const binding = mod.symbols.find((s) => s.name === iterated && s.startLine >= sym.startLine && s.startLine <= sym.endLine);
  if (!binding) return 'unknown';
  const producer = dataCalls.find((dc) => dc.mod.path === mod.path && dc.call.line === binding.startLine);
  if (!producer) return 'unknown';
  return producer.bounded ? 'bounded' : 'unbounded';
}

/** True for a loop header that iterates an inline array literal of at most four elements. */
function iteratesShortLiteral(header: string): boolean {
  const m = /\b(?:of|in)\s*(\[[^[\]]{0,160}\])/.exec(header);
  if (!m) return false;
  const inner = m[1]!.slice(1, -1).trim();
  if (inner.length === 0) return true;
  return inner.split(',').length <= 4;
}

/** The identifier a call's result is assigned to on its own line, if any. */
function assignedName(mod: ParsedModule, line: number): string | undefined {
  const sym = mod.symbols.find((s) => s.startLine === line && (s.kind === 'const' || s.kind === 'arrow'));
  return sym?.name;
}

interface Consumption { returned: boolean; iterated: boolean; serialised: boolean; varName?: string }

/** What happens to a query result: returned to a caller, iterated, or serialised into a response. */
function consumptionOf(mod: ParsedModule, sym: SymbolInfo | undefined, call: CallRef): Consumption {
  const varName = assignedName(mod, call.line);
  if (!sym) return { returned: false, iterated: false, serialised: false, varName };
  const body = codeText(sym.text, mod.language);
  const lines = body.split('\n');
  const offset = Math.min(Math.max(call.line - sym.startLine, 0), lines.length - 1);
  const returnedDirectly = /\breturn\b/.test(lines[offset] ?? '');

  let returned = returnedDirectly;
  let iterated = false;
  let serialised = false;
  if (varName) {
    const v = escapeRe(varName);
    iterated = new RegExp(`for\\s*(?:await\\s*)?\\([^)]*\\b(?:of|in)\\s+${v}\\b`).test(body)
      || new RegExp(`\\b${v}\\s*\\.\\s*(?:map|forEach|flatMap|filter|reduce)\\s*\\(`).test(body);
    returned = returned || new RegExp(`\\breturn\\b[^;]{0,200}\\b${v}\\b`).test(body);
    serialised = new RegExp(`(?:json|send|jsonify|JSONResponse|stringify)\\s*\\([^)]{0,200}\\b${v}\\b`).test(body);
  }
  return { returned, iterated, serialised, varName };
}

/** Calls belonging to a symbol's line range. */
function callsIn<T extends { call: CallRef; mod: ParsedModule }>(items: T[], path: string, sym: SymbolInfo): T[] {
  return items.filter((i) => i.mod.path === path && i.call.line >= sym.startLine && i.call.line <= sym.endLine);
}

function handlerSymbolFor(map: RepoMap, r: ApiEndpoint): SymbolInfo | undefined {
  const mod = map.modules.get(r.file);
  if (!mod?.parsed) return undefined;
  return mod.symbols.find((s) => s.name === r.handlerSymbol && s.endLine > s.startLine)
    ?? (r.line !== undefined ? enclosingSymbol(mod, r.line) : undefined);
}

const CACHE_PRIMITIVE_RE =
  /\b(?:unstable_cache|revalidateTag|revalidatePath|revalidate\s*[:=]|force-cache|s-maxage|stale-while-revalidate|Cache-Control|cacheControl|createCache|lru-cache|LRUCache|node-cache|NodeCache|ioredis|createClient\s*\(\s*\{?\s*url\s*:\s*process\.env\.REDIS|redis|memcached|useSWR|useQuery|QueryClient|@tanstack\/react-query|cacheManager|Cacheable|dataloader|DataLoader)\b/;

// ------------------------------------------------------------- analyzer ---

export const performanceAnalyzer: Analyzer = {
  id: 'performance',
  category: 'performance',
  description:
    'Query shape, pagination, caching, rendering, and payload risks that make work grow with data or traffic. Static risks only — nothing here is measured.',

  precondition(map: RepoMap): string | undefined {
    const parsed = [...map.modules.values()].filter((m) => m.parsed).length;
    if (parsed === 0) {
      return 'no source file could be parsed, so no call-graph facts are available for performance analysis';
    }
    return undefined;
  },

  run(ctx: AnalyzerContext): Finding[] {
    const { map } = ctx;
    const dataCalls = collectDataCalls(map);
    const findings: Finding[] = [];

    const nPlusOne = queriesInsideLoops(ctx, dataCalls);
    findings.push(...nPlusOne);
    findings.push(...requestsInsideLoops(ctx, dataCalls));

    const pagination = missingPagination(ctx, dataCalls);
    findings.push(...pagination);

    // A call site already reported as an endpoint-level pagination gap, or as an
    // N+1, is not reported again as an unbounded query: one defect, one finding.
    const claimed = new Set<string>();
    for (const f of [...nPlusOne, ...pagination]) {
      for (const e of f.evidence) if (e.startLine !== undefined) claimed.add(`${e.file}:${e.startLine}`);
    }
    findings.push(...unboundedQueries(ctx, dataCalls, claimed));

    findings.push(...unboundedListRendering(ctx, dataCalls));
    findings.push(...missingIndexes(ctx, dataCalls));
    findings.push(...serialIndependentReads(ctx, dataCalls));
    findings.push(...duplicateDataFetches(ctx, dataCalls));
    findings.push(...expensiveWorkInLoops(ctx));
    findings.push(...unoptimisedImages(ctx));
    findings.push(...heavyClientDependencies(ctx));
    findings.push(...absentCacheOnReadPath(ctx, dataCalls, findings));

    return findings;
  },
};

// ------------------------------------------------------------ N+1 queries ---

/**
 * A database read inside a loop body.
 *
 * This is AST-derived rather than textual: the parser sets `insideLoop` from the
 * enclosing for/while/forEach/map node, and the receiver has been resolved to a
 * model or a database binding. Two discriminations change the claim rather than
 * the detection: a loop that hands its promises to `Promise.all` issues the same
 * number of queries without serialising them, and a synchronous driver (no
 * `await` at the call site) blocks for the whole sequence. A loop over a short
 * inline array literal is not reported at all — its element count is fixed.
 */
function queriesInsideLoops(ctx: AnalyzerContext, dataCalls: DataCall[]): Finding[] {
  const { map } = ctx;
  const out: Finding[] = [];

  for (const dc of dataCalls) {
    if (dc.kind === 'network') continue;
    if (!dc.call.insideLoop) continue;

    const { mod, call } = dc;
    const sym = enclosingSymbol(mod, call.line);
    const loop = sym ? loopKindAbove(mod, sym, call.line) : UNKNOWN_LOOP;
    if (loop.boundedLiteral) continue;
    const source = sym ? loopSourceKind(mod, sym, call.line, dataCalls) : 'unknown';
    if (source === 'bounded') continue;
    const serialised = call.awaited && !loop.concurrent;
    const subject = dc.model?.name ?? 'the data layer';
    const isWrite = dc.kind === 'db_write';

    // A relation already fetched by an earlier query in the same scope makes this
    // a re-fetch of data the process is already holding.
    const redundant = sym ? includedRelationBefore(mod, sym, call, dc.model) : undefined;

    const evidence: Evidence[] = [
      map.evidenceLine(mod.path, call.line, `${call.callee}() sits inside ${loop.phrase}, so it runs once per element`),
    ];
    if (redundant) {
      evidence.push(map.evidenceLine(mod.path, redundant.line, `an earlier query in the same handler already fetched '${redundant.relation}' for every row`));
    }

    const routeHere = map.routes.find((r) => r.file === mod.path && sym && r.line !== undefined && r.line >= sym.startLine && r.line <= sym.endLine);

    out.push(ctx.finding({
      ruleId: 'performance.query.n_plus_one',
      title: `Database ${isWrite ? 'write' : 'query'} inside ${loop.phrase} (N+1 against ${subject})`,
      // Blast radius is largest when the iterated collection is itself an
      // unbounded query result: N is then the table size. A write loop is held
      // at medium because batching writes is a more delicate change than
      // batching reads, and the usual setting is a background path.
      severity: !isWrite && serialised && source === 'unbounded' ? 'high' : 'medium',
      confidence: 'strong',
      files: [mod.path],
      symbol: call.inSymbol,
      evidence,
      explanation:
        `${call.callee}() is issued inside ${loop.phrase}, so the number of database round trips is 1 for the outer collection plus one more for ` +
        `every element it contains — 1 + N, where N is the size of that collection at run time. N is not known statically and this scan does not ` +
        `measure it, so no multiplier is stated here; what is certain from the syntax tree is that the count scales with the data rather than staying fixed.` +
        (loop.concurrent
          ? ' The loop hands its promises to Promise.all, so the queries overlap rather than running one after another: the round-trip count still grows with N, but the waiting does not accumulate, which is why this is reported as a smaller risk than a serialised loop.'
          : call.awaited
            ? ' Because the call is awaited inside the loop, each round trip also waits for the previous one to finish, so the waiting accumulates on top of the query count.'
            : ' The call is not awaited at this site, so whether the round trips overlap depends on the driver and on how the results are collected; with a synchronous driver the loop blocks for the whole sequence. Either way the statement count grows with the collection.')
        + (source === 'unbounded'
          ? ' The collection being iterated is itself the result of a query with no row ceiling, so N here is the size of a table rather than a fixed batch.'
          : source === 'unknown'
            ? ' What the loop iterates could not be traced to a query, so N may be small and fixed — confirm the collection size before treating this as urgent.'
            : '')
        + (redundant
          ? ` The same handler already loaded '${redundant.relation}' through an include on an earlier query, so this loop re-fetches rows the process is already holding in memory.`
          : ''),
      userImpact: isWrite
        ? 'As the underlying collection grows, this request takes progressively longer and holds a database connection for the whole time. Users see a request that is fine with test data and times out once real volumes arrive, and a partial failure part-way through the loop leaves some rows written and some not.'
        : 'As the underlying collection grows, the page or endpoint takes progressively longer to respond and occupies a database connection throughout. Behaviour looks correct with a handful of seeded rows and degrades or times out at production volume, typically for the accounts with the most data — the heaviest users are hit first.',
      likelyRootCause: redundant
        ? 'The relation was added to an include for one purpose, and a later change fetched it again per row rather than reading the already-loaded field.'
        : 'The loop was written against a small development data set, where one query per element is indistinguishable from one query in total.',
      downstreamConsequences: [
        'Connection-pool pressure: one slow request of this shape can hold a connection long enough to starve other requests.',
        'The cost is invisible in local testing, because it is proportional to the row count, not to the code path.',
        redundant
          ? 'Any further handler that loops over the same collection almost certainly repeats the pattern.'
          : 'Adding a limit to the outer query reduces the symptom but leaves the per-element query in place.',
      ],
      remediation: redundant
        ? `Read the already-fetched relation from the loaded rows instead of querying again — the include on the earlier query has the data. Where the included relation is not enough, replace the loop with a single query: fetch all the rows you need in one call filtered by an \`in\` list of the parent identifiers, or use the ORM's aggregation (for example a grouped count) so the database does the per-parent work. If the relation is only needed for a count, select the count rather than the rows.`
        : `Replace the per-element query with one query for the whole set: filter by an \`in\` list of the identifiers gathered from the outer collection, use the ORM's relation loading (include/join/select_related/prefetch) to fetch the related rows alongside the parents, or push the per-element work into a single aggregate query. Where a per-element call genuinely cannot be merged, batch it (a DataLoader-style batching layer, or chunked \`in\` queries) and bound the concurrency rather than awaiting inside the loop.`,
      effort: 'small',
      verificationSteps: [
        'Enable the ORM or database query log for one request to this code path and confirm the number of statements no longer grows with the number of rows returned by the outer query.',
        'Seed the outer collection with a realistically large number of rows in a scratch database and compare the statement count before and after the change.',
        routeHere
          ? `Add a regression test that asserts the statement count for ${routeHere.method} ${routeHere.path} is constant with respect to the row count.`
          : 'Add a regression test that asserts the statement count is constant with respect to the row count.',
      ],
      references: [REF.excessAccess, REF.loopResource, REF.notMeasured],
    }));
  }
  return out;
}

/** An earlier query in the same scope that already loaded the relation now being re-queried. */
function includedRelationBefore(
  mod: ParsedModule, sym: SymbolInfo, call: CallRef, model: DataModel | undefined,
): { line: number; relation: string } | undefined {
  if (!model) return undefined;
  const target = model.name.toLowerCase();
  for (const earlier of mod.calls) {
    if (earlier.line >= call.line || earlier.line < sym.startLine) continue;
    const argText = earlier.args.join(' ');
    const includeIdx = /\b(?:include|select|relations|populate|with|joins?)\s*[:(]/.exec(argText)?.index;
    if (includeIdx === undefined) continue;
    for (const m of argText.slice(includeIdx).matchAll(/([A-Za-z_][\w]*)\s*:\s*(?:true|\{)/g)) {
      const key = m[1]!.toLowerCase();
      if (key === target || key === `${target}s` || key === `${target}es` || key.replace(/s$/, '') === target) {
        return { line: earlier.line, relation: m[1]! };
      }
    }
  }
  return undefined;
}

// --------------------------------------------------- requests in a loop ---

function requestsInsideLoops(ctx: AnalyzerContext, dataCalls: DataCall[]): Finding[] {
  const { map } = ctx;
  const out: Finding[] = [];

  for (const dc of dataCalls) {
    if (dc.kind !== 'network') continue;
    if (!dc.call.insideLoop || !dc.call.awaited) continue;

    const { mod, call } = dc;
    const sym = enclosingSymbol(mod, call.line);
    const loop = sym ? loopKindAbove(mod, sym, call.line) : UNKNOWN_LOOP;
    if (loop.boundedLiteral || loop.concurrent) continue;

    out.push(ctx.finding({
      ruleId: 'performance.network.request_in_loop',
      title: `Network request awaited inside ${loop.phrase}`,
      severity: 'medium',
      confidence: 'strong',
      status: 'needs_runtime_verification',
      files: [mod.path],
      symbol: call.inSymbol,
      evidence: [map.evidenceLine(mod.path, call.line, `${call.callee}() is awaited inside ${loop.phrase}, so one request is issued per element`)],
      explanation:
        `${call.callee}() is awaited inside ${loop.phrase}, so the code issues one outbound request per element of the collection and waits for each ` +
        'to return before starting the next. The request count and the accumulated wait both scale with the collection size, which is not known statically. ' +
        'Remote calls are also the most likely step to fail or stall, so a loop of them multiplies the exposure to a single slow dependency.',
      userImpact:
        'The operation appears to hang for the user while the requests drain one at a time, and a single unresponsive upstream call blocks everything behind it. ' +
        'If the surrounding request has a timeout, the whole operation fails after partial work has already been done.',
      likelyRootCause: 'A per-item API call was written inline because the collection was small when the code was first added.',
      downstreamConsequences: [
        'Rate limits at the upstream service are far easier to hit from a loop than from a batched call.',
        'Retries layered on top of a per-element request multiply the request count again.',
      ],
      remediation:
        'Use the upstream API\'s batch or bulk endpoint where one exists so the whole collection is sent in a single request. Otherwise run the calls ' +
        'concurrently with a bounded worker pool (collect the promises and await them with a concurrency cap rather than awaiting inside the loop), set an ' +
        'explicit per-request timeout, and decide deliberately what should happen when some elements fail — partial success needs a defined outcome.',
      effort: 'medium',
      verificationSteps: [
        'Count the outbound requests for one execution of this code path (a request log or a local proxy will show them) and confirm the count no longer scales with the collection size.',
        'Measure the wall-clock duration of this operation before and after the change with a realistic collection size — that measurement is what settles whether the serialisation mattered here.',
        'Confirm an unresponsive upstream now fails the individual element rather than stalling the whole operation.',
      ],
      references: [REF.loopResource, REF.amplification, REF.notMeasured],
    }));
  }
  return out;
}

// ------------------------------------------------------ unbounded queries ---

function unboundedQueries(ctx: AnalyzerContext, dataCalls: DataCall[], claimed: Set<string>): Finding[] {
  const { map } = ctx;
  const out: Finding[] = [];

  for (const dc of dataCalls) {
    if (dc.kind !== 'db_read') continue;
    if (!dc.collection || dc.bounded) continue;
    // An ambiguous leaf on raw SQL is only judged when the statement itself was readable.
    if (AMBIGUOUS_READS.has(dc.leaf) && !dc.model && !dc.sql) continue;
    if (dc.sql && !SQL_SELECT_RE.test(dc.sql)) continue;

    const { mod, call } = dc;
    if (claimed.has(`${mod.path}:${call.line}`)) continue;

    const sym = enclosingSymbol(mod, call.line);
    const consumption = consumptionOf(mod, sym, call);
    const subject = dc.model ? `the ${dc.model.name} table` : 'the queried table';

    // Blast radius: a result serialised into a response grows the payload as
    // well as the query. A value merely returned from a helper is not treated as
    // client-facing — that would be assuming a caller we have not traced.
    const inRequestPath =
      map.filesByPath.get(mod.path)?.role === 'route'
      || map.routes.some((r) => r.file === mod.path);
    const exposed = consumption.serialised || (inRequestPath && consumption.returned);
    const severity: Severity = exposed ? 'high' : 'medium';

    out.push(ctx.finding({
      ruleId: 'performance.query.unbounded',
      title: `${call.callee}() reads ${subject} with no row limit`,
      severity,
      confidence: dc.model ? 'strong' : 'moderate',
      status: 'needs_runtime_verification',
      files: [mod.path],
      symbol: call.inSymbol,
      evidence: [
        map.evidenceLine(mod.path, call.line, dc.sql
          ? 'SELECT with no LIMIT clause, so every matching row is returned'
          : 'no take/limit/cursor argument, so every matching row is returned'),
      ],
      explanation:
        `${call.callee}() is called without any row ceiling — no take, limit, first, or cursor argument` +
        (dc.sql ? ' and no LIMIT in the statement' : '') + '. ' +
        `The query therefore returns however many rows ${subject} currently holds, and every one of them is materialised in the application process. ` +
        (consumption.iterated ? 'The result is then iterated, so the work after the query grows with the row count too. ' : '') +
        (exposed ? 'The result is handed back to the caller, so the response body grows with the table as well. ' : '') +
        'The row count is a property of the deployed data, not of the code, so this scan cannot say how many rows that is today or how fast it is growing.',
      userImpact: exposed
        ? 'Users of this feature get a response whose size grows with the whole table. It is fast on seeded data and becomes slow, then memory-hungry, then a timeout as the table fills up — and the failure arrives suddenly, at whatever row count crosses the limit.'
        : 'The process holds the entire table in memory for the duration of this call. As the table grows this shows up as rising memory use and slower requests across the whole instance, not only in this feature, because the memory and the database connection are shared.',
      likelyRootCause: 'The query was written when the table was known to be small, and no ceiling was added because none was needed yet.',
      downstreamConsequences: [
        'Memory use for this request is proportional to the table size, so one call can affect every other request on the same instance.',
        exposed
          ? 'Clients have no way to ask for less: the absent limit is part of the contract they depend on, so adding one later is a breaking change unless it is introduced alongside pagination.'
          : 'A retry or a concurrent duplicate of this call multiplies the memory cost.',
      ],
      remediation:
        'Add an explicit ceiling to the query (take/limit, or LIMIT in raw SQL) and make it the default rather than an option. ' +
        (exposed
          ? 'Expose paging to the caller at the same time — a limit parameter with a sane default and a hard maximum, plus a cursor or offset — so reducing the result set does not silently drop data the client expected. '
          : 'Where the whole set genuinely must be processed, stream or page through it in chunks (cursor-based batches) so memory stays constant regardless of the row count. ') +
        'Select only the columns actually used, so the per-row cost is bounded as well as the row count.',
      effort: 'small',
      verificationSteps: [
        'Run the query against a table seeded with a realistically large number of rows and confirm the returned row count is capped.',
        'Measure the process memory for one call before and after the change at that row count — that measurement is what confirms the ceiling is effective.',
        exposed
          ? 'Confirm the client still receives a complete data set across pages, and that an explicit over-large limit is rejected rather than honoured.'
          : 'Confirm the chunked path processes every row exactly once.',
      ],
      references: [REF.noThrottle, REF.excessQuery, REF.notMeasured],
    }));
  }
  return out;
}

// ----------------------------------------------------- missing pagination ---

/**
 * A read endpoint that returns a collection and accepts no paging parameter.
 *
 * The two halves are checked together: an unbounded list read inside the handler
 * (so the response grows with the table) and the absence of any limit, offset,
 * cursor, or page input in the request contract (so the caller cannot ask for
 * less). Either alone is weaker; together they are an endpoint whose response
 * size is decided by the data.
 */
function missingPagination(ctx: AnalyzerContext, dataCalls: DataCall[]): Finding[] {
  const { map } = ctx;
  const out: Finding[] = [];

  const PAGING_INPUT_RE =
    /\b(?:limit|offset|cursor|page|pageSize|page_size|per_page|perPage|take|skip|after|before|pageToken|page_token|start|count|size)\b/;

  for (const r of map.routes) {
    if (r.method !== 'GET' && r.method !== 'ANY') continue;
    const mod = map.modules.get(r.file);
    const sym = handlerSymbolFor(map, r);
    if (!mod?.parsed || !sym) continue;

    const reads = callsIn(dataCalls, r.file, sym).filter(
      (dc) => dc.kind === 'db_read' && dc.collection && !dc.bounded && (dc.model !== undefined || dc.sql !== undefined),
    );
    if (reads.length === 0) continue;

    const body = codeText(sym.text, mod.language);
    const acceptsPaging =
      (r.requestShape !== undefined && PAGING_INPUT_RE.test(r.requestShape))
      || /(?:searchParams|query|params|args)\s*(?:\.\s*get\s*\(\s*['"]|\[\s*['"]|\.)\s*(?:limit|offset|cursor|page|pageSize|per_page|perPage|take|skip|after|before|size|count)\b/i.test(body)
      || /\b(?:limit|offset|cursor|page|pageSize|perPage|take|skip)\s*=\s*(?:Number|parseInt|Int|int)\s*\(/.test(body);
    if (acceptsPaging) continue;

    const primary = reads[0]!;
    const modelNames = [...new Set(reads.map((d) => d.model?.name).filter((n): n is string => !!n))];
    const subject = modelNames.length > 0 ? modelNames.join(', ') : 'the queried table';

    out.push(ctx.finding({
      ruleId: 'performance.api.missing_pagination',
      title: `${r.method} ${r.path} returns a whole collection with no pagination parameters`,
      severity: 'medium',
      confidence: 'strong',
      status: 'needs_runtime_verification',
      files: [r.file],
      symbol: r.handlerSymbol,
      evidence: [
        map.evidenceLine(r.file, r.line ?? sym.startLine, `${r.method} ${r.path} handler: its request contract carries no limit, offset, cursor, or page input`),
        map.evidenceLine(primary.mod.path, primary.call.line, `${primary.call.callee}() reads the collection with no row ceiling`),
      ],
      explanation:
        `The handler for ${r.method} ${r.path} reads a collection from ${subject} without a row ceiling, and the endpoint accepts no parameter a caller could ` +
        'use to ask for a bounded page: no limit, offset, cursor, or page input appears in the request contract or is read from the query string. ' +
        'The size of the response is therefore decided entirely by how much data the table holds. ' +
        'How large that is in production is not something this scan can see.',
      userImpact:
        'Every client of this endpoint — including the application\'s own pages — must download and parse the full collection on each call. ' +
        'The endpoint feels fine while the table is small and becomes a slow, heavy request that can time out as data accumulates, with mobile and ' +
        'low-bandwidth users affected first and worst.',
      likelyRootCause: 'The endpoint was written to serve one screen that showed everything, and pagination was deferred until the data grew.',
      downstreamConsequences: [
        'Clients written against the unpaginated shape will break when paging is added later, so the fix gets harder the longer it waits.',
        'Response size scales with the table, so caching layers and payload limits in front of this endpoint are harder to size.',
        'An unbounded read on a public or cheaply reachable endpoint is also an availability concern: repeated calls amplify load with no ceiling.',
      ],
      remediation:
        `Add paging to the endpoint: a limit parameter with a conservative default and an enforced maximum, plus a cursor (preferred — it stays correct while ` +
        `rows are inserted) or an offset. Apply that limit to the query itself rather than slicing in the application, and return the paging state ` +
        '(next cursor, or total count where it is cheap) so clients can iterate. Keep the default response bounded even when the caller sends no parameters, ' +
        'and version or feature-flag the change if existing clients depend on receiving everything.',
      effort: 'medium',
      verificationSteps: [
        `Call ${r.method} ${r.path} with no parameters against a table seeded with a realistically large number of rows and confirm the response is bounded.`,
        'Confirm an over-large limit value is clamped rather than honoured.',
        'Walk the collection with the cursor or offset and confirm every row is returned exactly once while rows are being inserted concurrently.',
        'Record the response size at a realistic row count before and after — that measurement is what confirms the payload is now bounded.',
      ],
      references: [REF.apiConsumption, REF.noThrottle, REF.notMeasured],
    }));
  }
  return out;
}

// ------------------------------------------------ unbounded list rendering ---

/**
 * A view that renders every element of a collection produced by an unbounded read.
 *
 * This is the cross-file half of the pagination problem: the query has no
 * ceiling in one module and the component maps over the whole result in
 * another, so neither file alone shows it.
 */
function unboundedListRendering(ctx: AnalyzerContext, dataCalls: DataCall[]): Finding[] {
  const { map } = ctx;
  const out: Finding[] = [];

  const unbounded = dataCalls.filter(
    (dc) => dc.kind === 'db_read' && dc.collection && !dc.bounded && (dc.model !== undefined || dc.sql !== undefined),
  );
  if (unbounded.length === 0) return out;

  const PAGING_UI_RE =
    /\b(?:pagination|paginate|pageSize|page_size|perPage|per_page|loadMore|load_more|infinite|virtual|useVirtualizer|react-window|react-virtual|react-virtualized|FlatList|windowSize|\.slice\s*\(|take\s*[:=])/i;

  for (const mod of map.modules.values()) {
    if (!mod.parsed || mod.jsx.length === 0) continue;
    const file = map.filesByPath.get(mod.path);
    const body = codeText(file?.text ?? null, mod.language);
    if (PAGING_UI_RE.test(body)) continue;

    for (const call of mod.calls) {
      const m = /^([A-Za-z_$][\w$]*)\.(?:map|flatMap)$/.exec(call.callee);
      if (!m) continue;
      const varName = m[1]!;

      // The binding this collection came from, and the call that produced it.
      const binding = mod.symbols.find((s) => s.name === varName && s.kind === 'const');
      if (!binding) continue;
      const producer = /=\s*(?:await\s+)?([A-Za-z_$][\w$.]*)\s*\(/.exec(binding.text)?.[1];
      if (!producer) continue;

      const source = resolveUnboundedProducer(map, mod, producer, binding.startLine, unbounded);
      if (!source) continue;

      const crossFile = source.dc.mod.path !== mod.path;
      const subject = source.dc.model ? source.dc.model.name : 'the queried table';
      const files = crossFile ? [mod.path, source.dc.mod.path] : [mod.path];

      out.push(ctx.finding({
        ruleId: 'performance.render.unbounded_list',
        title: `${varName} is rendered in full from an unbounded query (no pagination in the view)`,
        severity: 'medium',
        confidence: crossFile ? 'strong' : 'moderate',
        status: 'needs_runtime_verification',
        detectionSource: crossFile ? 'graph' : 'static',
        files,
        symbol: call.inSymbol,
        evidence: [
          map.evidenceLine(mod.path, call.line, `every element of '${varName}' is mapped to markup, with no slice, page, or virtualisation`),
          map.evidenceLine(mod.path, binding.startLine, `'${varName}' is produced by ${producer}()`),
          map.evidenceLine(source.dc.mod.path, source.dc.call.line, `${source.dc.call.callee}() reads ${subject} with no row ceiling`),
        ],
        trace: {
          kind: 'call',
          steps: [
            { file: mod.path, line: call.line, symbol: call.inSymbol, detail: `renders one element of '${varName}' per row, with no upper bound` },
            { file: mod.path, line: binding.startLine, symbol: call.inSymbol, detail: `'${varName}' is the result of ${producer}()` },
            ...(source.via ? [{ file: source.via.path, line: source.via.line, symbol: source.via.symbol, detail: `${producer}() is defined here` }] : []),
            { file: source.dc.mod.path, line: source.dc.call.line, detail: `${source.dc.call.callee}() has no take/limit, so the collection size is the table size` },
          ],
          complete: true,
        },
        explanation:
          `The view maps over every element of '${varName}' to produce markup, and '${varName}' is the result of ${producer}(), which reads ${subject} ` +
          'with no row ceiling. Neither file shows the problem on its own: the query has no limit in one place and the view assumes the result is small in ' +
          'another. The number of rendered nodes is therefore the number of rows in the table. No pagination, slice, or virtualisation appears in this module. ' +
          'How many rows that is in production is not visible to this scan.',
        userImpact:
          'The page gets slower to load and to interact with as rows accumulate: the whole collection is fetched, serialised to the client, and turned into ' +
          'DOM nodes before anything is usable. Low-powered devices feel it first — scrolling and typing become sluggish, and eventually the page may fail to ' +
          'render at all.',
        likelyRootCause: 'The list screen was built against a seeded data set where showing everything was reasonable.',
        downstreamConsequences: [
          'Server-rendered markup grows with the table, so the transferred document grows with it.',
          'Adding paging later touches both the view and the query, and changes the shape the view consumes.',
        ],
        remediation:
          `Page the data rather than the view: add a bounded limit to ${producer}() (and expose a cursor or page parameter), then render one page at a time with ` +
          'explicit navigation or an explicit "load more" step. For a list that genuinely must appear continuous, add windowing/virtualisation so the number of ' +
          'mounted nodes stays constant while the data set grows. Keep a server-side ceiling even when the view asks for everything, so one screen cannot ' +
          'request the whole table.',
        effort: 'medium',
        verificationSteps: [
          'Seed the table with a realistically large number of rows, load this view, and confirm the number of rendered elements is bounded.',
          'Record the transferred document size and the time to first interaction at that row count before and after the change — those measurements are what confirm the improvement.',
          'Confirm every row remains reachable through paging or scrolling after the change.',
        ],
        references: [REF.noThrottle, REF.excessiveIteration, REF.notMeasured],
      }));
      break; // one finding per view is enough; the remediation is the same for each list in it
    }
  }
  return out;
}

/** Resolve a producer function name to an unbounded read, following one import hop. */
function resolveUnboundedProducer(
  map: RepoMap, mod: ParsedModule, producer: string, bindingLine: number, unbounded: DataCall[],
): { dc: DataCall; via?: { path: string; line: number; symbol: string } } | undefined {
  // The producer may itself be the data call (`const rows = await prisma.x.findMany()`).
  const direct = unbounded.find((dc) => dc.mod.path === mod.path && dc.call.line === bindingLine);
  if (direct) return { dc: direct };

  const localName = producer.split('.')[0]!;

  // A function defined in this module.
  const localFn = mod.symbols.find(
    (s) => s.name === localName && (s.kind === 'function' || s.kind === 'arrow' || s.kind === 'method'),
  );
  if (localFn) {
    const inside = unbounded.find(
      (dc) => dc.mod.path === mod.path && dc.call.line >= localFn.startLine && dc.call.line <= localFn.endLine,
    );
    if (inside) return { dc: inside, via: { path: mod.path, line: localFn.startLine, symbol: localFn.name } };
  }

  // A function imported from another module in the project.
  for (const imp of mod.imports) {
    if (!imp.resolvedPath || !imp.names.includes(localName)) continue;
    const target = map.modules.get(imp.resolvedPath);
    if (!target?.parsed) continue;
    const fn = target.symbols.find(
      (s) => s.name === localName && (s.kind === 'function' || s.kind === 'arrow' || s.kind === 'method'),
    );
    if (!fn) continue;
    const inside = unbounded.find(
      (dc) => dc.mod.path === target.path && dc.call.line >= fn.startLine && dc.call.line <= fn.endLine,
    );
    if (inside) return { dc: inside, via: { path: target.path, line: fn.startLine, symbol: fn.name } };
  }
  return undefined;
}

// -------------------------------------------------------- missing indexes ---

/**
 * A column that queries filter on but that no index covers.
 *
 * This is a genuine cross-file correlation: the filter is in application code
 * and the index list is in the schema, so it is only visible by reading both.
 * The `where` keys are matched against the model's real columns, relation
 * filters are excluded (an index on this table does not serve a join predicate),
 * and a composite index counts only for its leading column.
 */
function missingIndexes(ctx: AnalyzerContext, dataCalls: DataCall[]): Finding[] {
  const { map } = ctx;
  const out: Finding[] = [];

  // field key -> every site that filters on it
  const sites = new Map<string, { model: DataModel; field: string; calls: DataCall[] }>();
  for (const dc of dataCalls) {
    if (!dc.model || dc.whereFields.length === 0 || !dc.whereBlock) continue;
    if (dc.kind === 'network') continue;

    // A predicate we cannot see in full (a spread of a where fragment built
    // elsewhere) cannot support the claim that nothing indexed narrows it.
    if (/\.\.\./.test(dc.whereBlock)) continue;
    // An existing index on any column in the same predicate already narrows the
    // scan, so a second single-column index is not the recommendation.
    if (dc.whereFields.some((f) => indexCovers(dc.model!, f))) continue;

    for (const field of dc.whereFields) {
      if (indexCovers(dc.model, field)) continue;
      if (isLowCardinality(dc.model, field)) continue;
      if (usesTextSearchOperator(dc.whereBlock, field)) continue;
      const key = `${dc.model.file}::${dc.model.name}.${field}`;
      const entry = sites.get(key) ?? { model: dc.model, field, calls: [] };
      entry.calls.push(dc);
      sites.set(key, entry);
    }
  }

  for (const { model, field, calls } of sites.values()) {
    const declLine = modelDeclarationLine(map, model);
    const fieldLine = modelFieldLine(map, model, field) ?? declLine;
    if (fieldLine === undefined) continue; // the schema line could not be located: do not guess

    const first = calls[0]!;
    const writesToo = calls.some((c) => c.kind === 'db_write');
    const inLoop = calls.some((c) => c.call.insideLoop);
    const callSites = [...new Set(calls.map((c) => `${c.mod.path}:${c.call.line}`))];

    const evidence: Evidence[] = [
      map.evidenceLine(first.mod.path, first.call.line, `filters ${model.name} on '${field}'`),
      map.evidenceLine(model.file, fieldLine, `'${field}' is declared here; the model's declared indexes are [${model.indexes.join(', ') || 'none'}]`),
    ];
    for (const extra of calls.slice(1, 3)) {
      evidence.push(map.evidenceLine(extra.mod.path, extra.call.line, `also filters ${model.name} on '${field}'`));
    }

    out.push(ctx.finding({
      ruleId: 'performance.db.missing_index',
      title: `${model.name}.${field} is filtered on in queries but is not indexed`,
      severity: 'medium',
      confidence: 'strong',
      status: 'needs_runtime_verification',
      detectionSource: 'graph',
      files: [model.file, ...[...new Set(calls.map((c) => c.mod.path))]],
      symbol: `${model.name}.${field}`,
      evidence,
      trace: {
        kind: 'data_policy',
        steps: [
          ...calls.slice(0, 3).map((c) => ({
            file: c.mod.path,
            line: c.call.line,
            symbol: c.call.inSymbol,
            detail: `${c.call.callee}() filters ${model.name} on '${field}'${c.call.insideLoop ? ' inside a loop' : ''}`,
          })),
          { file: model.file, line: declLine, detail: `${model.name} is declared here` },
          {
            file: model.file,
            line: fieldLine,
            detail: `'${field}' is a column of ${model.name}; declared indexes are [${model.indexes.join(', ') || 'none'}], none of which lead with '${field}'`,
          },
        ],
        complete: true,
      },
      explanation:
        `Application code filters ${model.name} on '${field}' at ${callSites.length} call site${callSites.length === 1 ? '' : 's'} (${callSites.slice(0, 3).join(', ')}` +
        `${callSites.length > 3 ? ', …' : ''}), but the model declares no index that leads with that column — its declared indexes are ` +
        `[${model.indexes.join(', ') || 'none'}]. Without one, the database has to examine rows it cannot rule out in advance, and the work for each of ` +
        `these queries grows with the size of the table rather than with the number of rows actually matched.` +
        (inLoop ? ' One of these call sites is inside a loop, so the unindexed lookup is repeated per element.' : '') +
        ' Whether the planner currently chooses a scan, and what that costs, depends on the deployed table size and statistics — neither is visible here.',
      userImpact:
        `Requests that look up ${model.name} by '${field}' get slower as the table grows, in a way that is invisible on a small development data set. ` +
        'The accounts with the most data notice first, and because a scan holds resources for longer than a lookup, the slowdown spreads to unrelated ' +
        'requests sharing the same database.',
      likelyRootCause:
        `'${field}' was added as a plain column — commonly a foreign key, which several databases do not index automatically — and the query that filters on it was written later.`,
      downstreamConsequences: [
        'Query planners may still choose a scan after the index exists if statistics are stale, so the index alone is not proof of a fix.',
        'Each added index costs write throughput and storage, so the set of indexes should match the queries that actually run, not every column.',
        writesToo
          ? `Writes also filter on '${field}', so an index here helps the update and delete paths as well as the reads.`
          : 'A composite index may serve this query better if it is always filtered alongside another column — check the real query shapes before adding a single-column index.',
      ],
      remediation:
        `Add an index on ${model.name}.${field} in the schema (for a Prisma schema, \`@@index([${field}])\` on the model, or \`@@unique\` where the column is ` +
        `genuinely unique; in SQL, \`CREATE INDEX\` — concurrently on a live table so the migration does not hold a write lock). If this column is always ` +
        'filtered together with another, prefer one composite index with the most selective leading column over two single-column indexes. Then confirm the ' +
        'planner actually uses it, and remove indexes that no query needs so write cost does not creep up.',
      effort: 'small',
      verificationSteps: [
        `Run EXPLAIN ANALYZE on the query that filters ${model.name} on '${field}' against a table with a realistic row count, before and after adding the index — that is the measurement that settles both the diagnosis and the fix.`,
        'Confirm the plan changes from a sequential or full scan to an index lookup, and that the examined-row count drops.',
        'Apply the migration on a copy of production-sized data and confirm the index build completes without blocking writes.',
        'Re-check the write paths for this table after the change to confirm insert and update throughput is still acceptable.',
      ],
      references: [REF.excessQuery, REF.amplification, REF.notMeasured],
    }));
  }
  return out;
}

/** Line of a model/table/class declaration, located in its own file. */
function modelDeclarationLine(map: RepoMap, model: DataModel): number | undefined {
  const file = map.filesByPath.get(model.file);
  if (!file?.text) return undefined;
  const name = escapeRe(model.name);
  const patterns = [
    new RegExp(`^\\s*model\\s+${name}\\b`),
    new RegExp(`^\\s*(?:export\\s+)?(?:abstract\\s+)?class\\s+${name}\\b`),
    new RegExp(`CREATE\\s+TABLE\\s+(?:IF\\s+NOT\\s+EXISTS\\s+)?["\`[]?${name}\\b`, 'i'),
    new RegExp(`^\\s*(?:export\\s+)?const\\s+${name}\\b`),
  ];
  const lines = file.text.split('\n');
  for (let i = 0; i < lines.length; i++) {
    if (patterns.some((p) => p.test(lines[i]!))) return i + 1;
  }
  return undefined;
}

/** Line where a field is declared inside its model block. */
function modelFieldLine(map: RepoMap, model: DataModel, field: string): number | undefined {
  const file = map.filesByPath.get(model.file);
  const start = modelDeclarationLine(map, model);
  if (!file?.text || start === undefined) return undefined;
  const lines = file.text.split('\n');
  const fieldRe = new RegExp(`^\\s*["\`[]?${escapeRe(field)}["\`\\]]?\\s*[\\s:=(]`);
  for (let i = start; i < lines.length; i++) {
    const line = lines[i]!;
    if (/^\s*(?:\}|\)\s*;?)\s*$/.test(line)) break; // end of the block
    if (fieldRe.test(line)) return i + 1;
  }
  return undefined;
}

// ----------------------------------------------------- serial independent ---

/**
 * Independent reads awaited one after another in the same scope.
 *
 * Deliberately narrow. Writes are excluded, because reordering or overlapping
 * writes changes behaviour and "run these concurrently" is not safe advice for
 * them. Any control flow between the two calls (a guard, an early return, a
 * branch) also disqualifies the pair, because concurrency would then execute
 * work the original code skipped.
 */
function serialIndependentReads(ctx: AnalyzerContext, dataCalls: DataCall[]): Finding[] {
  const { map } = ctx;
  const out: Finding[] = [];

  const bySymbol = new Map<string, DataCall[]>();
  for (const dc of dataCalls) {
    if (dc.kind === 'db_write') continue;
    if (!dc.call.awaited || dc.call.insideLoop) continue;
    const sym = enclosingSymbol(dc.mod, dc.call.line);
    if (!sym || sym.endLine === sym.startLine) continue;
    const key = `${dc.mod.path}::${sym.name}::${sym.startLine}`;
    const list = bySymbol.get(key) ?? [];
    list.push(dc);
    bySymbol.set(key, list);
  }

  for (const [, group] of bySymbol) {
    if (group.length < 2) continue;
    const ordered = [...group].sort((a, b) => a.call.line - b.call.line);
    const mod = ordered[0]!.mod;
    const sym = enclosingSymbol(mod, ordered[0]!.call.line);
    if (!sym) continue;
    const bodyLines = codeText(sym.text, mod.language).split('\n');

    const independent: DataCall[] = [ordered[0]!];
    for (let i = 1; i < ordered.length; i++) {
      const prev = independent[independent.length - 1]!;
      const curr = ordered[i]!;

      // Does this call use any earlier result?
      const argText = curr.call.args.join(' ');
      const dependsOnEarlier = independent.some((earlier) => {
        const name = assignedName(mod, earlier.call.line);
        return !!name && new RegExp(`\\b${escapeRe(name)}\\b`).test(argText);
      });
      if (dependsOnEarlier) break;

      // An identical repeated read is duplicated work, not serialised work, and
      // is reported as such by the duplicate-read rule. Overlapping two copies
      // of the same query would be the wrong advice.
      const identical = independent.some(
        (earlier) => earlier.call.callee === curr.call.callee
          && earlier.call.args.join('|') === curr.call.args.join('|'),
      );
      if (identical) break;

      // Is there control flow between them that concurrency would change?
      const from = Math.max(prev.call.line - sym.startLine + 1, 0);
      const to = Math.min(curr.call.line - sym.startLine, bodyLines.length);
      const between = bodyLines.slice(from, to).join('\n');
      if (/\b(?:if|else|return|throw|for|while|switch|try|catch|continue|break)\b|&&|\|\||\?\?/.test(between)) break;

      independent.push(curr);
    }
    if (independent.length < 2) continue;

    const callees = independent.map((d) => `${d.call.callee}()`);
    out.push(ctx.finding({
      ruleId: 'performance.async.serial_awaits',
      title: `${independent.length} independent reads awaited in sequence in ${sym.name}`,
      severity: 'low',
      confidence: 'moderate',
      status: 'needs_runtime_verification',
      files: [mod.path],
      symbol: sym.name,
      evidence: independent.map((d, i) =>
        map.evidenceLine(d.mod.path, d.call.line, i === 0
          ? 'first awaited read'
          : 'awaited only after the previous read has returned, although it does not use its result')),
      explanation:
        `${sym.name} awaits ${callees.join(', then ')} one after another. None of these calls references a value produced by an earlier one, and there is no ` +
        'branch, guard, or early return between them, so each simply waits for the previous round trip to finish before starting. The total wait is the sum ' +
        'of the individual waits rather than the longest of them. This scan does not measure those waits, so the size of the saving is unknown — only that ' +
        'the dependency order does not require the sequence.',
      userImpact:
        'The request takes longer than the work requires, because independent waiting is stacked rather than overlapped. Users experience it as a page or ' +
        'action that is consistently sluggish rather than intermittently so.',
      likelyRootCause: 'The reads were added one at a time, each as a straightforward `await` on the line after the last.',
      downstreamConsequences: [
        'Each additional independent read added to this handler extends the response time further.',
        'Overlapping the calls holds more connections at once, so the concurrency needs to be weighed against pool size.',
      ],
      remediation:
        'Start the independent reads together and await them as a group (`Promise.all`, or `Promise.allSettled` where one failure should not discard the ' +
        'others), keeping the dependent calls in sequence. Check the error semantics before changing it: with Promise.all the first rejection discards the ' +
        'other results, so handle partial failure deliberately. Where the reads hit the same store, consider whether one query could return everything ' +
        'instead, which is cheaper than overlapping several.',
      effort: 'small',
      verificationSteps: [
        'Measure the handler duration before and after the change under a realistic data set — that measurement is what establishes whether the serialisation mattered here.',
        'Confirm the behaviour when one of the grouped calls fails matches what the sequential version did.',
        'Confirm the database connection pool tolerates the additional simultaneous queries under load.',
      ],
      references: [REF.notMeasured],
    }));
  }
  return out;
}

// ------------------------------------------------------ duplicate fetches ---

/**
 * The same read issued more than once with identical arguments *within one scope*.
 *
 * Restricted to a single enclosing function on purpose. Two different endpoints
 * running the same query is normal and not a defect; the same query twice in one
 * execution path is work done twice for one answer.
 */
function duplicateDataFetches(ctx: AnalyzerContext, dataCalls: DataCall[]): Finding[] {
  const { map } = ctx;
  const out: Finding[] = [];

  const groups = new Map<string, DataCall[]>();
  for (const dc of dataCalls) {
    if (dc.kind === 'db_write') continue;
    const argText = dc.call.args.join('|').trim();
    if (argText.length === 0) continue; // an argument-free call tells us nothing about the result set
    if (/=>|function\s*\(/.test(argText)) continue; // a callback argument is not a query key
    const sym = enclosingSymbol(dc.mod, dc.call.line);
    if (!sym) continue;
    const key = `${dc.mod.path}::${sym.name}::${sym.startLine}::${dc.call.callee}(${argText})`;
    const list = groups.get(key) ?? [];
    list.push(dc);
    groups.set(key, list);
  }

  for (const [groupKey, group] of groups) {
    if (group.length < 2) continue;
    const sites = [...new Set(group.map((d) => `${d.mod.path}:${d.call.line}`))];
    if (sites.length < 2) continue;
    const key = groupKey.split('::').slice(3).join('::');
    const scope = group[0]!.call.inSymbol ?? enclosingSymbol(group[0]!.mod, group[0]!.call.line)?.name ?? 'this scope';
    const callee = group[0]!.call.callee;

    out.push(ctx.finding({
      ruleId: 'performance.fetch.duplicate_request',
      title: `${callee}() is issued with identical arguments ${sites.length} times in ${scope}`,
      severity: 'low',
      confidence: 'moderate',
      status: 'needs_runtime_verification',
      files: [group[0]!.mod.path],
      symbol: scope,
      evidence: group.slice(0, 4).map((d) =>
        map.evidenceLine(d.mod.path, d.call.line, `identical read: ${key.slice(0, 160)}`)),
      explanation:
        `The same read — ${key.slice(0, 200)} — appears ${sites.length} times inside ${scope} (${sites.slice(0, 3).join(', ')}${sites.length > 3 ? ', …' : ''}). ` +
        'Identical arguments mean identical result sets, so one execution of this function does the same work more than once and discards or recomputes the ' +
        'duplicate. Whether every one of these lines runs on each pass depends on the branches taken at run time, which this scan does not execute.',
      userImpact:
        'Where these lines run together, the user waits for repeated work that produces the same answer, and the data store serves duplicate load for no ' +
        'additional information. It can also produce visible inconsistency: two reads of the same key at different moments can disagree.',
      likelyRootCause: 'Each consumer in this function fetched what it needed independently, with no shared read between them.',
      downstreamConsequences: [
        'Duplicate reads multiply load on the data store under traffic without any change in the data returned.',
        'The two copies can drift apart within one pass, producing inconsistent output that is hard to reproduce.',
      ],
      remediation:
        'Read once into a local binding and reuse it, or put the read behind a shared, request-scoped layer: a per-request cache, a batching loader (DataLoader-style) ' +
        'that collapses identical keys, or the data-fetching library\'s own deduplication and cache keys where one is already in use. Pick the owner of the ' +
        'read deliberately rather than letting each consumer fetch for itself.',
      effort: 'small',
      verificationSteps: [
        'Log the queries issued for one request that exercises these paths and confirm the identical read appears once.',
        'Confirm the consumers all observe the same snapshot after the change.',
        'Compare the statement count per request before and after — that measurement shows whether the duplication was real on a live path.',
      ],
      references: [REF.amplification, REF.notMeasured],
    }));
  }
  return out;
}

// ------------------------------------------------- expensive work in loops ---

/**
 * Synchronous operations whose per-call cost is inherent.
 *
 * Plain hashing (`createHash`) is deliberately absent: hashing one item per
 * element is what checksum and fingerprint code is *for*, so flagging it would
 * be noise. Key-derivation functions are included because they are deliberately
 * slow and a loop of them is always worth questioning.
 */
const EXPENSIVE_SYNC = new Map<string, string>([
  ['pbkdf2Sync', 'a synchronous key-derivation function'],
  ['scryptSync', 'a synchronous key-derivation function'],
  ['hashSync', 'synchronous password hashing'],
  ['compareSync', 'synchronous password comparison'],
  ['readFileSync', 'a blocking file read'],
  ['writeFileSync', 'a blocking file write'],
  ['appendFileSync', 'a blocking file write'],
  ['readdirSync', 'a blocking directory read'],
  ['statSync', 'a blocking file-system stat'],
  ['existsSync', 'a blocking file-system check'],
  ['execSync', 'a blocking subprocess'],
  ['spawnSync', 'a blocking subprocess'],
  ['structuredClone', 'a deep clone of the whole value'],
]);

/**
 * Synchronous, known-expensive work inside a loop.
 *
 * The list is restricted to operations whose cost is inherent — key derivation,
 * blocking file-system and subprocess calls, deep cloning. Ordinary collection
 * operations are left out on purpose: `list.includes(x)` inside a loop is
 * quadratic in principle and completely irrelevant in most real code, and
 * reporting it would bury the findings that matter.
 *
 * Blocking file-system work is only reported for a project that serves requests.
 * In a command-line tool or a build step, reading each file in a loop with the
 * synchronous API is an ordinary and reasonable choice; in a request handler it
 * stalls every other request sharing the process.
 */
function expensiveWorkInLoops(ctx: AnalyzerContext): Finding[] {
  const { map } = ctx;
  const out: Finding[] = [];
  const servesRequests = map.routes.length > 0;

  for (const mod of map.modules.values()) {
    if (!mod.parsed) continue;
    for (const call of mod.calls) {
      if (!call.insideLoop) continue;
      const leaf = calleeSegments(call.callee).pop() ?? '';
      const what = EXPENSIVE_SYNC.get(leaf);
      if (!what) continue;

      const fileSystem = /^(?:readFileSync|writeFileSync|appendFileSync|readdirSync|statSync|existsSync)$/.test(leaf);
      if (fileSystem && !servesRequests) continue;

      const sym = enclosingSymbol(mod, call.line);
      const loop = sym ? loopKindAbove(mod, sym, call.line) : UNKNOWN_LOOP;
      if (loop.boundedLiteral) continue;
      const blocking = /Sync$/.test(leaf);

      out.push(ctx.finding({
        ruleId: 'performance.compute.expensive_in_loop',
        title: `${call.callee}() performs ${what} inside ${loop.phrase}`,
        severity: blocking && servesRequests ? 'medium' : 'low',
        confidence: 'moderate',
        status: 'needs_runtime_verification',
        files: [mod.path],
        symbol: call.inSymbol,
        evidence: [map.evidenceLine(mod.path, call.line, `${what} repeated once per iteration`)],
        explanation:
          `${call.callee}() is called inside ${loop.phrase}, so ${what} is repeated for every element. The per-iteration cost of this operation is ` +
          'inherent rather than incidental, so the total scales with the collection size. ' +
          (blocking && servesRequests
            ? 'Because the call is synchronous, it also blocks the event loop for its whole duration, which stalls every other request handled by the same process, not just this one.'
            : 'Whether the collection is large enough for this to matter is not visible statically.'),
        userImpact: blocking && servesRequests
          ? 'While this loop runs, the process cannot serve anything else, so unrelated users see requests stall. The effect grows with the collection and with traffic at the same time.'
          : 'The operation takes longer as the collection grows, which users experience as a request that degrades with data volume rather than failing outright.',
        likelyRootCause: 'The operation was placed where it was needed, inside the loop, without separating the part that does not vary per element.',
        downstreamConsequences: [
          'Work that does not depend on the loop variable is repeated needlessly on every iteration.',
          blocking && servesRequests
            ? 'A blocking call in a request path makes response time depend on what other requests are doing, which makes incidents hard to attribute.'
            : 'Cost grows with both the collection size and the request rate, so load tests with small fixtures will not reveal it.',
        ],
        remediation:
          (blocking && servesRequests
            ? 'Replace the synchronous call with its asynchronous form so the event loop stays free, and '
            : '') +
          'hoist anything that does not depend on the loop variable out of the loop. Where the per-element work is genuinely required, do it in one batched ' +
          'operation (one read of all the files, one subprocess invocation over the whole set, one clone of the shared value) or move the whole job off the ' +
          'request path into a background worker with bounded concurrency.',
        effort: 'small',
        verificationSteps: [
          'Profile this code path with a realistically sized collection and confirm this operation is no longer proportional to the element count — the profile is the measurement that settles whether it was significant.',
          blocking && servesRequests
            ? 'Confirm the event loop is no longer blocked during this operation (an event-loop lag metric or the runtime profiler will show it).'
            : 'Confirm the loop body no longer repeats work that is identical across iterations.',
        ],
        references: [REF.loopResource, REF.excessiveIteration, REF.notMeasured],
      }));
    }
  }
  return out;
}

// ---------------------------------------------------------------- images ---

/**
 * Raw <img> in a framework that ships an image pipeline.
 *
 * Only reported where the framework provides the alternative, because
 * "use the optimised component" is only actionable when there is one.
 */
function unoptimisedImages(ctx: AnalyzerContext): Finding[] {
  const { map } = ctx;
  const out: Finding[] = [];

  const nextJs = map.hasTech('Next.js');
  if (!nextJs) return out;

  for (const mod of map.modules.values()) {
    if (!mod.parsed || mod.jsx.length === 0) continue;
    const usesImageComponent = mod.imports.some((i) => /^next\/(?:image|legacy\/image)$/.test(i.specifier));
    if (usesImageComponent) continue;

    const imgs = mod.jsx.filter((j) => j.tag === 'img');
    if (imgs.length === 0) continue;
    const first = imgs[0]!;
    const sized = first.attrs.some((a) => a.name === 'width') && first.attrs.some((a) => a.name === 'height');
    const lazy = first.attrs.some((a) => a.name === 'loading' && /lazy/.test(a.value ?? ''));
    const srcset = first.attrs.some((a) => a.name === 'srcSet' || a.name === 'sizes');

    out.push(ctx.finding({
      ruleId: 'performance.image.unoptimized',
      title: `Raw <img> used in a Next.js view instead of the framework's image component`,
      severity: 'low',
      confidence: 'moderate',
      status: 'needs_runtime_verification',
      files: [mod.path],
      symbol: first.tag,
      evidence: [
        map.evidenceLine(mod.path, first.line, `plain <img> element${srcset ? '' : ' with no srcSet/sizes, so one file is served to every viewport'}`),
      ],
      explanation:
        `This module renders ${imgs.length} plain <img> element${imgs.length === 1 ? '' : 's'} and does not import next/image, so the framework's image ` +
        'pipeline is bypassed: no resizing per viewport, no modern-format negotiation (AVIF/WebP), and no automatic lazy-loading or caching policy. The ' +
        'browser downloads whatever file the src points at, at whatever dimensions it was authored, however small the rendered box is. ' +
        (srcset ? 'Responsive sources are declared manually here, which covers part of the gap. ' : '') +
        (sized ? 'Explicit width and height are set, which does avoid layout shift. ' : 'No width and height are set, so the surrounding layout shifts once the image loads. ') +
        'The actual file sizes are not read by this scan, so the size of the waste is unknown.',
      userImpact:
        'Users download more image data than their screen can use, which is slowest and most expensive exactly where it matters most — mobile connections ' +
        'and metered data. The page also takes longer to become stable and interactive while the images arrive.',
      likelyRootCause: 'The markup was written as plain HTML, which works, so the framework component was never swapped in.',
      downstreamConsequences: [
        'Image weight tends to grow silently as content is added, because nothing in the pipeline enforces a ceiling.',
        lazy ? 'Lazy-loading is declared, so off-screen images are deferred, but each one is still unoptimised when it loads.' : 'Off-screen images compete with above-the-fold content for bandwidth.',
      ],
      remediation:
        'Use next/image (or the framework\'s equivalent) with explicit width and height, or `fill` with a sized container, so the pipeline generates and ' +
        'caches per-viewport variants in modern formats. Configure the allowed remote patterns narrowly rather than permitting every host. Where a plain ' +
        '<img> must stay — an inline SVG, or an external host that cannot be proxied — declare srcSet and sizes, set width and height, and add ' +
        'loading="lazy" plus decoding="async" for anything below the fold.',
      effort: 'small',
      verificationSteps: [
        'Load the page and record the transferred bytes and the served format for each image before and after the change — that measurement is what confirms the saving.',
        'Confirm the rendered dimensions match the requested variant at mobile, tablet, and desktop widths.',
        'Confirm no layout shift is introduced when the images load.',
      ],
      references: ['web.dev: Optimize images', REF.notMeasured],
    }));
  }
  return out;
}

// -------------------------------------------------------- client payload ---

const HEAVY_PACKAGES = new Map<string, string>([
  ['moment', 'a large date library with built-in locales; the modern alternatives are a fraction of the size'],
  ['lodash', 'a utility bundle whose root entry point is not reliably tree-shaken'],
  ['underscore', 'a utility bundle shipped as one module'],
  ['rxjs', 'a large reactive library when imported as a namespace'],
  ['three', 'a 3D engine'],
  ['chart.js', 'a charting library with all chart types registered'],
  ['highcharts', 'a charting library'],
  ['plotly.js', 'a very large plotting library'],
  ['pdfjs-dist', 'a PDF renderer'],
  ['monaco-editor', 'a full code editor'],
  ['@tensorflow/tfjs', 'a machine-learning runtime'],
  ['fabric', 'a canvas framework'],
  ['jquery', 'a DOM library that duplicates what the framework already does'],
  ['immutable', 'a persistent-collections library'],
  ['exceljs', 'a spreadsheet writer'],
  ['xlsx', 'a spreadsheet parser'],
  ['html2canvas', 'a DOM rasteriser'],
  ['jspdf', 'a PDF writer'],
  ['video.js', 'a video player framework'],
  ['@mui/icons-material', 'an icon barrel with thousands of components'],
  ['aws-sdk', 'the full v2 AWS SDK; the v3 clients are per-service'],
  ['firebase', 'the full Firebase bundle; the modular entry points are per-product'],
]);

/** Packages whose root entry point pulls in the whole library even with named imports. */
const BARREL_PACKAGES = new Set(['lodash', 'underscore', '@mui/icons-material', 'rxjs', 'immutable']);

function isClientModule(map: RepoMap, mod: ParsedModule): boolean {
  const file = map.filesByPath.get(mod.path);
  const head = codeText(file?.text ?? null, mod.language).slice(0, 400);
  if (/^\s*['"]use client['"]/m.test(head)) return true;
  // In a React application without a server-component framework, every component ships to the browser.
  if (map.hasTech('React') && !map.hasTech('Next.js') && (file?.role === 'component' || /\.[jt]sx$/.test(mod.path))) return true;
  return false;
}

function heavyClientDependencies(ctx: AnalyzerContext): Finding[] {
  const { map } = ctx;
  const out: Finding[] = [];

  for (const mod of map.modules.values()) {
    if (!mod.parsed) continue;
    if (!isClientModule(map, mod)) continue;

    for (const imp of mod.imports) {
      if (!imp.external) continue;
      const why = HEAVY_PACKAGES.get(imp.specifier);
      if (!why) continue;
      const wholeModule = imp.names.includes('*') || imp.names.includes('default') || BARREL_PACKAGES.has(imp.specifier);
      if (!wholeModule) continue;

      out.push(ctx.finding({
        ruleId: 'performance.bundle.heavy_client_dependency',
        title: `Client module imports all of '${imp.specifier}'`,
        severity: 'medium',
        confidence: 'moderate',
        status: 'needs_runtime_verification',
        files: [mod.path],
        symbol: imp.specifier,
        evidence: [map.evidenceLine(mod.path, imp.line, `whole-module import of '${imp.specifier}' from code that ships to the browser`)],
        explanation:
          `This module runs in the browser and imports '${imp.specifier}' in a form that pulls the whole library in — ${why}. ` +
          'A whole-module import (default or namespace, or any import from a barrel entry point) defeats tree-shaking, so the bundle carries the entire ' +
          'library whether or not the code uses more than a function or two of it. The actual byte cost depends on the bundler, the version, and what else ' +
          'shares the chunk, none of which this scan measures.',
        userImpact:
          'Every visitor downloads, parses, and compiles this library before the page becomes interactive, on every first visit. The cost falls hardest on ' +
          'mid-range phones and slow connections, where parse and compile time dominates rather than download time.',
        likelyRootCause: 'The import was written in the most convenient form, and the bundle size was not visible at the time.',
        downstreamConsequences: [
          'The library lands in whichever chunk this module belongs to, so it can be pulled into the initial load even if the feature using it is secondary.',
          'Bundle growth of this kind is cumulative and rarely noticed in review, because each individual import looks small.',
        ],
        remediation:
          `Import only what is used (a per-function or per-module entry point such as 'lodash-es/debounce', a modular SDK client, or the single chart type ` +
          'actually registered), or replace the library with a platform capability where one exists (Intl for date and number formatting, fetch for HTTP, ' +
          'the DOM API for selection). Where the library genuinely is needed, load it lazily at the point of use (dynamic import behind the interaction that ' +
          'needs it) so it is not part of the initial payload. Confirm the result with a bundle analysis rather than by inspection.',
        effort: 'small',
        verificationSteps: [
          'Run the bundler\'s analyser before and after the change and compare the size attributed to this package — that measurement is what establishes the saving.',
          'Confirm the feature still works with the narrowed import, including any locale or plugin behaviour the full build provided implicitly.',
          'Confirm the package no longer appears in the initial chunk if it was moved behind a dynamic import.',
        ],
        references: ['web.dev: Reduce JavaScript payloads with code splitting', REF.notMeasured],
      }));
    }
  }
  return out;
}

// ----------------------------------------------------------------- cache ---

/**
 * A read endpoint that repeats database work on every request with no caching
 * layer anywhere in the project.
 *
 * Gated hard on purpose. It only fires for a handler that issues several reads
 * or an unbounded one, only when the project shows no caching primitive at all,
 * and never for a file whose query shape this analyzer has already reported on —
 * a handler that already has an N+1 or a pagination finding does not need a
 * third note saying the same work is uncached.
 */
function absentCacheOnReadPath(ctx: AnalyzerContext, dataCalls: DataCall[], already: Finding[]): Finding[] {
  const { map } = ctx;
  const out: Finding[] = [];

  const projectUsesCaching = [...map.modules.values()].some((m) => {
    if (!m.parsed) return false;
    const file = map.filesByPath.get(m.path);
    return CACHE_PRIMITIVE_RE.test(codeText(file?.text ?? null, m.language));
  });
  if (projectUsesCaching) return out;

  const QUERY_SHAPE_RULES = new Set([
    'performance.query.n_plus_one',
    'performance.query.unbounded',
    'performance.api.missing_pagination',
    'performance.render.unbounded_list',
  ]);
  const reportedFiles = new Set(
    already.filter((f) => QUERY_SHAPE_RULES.has(f.ruleId)).flatMap((f) => f.files),
  );

  for (const r of map.routes) {
    if (r.method !== 'GET') continue;
    if (reportedFiles.has(r.file)) continue;
    const mod = map.modules.get(r.file);
    const sym = handlerSymbolFor(map, r);
    if (!mod?.parsed || !sym) continue;

    const inHandler = callsIn(dataCalls, r.file, sym);
    if (inHandler.some((d) => d.kind === 'db_write')) continue; // not a pure read path
    const reads = inHandler.filter((d) => d.kind === 'db_read');
    const unbounded = reads.filter((d) => d.collection && !d.bounded);
    if (reads.length < 2 && unbounded.length === 0) continue;

    out.push(ctx.finding({
      ruleId: 'performance.cache.absent_on_read_path',
      title: `${r.method} ${r.path} re-reads the database on every request with no caching layer`,
      severity: 'low',
      confidence: 'moderate',
      status: 'needs_runtime_verification',
      files: [r.file],
      symbol: r.handlerSymbol,
      evidence: [
        map.evidenceLine(r.file, r.line ?? sym.startLine, `read-only handler issuing ${reads.length} database read${reads.length === 1 ? '' : 's'} per request`),
        map.evidenceLine(reads[0]!.mod.path, reads[0]!.call.line, `${reads[0]!.call.callee}() runs on every request to this endpoint`),
      ],
      explanation:
        `The handler for ${r.method} ${r.path} only reads data, issues ${reads.length} database read${reads.length === 1 ? '' : 's'} per request, and nothing ` +
        'in the project declares a caching strategy: no cache-control or revalidation directive, no request-scoped or shared cache, no data-fetching library ' +
        'with its own cache. Every call therefore repeats the same work. Whether that work is worth caching depends on how often the endpoint is called and ' +
        'how often the underlying data changes, neither of which this scan can observe.',
      userImpact:
        'Repeat views of this data cost the user the full round trip every time, and the database carries load proportional to traffic rather than to the ' +
        'rate the data actually changes. Under a traffic spike the endpoint degrades for everyone at once.',
      likelyRootCause: 'Caching was left until it was needed, and the default behaviour of the framework is to revalidate on every request.',
      downstreamConsequences: [
        'Load scales with request volume rather than with data change, so headroom has to be bought in database capacity.',
        'Introducing caching later requires deciding on invalidation, which is harder to retrofit than to design in.',
      ],
      remediation:
        'Decide the freshness requirement for this data explicitly, then implement it: a cache-control or revalidation directive for responses that may be ' +
        'briefly stale, a shared cache (or the framework\'s own cache primitive) keyed by the inputs for expensive reads, or a request-scoped cache where the ' +
        'same data is read several times while serving one request. Pair any cache with an invalidation path tied to the writes that change the data, and do ' +
        'not cache per-user data in a shared or public cache.',
      effort: 'medium',
      verificationSteps: [
        'Record the request rate for this endpoint and the change rate of the underlying data — that comparison is what decides whether caching is justified and what freshness window is acceptable.',
        'After adding a cache, confirm the database statement count per request drops for repeat calls and that a write invalidates the cached value.',
        'Confirm no response containing data specific to one user can be served to another.',
      ],
      references: [REF.amplification, REF.notMeasured],
    }));
  }
  return out;
}
