import type { ApiEndpoint, Confidence, DataModel, Evidence, Finding } from '@codelens/core';
import type { RepoMap } from '../graph/repomap.ts';
import type { CallRef, ParsedModule, SymbolInfo } from '../parse/types.ts';
import type { Analyzer, AnalyzerContext } from './types.ts';
import { codeText } from './text.ts';

/**
 * Scalability and concurrency audit.
 *
 * This analyzer produces *structural* findings only. It never states a
 * concurrent-user capacity, a requests-per-second figure, a latency, or any
 * other throughput number, because nothing here runs a load test and a number
 * no one measured is a fabrication (see docs/LIMITATIONS.md). Where sizing or
 * real contention can only be settled by measurement, the finding says so in
 * its verification steps instead of guessing.
 *
 * Confidence discipline, matching the rest of the analyzer suite:
 *   - a pattern match in one file is `moderate`;
 *   - a pattern plus a traced relationship (the shared object reaching a route
 *     through the import graph, the written row resolving to a model in the
 *     schema) is `strong`;
 *   - `confirmed` is not used here. Every claim in this category depends on how
 *     the application is deployed and how often the path is entered
 *     concurrently, and neither of those is visible in a source snapshot.
 *
 * False positives are the main risk in this category, so the rules are
 * deliberately narrow:
 *   - module-level state is reported only when it is *mutated* from a function
 *     that a route can reach. A frozen lookup table, a constant, a logger or a
 *     database client created once per process is correct design and is
 *     ignored.
 *   - a write is counted only when some segment of the callee resolves to a
 *     data model in the repository map, so `client.chat.completions.create()`
 *     is never mistaken for a database write.
 *   - the whole analyzer is skipped when the project has no request-serving
 *     surface.
 *
 * Deliberately not covered, rather than guessed at: queue topology and
 * dead-letter configuration (they live in infrastructure the snapshot does not
 * contain), and failure isolation between services (bulkheads and circuit
 * breakers cannot be distinguished from ordinary error handling by shape
 * alone). The retry and timeout rules below cover the parts of that ground that
 * are visible in source.
 */

const REF = {
  twelveFactorProcesses: 'The Twelve-Factor App — VI. Processes (stateless, share-nothing processes)',
  twelveFactorDisposability: 'The Twelve-Factor App — IX. Disposability',
  cweResource: 'CWE-400 Uncontrolled Resource Consumption',
  cweLimits: 'CWE-770 Allocation of Resources Without Limits or Throttling',
  cweRace: 'CWE-362 Concurrent Execution using Shared Resource with Improper Synchronization',
  cweToctou: 'CWE-367 Time-of-check Time-of-use Race Condition',
  owaspResource: 'OWASP API Security Top 10 — API4:2023 Unrestricted Resource Consumption',
  sreOverload: 'Google SRE Book — Handling Overload',
  sreCascading: 'Google SRE Book — Addressing Cascading Failures',
  idempotentReceiver: 'Enterprise Integration Patterns — Idempotent Receiver',
} as const;

// --------------------------------------------------------------- patterns ---

/** Packages whose pool/client constructors we understand well enough to judge. */
const DB_DRIVER_PACKAGE_RE =
  /^(pg|pg-pool|mysql|mysql2(?:\/promise)?|mariadb|oracledb|mssql|tedious|sequelize|mongodb|@prisma\/client|@planetscale\/database|postgres)$/;

/**
 * Named exports that construct a pool whose size is set in the options object.
 *
 * Prisma's client is deliberately absent: its pool is sized through the
 * `connection_limit` parameter of the connection URL, which lives in
 * configuration this snapshot does not contain, so "no size option at the
 * construction site" would not be evidence of anything.
 */
const POOL_BOUND_CTOR_RE = /^(Pool|createPool|Sequelize|MongoClient|ConnectionPool)$/;

/** Constructors that own a connection or a pool, so one per request is always wrong. */
const PER_REQUEST_CTOR_RE =
  /^(Pool|PrismaClient|MongoClient|Sequelize|ConnectionPool|Client|createPool|createConnection)$/;

/** An explicit bound on a pool, in any of the spellings the drivers use. */
const POOL_BOUND_RE =
  /\b(max|maxConnections|max_connections|connectionLimit|connection_limit|poolSize|pool_size|maxPoolSize|minPoolSize|poolMax|maxSize|max_size)\s*[:=]/;

/** A bound carried in the connection URL instead of the options object. */
const POOL_BOUND_URL_RE = /[?&](connection_limit|pool_max_conns|max_connections|poolSize|pool_size|maxPoolSize)=/;

/** Methods that persist a change. The *root* is validated separately. */
const WRITE_METHOD_RE =
  /\.(create|createMany|createManyAndReturn|update|updateMany|upsert|delete|deleteMany|destroy|save|insert|insertOne|insertMany|updateOne|replaceOne|findOneAndUpdate|findOneAndReplace|findByIdAndUpdate|findByIdAndDelete|bulkCreate|increment|decrement)$/;

/** Methods that read without changing anything. */
const READ_METHOD_RE =
  /\.(findUnique|findUniqueOrThrow|findFirst|findFirstOrThrow|findMany|findOne|findAll|findByPk|findById|find|get|count|aggregate|exists)$/;

/** Roots that unambiguously denote a datastore handle, used when no model matched. */
const STRICT_DB_ROOT_RE = /^(prisma|db|knex|sequelize|pool|trx|tx|em|datasource|dataSource|mongoose)$/;

/** A transaction boundary, in any of the common spellings. */
const TRANSACTION_RE =
  /\$transaction|\.transaction\s*\(|withTransaction|startTransaction|runInTransaction|unitOfWork|\bBEGIN\b|\bCOMMIT\b|SERIALIZABLE/i;

/** An atomic, server-side mutation that needs no read-modify-write. */
const ATOMIC_WRITE_RE = /increment\s*:|decrement\s*:|\$inc\b|\bsql`|=\s*\w+\s*[+-]\s*\d|RETURNING\b/i;

/** An optimistic-lock or compare-and-set predicate. */
const OPTIMISTIC_LOCK_RE = /\b(version|revision|etag|updatedAt|updated_at|lockVersion|rowVersion)\b\s*:/;

/** Evidence that this endpoint receives at-least-once provider deliveries. */
const AT_LEAST_ONCE_PATH_RE = /webhook|callback|\bhooks?\b|\/events?\b|notification/i;
const SIGNATURE_HEADER_RE = /signature|x-hub-signature|svix-id|svix-signature|x-signature|t=\d|hmac/i;

/** Names that mark a store as a dedup ledger rather than business data. */
const LEDGER_NAME_RE = /event|webhook|delivery|idempot|processed|receipt|message/i;

/** Mutating operations on a collection or counter held in a module variable. */
function mutationRe(name: string): RegExp {
  const n = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return new RegExp(
    `\\b${n}\\s*(?:` +
      `\\.(?:set|add|push|unshift|pop|shift|splice|delete|clear|sort|fill|reverse)\\s*\\(` +
      `|\\[[^\\]]{0,80}\\]\\s*=(?!=)` +
      `|\\s*(?:\\+\\+|--|\\+=|-=|\\|\\|=|\\?\\?=)` +
      `|\\s*=(?!=)` +
      `)`,
  );
}

/** Initialisers that create mutable in-process state rather than a constant. */
const MUTABLE_INIT_RE =
  /=\s*(?:new\s+(?:Map|Set|WeakMap|WeakSet|Array|LRUCache)\s*(?:<[^>]*>)?\s*\(|\[\s*\]|\{\s*\}|0\s*(?:;|$)|Object\.create\s*\(\s*null\s*\))/;

/** Local filesystem writes. */
const FS_WRITE_RE =
  /(?:^|\.)(writeFile|writeFileSync|appendFile|appendFileSync|createWriteStream|copyFile|copyFileSync|rename|renameSync|outputFile|writeJson|toFile)$/;

/** Directory names that mean "served to users", i.e. shared storage. */
const SHARED_DIR_RE = /\b(public|uploads?|static|media|avatars?|attachments?|storage|assets|files|documents|images)\b/;

/** Outbound HTTP calls. */
const OUTBOUND_CALL_RE =
  /(?:^|\.)(fetch|request|get|post|put|patch|delete|head|got|axios|send)$/;
const OUTBOUND_ROOT_RE = /^(fetch|axios|got|http|https|request|superagent|ky|undici|client|api|httpClient)$/;

/** A timeout or cancellation on an outbound call. */
const TIMEOUT_RE =
  /\bsignal\s*:|AbortSignal|AbortController|\btimeout\s*:|timeoutMs|requestTimeout|Promise\.race|setTimeout\s*\(\s*\(\s*\)\s*=>\s*controller|deadline/i;

/** AI provider SDKs: their call budgets belong to the AI analyzer, not here. */
const AI_SDK_RE = /^(openai|@anthropic-ai\/sdk|@google\/generative-ai|@google\/genai|cohere-ai|replicate|@mistralai\/mistralai|ai|@ai-sdk\/\w+)$/;

/** Backoff between retries. */
const BACKOFF_RE = /sleep|delay|backoff|jitter|setTimeout|Math\.pow|<<|\*\s*2|wait\s*\(|retryAfter|retry_after/i;

/** A ceiling on the number of retries. */
const RETRY_CAP_RE = /maxRetries|max_retries|maxAttempts|max_attempts|retries\s*[<>]=?\s*\d|attempts?\s*[<>]=?\s*\d|<\s*\d+\s*;|\.\.\.Array\s*\(\s*\d/;

const RETRY_INTENT_RE = /\bretry|retries|retrying|attempt|attempts\b/i;

// ---------------------------------------------------------------- helpers ---

interface HandlerRef {
  route: ApiEndpoint;
  mod: ParsedModule;
  sym: SymbolInfo;
  /** Handler source with comments stripped: comments describing a defect must
   *  not satisfy a guard, and a commented-out call must not look live. */
  body: string;
}

function handlersOf(map: RepoMap): HandlerRef[] {
  const out: HandlerRef[] = [];
  for (const route of map.routes) {
    const mod = map.modules.get(route.file);
    if (!mod?.parsed) continue;
    const named = mod.symbols.find(
      (s) => s.name === route.handlerSymbol && s.endLine > s.startLine,
    );
    const positional = route.line === undefined
      ? undefined
      : mod.symbols.find(
          (s) =>
            s.startLine <= route.line! && s.endLine >= route.line! &&
            (s.kind === 'function' || s.kind === 'arrow' || s.kind === 'method'),
        );
    const sym = named ?? positional;
    if (!sym) continue;
    out.push({ route, mod, sym, body: codeText(sym.text, mod.language) });
  }
  return out;
}

function callsIn(mod: ParsedModule, sym: SymbolInfo): CallRef[] {
  return mod.calls.filter((c) => c.line >= sym.startLine && c.line <= sym.endLine);
}

/** Line ranges of every function-like symbol, used to tell module scope apart. */
function functionRanges(mod: ParsedModule): Array<{ start: number; end: number }> {
  return mod.symbols
    .filter((s) => (s.kind === 'function' || s.kind === 'arrow' || s.kind === 'method' || s.kind === 'class') && s.endLine > s.startLine)
    .map((s) => ({ start: s.startLine, end: s.endLine }));
}

function isModuleScope(ranges: Array<{ start: number; end: number }>, line: number): boolean {
  return !ranges.some((r) => r.start <= line && r.end >= line);
}

function moduleText(map: RepoMap, mod: ParsedModule): string {
  return codeText(map.filesByPath.get(mod.path)?.text ?? '', mod.language);
}

function lineText(map: RepoMap, path: string, line: number): string {
  const text = map.filesByPath.get(path)?.text;
  if (!text) return '';
  return text.split('\n')[line - 1] ?? '';
}

/** A client-side module: its state is per-browser, which is a different subject. */
function isClientModule(map: RepoMap, mod: ParsedModule): boolean {
  const raw = map.filesByPath.get(mod.path)?.text ?? '';
  if (/^\s*(?:["']use client["'])/m.test(raw.slice(0, 400))) return true;
  const file = map.filesByPath.get(mod.path);
  return file?.role === 'component';
}

function isServerCandidate(map: RepoMap, mod: ParsedModule): boolean {
  const file = map.filesByPath.get(mod.path);
  if (!file) return false;
  if (file.role === 'test' || file.role === 'generated' || file.role === 'vendored') return false;
  if (file.generated || file.vendored) return false;
  if (isClientModule(map, mod)) return false;
  return true;
}

/** First verified evidence from the candidates, or undefined if none resolves. */
function firstVerified(...candidates: Evidence[]): Evidence | undefined {
  return candidates.find((e) => e.verified);
}

/** Evidence pointing at a model's declaration, whatever the schema dialect. */
function modelEvidence(map: RepoMap, model: DataModel, note: string): Evidence | undefined {
  return firstVerified(
    map.evidenceAt(model.file, `model ${model.name}`, note),
    map.evidenceAt(model.file, `class ${model.name}`, note),
    map.evidenceAt(model.file, `CREATE TABLE "${model.name}"`, note),
    map.evidenceAt(model.file, `CREATE TABLE ${model.name}`, note),
    map.evidenceAt(model.file, model.name, note),
  );
}

function singular(word: string): string {
  if (/ies$/i.test(word)) return word.slice(0, -3) + 'y';
  if (/(ses|xes|zes|ches|shes)$/i.test(word)) return word.slice(0, -2);
  if (/s$/i.test(word) && !/ss$/i.test(word)) return word.slice(0, -1);
  return word;
}

/**
 * The data model a dotted callee writes to, when one can be resolved.
 *
 * This is the guard that keeps `client.chat.completions.create()` and
 * `queue.add()` out of the write rules: a call only counts as persistence when
 * one of its segments names a model the repository map actually found, or the
 * root is an unambiguous datastore handle.
 */
function modelForCallee(map: RepoMap, callee: string): DataModel | undefined {
  const segments = callee.split('.').slice(0, -1).map((s) => s.replace(/\(\)$/, ''));
  for (const seg of segments) {
    if (!seg) continue;
    const want = singular(seg).toLowerCase();
    const hit = map.models.find((m) => {
      const name = m.name.toLowerCase();
      return name === want || singular(name) === want || name.replace(/_/g, '') === want;
    });
    if (hit) return hit;
  }
  return undefined;
}

interface WriteSite { call: CallRef; model?: DataModel }

function writeSites(map: RepoMap, calls: CallRef[]): WriteSite[] {
  const out: WriteSite[] = [];
  for (const call of calls) {
    if (!WRITE_METHOD_RE.test(call.callee)) continue;
    const model = modelForCallee(map, call.callee);
    const root = call.callee.split('.')[0]!.replace(/\(\)$/, '');
    if (!model && !STRICT_DB_ROOT_RE.test(root)) continue;
    out.push({ call, model });
  }
  return out;
}

function readSites(map: RepoMap, calls: CallRef[]): WriteSite[] {
  const out: WriteSite[] = [];
  for (const call of calls) {
    if (!READ_METHOD_RE.test(call.callee)) continue;
    const model = modelForCallee(map, call.callee);
    const root = call.callee.split('.')[0]!.replace(/\(\)$/, '');
    if (!model && !STRICT_DB_ROOT_RE.test(root)) continue;
    out.push({ call, model });
  }
  return out;
}

/** Walk the import graph upwards to a file that defines a route. */
function reachesRoute(
  map: RepoMap,
  from: string,
  routeFiles: Set<string>,
): { routeFile: string; chain: string[] } | undefined {
  if (routeFiles.has(from)) return { routeFile: from, chain: [from] };
  const seen = new Set<string>([from]);
  let frontier: Array<{ path: string; chain: string[] }> = [{ path: from, chain: [from] }];
  for (let depth = 0; depth < 4 && frontier.length > 0; depth++) {
    const next: Array<{ path: string; chain: string[] }> = [];
    for (const node of frontier) {
      for (const importer of map.importers.get(node.path) ?? []) {
        if (seen.has(importer)) continue;
        seen.add(importer);
        const chain = [...node.chain, importer];
        if (routeFiles.has(importer)) return { routeFile: importer, chain };
        next.push({ path: importer, chain });
      }
    }
    frontier = next;
  }
  return undefined;
}

/** Imported names from a database driver package, filtered by constructor kind. */
function driverImports(mod: ParsedModule, which: RegExp): Array<{ name: string; specifier: string; line: number }> {
  const out: Array<{ name: string; specifier: string; line: number }> = [];
  for (const imp of mod.imports) {
    if (!DB_DRIVER_PACKAGE_RE.test(imp.specifier)) continue;
    for (const name of imp.names) {
      if (which.test(name)) out.push({ name, specifier: imp.specifier, line: imp.line });
    }
  }
  return out;
}

// --------------------------------------------------------------- analyzer ---

export const scalabilityAnalyzer: Analyzer = {
  id: 'scalability',
  category: 'scalability',
  description:
    'Statelessness, connection management, concurrency control, retries, timeouts and resource bounds. Structural risks only — no capacity or throughput figures are produced.',

  precondition(map: RepoMap): string | undefined {
    if (map.routes.length === 0) {
      return 'no HTTP routes were detected, so this project has no request-serving surface whose scaling behaviour could be assessed';
    }
    return undefined;
  },

  run(ctx: AnalyzerContext): Finding[] {
    const findings: Finding[] = [];

    findings.push(...connectionPoolBounds(ctx));
    findings.push(...clientPerRequest(ctx));
    findings.push(...inProcessMutableState(ctx));

    // A handler never produces two scalability findings for the same mechanism:
    // the more structural one wins and the narrower one yields.
    const stateful = localFilesystemStorage(ctx);
    findings.push(...stateful.findings);
    findings.push(...unboundedBodyBuffering(ctx, stateful.handlers));

    const sequences = unatomicWriteSequence(ctx);
    findings.push(...sequences.findings);
    findings.push(...readModifyWrite(ctx, sequences.handlers));

    findings.push(...retryWithoutBackoffOrCap(ctx));
    findings.push(...missingOutboundTimeouts(ctx));
    findings.push(...inProcessBackgroundWork(ctx));

    return findings;
  },
};

// ------------------------------------------------- connection management ---

/**
 * A pool constructed with no explicit bound.
 *
 * The honest claim here is narrow: the ceiling is whatever the driver's default
 * is, that default applies *per process*, and nothing in the source ties it to
 * the database's own connection limit or to how many instances will run. We do
 * not call it "unbounded" (most drivers do have a default) and we do not say
 * what the right number is — that needs the database's configuration and a
 * load test.
 */
function connectionPoolBounds(ctx: AnalyzerContext): Finding[] {
  const { map } = ctx;
  const out: Finding[] = [];
  const routeFiles = new Set(map.routes.map((r) => r.file));

  for (const mod of map.modules.values()) {
    if (!mod.parsed || !isServerCandidate(map, mod)) continue;
    const ctors = driverImports(mod, POOL_BOUND_CTOR_RE);
    if (ctors.length === 0) continue;

    const ranges = functionRanges(mod);

    for (const ctor of ctors) {
      const ctorRe = new RegExp(`(?:new\\s+)?\\b${ctor.name}\\s*\\(`);

      for (const sym of mod.symbols) {
        if (sym.kind !== 'const' && sym.kind !== 'arrow') continue;
        if (!isModuleScope(ranges, sym.startLine)) continue;
        const body = codeText(sym.text, mod.language);
        if (!ctorRe.test(body)) continue;
        if (POOL_BOUND_RE.test(body) || POOL_BOUND_URL_RE.test(body)) continue;

        // The bound may be set on a config object defined elsewhere in the file,
        // or carried in the connection string literal. Check both before reporting.
        const whole = moduleText(map, mod);
        if (POOL_BOUND_URL_RE.test(whole)) continue;
        const configuredNearby = new RegExp(`${POOL_BOUND_RE.source}`).test(whole) &&
          /pool\s*[:=]/.test(whole);
        if (configuredNearby) continue;

        const evidence = firstVerified(
          map.evidenceLine(mod.path, sym.startLine, `${ctor.name} from '${ctor.specifier}' is constructed here with no size option`),
        );
        if (!evidence) continue;

        // Who shares this pool: the bindings other modules import from here,
        // either the pool itself or a function in this module that uses it.
        const usingFunctions = mod.symbols
          .filter((s) => (s.kind === 'function' || s.kind === 'arrow') && s.name !== sym.name)
          .filter((s) => new RegExp(`\\b${sym.name}\\b`).test(codeText(s.text, mod.language)))
          .map((s) => s.name);
        const sharedNames = new Set<string>([sym.name, ...usingFunctions]);

        const consumers: Array<{ file: string; line?: number; names: string[] }> = [];
        for (const importerPath of map.importers.get(mod.path) ?? []) {
          const importer = map.modules.get(importerPath);
          const ref = importer?.imports.find((i) => i.resolvedPath === mod.path);
          if (!ref) continue;
          const shared = ref.names.filter((n) => sharedNames.has(n));
          if (shared.length === 0) continue;
          consumers.push({ file: importerPath, line: ref.line, names: shared });
        }

        const firstQuery = mod.calls.find((c) => c.callee.startsWith(`${sym.name}.`));
        // Reachability is asserted only for a module that actually shares this
        // pool, never for an unrelated importer of the same file.
        const reach = consumers
          .map((c) => reachesRoute(map, c.file, routeFiles))
          .find((r) => r !== undefined);
        const traced = consumers.length > 0;
        const confidence: Confidence = traced ? 'strong' : 'moderate';

        const extraEvidence: Evidence[] = [];
        if (firstQuery) {
          const e = firstVerified(map.evidenceLine(mod.path, firstQuery.line, 'every query taken out of this pool shares that one ceiling'));
          if (e) extraEvidence.push(e);
        }
        for (const consumer of consumers.slice(0, 3)) {
          const e = firstVerified(
            map.evidenceLine(consumer.file, consumer.line ?? 1, `imports ${consumer.names.join(', ')}, so requests served by this module queue on the same pool`),
          );
          if (e) extraEvidence.push(e);
        }

        out.push(ctx.finding({
          ruleId: 'scalability.db.pool_without_explicit_bound',
          title: `Database connection pool is created with no explicit size bound (${mod.path})`,
          severity: 'medium',
          confidence,
          detectionSource: traced ? 'graph' : 'static',
          files: [mod.path, ...consumers.slice(0, 3).map((c) => c.file)],
          symbol: sym.name,
          evidence: [evidence, ...extraEvidence],
          trace: traced
            ? {
                kind: 'import',
                steps: [
                  { file: mod.path, line: sym.startLine, symbol: sym.name, detail: `${ctor.name} constructed once at module scope with no size option` },
                  ...(firstQuery ? [{ file: mod.path, line: firstQuery.line, detail: `${firstQuery.callee}() draws a connection from that pool` }] : []),
                  ...consumers.slice(0, 3).map((c) => ({
                    file: c.file,
                    line: c.line,
                    detail: `imports ${c.names.join(', ')} from the pool module, so this request path shares the pool`,
                  })),
                  ...(reach
                    ? [{ file: reach.routeFile, detail: 'that consumer is reachable from an HTTP route, so the one pool is shared across concurrent requests' }]
                    : []),
                ],
                complete: true,
              }
            : undefined,
          explanation:
            `The pool is constructed once per process at ${mod.path}:${sym.startLine} and no size option ` +
            '(`max`, `connectionLimit`, `poolSize`, `connection_limit` or the driver\'s equivalent) is set, so the number of connections this process will ' +
            'hold is whatever the driver defaults to. Two things follow. First, the limit is implicit: nobody reading this code can see ' +
            'what it is, and it changes if the driver is upgraded. Second, it is a per-process limit, while the constraint that actually ' +
            'matters is the database server\'s own maximum connection count, shared by every instance of this application plus migrations ' +
            'and any admin tooling. Nothing in the source connects the two numbers, so adding instances to absorb load silently multiplies ' +
            'the demand on the database. No concurrency figure is stated here deliberately: the point at which this becomes material depends on the ' +
            'database configuration and the real request mix, and neither is visible in a source snapshot.',
          userImpact:
            'Once every connection in the pool is busy, further requests do not fail — they wait for one to be released. Users see pages ' +
            'that touch the database get slower and then time out, while health checks that do not touch the database keep reporting the ' +
            'application as healthy. If instances are added, the database can begin refusing connections outright, which appears to users ' +
            'as errors scattered across unrelated parts of the application at the same time.',
          likelyRootCause:
            'The pool was created with the minimum options needed to connect during development, where one process and a handful of concurrent requests never reach the default ceiling.',
          downstreamConsequences: [
            'A saturated pool with no acquisition timeout turns a slow query into a queue that every request joins, which is how one slow endpoint takes down unrelated ones.',
            'Serverless or autoscaled deployments create a new pool per instance, so the total connection demand tracks instance count rather than anything configured here.',
            'Because the limit is implicit, a driver upgrade can change the application\'s capacity profile with no code change.',
          ],
          remediation:
            'Set the pool size explicitly where the pool is constructed, and derive the value rather than picking it: divide the database\'s ' +
            'configured maximum connections by the maximum number of application instances you will run (including the overlap during a ' +
            'rolling deploy), and leave headroom for migrations and administrative sessions. Set an acquisition timeout as well ' +
            '(`connectionTimeoutMillis` or the driver\'s equivalent) so a saturated pool fails fast with a clear error instead of queueing ' +
            'indefinitely, and an idle timeout so idle instances release connections. Where the instance count is elastic, put an external ' +
            'pooler in front of the database so the application\'s pool size no longer has to be coordinated by hand. Record the chosen ' +
            'numbers and their derivation next to the construction site.',
          effort: 'small',
          verificationSteps: [
            'Read the database\'s configured connection maximum (on PostgreSQL, `SHOW max_connections`) and the per-user limit, then write down pool size × maximum instance count including deploy overlap and confirm the total fits with headroom.',
            'Set the bound explicitly, then run a load test at the concurrency you intend to support and watch connection-acquisition wait time: this is the only way to size the pool, and it cannot be derived from the source.',
            'With the pool deliberately saturated, confirm that a request fails with a clear acquisition timeout rather than hanging, and that the readiness probe reflects it.',
            'Confirm the number of established connections per instance against the database\'s own connection view (for example `pg_stat_activity`) during that load test.',
          ],
          references: [REF.twelveFactorProcesses, REF.sreOverload, REF.cweLimits],
        }));
      }
    }
  }
  return out;
}

/** A pool or client constructed inside a request handler. */
function clientPerRequest(ctx: AnalyzerContext): Finding[] {
  const { map } = ctx;
  const out: Finding[] = [];

  for (const h of handlersOf(map)) {
    const ctors = driverImports(h.mod, PER_REQUEST_CTOR_RE);
    if (ctors.length === 0) continue;
    const ctor = ctors.find((c) => new RegExp(`(?:new\\s+)?\\b${c.name}\\s*\\(`).test(h.body));
    if (!ctor) continue;
    const ctorName = ctor.name;

    const offset = h.body.split('\n').findIndex((l) => new RegExp(`\\b${ctorName}\\s*\\(`).test(l));
    const line = h.sym.startLine + Math.max(offset, 0);
    const evidence = firstVerified(
      map.evidenceLine(h.mod.path, line, `${ctorName} is constructed inside the request handler, so once per request`),
      map.evidenceLine(h.mod.path, h.sym.startLine, 'request handler that constructs its own database client'),
    );
    if (!evidence) continue;

    out.push(ctx.finding({
      ruleId: 'scalability.db.client_constructed_per_request',
      title: `${h.route.method} ${h.route.path} constructs a database client per request`,
      severity: 'high',
      confidence: 'strong',
      files: [h.mod.path],
      symbol: h.sym.name,
      evidence: [evidence],
      explanation:
        `The handler creates ${ctorName} inside its own body, so a new connection (or a new pool) is established on every request and ` +
        'discarded when the handler returns. Connection establishment is one of the most expensive operations in a request path — TCP ' +
        'handshake, TLS negotiation, authentication and session setup — and it is being paid per request rather than once per process. ' +
        'Worse, each new pool brings its own ceiling, so the total number of connections the application opens is governed by concurrent ' +
        'request count rather than by anything configured.',
      userImpact:
        'Every request carries the full cost of opening a database connection, so the application feels slow even when the queries ' +
        'themselves are fast. Under concurrent load the database starts refusing new connections, and users see errors on endpoints that ' +
        'were working a moment earlier.',
      likelyRootCause:
        'The client was created where it was first needed. In development, where requests arrive one at a time, this is indistinguishable from correct code.',
      downstreamConsequences: [
        'Connections may not be closed on every path through the handler, which leaks them until the database refuses more.',
        'Prepared-statement and query-plan caches, which are per connection, never warm up.',
      ],
      remediation:
        'Construct the client or pool once per process in a module that is imported by the handlers, and export the instance. In a ' +
        'development setup that hot-reloads modules, cache the instance on a global so reloads reuse it instead of accumulating pools. ' +
        'Keep the explicit pool bound and acquisition timeout on that single instance.',
      effort: 'small',
      verificationSteps: [
        'Count established connections at the database while issuing concurrent requests to this endpoint, and confirm the count stops tracking request concurrency after the change.',
        'Confirm the shared instance is reused across requests (log the instance identity once at construction and confirm it is logged once per process, not once per request).',
        'Confirm hot reloading in development does not accumulate pools.',
      ],
      references: [REF.twelveFactorProcesses, REF.cweResource],
    }));
  }
  return out;
}

// ----------------------------------------------------------- statelessness ---

/**
 * Module-level mutable state mutated at request time.
 *
 * The guard that makes this reportable rather than noisy: the variable must be
 * initialised to something mutable (a Map, Set, array, object or counter), it
 * must be *written* from inside a function body, and that function must sit in
 * a module a route can reach. A frozen table, a constant, a logger and a client
 * singleton all fail those tests and are left alone.
 */
function inProcessMutableState(ctx: AnalyzerContext): Finding[] {
  const { map } = ctx;
  const out: Finding[] = [];
  const routeFiles = new Set(map.routes.map((r) => r.file));

  for (const mod of map.modules.values()) {
    if (!mod.parsed || !isServerCandidate(map, mod)) continue;

    const reach = reachesRoute(map, mod.path, routeFiles);
    if (!reach) continue;

    const ranges = functionRanges(mod);
    const whole = moduleText(map, mod);

    interface Held { name: string; declLine: number; mutator: string; mutationLine: number; purpose: string }
    const held: Held[] = [];

    for (const sym of mod.symbols) {
      if (sym.kind !== 'const' && sym.kind !== 'arrow') continue;
      if (!isModuleScope(ranges, sym.startLine)) continue;
      const decl = codeText(sym.text, mod.language);
      if (!MUTABLE_INIT_RE.test(decl)) continue;
      if (/as const|Object\.freeze/.test(decl)) continue;
      if (new RegExp(`Object\\.freeze\\s*\\(\\s*${sym.name}\\b`).test(whole)) continue;

      // The write must happen inside a function, i.e. at request time. A table
      // populated once at module load and only read afterwards is not a fault.
      const re = mutationRe(sym.name);
      const mutators = mod.symbols
        .filter((s) => (s.kind === 'function' || s.kind === 'arrow' || s.kind === 'method') && s.endLine > s.startLine)
        .filter((s) => s.startLine !== sym.startLine)
        .filter((s) => re.test(codeText(s.text, mod.language)));
      if (mutators.length === 0) continue;

      const mutator = mutators[0]!;
      const offset = codeText(mutator.text, mod.language).split('\n').findIndex((l) => re.test(l));
      held.push({
        name: sym.name,
        declLine: sym.startLine,
        mutator: mutator.name,
        mutationLine: mutator.startLine + Math.max(offset, 0),
        purpose: /limit|throttle|attempt|quota|bucket|rate/i.test(sym.name)
          ? 'rate_limit'
          : /session|token|auth|login/i.test(sym.name)
            ? 'session'
            : /cache|memo|store|lookup|index/i.test(sym.name)
              ? 'cache'
              : 'general',
      });
    }

    if (held.length === 0) continue;

    // One finding per module: the defect is that this module keeps request
    // state in process memory, not that it does so in several variables.
    const dominant =
      held.find((h) => h.purpose === 'rate_limit') ??
      held.find((h) => h.purpose === 'session') ??
      held.find((h) => h.purpose === 'cache') ??
      held[0]!;

    const evidence: Evidence[] = [];
    for (const h of held.slice(0, 4)) {
      const decl = firstVerified(map.evidenceLine(mod.path, h.declLine, `'${h.name}' holds mutable state in a module-level variable, so it exists in one process only`));
      if (decl) evidence.push(decl);
      const write = firstVerified(map.evidenceLine(mod.path, h.mutationLine, `${h.mutator}() writes to '${h.name}' at request time`));
      if (write) evidence.push(write);
    }
    if (evidence.length === 0) continue;

    const purposeText =
      dominant.purpose === 'rate_limit'
        ? `The name and usage of '${dominant.name}' suggest a rate limiter. A rate limiter in process memory counts only the requests that ` +
          'happened to land on this instance, so the effective allowance is the configured allowance multiplied by the number of instances, ' +
          'and it resets to nothing on every deploy.'
        : dominant.purpose === 'session'
          ? `The name and usage of '${dominant.name}' suggest session or authentication state. Session state in process memory means a user ` +
            'is only recognised by the instance that served their previous request, and is signed out by any deploy or restart.'
          : dominant.purpose === 'cache'
            ? `The name and usage of '${dominant.name}' suggest a cache. A per-process cache is not wrong in itself, but it gives each ` +
              'instance a different view of the data, so an invalidation applied on one instance leaves the others serving stale values with ' +
              'no way to clear them.'
            : 'Whatever this state holds, each instance holds a different copy of it.';

    const traced = reach.routeFile !== mod.path;
    const names = held.map((h) => `'${h.name}'`).join(', ');

    out.push(ctx.finding({
      ruleId: 'scalability.state.in_process_mutable_state',
      title: held.length === 1
        ? `Request-time state is held in process memory: ${names} in ${mod.path}`
        : `Request-time state is held in process memory: ${held.length} variables in ${mod.path}`,
      severity: dominant.purpose === 'rate_limit' || dominant.purpose === 'session' ? 'high' : 'medium',
      confidence: traced ? 'strong' : 'moderate',
      detectionSource: traced ? 'graph' : 'static',
      files: traced ? [mod.path, reach.routeFile] : [mod.path],
      symbol: dominant.name,
      evidence,
      trace: traced
        ? {
            kind: 'import',
            steps: [
              { file: mod.path, line: dominant.declLine, symbol: dominant.name, detail: `${names} declared as mutable state at module scope` },
              { file: mod.path, line: dominant.mutationLine, symbol: dominant.mutator, detail: 'written during request handling' },
              ...reach.chain.slice(1).map((p) => ({ file: p, detail: 'imports the module holding that state' })),
              { file: reach.routeFile, detail: 'defines an HTTP route, so the state is reached by concurrent requests' },
            ],
            complete: true,
          }
        : undefined,
      explanation:
        `${names} ${held.length === 1 ? 'is declared' : 'are declared'} at module scope in ${mod.path} and written during request handling ` +
        `(for example by ${dominant.mutator}()). That makes the process stateful: the value exists only in the memory of whichever instance ` +
        'happened to execute the write. It is not shared with other instances, and it is lost on restart, redeploy, crash, or a scale-to-zero ' +
        'on a serverless platform. ' + purposeText +
        ' A second concern applies regardless of purpose: no eviction and no size ceiling is visible, so whatever is inserted stays for the ' +
        'lifetime of the process.',
      userImpact:
        dominant.purpose === 'rate_limit'
          ? 'The protection users are relying on is weaker than it looks: an attacker spreading requests across instances gets a multiple of ' +
            'the intended allowance, and a deploy clears the counters entirely.'
          : dominant.purpose === 'session'
            ? 'Users are signed out or lose their place whenever a request is routed to a different instance or a deploy happens, which reads ' +
              'as random, unreproducible logouts.'
            : 'Behaviour depends on which instance serves the request: the same action can succeed on one instance and fail or return stale ' +
              'data on another, and the inconsistency disappears when retried, which makes it nearly impossible for users to report.',
      likelyRootCause:
        'The simplest thing that works on one process was used, and a single development instance never exposes the difference.',
      downstreamConsequences: [
        'Horizontal scaling changes behaviour rather than just capacity, so the first scale-out is the first time this is noticed.',
        'Memory grows for the lifetime of the process when entries are inserted and never evicted, until the platform restarts it.',
        'Local reproduction almost always succeeds, because one process is internally consistent.',
      ],
      remediation:
        'Move this state out of the process into a store every instance shares — Redis, the database, or the platform\'s own key-value store ' +
        '— and key it by whatever identity the logic needs. ' +
        (dominant.purpose === 'rate_limit'
          ? 'For a rate limiter, use an atomic counter with an expiry in that shared store (an INCR with a TTL, or a token bucket evaluated server-side) so the limit holds across instances.'
          : dominant.purpose === 'session'
            ? 'For session state, use a signed cookie or a shared session store so any instance can serve any request.'
            : 'If a per-process cache is genuinely wanted, keep it but bound it: set a maximum size and a time-to-live, and make correctness independent of whether an entry is present.') +
        ' Where the state must stay in process for now, record that the application cannot run more than one instance, and enforce that in the ' +
        'deployment configuration rather than leaving it implied.',
      effort: 'medium',
      verificationSteps: [
        'Run two instances behind the load balancer and exercise the path repeatedly; confirm the behaviour no longer depends on which instance answers.',
        'Restart one instance mid-test and confirm nothing a user depends on was lost.',
        dominant.purpose === 'rate_limit'
          ? 'Confirm the limit still holds when requests are spread across both instances, and that it survives a restart.'
          : 'Confirm the state survives a redeploy of the application.',
        'Add a test that fails if this module regains module-level mutable state.',
      ],
      references: [REF.twelveFactorProcesses, REF.twelveFactorDisposability, REF.cweLimits],
    }));
  }
  return out;
}

/**
 * A request handler writing to the instance's own filesystem and then serving
 * that path back. The "serves it back" half is what distinguishes shared
 * storage from a temporary scratch file, so it is required.
 */
function localFilesystemStorage(ctx: AnalyzerContext): { findings: Finding[]; handlers: Set<string> } {
  const { map } = ctx;
  const out: Finding[] = [];
  const handlers = new Set<string>();

  for (const h of handlersOf(map)) {
    for (const call of callsIn(h.mod, h.sym)) {
      if (!FS_WRITE_RE.test(call.callee)) continue;
      const dest = call.args[0] ?? '';
      if (!dest) continue;
      // A temporary file used for processing is a different subject.
      if (/tmpdir|os\.tmp|["'`]\/(?:tmp|var\/tmp)\b|tempy|mkdtemp/i.test(dest)) continue;

      const local = /^[`'"]\s*\.{0,2}\//.test(dest) || /__dirname|process\.cwd\(\)|path\.join\(/.test(dest) || /^[`'"][\w.-]+\//.test(dest);
      if (!local) continue;

      // The directory must be one the application serves back, which is what
      // distinguishes storage from a scratch file written and discarded.
      const withoutDest = h.body.replace(dest, '');
      const sharedDir = dest
        .replace(/^[`'"]|[`'"]$/g, '')
        .split('/')
        .filter((s) => s && !s.includes('${') && !s.startsWith('.'))
        .filter((d) => SHARED_DIR_RE.test(d))
        .find((d) => new RegExp(`['"\`/]${d}\\b`).test(withoutDest));
      if (!sharedDir) continue;

      const evidence = [
        firstVerified(map.evidenceLine(h.mod.path, call.line, `written to a path inside the running instance's own filesystem ('${sharedDir}')`)),
      ].filter((e): e is Evidence => e !== undefined);
      if (evidence.length === 0) continue;

      const returnOffset = h.body.split('\n').findIndex((l, i) => i > (call.line - h.sym.startLine) && new RegExp(`['"\`/]${sharedDir}\\b`).test(l));
      if (returnOffset >= 0) {
        const e = firstVerified(map.evidenceLine(h.mod.path, h.sym.startLine + returnOffset, 'the same path is handed back to the client as the location of the stored file'));
        if (e) evidence.push(e);
      }

      const containerFile = map.files.find((f) =>
        /(^|\/)Dockerfile$/.test(f.path) || /(^|\/)docker-compose\.ya?ml$/.test(f.path) || /(^|\/)(fly|railway|render)\.(toml|ya?ml)$/.test(f.path));
      let containerEvidence: Evidence | undefined;
      if (containerFile) {
        containerEvidence = firstVerified(
          map.evidenceAt(containerFile.path, 'FROM', 'the deployment unit is an image whose filesystem is recreated on each deploy, so files written at request time do not survive it'),
          map.evidenceLine(containerFile.path, 1, 'the deployment unit is an image whose filesystem is recreated on each deploy'),
        );
        if (containerEvidence) evidence.push(containerEvidence);
      }

      out.push(ctx.finding({
        ruleId: 'scalability.state.local_filesystem_as_storage',
        title: `${h.route.method} ${h.route.path} stores uploaded files on the instance's local filesystem`,
        severity: 'medium',
        confidence: containerEvidence ? 'strong' : 'moderate',
        detectionSource: containerEvidence ? 'graph' : 'static',
        files: containerFile && containerEvidence ? [h.mod.path, containerFile.path] : [h.mod.path],
        symbol: h.sym.name,
        evidence,
        trace: containerEvidence && containerFile
          ? {
              kind: 'call',
              steps: [
                { file: h.mod.path, line: call.line, symbol: h.sym.name, detail: `${call.callee}() writes the uploaded file under '${sharedDir}' on the local filesystem` },
                { file: h.mod.path, line: h.sym.startLine, symbol: h.sym.name, detail: 'the handler returns that same path to the client, so the file is expected to be readable later' },
                { file: containerFile.path, detail: 'the application is packaged as a container image, so that filesystem is per instance and is recreated on deploy' },
              ],
              complete: true,
            }
          : undefined,
        explanation:
          `The handler writes the uploaded file into the local '${sharedDir}' directory of the process that served the request, and returns a ` +
          'path under that directory as the file\'s location. That makes the write instance-local while the read is expected to work from ' +
          'anywhere. With a single long-lived instance and a persistent disk this behaves correctly, which is why it survives development. ' +
          'With more than one instance, a file written by one instance is simply absent from the others, and the request that reads it back ' +
          'fails depending on where it lands. Where the deployment unit is an image or a serverless function, the filesystem is recreated ' +
          'on every deploy and may be read-only or ephemeral, so the file can disappear without any scaling at all. A second effect belongs ' +
          'to the same write: the upload is materialised fully in memory before it is written, so concurrent uploads consume memory in ' +
          'proportion to their combined size with no ceiling in the code.',
        userImpact:
          'Uploaded files are intermittently missing. A user uploads a file, sees it succeed, and then gets a broken image or a 404 when the ' +
          'page that displays it is served by a different instance — or after the next deploy. The failure is not reproducible on demand, ' +
          'which usually means it is reported as "sometimes my images disappear" and never diagnosed.',
        likelyRootCause:
          'Writing to the local filesystem is the shortest path to a working upload endpoint, and it keeps working until there is a second instance or a redeploy.',
        downstreamConsequences: [
          'Backups of the database do not contain these files, so a restore produces records pointing at files that no longer exist.',
          'Serving user-uploaded files from the application\'s own static directory also puts them inside the application\'s origin, which has security consequences beyond scaling.',
          'Horizontal scaling becomes a data-loss event rather than a capacity change.',
        ],
        remediation:
          'Write the file to a storage service every instance shares — object storage (S3, GCS, R2, Azure Blob) or a mounted network volume ' +
          '— and persist only the resulting key in the database. Prefer streaming the request body straight to that store, or issuing the ' +
          'client a pre-signed upload URL so the file never passes through the application process at all; either removes the in-memory ' +
          'buffering as well. Serve the file back through the store\'s own URL or a signed redirect rather than from the application\'s ' +
          'static directory. If local storage must be kept for now, attach a persistent volume, pin the deployment to a single instance, and ' +
          'state that constraint in the deployment configuration.',
        effort: 'medium',
        verificationSteps: [
          'Run two instances, upload through one and immediately fetch the returned path repeatedly; confirm every fetch succeeds (before the change, some will not).',
          'Redeploy the application and confirm a file uploaded before the deploy is still retrievable.',
          'Upload a large file and watch the process\'s memory while doing so, to confirm the body is streamed rather than buffered.',
          'Confirm the stored object is covered by the same backup and retention policy as the database rows that reference it.',
        ],
        references: [REF.twelveFactorProcesses, REF.twelveFactorDisposability, REF.cweResource],
      }));
      handlers.add(`${h.mod.path}#${h.sym.name}`);
      break; // one finding per handler
    }
  }
  return { findings: out, handlers };
}

/**
 * A handler that reads an entire request body or upload into memory with no
 * size check. Suppressed when a statelessness finding already covers the same
 * handler, so one handler never produces two scalability findings.
 */
function unboundedBodyBuffering(ctx: AnalyzerContext, alreadyReported: Set<string>): Finding[] {
  const { map } = ctx;
  const out: Finding[] = [];

  const SIZE_GUARD_RE = /\.size\s*[<>]|maxSize|MAX_(?:SIZE|BYTES|UPLOAD|FILE)|sizeLimit|bodyLimit|limit\s*:\s*['"`]?\d|content-length|contentLength|byteLength\s*[<>]/i;

  for (const h of handlersOf(map)) {
    if (alreadyReported.has(`${h.mod.path}#${h.sym.name}`)) continue;
    if (SIZE_GUARD_RE.test(h.body)) continue;

    const buffering = callsIn(h.mod, h.sym).find((c) =>
      /(?:^|\.)(arrayBuffer|formData|blob)$/.test(c.callee) ||
      /^Buffer\.(from|concat)$/.test(c.callee) ||
      /(?:^|\.)(?:readAll|consume|buffer)$/.test(c.callee));
    if (!buffering) continue;
    // Only meaningful where a body is actually accepted.
    if (!['POST', 'PUT', 'PATCH'].includes(h.route.method)) continue;

    const evidence = firstVerified(
      map.evidenceLine(h.mod.path, buffering.line, 'the whole request payload is materialised in memory before anything checks its size'),
    );
    if (!evidence) continue;

    out.push(ctx.finding({
      ruleId: 'scalability.resource.unbounded_body_buffering',
      title: `${h.route.method} ${h.route.path} buffers the whole request body in memory with no size limit`,
      severity: 'medium',
      confidence: 'moderate',
      files: [h.mod.path],
      symbol: h.sym.name,
      evidence: [evidence],
      explanation:
        `The handler calls ${buffering.callee}() to materialise the entire payload before any size check runs, and no limit on the body or ` +
        'upload size appears anywhere in the handler. Memory consumption therefore scales with the product of payload size and concurrent ' +
        'requests, both of which are chosen by the caller rather than by the application. Whether the process actually runs out of memory ' +
        'depends on the instance\'s memory limit and on real traffic, neither of which can be read from source — this is reported as a ' +
        'missing bound, not as a measured failure.',
      userImpact:
        'A few large concurrent uploads can push the process to its memory limit, at which point the platform kills and restarts it. Every ' +
        'request in flight on that instance fails at once, so users who were doing something unrelated see errors.',
      likelyRootCause: 'Reading the body in one call is the simplest form of the code, and development payloads are small.',
      downstreamConsequences: [
        'An out-of-memory restart drops all in-flight requests, not only the oversized one, so one caller can disrupt everyone on that instance.',
        'Retries of a failed large upload amplify the load that caused the failure.',
      ],
      remediation:
        'Reject oversized payloads before reading them: check the declared content length and enforce a maximum at the framework or proxy ' +
        'layer, and return 413 rather than reading on. Stream the body to its destination instead of buffering it, so memory use is bounded ' +
        'by the chunk size rather than the payload size. Where the payload is a file, prefer a pre-signed direct-to-storage upload so the ' +
        'application never holds it.',
      effort: 'small',
      verificationSteps: [
        'Send a payload larger than the intended maximum and confirm the response is 413 and that the process\'s memory does not rise with the payload size.',
        'Send several large payloads concurrently and confirm the process stays within its memory limit.',
        'Confirm the limit is enforced at the proxy or framework layer as well, so it holds for handlers added later.',
      ],
      references: [REF.owaspResource, REF.cweLimits, REF.cweResource],
    }));
  }
  return out;
}

// ------------------------------------------------------ concurrency control ---

/**
 * Several persisted writes in one handler with no transaction around them.
 *
 * Reported when the endpoint receives at-least-once deliveries (so concurrent
 * duplicates are expected rather than hypothetical) or when two writes touch
 * the same model. Framed as concurrency and duplicate delivery, which is a
 * different question from whether the handler is idempotent in the single-
 * delivery sense.
 */
function unatomicWriteSequence(ctx: AnalyzerContext): { findings: Finding[]; handlers: Set<string> } {
  const { map } = ctx;
  const out: Finding[] = [];
  const handlers = new Set<string>();

  for (const h of handlersOf(map)) {
    const calls = callsIn(h.mod, h.sym);
    const writes = writeSites(map, calls);
    if (writes.length < 2) continue;
    if (TRANSACTION_RE.test(h.body)) continue;

    const atLeastOnce =
      AT_LEAST_ONCE_PATH_RE.test(h.route.path) ||
      SIGNATURE_HEADER_RE.test(h.body) ||
      h.mod.imports.some((i) => /stripe|svix|@octokit\/webhooks|twilio|shopify/i.test(i.specifier));

    const sameModel = writes.some((a, i) =>
      writes.slice(i + 1).some((b) => a.model && b.model && a.model.name === b.model.name));

    if (!atLeastOnce && !sameModel) continue;

    const first = writes[0]!;
    const rest = writes.slice(1);

    // Is there a ledger write, and can it actually reject a replay?
    const ledger = writes.find((w) => w.model && LEDGER_NAME_RE.test(w.model.name));
    const ledgerUnique = ledger?.model?.fields.some((f) => f.unique && !/^id$/i.test(f.name)) ?? false;
    const ledgerAfterMutation = ledger !== undefined && ledger.call.line > first.call.line;

    const guardBefore = readSites(map, calls).some(
      (r) => r.call.line < first.call.line && r.model !== undefined && LEDGER_NAME_RE.test(r.model.name),
    ) || /upsert|onConflict|skipDuplicates|ON\s+CONFLICT|INSERT\s+IGNORE/i.test(
      h.body.split('\n').slice(0, Math.max(first.call.line - h.sym.startLine, 1)).join('\n'),
    );

    const evidence = [
      firstVerified(map.evidenceLine(h.mod.path, first.call.line, `first persisted write (${first.call.callee}), applied before anything establishes that this delivery is new`)),
      ...rest.slice(0, 2).map((w) => firstVerified(map.evidenceLine(h.mod.path, w.call.line, `a further write (${w.call.callee}) in the same handler, outside any transaction`))),
    ].filter((e): e is Evidence => e !== undefined);
    if (evidence.length === 0) continue;

    if (first.model) {
      const me = modelEvidence(map, first.model, `the row being changed lives here; nothing in the handler constrains the change to a single application of it`);
      if (me) evidence.push(me);
    }
    if (ledger?.model && !ledgerUnique) {
      const le = modelEvidence(map, ledger.model, `this store is written as a record of the delivery, but no field other than the primary key is unique, so it cannot reject a replay`);
      if (le) evidence.push(le);
    }

    const models = [...new Set(writes.map((w) => w.model?.name).filter((n): n is string => n !== undefined))];
    const traced = models.length > 0;

    out.push(ctx.finding({
      ruleId: 'scalability.concurrency.unatomic_write_sequence',
      title: atLeastOnce
        ? `${h.route.method} ${h.route.path} applies several writes with no transaction on an at-least-once delivery path`
        : `${h.route.method} ${h.route.path} applies several writes to ${models[0] ?? 'the same record'} with no transaction`,
      severity: 'medium',
      confidence: traced ? 'strong' : 'moderate',
      detectionSource: traced ? 'graph' : 'static',
      files: traced ? [h.mod.path, ...new Set(writes.map((w) => w.model?.file).filter((f): f is string => f !== undefined))] : [h.mod.path],
      symbol: h.sym.name,
      evidence,
      trace: traced
        ? {
            kind: atLeastOnce ? 'webhook_idempotency' : 'call',
            steps: [
              {
                file: h.mod.path,
                line: h.route.line ?? h.sym.startLine,
                symbol: h.sym.name,
                detail: atLeastOnce
                  ? 'endpoint receives provider deliveries, which are at-least-once by design, so two invocations for one event must be assumed'
                  : 'endpoint may be entered concurrently for the same record',
              },
              ...writes.slice(0, 3).map((w) => ({
                file: h.mod.path,
                line: w.call.line,
                symbol: h.sym.name,
                detail: `${w.call.callee}() writes ${w.model?.name ?? 'persisted state'}`,
              })),
              ...(first.model ? [{ file: first.model.file, detail: `${first.model.name} is the model being changed` }] : []),
              ...(ledger?.model
                ? [{
                    file: ledger.model.file,
                    detail: ledgerUnique
                      ? `${ledger.model.name} has a unique field that could reject a replay, but the write to it happens after the state change`
                      : `${ledger.model.name} records the delivery but has no unique field to reject a replay`,
                  }]
                : []),
              { file: h.mod.path, detail: 'no transaction, conditional update, or pre-write guard appears anywhere in the handler' },
            ],
            complete: true,
          }
        : undefined,
      explanation:
        `The handler performs ${writes.length} separate persisted writes (${writes.map((w) => w.call.callee).join(', ')}) with no transaction ` +
        'around them and no condition that would make a repeated application a no-op. ' +
        (atLeastOnce
          ? 'This endpoint is a provider callback, and callback delivery is at-least-once by design: providers retry on timeout, on a ' +
            'non-2xx response, and sometimes simply twice. Two deliveries of the same event can therefore be in this handler at the same ' +
            'time, on the same or on different instances. '
          : 'Two requests can be inside this handler for the same record at the same time. ') +
        'Because the writes are independent statements, the two executions interleave freely: both can apply the state change, and the ' +
        'sequence can stop between the first write and the last, leaving the record changed and the rest of the work undone. ' +
        (ledger
          ? ledgerAfterMutation
            ? `There is a record kept of the delivery (${ledger.call.callee}), but it is written after the state change, so it documents what ` +
              'happened rather than preventing it; and ' +
              (ledgerUnique
                ? 'although a unique field exists that could reject a duplicate, the rejection would come too late to stop the first write.'
                : 'no unique constraint on that store exists to reject a duplicate in any case.')
            : 'The delivery record is written before the state change, but without a unique constraint and a transaction it does not exclude a concurrent duplicate.'
          : 'Nothing in the handler records which deliveries have already been applied.') +
        (guardBefore ? '' : ' No read, conditional update, or upsert guards the first write.'),
      userImpact:
        atLeastOnce
          ? 'A duplicate delivery applies the same change twice. Where the change is a state transition on a payment or an order, the user ' +
            'can be shown a state that was reached by a retry rather than by the event that was actually final — for example a cancelled or ' +
            'failed transaction left showing as completed — and a partial run leaves the record changed with the follow-up work missing. ' +
            'These cases are rare per request and routine at volume, and they tend to surface as support tickets about money rather than as errors in logs.'
          : 'Two users (or one user clicking twice) acting on the same record at the same moment can both have their change applied, so the ' +
            'record ends in a state neither of them asked for. The application reports success to both.',
      likelyRootCause:
        'The writes were added in the order the work happens, which reads correctly as a sequence. Nothing in local testing executes the handler twice at once.',
      downstreamConsequences: [
        'Corrupted state persists after the race, so the damage outlives the request that caused it and has to be repaired by hand.',
        'The failure rate rises with traffic and with provider retry storms, which is exactly when there is least capacity to investigate it.',
        'Because each individual request succeeds, no error signal is produced and the problem is invisible to monitoring.',
      ],
      remediation:
        'Make the whole sequence one atomic unit and make a repeat application impossible. Put the writes in a single database transaction ' +
        'so they either all apply or none do. Then add a uniqueness guarantee the database enforces: for a delivery callback, store the ' +
        'provider\'s event identifier in a table with a unique constraint and insert it inside that same transaction and before the state ' +
        'change, so a duplicate delivery fails the insert and the transaction rolls back untouched. Make the state change conditional as ' +
        'well, so it is a no-op when already applied — for example by including the expected current state in the where clause (a ' +
        'compare-and-set) rather than writing the new state unconditionally. Where several callers legitimately contend for one record, take ' +
        'a row lock (`SELECT ... FOR UPDATE`) or use an optimistic-lock version column and retry on conflict. None of this needs a ' +
        'distributed lock; the database already provides the guarantee.',
      effort: 'medium',
      verificationSteps: [
        'Send the same request twice concurrently and confirm exactly one application takes effect and the second is rejected or is a no-op.',
        'Send the same request twice in sequence and confirm the second changes nothing.',
        'Kill the process between the writes (or inject a failure after the first) and confirm no partially applied state remains.',
        'Confirm the uniqueness guarantee is enforced by a database constraint, not only by application code, by attempting the duplicate insert directly.',
        'Add a regression test that runs the handler twice concurrently; this is the test that would have caught it.',
      ],
      references: [REF.cweRace, REF.idempotentReceiver, REF.cweToctou],
    }));
    handlers.add(`${h.mod.path}#${h.sym.name}`);
  }
  return { findings: out, handlers };
}

/** Read a row, compute from it, write it back — with nothing making that atomic. */
function readModifyWrite(ctx: AnalyzerContext, suppressed: Set<string>): Finding[] {
  const { map } = ctx;
  const out: Finding[] = [];

  for (const h of handlersOf(map)) {
    if (suppressed.has(`${h.mod.path}#${h.sym.name}`)) continue;
    if (TRANSACTION_RE.test(h.body)) continue;

    const calls = callsIn(h.mod, h.sym);
    const reads = readSites(map, calls);
    const writes = writeSites(map, calls);
    if (reads.length === 0 || writes.length === 0) continue;

    const pair = writes
      .map((w) => ({ w, r: reads.find((r) => r.model && w.model && r.model.name === w.model.name && r.call.line < w.call.line) }))
      .find((p) => p.r !== undefined);
    if (!pair?.r) continue;

    const writeArgs = pair.w.call.args.join(' ');
    if (ATOMIC_WRITE_RE.test(writeArgs)) continue;
    if (OPTIMISTIC_LOCK_RE.test(writeArgs)) continue;
    // The written value must depend on what was read, or this is not a read-modify-write.
    const readBinding = /(?:const|let|var)\s+(\w+)\s*=\s*(?:await\s+)?[^\n]*\b/.exec(
      lineText(map, h.mod.path, pair.r.call.line),
    )?.[1];
    if (!readBinding) continue;
    if (!new RegExp(`\\b${readBinding}\\b`).test(writeArgs)) continue;

    const model = pair.w.model!;
    const evidence = [
      firstVerified(map.evidenceLine(h.mod.path, pair.r.call.line, `${model.name} is read here`)),
      firstVerified(map.evidenceLine(h.mod.path, pair.w.call.line, `and written back using a value derived from that read, with nothing making the pair atomic`)),
    ].filter((e): e is Evidence => e !== undefined);
    if (evidence.length < 2) continue;

    const me = modelEvidence(map, model, 'the contended model');
    if (me) evidence.push(me);

    out.push(ctx.finding({
      ruleId: 'scalability.concurrency.read_modify_write',
      title: `${h.route.method} ${h.route.path} reads ${model.name} and writes it back without a transaction or lock`,
      severity: 'medium',
      confidence: 'strong',
      detectionSource: 'graph',
      files: [h.mod.path, model.file],
      symbol: h.sym.name,
      evidence,
      trace: {
        kind: 'call',
        steps: [
          { file: h.mod.path, line: pair.r.call.line, symbol: h.sym.name, detail: `${pair.r.call.callee}() reads the current value` },
          { file: h.mod.path, line: pair.w.call.line, symbol: h.sym.name, detail: `${pair.w.call.callee}() writes a value computed from it` },
          { file: model.file, detail: `${model.name} carries no version or lock column referenced by this update` },
          { file: h.mod.path, detail: 'no transaction, row lock, or atomic operator appears in the handler' },
        ],
        complete: true,
      },
      explanation:
        `The handler reads a ${model.name}, derives a new value from what it read, and writes that value back as a plain update. Between the ` +
        'read and the write, another request can complete the same sequence. The second write then overwrites the first with a value computed ' +
        'from stale data, and the first change is lost silently — the classic lost update. Nothing here makes the pair atomic: there is no ' +
        'transaction, no row lock, no version check in the update\'s predicate, and the new value is computed in application code rather than ' +
        'by the database.',
      userImpact:
        'Simultaneous actions on the same record quietly cancel each other out. A quantity, balance or counter ends lower or higher than the ' +
        'sum of what users actually did, and both users were told their action succeeded. Because each request returns 200, nothing in the ' +
        'logs marks the moment it went wrong.',
      likelyRootCause:
        'Read-then-write is the natural way to express the change in application code, and it is correct whenever requests do not overlap.',
      downstreamConsequences: [
        'The divergence accumulates, so the stored value drifts further from reality the more the endpoint is used.',
        'Reconciling the damage afterwards usually requires a source of truth the application does not keep.',
      ],
      remediation:
        'Let the database do the arithmetic, so there is no window: use an atomic operator (`{ increment: n }`, `SET column = column + n`, ' +
        '`$inc`) instead of writing a value computed in application code. Where the new value genuinely cannot be expressed that way, wrap ' +
        'the read and the write in one transaction and take a row lock on the read (`SELECT ... FOR UPDATE`), or add a version column and ' +
        'make the update conditional on it, retrying on conflict. Add a database-level constraint (for example a non-negative check) so an ' +
        'incorrect result is rejected rather than stored.',
      effort: 'medium',
      verificationSteps: [
        'Issue many concurrent requests against the same record and confirm the final value equals the number of successful requests (before the change it will be lower).',
        'Confirm the update is now either atomic in the database or guarded by a lock or version check, by reading the generated SQL.',
        'Confirm a conflicting update fails or retries rather than silently overwriting.',
        'Add a concurrency test to the suite covering this endpoint.',
      ],
      references: [REF.cweRace, REF.cweToctou],
    }));
  }
  return out;
}

// --------------------------------------------------------- retries & timeouts ---

/** A retry loop with no backoff, or no ceiling on attempts. */
function retryWithoutBackoffOrCap(ctx: AnalyzerContext): Finding[] {
  const { map } = ctx;
  const out: Finding[] = [];
  const routeFiles = new Set(map.routes.map((r) => r.file));

  for (const mod of map.modules.values()) {
    if (!mod.parsed || !isServerCandidate(map, mod)) continue;
    if (!reachesRoute(map, mod.path, routeFiles)) continue;

    for (const sym of mod.symbols) {
      if (sym.kind !== 'function' && sym.kind !== 'arrow' && sym.kind !== 'method') continue;
      if (sym.endLine <= sym.startLine) continue;
      const body = codeText(sym.text, mod.language);

      const isRetry = RETRY_INTENT_RE.test(body) && /\bfor\s*\(|\bwhile\s*\(|\.catch\s*\(|catch\s*\(/.test(body);
      if (!isRetry) continue;

      const unbounded = /while\s*\(\s*(?:true|1)\s*\)/.test(body) || !RETRY_CAP_RE.test(body);
      const noBackoff = !BACKOFF_RE.test(body);
      if (!unbounded && !noBackoff) continue;

      const offset = body.split('\n').findIndex((l) => RETRY_INTENT_RE.test(l) || /while\s*\(\s*(?:true|1)\s*\)/.test(l));
      const evidence = firstVerified(
        map.evidenceLine(mod.path, sym.startLine + Math.max(offset, 0), unbounded && noBackoff
          ? 'retried in a loop with neither a delay between attempts nor a ceiling on their number'
          : unbounded
            ? 'retried in a loop with no ceiling on the number of attempts'
            : 'retried immediately, with no delay between attempts'),
        map.evidenceLine(mod.path, sym.startLine, 'retry logic without backoff or a cap'),
      );
      if (!evidence) continue;

      const problems: string[] = [];
      if (noBackoff) problems.push('there is no delay between attempts');
      if (unbounded) problems.push('there is no visible ceiling on the number of attempts');

      out.push(ctx.finding({
        ruleId: 'scalability.retry.no_backoff_or_cap',
        title: `Retry loop in ${sym.name}() has ${noBackoff && unbounded ? 'no backoff and no attempt cap' : noBackoff ? 'no backoff between attempts' : 'no cap on attempts'}`,
        severity: 'medium',
        confidence: 'moderate',
        files: [mod.path],
        symbol: sym.name,
        evidence: [evidence],
        explanation:
          `${sym.name}() retries a failed operation, but ${problems.join(' and ')}. Retries without backoff convert a dependency that is ` +
          'struggling into a dependency that is being attacked: every caller that fails retries immediately, so the load on the failing ' +
          'component rises at exactly the moment it needs less. Without a ceiling, a persistent failure is retried for as long as the process ' +
          'lives, holding a request slot, a connection and whatever memory the attempt needs. Whether this has already caused an outage is ' +
          'not determinable from source; the missing bound is.',
        userImpact:
          'When a dependency is slow, requests that touch it hang rather than failing, and the retries keep the dependency from recovering. ' +
          'Users see the whole application become unresponsive for longer than the underlying problem actually lasted, and the recovery is ' +
          'slower than it should be once the dependency comes back.',
        likelyRootCause: 'A retry was added to smooth over a transient failure, and the transient case is the only one it was tested against.',
        downstreamConsequences: [
          'Synchronised retries across instances produce load spikes at regular intervals, which is how a brief failure becomes a sustained one.',
          'A permanently failing operation that is retried forever never reaches an error path, so nothing records it and no alert fires.',
        ],
        remediation:
          'Cap the number of attempts, and wait between them with exponential backoff plus jitter so concurrent callers do not retry in ' +
          'lockstep. Retry only errors that can plausibly succeed on a second attempt (timeouts, connection resets, 429 and 5xx) and never ' +
          'retry a deterministic failure such as a validation error. Bound the total time spent retrying by the caller\'s own deadline, so ' +
          'retries cannot outlive the request that wanted the result. When the attempts are exhausted, surface the failure and, for work that ' +
          'must not be dropped, move the item to a dead-letter store that a human or a scheduled job can inspect and re-drive, rather than ' +
          'retrying in the request path indefinitely.',
        effort: 'small',
        verificationSteps: [
          'Point the operation at a dependency that always fails and confirm the attempts stop after the configured cap, within the configured total time budget.',
          'Confirm the delay grows between attempts and differs between concurrent callers (jitter), by logging attempt timestamps.',
          'Confirm a deterministic failure is not retried at all.',
          'Confirm the exhausted case produces a recorded error, and that work which must not be lost ends up somewhere it can be re-driven from.',
        ],
        references: [REF.sreCascading, REF.sreOverload, REF.cweResource],
      }));
    }
  }
  return out;
}

/**
 * Outbound calls in the server request path with no timeout.
 *
 * Reported once for the project with each site as evidence, rather than once
 * per call: the risk is a property of the outbound layer, and a finding per
 * call site would be the same claim repeated. AI provider calls are excluded —
 * their budgets belong to the AI analyzer.
 */
function missingOutboundTimeouts(ctx: AnalyzerContext): Finding[] {
  const { map } = ctx;
  const sites: Array<{ file: string; line: number; callee: string; route: string; symbol: string }> = [];

  for (const h of handlersOf(map)) {
    const aiRoots = new Set(
      h.mod.imports.filter((i) => AI_SDK_RE.test(i.specifier)).flatMap((i) => i.names),
    );
    const aiClientNames = h.mod.symbols
      .filter((s) => [...aiRoots].some((n) => new RegExp(`new\\s+${n}\\s*\\(`).test(s.text)))
      .map((s) => s.name);

    for (const call of callsIn(h.mod, h.sym)) {
      if (!OUTBOUND_CALL_RE.test(call.callee)) continue;
      const parts = call.callee.split('.');
      const root = parts[0]!.replace(/\(\)$/, '');
      if (parts.length > 1 && !OUTBOUND_ROOT_RE.test(root)) continue;
      if (parts.length === 1 && !/^(fetch|got|request|axios)$/.test(root)) continue;
      if (aiClientNames.includes(root)) continue;
      if (!call.awaited) continue;

      const argText = call.args.join(' ');
      if (TIMEOUT_RE.test(argText)) continue;
      if (TIMEOUT_RE.test(h.body)) continue;
      if (TIMEOUT_RE.test(moduleText(map, h.mod))) continue;

      sites.push({
        file: h.mod.path,
        line: call.line,
        callee: call.callee,
        route: `${h.route.method} ${h.route.path}`,
        symbol: h.sym.name,
      });
    }
  }
  if (sites.length === 0) return [];

  const evidence = sites
    .slice(0, 5)
    .map((s) => firstVerified(map.evidenceLine(s.file, s.line, `${s.callee}() is awaited in ${s.route} with no timeout or abort signal, so the response time of this request is bounded by the upstream, not by us`)))
    .filter((e): e is Evidence => e !== undefined);
  if (evidence.length === 0) return [];

  const files = [...new Set(sites.map((s) => s.file))];

  return [ctx.finding({
    ruleId: 'scalability.timeout.outbound_call_without_timeout',
    title: `Outbound calls in the request path have no timeout (${sites.length} call site${sites.length === 1 ? '' : 's'})`,
    severity: 'medium',
    confidence: 'moderate',
    status: 'needs_runtime_verification',
    files,
    symbol: sites[0]!.symbol,
    evidence,
    explanation:
      (sites.length === 1
        ? 'An awaited outbound call in a server request handler sets no timeout and no abort signal, '
        : `${sites.length} awaited outbound calls in server request handlers set no timeout and no abort signal, `) +
      'and no timeout is configured on the client or anywhere in the enclosing module. How long the request waits is therefore ' +
      'decided by the upstream service. A dependency that fails by returning an error is harmless; a dependency that fails by answering ' +
      'slowly holds one of this application\'s request slots, one connection, and one set of buffers for as long as it chooses to take. With ' +
      'enough concurrency, all of the slots end up held, and the application stops serving requests that have nothing to do with the slow ' +
      'dependency. How much concurrency that takes depends on the runtime\'s limits and the real traffic, so this finding needs runtime ' +
      'verification to quantify: what is determinable from the source is that nothing bounds the wait.' +
      (sites.some((s) => /fetch$/.test(s.callee))
        ? ' Note that the platform\'s default `fetch` has no timeout at all, so the absence of a signal here means the absence of any limit.'
        : ''),
    userImpact:
      'When an external dependency slows down, users do not get a quick error — they get a page that never finishes loading. Shortly after, ' +
      'parts of the application that do not use that dependency stop responding too, because the slow calls have consumed the capacity to ' +
      'serve anything. From outside it looks like the whole application is down, and it stays that way until the dependency recovers.',
    likelyRootCause:
      'No timeout is the default in most HTTP clients, so omitting one is easy to do and invisible until a dependency degrades rather than fails.',
    downstreamConsequences: [
      'Held request slots mean one slow dependency takes down endpoints that never call it, which is the standard shape of a cascading failure.',
      'Without a deadline there is nothing for a retry or a circuit breaker to key off, so neither can be added usefully later.',
      'Load balancer and platform timeouts fire first and return a generic error, which hides which dependency was responsible.',
    ],
    remediation:
      'Give every outbound call an explicit deadline. With `fetch`, pass `signal: AbortSignal.timeout(ms)`; with a client library, set its ' +
      'timeout option at construction so it applies to every call and cannot be forgotten at a new call site. Choose the value from the ' +
      'budget for the whole request rather than per call, and propagate the remaining budget to calls made further down. Treat the timeout ' +
      'as a real outcome: decide for each call whether to fail the request, serve degraded content, or fall back to a cached value. Where a ' +
      'dependency is not needed to answer the user, move it out of the request path entirely.',
    effort: 'small',
    verificationSteps: [
      'Point each call at a deliberately slow endpoint (a server that accepts the connection and never responds) and confirm the handler returns within the configured deadline.',
      'Under that condition, run a load test and confirm unrelated endpoints keep serving — this is the measurement that establishes whether slot exhaustion actually occurs, and it cannot be inferred from the source.',
      'Confirm the timeout is set on the client once rather than at individual call sites, so new call sites inherit it.',
      'Confirm the timeout path returns a deliberate response and is recorded distinctly from other errors in logs.',
    ],
    references: [REF.sreCascading, REF.cweResource, REF.owaspResource],
  })];
}

/**
 * Background work owned by the request-serving process: a module-scope timer,
 * or a write fired off without being awaited.
 */
function inProcessBackgroundWork(ctx: AnalyzerContext): Finding[] {
  const { map } = ctx;
  const out: Finding[] = [];
  const routeFiles = new Set(map.routes.map((r) => r.file));

  // --- module-scope timers ---
  for (const mod of map.modules.values()) {
    if (!mod.parsed || !isServerCandidate(map, mod)) continue;
    if (!reachesRoute(map, mod.path, routeFiles)) continue;
    const ranges = functionRanges(mod);
    const timer = mod.calls.find(
      (c) => /^(setInterval|setTimeout)$/.test(c.callee) && isModuleScope(ranges, c.line),
    );
    if (!timer) continue;
    const evidence = firstVerified(
      map.evidenceLine(mod.path, timer.line, `${timer.callee}() is registered at module scope, so every process that imports this module runs it`),
    );
    if (!evidence) continue;

    out.push(ctx.finding({
      ruleId: 'scalability.jobs.in_process_scheduler',
      title: `Scheduled work runs inside the request-serving process (${mod.path})`,
      severity: 'medium',
      confidence: 'moderate',
      files: [mod.path],
      evidence: [evidence],
      explanation:
        `A ${timer.callee}() is registered at module scope in a module the request path imports, so the schedule is owned by the web process ` +
        'rather than by anything that coordinates across instances. Two consequences follow from that alone. Every instance runs its own copy ' +
        'of the schedule, so the work happens once per instance rather than once; and the schedule exists only in memory, so a restart, a ' +
        'deploy or a scale-to-zero cancels whatever had not yet run, with no record that it was due.',
      userImpact:
        'Work that users rely on happening on a schedule — a reminder, a cleanup, a recalculation — happens several times or not at all, ' +
        'depending on how many instances are running and when the last deploy was. Duplicated work can mean a duplicated side effect, such as ' +
        'the same notification arriving more than once.',
      likelyRootCause: 'An in-process timer is the quickest way to make periodic work happen, and with one instance it behaves as intended.',
      downstreamConsequences: [
        'Work that must happen exactly once needs a lock that does not exist here, so correctness depends on instance count.',
        'Nothing records whether a run happened, so a missed run is undetectable after the fact.',
      ],
      remediation:
        'Move periodic work to a scheduler outside the request-serving process: the platform\'s cron, a queue with a delayed message, or a ' +
        'dedicated worker process. Make each run idempotent and record the fact that it ran, so a repeat is harmless and a miss is visible. ' +
        'If the timer must stay in process for now, guard it with a lock held in a shared store so only one instance acts, and restrict it to ' +
        'a single designated process rather than every web instance.',
      effort: 'medium',
      verificationSteps: [
        'Run two instances and confirm the work happens once per scheduled interval in total, not once per instance.',
        'Restart during an interval and confirm the run that was due still happens.',
        'Confirm each run is recorded, so a missing run can be detected.',
      ],
      references: [REF.twelveFactorDisposability, REF.twelveFactorProcesses],
    }));
  }

  // --- fire-and-forget writes in a handler ---
  for (const h of handlersOf(map)) {
    for (const w of writeSites(map, callsIn(h.mod, h.sym))) {
      if (w.call.awaited) continue;
      const text = lineText(map, h.mod.path, w.call.line);
      const nextText = lineText(map, h.mod.path, w.call.line + 1);
      if (/\breturn\b|\bawait\b|Promise\.all|Promise\.allSettled|\.then\s*\(|\.catch\s*\(/.test(text)) continue;
      if (/^\s*\.(then|catch|finally)\s*\(/.test(nextText)) continue;

      const evidence = firstVerified(
        map.evidenceLine(h.mod.path, w.call.line, 'a persisted write started without being awaited, so the handler can return before it completes or fails'),
      );
      if (!evidence) continue;

      out.push(ctx.finding({
        ruleId: 'scalability.jobs.fire_and_forget_write',
        title: `${h.route.method} ${h.route.path} starts a database write without awaiting it`,
        severity: 'medium',
        confidence: 'moderate',
        files: [h.mod.path],
        symbol: h.sym.name,
        evidence: [evidence],
        explanation:
          `${w.call.callee}() is started but not awaited, and no completion or error handler is attached. The handler can therefore return a ` +
          'success response while the write is still in flight. On a serverless or request-scoped runtime the execution context can be frozen ' +
          'or torn down as soon as the response is sent, so the write may never complete at all. If it fails, the rejection has nowhere to go: ' +
          'in Node it becomes an unhandled rejection, which by default terminates the process and takes every other in-flight request with it.',
        userImpact:
          'A user is told their action succeeded when the write behind it may not have happened. The data is missing afterwards with no error ' +
          'anywhere to explain it, and the loss is intermittent, which makes it look like the user misremembered.',
        likelyRootCause: 'The await was omitted to keep the response fast, treating the write as something that can happen in the background.',
        downstreamConsequences: [
          'An unhandled rejection can terminate the process, so one failed background write fails unrelated concurrent requests.',
          'Request-scoped runtimes may cancel the work on response, so the behaviour differs between local and deployed environments.',
        ],
        remediation:
          'Await the write, and if latency is the reason it was not awaited, hand the work to something built to own it: enqueue a message and ' +
          'let a worker perform the write, so it is retried and its failures are visible. Where the runtime provides a mechanism for work that ' +
          'outlives the response (a background-task API), use it explicitly rather than relying on a floating promise. At minimum attach an ' +
          'error handler so a failure is recorded instead of taking the process down.',
        effort: 'small',
        verificationSteps: [
          'Make the write fail and confirm the process survives and the failure is recorded.',
          'On the deployed runtime, issue the request and confirm the write is present afterwards (locally it usually completes; that is what hides this).',
          'Confirm the response no longer claims success for work that has not been committed.',
        ],
        references: [REF.twelveFactorDisposability, REF.cweResource],
      }));
      break;
    }
  }

  return out;
}
