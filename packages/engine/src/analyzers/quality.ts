import type { Confidence, Evidence, Finding, Severity } from '@codelens/core';
import type { RepoMap } from '../graph/repomap.ts';
import type { ParsedModule, SymbolInfo } from '../parse/types.ts';
import type { Analyzer, AnalyzerContext } from './types.ts';
import { codeText } from './text.ts';

/**
 * Code quality and maintainability.
 *
 * The rule this analyzer is written against: a finding must say what the defect
 * costs, not that the code is "poor quality". "This function is long" is not a
 * finding. "This function has twenty-three decision points, so a reviewer
 * cannot see which branch a change affects and the untested branches are the
 * ones that will break" is.
 *
 * Confidence discipline matches the security analyzer:
 *   - a measurement over one file's own text is `moderate` or `strong`
 *     depending on how little else it could be;
 *   - a measurement plus a traced cross-file relationship (importer index,
 *     resolved import cycle, layer crossing) is `strong`;
 *   - `confirmed` is reserved for facts read directly out of a configuration
 *     file, where there is nothing to interpret.
 *
 * Where a conclusion depends on something static analysis cannot see — a module
 * loaded by a string-built dynamic import, a framework convention we do not
 * model — the finding is downgraded and the note says which gap applies, rather
 * than being reported as certain.
 */

// ---------------------------------------------------------------- tunables ---

/**
 * Thresholds are deliberately high. A rule that fires on healthy code costs
 * more than a rule that stays silent, because one bad finding makes a reader
 * discount the whole report.
 */
const T = {
  /** Minimum normalised tokens in a body before duplication is considered. */
  dupMinTokens: 30,
  /** Minimum code lines in a body before duplication is considered. */
  dupMinLines: 3,
  /** Token-length ratio below which two bodies are not treated as candidates. */
  dupMinLengthRatio: 0.75,
  /** Cheap multiset prefilter before the (quadratic) sequence comparison. */
  dupPrefilter: 0.8,
  /** Sequence similarity at or above this, and below 1.0, is divergent duplication. */
  dupDivergent: 0.9,
  /** Bound on sequence comparisons, so a large repository cannot stall a scan. */
  dupMaxComparisons: 60_000,
  dupMaxFindings: 20,

  /** Cyclomatic-ish decision count that makes a function hard to review. */
  complexityReportable: 15,
  complexityHigh: 30,
  complexityMinSpan: 50,
  /** A very long function is reportable at a lower decision count. */
  longSpan: 200,
  longSpanComplexity: 8,
  complexityMaxFindings: 8,

  godModuleLines: 500,
  godModuleExports: 25,
  godModuleFunctions: 3,

  fanOutInternal: 15,
  fanOutHigh: 25,
  fanInHub: 20,
  hubLines: 300,
  hubExportedFunctions: 3,

  cycleMaxFindings: 8,

  deadCodeMinCodeLines: 5,
  deadCodeMaxFindings: 25,

  anyTotal: 20,
  anyPerFile: 1.0,
  anyMinTsFiles: 5,

  envModules: 3,
  envVars: 4,

  docImporters: 3,
  docExportedFunctions: 5,

  namingMinEach: 2,
  namingMinTotal: 5,
} as const;

const REF = {
  cleanCode: 'Martin Fowler, Refactoring (2nd ed.) — Duplicated Code, Long Function, Shotgun Surgery',
  cwe1041: 'CWE-1041 Use of Redundant Code',
  cwe1121: 'CWE-1121 Excessive McCabe Cyclomatic Complexity',
  cwe561: 'CWE-561 Dead Code',
  cwe1047: 'CWE-1047 Modules with Circular Dependencies',
  cwe1109: 'CWE-1109 Use of Same Variable for Multiple Purposes',
  tsStrict: 'TypeScript handbook — Compiler Options: strict',
  twelveFactor: 'The Twelve-Factor App — III. Config',
  rscBoundary: 'React Server Components — the server/client boundary',
} as const;

// ------------------------------------------------------------- shared index --

interface DupCandidate {
  path: string;
  symbol: SymbolInfo;
  /** Normalised tokens of the body (declaration and comments removed). */
  tokens: string[];
  /** Normalised code lines of the body, with their original line numbers. */
  lines: Array<{ norm: string; line: number }>;
  bodyStartLine: number;
}

interface QIndex {
  /** Comment-stripped lines per file, computed once. */
  stripped: Map<string, string[]>;
  /** Comment-stripped lines with literal contents blanked, computed once. */
  masked: Map<string, string[]>;
  /** Importer index widened with `export … from` re-export edges. */
  importers: Map<string, Set<string>>;
  /** Importers that are not test files — i.e. production reachability. */
  prodImporters: Map<string, Set<string>>;
  /** Every string literal value in the project, for dynamic-reference guards. */
  literals: Set<string>;
  /** True when some module builds a module specifier at runtime. */
  dynamicSpecifiers: boolean;
  /** Paths named inside manifests, CI files and infrastructure files. */
  referencedInConfig: Set<string>;
  /** Modules eligible for source-level rules. */
  analysable: ParsedModule[];
  /** True when React is present without a server-component framework. */
  clientOnlyReact: boolean;
}

export const qualityAnalyzer: Analyzer = {
  id: 'quality',
  category: 'quality',
  description:
    'Duplicated and drifted logic, complexity, dead code, dependency cycles, coupling, layering, type safety and configuration handling.',

  precondition(map: RepoMap): string | undefined {
    const parsed = [...map.modules.values()].filter((m) => m.parsed);
    if (parsed.length === 0) {
      return 'no source file in this snapshot produced an AST, so there is nothing to measure';
    }
    return undefined;
  },

  run(ctx: AnalyzerContext): Finding[] {
    const idx = buildIndex(ctx.map);
    const findings: Finding[] = [];

    findings.push(...duplicatedLogic(ctx, idx));
    findings.push(...overComplexFunctions(ctx, idx));
    findings.push(...dependencyCycles(ctx, idx));
    findings.push(...deadCode(ctx, idx));
    findings.push(...layerViolations(ctx, idx));
    findings.push(...moduleScopeClients(ctx, idx));
    findings.push(...couplingPressure(ctx, idx));
    findings.push(...godModules(ctx, idx));
    findings.push(...typeSafety(ctx, idx));
    findings.push(...scatteredConfiguration(ctx, idx));
    findings.push(...undocumentedSharedApi(ctx, idx));
    findings.push(...inconsistentNaming(ctx, idx));

    return findings;
  },
};

// ------------------------------------------------------------------ helpers --

const TEST_PATH_RE =
  /(^|\/)(__tests__|__mocks__|tests?|spec|e2e|fixtures?|mocks?|stubs?|testdata)\//i;
const TEST_FILE_RE =
  /\.(test|spec|stories|cy|e2e)\.[cm]?[jt]sx?$|(^|\/)(test_[^/]+|conftest)\.py$|_test\.(py|go)$/i;

function isTestLike(map: RepoMap, path: string): boolean {
  const role = map.filesByPath.get(path)?.role;
  if (role === 'test') return true;
  return TEST_PATH_RE.test(path) || TEST_FILE_RE.test(path);
}

const EXCLUDED_ROLES = new Set([
  'test', 'generated', 'vendored', 'documentation', 'asset', 'unknown',
]);

/** A module whose own source is fair game for a quality measurement. */
function isAnalysable(map: RepoMap, mod: ParsedModule): boolean {
  if (!mod.parsed) return false;
  const file = map.filesByPath.get(mod.path);
  if (!file || file.generated || file.vendored || file.binary) return false;
  if (EXCLUDED_ROLES.has(file.role)) return false;
  if (isTestLike(map, mod.path)) return false;
  return true;
}

function strippedLinesOf(map: RepoMap, idx: QIndex, path: string): string[] {
  const cached = idx.stripped.get(path);
  if (cached) return cached;
  const file = map.filesByPath.get(path);
  const lines = codeText(file?.text ?? null, file?.language).split('\n');
  idx.stripped.set(path, lines);
  return lines;
}

function maskedLinesOf(map: RepoMap, idx: QIndex, path: string): string[] {
  const cached = idx.masked.get(path);
  if (cached) return cached;
  const lines = maskLiterals(strippedLinesOf(map, idx, path).join('\n')).split('\n');
  idx.masked.set(path, lines);
  return lines;
}

/** The comment-free source of a symbol, taken from its AST line span. */
function symbolSource(map: RepoMap, idx: QIndex, path: string, sym: SymbolInfo): string {
  const lines = strippedLinesOf(map, idx, path);
  return lines.slice(sym.startLine - 1, sym.endLine).join('\n');
}

/** As `symbolSource`, with literal contents blanked for construct counting. */
function maskedSymbolSource(map: RepoMap, idx: QIndex, path: string, sym: SymbolInfo): string {
  const lines = maskedLinesOf(map, idx, path);
  return lines.slice(sym.startLine - 1, sym.endLine).join('\n');
}

/** Evidence that is known to resolve; falls back to the first line of the file. */
function solidEvidence(map: RepoMap, path: string, candidates: Array<Evidence | undefined>, note: string): Evidence {
  for (const c of candidates) if (c?.verified) return c;
  const first = map.evidenceLine(path, 1, note);
  return first;
}

/**
 * Blank the contents of string, template and regular-expression literals,
 * keeping length and line structure.
 *
 * Every measurement in this analyzer that counts language constructs runs over
 * this view first. Without it, a function whose body contains long prose
 * strings — an error message, a generated report, a remediation paragraph —
 * scores as if every "if", "for" and "and" inside the prose were a branch. That
 * single mistake would make the complexity rule report the most
 * documentation-heavy code as the most complex, which is worse than useless.
 */
function maskLiterals(source: string): string {
  const blanked = source
    .replace(/`(?:[^`\\]|\\[\s\S])*`/g, (m) => blank(m))
    .replace(/'(?:[^'\\\n]|\\.)*'/g, (m) => blank(m))
    .replace(/"(?:[^"\\\n]|\\.)*"/g, (m) => blank(m));
  // Regular-expression literals, once strings can no longer be confused for one.
  return blanked.replace(/(^|[=(,:[!&|?{;+\s])\/(?:[^/\n\\]|\\.)+\/[gimsuyd]*/g, (m, lead: string) =>
    lead + blank(m.slice(lead.length)));
}

function blank(text: string): string {
  let out = '';
  for (const ch of text) out += ch === '\n' ? '\n' : ' ';
  return out;
}

const FUNCTION_KINDS = new Set(['function', 'method', 'arrow']);

/** True when `inner` sits inside `outer` in the same file. */
function contains(outer: SymbolInfo, inner: SymbolInfo): boolean {
  if (outer === inner) return false;
  return outer.startLine <= inner.startLine && outer.endLine >= inner.endLine
    && (outer.startLine !== inner.startLine || outer.endLine !== inner.endLine);
}

/** Symbols declared at module scope, i.e. not nested inside a function. */
function topLevelSymbols(mod: ParsedModule): SymbolInfo[] {
  const fns = mod.symbols.filter((s) => FUNCTION_KINDS.has(s.kind) || s.kind === 'class');
  return mod.symbols.filter((s) => !fns.some((f) => contains(f, s)));
}

// ---- inlined module resolution (mirrors parse/resolve.ts, local by design) --

const EXTS = ['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs', '.mts', '.cts'];

function normalisePath(p: string): string {
  const out: string[] = [];
  for (const seg of p.split('/')) {
    if (seg === '' || seg === '.') continue;
    if (seg === '..') { out.pop(); continue; }
    out.push(seg);
  }
  return out.join('/');
}

function dirOf(p: string): string {
  const i = p.lastIndexOf('/');
  return i === -1 ? '' : p.slice(0, i);
}

function resolveLocal(specifier: string, fromPath: string, files: Set<string>): string | undefined {
  const tryAll = (base: string): string | undefined => {
    if (files.has(base)) return base;
    for (const e of EXTS) if (files.has(base + e)) return base + e;
    for (const e of EXTS) if (files.has(`${base}/index${e}`)) return `${base}/index${e}`;
    return undefined;
  };
  if (specifier.startsWith('.')) return tryAll(normalisePath(`${dirOf(fromPath)}/${specifier}`));
  const alias = /^[@~]\/(.+)$/.exec(specifier);
  if (alias) {
    for (const root of ['src', 'app', 'lib', '']) {
      const hit = tryAll(normalisePath(root ? `${root}/${alias[1]}` : alias[1]!));
      if (hit) return hit;
    }
  }
  return undefined;
}

// ----------------------------------------------------------- index building --

function buildIndex(map: RepoMap): QIndex {
  const idx: QIndex = {
    stripped: new Map(),
    masked: new Map(),
    importers: new Map(),
    prodImporters: new Map(),
    literals: new Set(),
    dynamicSpecifiers: false,
    referencedInConfig: new Set(),
    analysable: [],
    clientOnlyReact: false,
  };

  const filePaths = new Set(map.files.map((f) => f.path));

  // Start from the map's own importer index.
  for (const [target, importers] of map.importers) {
    idx.importers.set(target, new Set(importers));
  }

  for (const mod of map.modules.values()) {
    if (mod.parsed) {
      for (const lit of mod.stringLiterals) idx.literals.add(lit.value);
    }
    if (isAnalysable(map, mod)) idx.analysable.push(mod);

    // `export … from './x'` is a real dependency edge, but the parser records
    // it as neither an import nor an export, so a barrel file would otherwise
    // make every module it re-exports look unreferenced. That single gap would
    // turn the dead-code rule into a false-positive generator, so it is closed
    // here rather than worked around with a path heuristic.
    const text = codeText(map.filesByPath.get(mod.path)?.text ?? null, mod.language);
    const reexport = /export\s+(?:type\s+)?(?:\*(?:\s+as\s+[\w$]+)?|\{[\s\S]*?\})\s+from\s*['"]([^'"]+)['"]/g;
    for (const m of text.matchAll(reexport)) {
      const resolved = resolveLocal(m[1]!, mod.path, filePaths);
      if (!resolved) continue;
      const set = idx.importers.get(resolved) ?? new Set<string>();
      set.add(mod.path);
      idx.importers.set(resolved, set);
    }

    // A specifier assembled at runtime cannot be resolved, so any dead-code
    // conclusion in this repository has to be downgraded.
    if (/\b(?:import|require)\s*\(\s*[^'"`)\s]/.test(text)) idx.dynamicSpecifiers = true;
  }

  for (const [target, importers] of idx.importers) {
    const prod = new Set<string>();
    for (const p of importers) if (!isTestLike(map, p)) prod.add(p);
    idx.prodImporters.set(target, prod);
  }

  // Manifests, CI definitions and infrastructure files can make a file an entry
  // point without any module importing it.
  for (const f of map.files) {
    if (!f.text) continue;
    if (!['manifest', 'config', 'ci', 'infrastructure'].includes(f.role)) continue;
    for (const candidate of map.modules.keys()) {
      const noExt = candidate.replace(/\.[cm]?[jt]sx?$/, '');
      if (f.text.includes(candidate) || f.text.includes(noExt)) idx.referencedInConfig.add(candidate);
    }
  }

  const rscFramework = ['Next.js', 'Remix', 'Astro', 'Nuxt', 'SvelteKit', 'Gatsby']
    .some((n) => map.hasTech(n));
  idx.clientOnlyReact = (map.hasTech('React') || map.hasTech('Vue')) && !rscFramework;

  return idx;
}

// -------------------------------------------------------------- duplication --

function tokenise(source: string): string[] {
  return source.match(/[A-Za-z_$][\w$]*|\d+(?:\.\d+)?|[^\s\w]/g) ?? [];
}

/**
 * The body of a symbol, with its declaration and name removed.
 *
 * The declaration is dropped deliberately: comparing whole symbols would make
 * two exact copies under different names look like a drifted pair, which is the
 * distinction this analyzer exists to draw.
 */
function bodyOf(source: string, startLine: number): { text: string; startLine: number } | undefined {
  const brace = source.indexOf('{');
  const arrow = source.indexOf('=>');
  let cut = -1;
  if (brace !== -1 && (arrow === -1 || brace < arrow + 4)) cut = brace;
  else if (arrow !== -1) cut = arrow + 2;
  if (cut === -1) {
    // Indentation-delimited languages: the body is what follows a header line
    // ending in a colon.
    const firstBreak = source.indexOf('\n');
    if (firstBreak === -1) return undefined;
    if (!/:\s*$/.test(source.slice(0, firstBreak))) return undefined;
    return { text: source.slice(firstBreak + 1), startLine: startLine + 1 };
  }
  const text = source.slice(cut);
  const consumedNewlines = (source.slice(0, cut).match(/\n/g) ?? []).length;
  return { text, startLine: startLine + consumedNewlines };
}

function normalisedLines(bodyText: string, bodyStartLine: number): Array<{ norm: string; line: number }> {
  const out: Array<{ norm: string; line: number }> = [];
  const raw = bodyText.split('\n');
  for (let i = 0; i < raw.length; i++) {
    const norm = raw[i]!.replace(/\s+/g, ' ').trim();
    if (norm === '' || norm === '{' || norm === '}' || norm === '});' || norm === ');') continue;
    out.push({ norm, line: bodyStartLine + i });
  }
  return out;
}

function multisetDice(a: string[], b: string[]): number {
  const counts = new Map<string, number>();
  for (const t of a) counts.set(t, (counts.get(t) ?? 0) + 1);
  let shared = 0;
  for (const t of b) {
    const n = counts.get(t);
    if (n && n > 0) { counts.set(t, n - 1); shared++; }
  }
  return (2 * shared) / (a.length + b.length);
}

/** Sequence similarity: 2·LCS / (|a| + |b|). Order-sensitive, unlike Dice. */
function sequenceSimilarity(a: string[], b: string[]): number {
  const n = a.length;
  const m = b.length;
  let prev = new Int32Array(m + 1);
  let cur = new Int32Array(m + 1);
  for (let i = 1; i <= n; i++) {
    for (let j = 1; j <= m; j++) {
      cur[j] = a[i - 1] === b[j - 1]
        ? prev[j - 1]! + 1
        : Math.max(prev[j]!, cur[j - 1]!);
    }
    const swap = prev; prev = cur; cur = swap;
    cur.fill(0);
  }
  return (2 * prev[m]!) / (n + m);
}

function dupCandidates(map: RepoMap, idx: QIndex): DupCandidate[] {
  const out: DupCandidate[] = [];
  for (const mod of idx.analysable) {
    for (const sym of mod.symbols) {
      if (!FUNCTION_KINDS.has(sym.kind)) continue;
      if (sym.endLine - sym.startLine + 1 < T.dupMinLines + 1) continue;
      const source = symbolSource(map, idx, mod.path, sym);
      const body = bodyOf(source, sym.startLine);
      if (!body) continue;
      const lines = normalisedLines(body.text, body.startLine);
      if (lines.length < T.dupMinLines) continue;
      const tokens = tokenise(lines.map((l) => l.norm).join('\n'));
      if (tokens.length < T.dupMinTokens) continue;
      out.push({ path: mod.path, symbol: sym, tokens, lines, bodyStartLine: body.startLine });
    }
  }
  return out;
}

interface DupPair { a: DupCandidate; b: DupCandidate; similarity: number }

function duplicatedLogic(ctx: AnalyzerContext, idx: QIndex): Finding[] {
  const { map } = ctx;
  const candidates = dupCandidates(map, idx);
  if (candidates.length < 2) return [];

  // Longest first, so when a symbol takes part in several near-duplicates the
  // pair reported is the one with the most code behind it.
  candidates.sort((x, y) => y.tokens.length - x.tokens.length);

  const pairs: DupPair[] = [];
  let comparisons = 0;

  for (let i = 0; i < candidates.length; i++) {
    for (let j = i + 1; j < candidates.length; j++) {
      const a = candidates[i]!;
      const b = candidates[j]!;
      if (a.path === b.path && (contains(a.symbol, b.symbol) || contains(b.symbol, a.symbol))) continue;
      const ratio = Math.min(a.tokens.length, b.tokens.length) / Math.max(a.tokens.length, b.tokens.length);
      if (ratio < T.dupMinLengthRatio) continue;
      if (multisetDice(a.tokens, b.tokens) < T.dupPrefilter) continue;
      if (comparisons >= T.dupMaxComparisons) break;
      comparisons++;
      const similarity = sequenceSimilarity(a.tokens, b.tokens);
      if (similarity < T.dupDivergent) continue;
      pairs.push({ a, b, similarity });
    }
    if (comparisons >= T.dupMaxComparisons) break;
  }

  // Divergent copies first: a drifted copy is the dangerous one.
  pairs.sort((p, q) => {
    const pd = p.similarity < 1 ? 0 : 1;
    const qd = q.similarity < 1 ? 0 : 1;
    if (pd !== qd) return pd - qd;
    return q.a.tokens.length - p.a.tokens.length;
  });

  const used = new Set<SymbolInfo>();
  const out: Finding[] = [];

  for (const pair of pairs) {
    if (out.length >= T.dupMaxFindings) break;
    if (used.has(pair.a.symbol) || used.has(pair.b.symbol)) continue;
    const verdict = classifyPair(pair);
    // A family of parallel variants is not duplication worth reporting.
    if (verdict.kind === 'parallel_family') continue;
    used.add(pair.a.symbol);
    used.add(pair.b.symbol);
    const finding = verdict.kind === 'drift' || verdict.kind === 'structural'
      ? divergentDuplicateFinding(ctx, pair, verdict)
      : clonedBodyFinding(ctx, pair, verdict);
    if (finding) out.push(finding);
  }
  return out;
}

type DupKind = 'identical' | 'clone' | 'drift' | 'structural' | 'parallel_family';

interface DupDiff { aLine: number; bLine: number; aText: string; bText: string }

interface DupVerdict {
  kind: DupKind;
  diffs: DupDiff[];
  /** Share of body lines that differ, when the bodies align line for line. */
  diffRatio: number;
}

/**
 * Decide what kind of duplication a near-identical pair actually is.
 *
 * This is the part that keeps the rule honest. Two bodies with the same shape
 * are not automatically a defect:
 *
 *   - when nearly every line differs by a literal, the pair is a deliberate
 *     family of parallel variants (three predicates over the same record, one
 *     per prefix set). Reporting those as "drifted copies" is a false positive,
 *     so they are dropped entirely;
 *   - when the lines differ only in which binding they name, the pair is a
 *     copy waiting to be parameterised — worth saying, but not alarming;
 *   - when the copies agree on almost everything and disagree on a literal, an
 *     operator or a comparison, that is drift: somebody changed one copy. That
 *     is the case worth a reader's attention.
 */
function classifyPair(pair: DupPair): DupVerdict {
  const { a, b, similarity } = pair;
  if (similarity >= 1) return { kind: 'identical', diffs: [], diffRatio: 0 };
  if (a.lines.length !== b.lines.length) return { kind: 'structural', diffs: [], diffRatio: 1 };

  const diffs: DupDiff[] = [];
  for (let i = 0; i < a.lines.length; i++) {
    const al = a.lines[i]!;
    const bl = b.lines[i]!;
    if (al.norm !== bl.norm) {
      diffs.push({ aLine: al.line, bLine: bl.line, aText: al.norm, bText: bl.norm });
    }
  }
  if (diffs.length === 0) return { kind: 'identical', diffs, diffRatio: 0 };

  const diffRatio = diffs.length / a.lines.length;
  if (diffRatio >= 0.5) return { kind: 'parallel_family', diffs, diffRatio };

  const behavioural = diffs.some((d) => differenceLooksBehavioural(d.aText, d.bText));
  return { kind: behavioural ? 'drift' : 'clone', diffs, diffRatio };
}

/** Whether a difference changes behaviour rather than only which name is used. */
function differenceLooksBehavioural(aText: string, bText: string): boolean {
  // A digit inside an identifier (VALUE_1, sha256) is not a literal: counting
  // it as one would report a renamed copy as a drifted one.
  const numbers = (s: string): string[] => s.match(/(?<![\w$])\d+(?:\.\d+)?/g) ?? [];
  if (numbers(aText).join(',') !== numbers(bText).join(',')) return true;
  const ops = (s: string): string[] => s.match(/===|!==|==|!=|>=|<=|[<>+\-*/%]|&&|\|\||\?\?|!/g) ?? [];
  if (ops(aText).join(',') !== ops(bText).join(',')) return true;
  const strings = (s: string): string[] => s.match(/'[^']*'|"[^"]*"|`[^`]*`/g) ?? [];
  return strings(aText).join(',') !== strings(bText).join(',');
}

/** A title fragment that stays readable when both copies share a name. */
function pairLabel(a: DupCandidate, b: DupCandidate): string {
  const base = (path: string): string => path.slice(path.lastIndexOf('/') + 1);
  if (a.symbol.name !== b.symbol.name) return `${a.symbol.name}() and ${b.symbol.name}()`;
  if (a.path !== b.path) return `${a.symbol.name}() in ${base(a.path)} and in ${base(b.path)}`;
  return `two copies of ${a.symbol.name}() in ${base(a.path)}`;
}

function divergentDuplicateFinding(ctx: AnalyzerContext, pair: DupPair, verdict: DupVerdict): Finding | undefined {
  const { map } = ctx;
  const { a, b, similarity } = pair;
  const diff = verdict.diffs[0];
  const structural = verdict.kind === 'structural';
  const sameFile = a.path === b.path;
  const pct = Math.round(similarity * 100);

  const aEv = solidEvidence(map, a.path, [
    map.evidenceLine(a.path, diff?.aLine ?? a.symbol.startLine, `${a.symbol.name}() — first copy of the logic`),
    map.evidenceLine(a.path, a.symbol.startLine, `${a.symbol.name}() — first copy of the logic`),
  ], `${a.symbol.name}() — first copy of the logic`);

  const bEv = solidEvidence(map, b.path, [
    map.evidenceLine(b.path, diff?.bLine ?? b.symbol.startLine,
      diff ? `${b.symbol.name}() — second copy, which disagrees with the first at this line`
        : `${b.symbol.name}() — second copy of the same logic`),
    map.evidenceLine(b.path, b.symbol.startLine, `${b.symbol.name}() — second copy`),
  ], `${b.symbol.name}() — second copy`);

  if (!aEv.verified || !bEv.verified) return undefined;

  const divergenceSentence = diff
    ? `The bodies line up statement for statement except at ${verdict.diffs.length === 1 ? 'one line' : `${verdict.diffs.length} lines`}: ` +
      `${a.path}:${diff.aLine} reads \`${diff.aText}\` while ${b.path}:${diff.bLine} reads \`${diff.bText}\`.`
    : 'The bodies do not line up statement for statement — one copy has gained or lost a statement — so compare the two spans ' +
      'directly rather than trusting a single line reference.';

  return ctx.finding({
    ruleId: 'quality.duplication.divergent_logic',
    title: `${pairLabel(a, b)}: near-duplicate logic that has already drifted apart`,
    severity: structural ? 'medium' : 'high',
    confidence: structural ? 'moderate' : 'strong',
    status: structural ? 'suspected' : undefined,
    detectionSource: sameFile ? 'static' : 'graph',
    files: sameFile ? [a.path] : [a.path, b.path],
    symbol: a.symbol.name,
    evidence: [aEv, bEv],
    trace: sameFile ? undefined : {
      kind: 'import',
      steps: [
        { file: a.path, line: a.symbol.startLine, symbol: a.symbol.name, detail: `body of ${a.symbol.name}() normalised to ${a.tokens.length} tokens` },
        { file: b.path, line: b.symbol.startLine, symbol: b.symbol.name, detail: `body of ${b.symbol.name}() normalised to ${b.tokens.length} tokens` },
        { file: b.path, line: diff?.bLine ?? b.symbol.startLine, detail: `sequence similarity ${pct}% against the first copy, so the two are copies that no longer agree` },
      ],
      complete: true,
    },
    explanation:
      (sameFile
        ? `${a.symbol.name}() and ${b.symbol.name}(), both in ${a.path}, implement the same rule twice. `
        : `${a.symbol.name}() in ${a.path} and ${b.symbol.name}() in ${b.path} implement the same rule twice. `) +
      `After stripping comments ` +
      `and normalising whitespace, their bodies are ${pct}% identical as token sequences — close enough that one was copied from the ` +
      `other, and not identical. ${divergenceSentence} ` +
      (structural
        ? 'A structural difference between two copies of one rule means they have genuinely parted company, not merely been renamed. '
        : 'The difference is not cosmetic — a literal, an operator or a comparison differs — so the two copies compute different ' +
          'answers for the same input. ') +
      'Two copies that still agree are a tidiness problem. Two copies that have drifted are a correctness problem that is invisible at ' +
      'every individual call site: whichever copy a caller happens to reach decides the answer it gets, and both call sites look ' +
      'correct on their own.',
    userImpact:
      'Users get different results from the same input depending on which code path serves their request — one route, job or screen ' +
      'applies the older version of the rule and another applies the newer one, with no error raised in either. When the rule is next ' +
      'corrected in one copy, the other keeps the old behaviour, so the defect reappears for whoever takes the untouched path, and it ' +
      'reappears without any change to the code that gets blamed.',
    likelyRootCause:
      'One function was copied to serve a second caller — typically because the original was awkward to import from — and a later ' +
      'change was applied to only one of them.',
    downstreamConsequences: [
      'A fix or a test added against one copy gives no protection to the other.',
      'Reviewers reading either copy in isolation see nothing wrong, so the divergence survives review.',
      'Any further copy made from either version inherits that version of the rule.',
    ],
    remediation:
      'Decide which behaviour is correct — the two cannot both be — then keep exactly one implementation and have the other call site ' +
      'use it. ' +
      (sameFile
        ? 'Keep the surviving function in this file and delete the other. '
        : 'Put the surviving function where both callers can import it — a shared module, rather than one of these two files importing ' +
          'the other — and delete the copy. ') +
      'Before deleting, write a test for each input where the two disagreed, pinning the ' +
      'intended answer, so the behaviour change on the losing call path is deliberate and visible in the diff instead of a side effect ' +
      'of the refactor.',
    effort: 'small',
    verificationSteps: [
      `Confirm one definition of this logic remains and that every call site of ${a.symbol.name}() and ${b.symbol.name}() resolves to it.`,
      diff
        ? `Add a test for the input that distinguished the copies (${a.path}:${diff.aLine} versus ${b.path}:${diff.bLine}) and assert the intended result.`
        : 'Add tests covering the inputs where the two implementations disagree, including the statement present in only one of them.',
      'Search the repository for any further copy of the same rule before closing this out.',
    ],
    references: [REF.cleanCode, REF.cwe1041],
  });
}

function clonedBodyFinding(ctx: AnalyzerContext, pair: DupPair, verdict: DupVerdict): Finding | undefined {
  const { map } = ctx;
  const { a, b } = pair;
  const sameFile = a.path === b.path;
  const renamed = verdict.kind === 'clone';
  const diff = verdict.diffs[0];

  const aEv = map.evidenceLine(map.filesByPath.has(a.path) ? a.path : a.path, a.symbol.startLine,
    `${a.symbol.name}() — one of two equivalent bodies`);
  const bEv = map.evidenceLine(b.path, diff?.bLine ?? b.symbol.startLine,
    renamed
      ? `${b.symbol.name}() — the same body with a different binding at this line`
      : `${b.symbol.name}() — the other equivalent body`);
  if (!aEv.verified || !bEv.verified) return undefined;

  return ctx.finding({
    ruleId: 'quality.duplication.identical_logic',
    title: renamed
      ? `${pairLabel(a, b)}: the same body with a different binding substituted`
      : `${pairLabel(a, b)}: equivalent bodies`,
    severity: 'low',
    confidence: 'strong',
    detectionSource: sameFile ? 'static' : 'graph',
    files: sameFile ? [a.path] : [a.path, b.path],
    symbol: a.symbol.name,
    evidence: [aEv, bEv],
    trace: sameFile ? undefined : {
      kind: 'import',
      steps: [
        { file: a.path, line: a.symbol.startLine, symbol: a.symbol.name, detail: 'first implementation' },
        { file: b.path, line: b.symbol.startLine, symbol: b.symbol.name, detail: renamed ? 'same statements, differing only in which binding they name' : 'equivalent statements' },
      ],
      complete: true,
    },
    explanation:
      (sameFile
        ? `${a.symbol.name}() and ${b.symbol.name}(), both in ${a.path}, have the same body after comments and whitespace are `
        : `${a.symbol.name}() in ${a.path} and ${b.symbol.name}() in ${b.path} have the same body after comments and whitespace are `) +
      `removed (${a.tokens.length} tokens each)` +
      (renamed && diff
        ? `, differing only in which binding is named — ${a.path}:${diff.aLine} reads \`${diff.aText}\` where ${b.path}:${diff.bLine} ` +
          'reads `' + diff.bText + '`. That is one function with a substituted input, written out twice. '
        : '. ') +
      'The copies agree today, which is what keeps this low severity. What they do not have is anything holding them in step: the ' +
      'first change applied to one of them produces the drifted pair that is genuinely hard to find, because at that point nothing ' +
      'reports the two as related any more.',
    userImpact:
      'No user-visible difference today. The cost arrives with the next change to this rule: it will be applied to one copy, and the ' +
      'paths that use the other keep the old behaviour, so the same action produces different results depending on how it was reached.',
    likelyRootCause: renamed
      ? 'The varying input was substituted by copying the function rather than by adding a parameter.'
      : 'Copy-and-paste reuse, usually because importing the original would have meant moving it.',
    downstreamConsequences: [
      'Test coverage of one copy reports as coverage of the behaviour, while the other copy stays untested.',
      'Code search returns two results for one rule, so later readers cannot tell which is authoritative.',
    ],
    remediation: renamed
      ? 'Keep one function and pass the varying value in as a parameter, then have both call sites use it. This is the cheapest kind of ' +
        'de-duplication to do and to review, because the extraction is mechanical and the parameter makes the real difference between ' +
        'the two uses explicit at the call site instead of implicit in a second function name.'
      : 'Extract the body into one shared function and call it from both sites. Keep it in a module both callers can already import, so ' +
        'the change does not introduce a new dependency direction between these two files.',
    effort: 'trivial',
    verificationSteps: [
      'Confirm a single definition remains and both call sites resolve to it.',
      'Run the existing test suite; a pure extraction should not change behaviour.',
    ],
    references: [REF.cleanCode, REF.cwe1041],
  });
}

// ---------------------------------------------------------------- complexity --

/**
 * Decision points in a body: McCabe-style, counted over the masked AST span.
 *
 * `body` must already have its literals masked, otherwise prose is counted as
 * control flow.
 */
function decisionPoints(body: string, language: string): { total: number; detail: Record<string, number> } {
  const count = (re: RegExp): number => (body.match(re) ?? []).length;
  const pythonish = language === 'python' || language === 'ruby';
  const detail: Record<string, number> = {
    conditionals: count(/\bif\b|\belif\b|\bunless\b/g),
    loops: count(/\bfor\b|\bwhile\b/g),
    switchCases: count(/\bcase\s/g),
    catches: count(/\bcatch\b|\bexcept\b|\brescue\b/g),
    logicalOperators: count(pythonish ? /\band\b|\bor\b/g : /&&|\|\||\?\?/g),
    ternaries: count(/(?<![\w$\])?])\?(?![.?:])/g),
  };
  let total = 0;
  for (const v of Object.values(detail)) total += v;
  return { total, detail };
}

function overComplexFunctions(ctx: AnalyzerContext, idx: QIndex): Finding[] {
  const { map } = ctx;
  const out: Finding[] = [];

  const measured: Array<{
    mod: ParsedModule; sym: SymbolInfo; span: number; complexity: number;
    detail: Record<string, number>;
  }> = [];

  for (const mod of idx.analysable) {
    for (const sym of mod.symbols) {
      if (!FUNCTION_KINDS.has(sym.kind)) continue;
      const span = sym.endLine - sym.startLine + 1;
      if (span < T.complexityMinSpan && span < T.longSpan) continue;
      const source = maskedSymbolSource(map, idx, mod.path, sym);
      const body = bodyOf(source, sym.startLine);
      if (!body) continue;
      const { total, detail } = decisionPoints(body.text, mod.language);
      const complexity = total + 1;
      const reportable =
        (complexity >= T.complexityReportable && span >= T.complexityMinSpan) ||
        complexity >= T.complexityHigh ||
        (span >= T.longSpan && complexity >= T.longSpanComplexity);
      if (!reportable) continue;
      measured.push({ mod, sym, span, complexity, detail });
    }
  }

  // Report the outermost function only: a nested arrow inside a huge handler is
  // the same problem counted twice, so the enclosing symbol is settled first.
  measured.sort((a, b) => b.span - a.span);
  const outermost = measured.filter((m, i) => !measured.slice(0, i).some(
    (p) => p.mod.path === m.mod.path && contains(p.sym, m.sym),
  ));
  // Then report worst-first, so a capped list is the list that matters.
  outermost.sort((a, b) => b.complexity - a.complexity);

  for (const m of outermost) {
    if (out.length >= T.complexityMaxFindings) break;

    const ev = map.evidenceLine(m.mod.path, m.sym.startLine,
      `${m.sym.name} spans ${m.span} lines with ${m.complexity} independent paths through it`);
    if (!ev.verified) continue;

    const parts = Object.entries(m.detail)
      .filter(([, v]) => v > 0)
      .map(([k, v]) => `${v} ${k.replace(/([A-Z])/g, ' $1').toLowerCase()}`)
      .join(', ');

    const callsInside = m.mod.calls.filter((c) => c.line >= m.sym.startLine && c.line <= m.sym.endLine);
    const awaitedCalls = callsInside.filter((c) => c.awaited).length;
    const severity: Severity = m.complexity >= T.complexityHigh ? 'high' : 'medium';

    out.push(ctx.finding({
      ruleId: 'quality.complexity.excessive_decision_count',
      title: `${m.sym.name} has ${m.complexity} paths through it across ${m.span} lines`,
      severity,
      confidence: 'strong',
      files: [m.mod.path],
      symbol: m.sym.name,
      evidence: [ev],
      explanation:
        `${m.sym.name} contains ${parts || 'no branching'} — ${m.complexity} independent paths — inside a single ${m.span}-line body` +
        (awaitedCalls > 0 ? `, with ${awaitedCalls} awaited call(s) interleaved between the branches` : '') +
        '. The problem is not the length. It is that a reader changing one branch cannot see, within one screen, which of the other ' +
        `${m.complexity - 1} paths share state with it, so the blast radius of an edit here is not visible to the person making it. ` +
        'It also sets the number of tests needed to cover the function: full branch coverage requires at least one case per path, ' +
        'which is why functions shaped like this are usually tested only on their happy path.',
      userImpact:
        'Changes in this function are the ones most likely to reach users as a regression: a path that was not exercised during review ' +
        'or testing behaves differently, and because the paths are entangled the symptom usually appears somewhere other than the edit. ' +
        'The practical effect is slower fixes and repeat failures in the same area.',
      likelyRootCause:
        'A function that started small accumulated cases — extra conditions, an extra mode, an error branch — without ever being split, ' +
        'because each individual addition was small.',
      downstreamConsequences: [
        'Branch coverage is expensive to reach here, so the untested paths stay untested.',
        'Code review degrades to reading the diff rather than the function, which is how interaction bugs get through.',
        'Any extraction done later is riskier because shared mutable state has had time to spread across the branches.',
      ],
      remediation:
        'Split along the seams rather than by line count: pull each independent decision into a named function that takes what it needs ' +
        'and returns a value, replace nested conditionals with early returns to flatten the paths, and move any dispatch on a mode or ' +
        'type to a lookup keyed by that value. Do the extraction in steps with the tests running between each, and add a test for a path ' +
        'before you move it so the extraction is verifiable rather than hopeful.',
      effort: m.span >= T.longSpan ? 'large' : 'medium',
      verificationSteps: [
        `Confirm the behaviour of ${m.sym.name} is unchanged by running the existing tests before and after each extraction step.`,
        'Confirm each extracted function is reachable from a test that fails if its logic is removed.',
        'Re-measure the decision count of the remaining function and confirm it has actually fallen, not moved.',
      ],
      references: [REF.cwe1121, REF.cleanCode],
    }));
  }
  return out;
}

// ---------------------------------------------------------------- cycles -----

interface Edge { from: string; to: string; line: number; specifier: string }

function valueEdges(map: RepoMap, idx: QIndex): Edge[] {
  const out: Edge[] = [];
  for (const mod of map.modules.values()) {
    if (!mod.parsed) continue;
    const lines = strippedLinesOf(map, idx, mod.path);
    for (const imp of mod.imports) {
      if (!imp.resolvedPath) continue;
      if (imp.resolvedPath === mod.path) continue;
      // `import type` is erased at compile time, so a cycle made only of type
      // imports is not a cycle at runtime and must not be reported as one.
      if (isTypeOnlyImport(lines, imp.line)) continue;
      out.push({ from: mod.path, to: imp.resolvedPath, line: imp.line, specifier: imp.specifier });
    }
  }
  return out;
}

/** One concrete cycle per strongly connected component, via depth-first walk. */
function findCycles(edges: Edge[]): Edge[][] {
  const adjacency = new Map<string, Edge[]>();
  for (const e of edges) {
    const list = adjacency.get(e.from) ?? [];
    list.push(e);
    adjacency.set(e.from, list);
  }

  const cycles: Edge[][] = [];
  const seenKeys = new Set<string>();
  const state = new Map<string, number>(); // 0 unvisited, 1 on stack, 2 done
  const stack: Edge[] = [];

  const visit = (node: string): void => {
    state.set(node, 1);
    for (const edge of adjacency.get(node) ?? []) {
      const s = state.get(edge.to) ?? 0;
      if (s === 1) {
        // Found a back edge: the cycle is the stack from edge.to onwards.
        const start = stack.findIndex((e) => e.from === edge.to);
        if (start === -1) continue;
        const cycle = [...stack.slice(start), edge];
        const nodes = cycle.map((e) => e.from);
        const key = [...nodes].sort().join('>');
        if (!seenKeys.has(key)) { seenKeys.add(key); cycles.push(cycle); }
        continue;
      }
      if (s === 0) {
        stack.push(edge);
        visit(edge.to);
        stack.pop();
      }
    }
    state.set(node, 2);
  };

  for (const node of adjacency.keys()) {
    if ((state.get(node) ?? 0) === 0) visit(node);
  }
  return cycles;
}

/**
 * Whether the import statement starting at `line` is erased at compile time.
 *
 * Both spellings matter: `import type { A } from …` and the per-specifier
 * `import { type A, type B } from …`. Treating an erased import as a runtime
 * edge would report a type-only loop as a dependency cycle, which is the one
 * false positive this rule can plausibly produce.
 */
function isTypeOnlyImport(lines: string[], line: number): boolean {
  let statement = '';
  for (let i = line - 1; i < lines.length && i < line + 29; i++) {
    statement += (lines[i] ?? '') + ' ';
    if (/\bfrom\b/.test(statement)) break;
  }
  if (/\b(?:import|export)\s+type\b/.test(statement)) return true;
  const braces = /\{([^}]*)\}/.exec(statement);
  if (!braces) return false;
  const specifiers = braces[1]!.split(',').map((x) => x.trim()).filter((x) => x.length > 0);
  if (specifiers.length === 0) return false;
  // A default or namespace binding outside the braces is a value import.
  if (/\b(?:import|export)\s+(?:[\w$]+\s*,|\*)/.test(statement)) return false;
  return specifiers.every((x) => /^type\s/.test(x));
}

function dependencyCycles(ctx: AnalyzerContext, idx: QIndex): Finding[] {
  const { map } = ctx;
  const out: Finding[] = [];
  const cycles = findCycles(valueEdges(map, idx));

  cycles.sort((a, b) => a.length - b.length);

  for (const cycle of cycles) {
    if (out.length >= T.cycleMaxFindings) break;
    const files = [...new Set(cycle.map((e) => e.from))];
    if (files.some((f) => isTestLike(map, f))) continue;

    const evidence: Evidence[] = [];
    for (const edge of cycle) {
      const ev = map.evidenceLine(edge.from, edge.line,
        `imports '${edge.specifier}', which resolves to ${edge.to}`);
      if (ev.verified) evidence.push(ev);
    }
    if (evidence.length !== cycle.length) continue;

    const pathText = [...files, files[0]!].join(' → ');
    const twoNode = files.length === 2;

    out.push(ctx.finding({
      ruleId: 'quality.architecture.dependency_cycle',
      title: `Import cycle across ${files.length} module(s): ${pathText}`,
      severity: twoNode ? 'medium' : 'high',
      confidence: 'strong',
      detectionSource: 'graph',
      files,
      evidence,
      trace: {
        kind: 'import',
        steps: cycle.map((e) => ({
          file: e.from,
          line: e.line,
          detail: `imports '${e.specifier}' → ${e.to}`,
        })),
        complete: true,
      },
      explanation:
        `These modules import each other in a loop: ${pathText}. Every import in the loop is a value import — type-only imports were ` +
        'excluded, because those disappear at compile time and cannot form a runtime cycle. A cycle means there is no order in which ' +
        'these modules can be initialised correctly: whichever one the bundler or runtime loads first sees the others only partly ' +
        'evaluated, so a binding read at module scope during that window is `undefined`. It also means the modules cannot be reasoned ' +
        'about, tested, or extracted separately — they are one unit with several filenames.',
      userImpact:
        'Cycles of this kind surface as failures that depend on load order rather than on user input: a value is `undefined` the first ' +
        'time a page or endpoint is hit after a cold start, or after an unrelated import is added and the order shifts. Users see an ' +
        'error that nobody can reproduce locally, and the file that was last edited is usually not the file at fault.',
      likelyRootCause:
        'A helper was needed in the opposite direction from the existing dependency, and it was imported in place rather than moved to ' +
        'a module both sides could depend on.',
      downstreamConsequences: [
        'Load-order bugs are reproducible only with the same entry point and bundler settings, which makes them expensive to chase.',
        'Neither module can be unit tested without pulling in the whole cycle.',
        'Tree-shaking and code splitting are limited, because the bundler must keep the group together.',
      ],
      remediation:
        'Break the loop at one edge rather than adding a lazy `require` to hide it. Move the shared pieces the loop exists for into a ' +
        'module that neither participant imports back — types and constants first, then any helper both sides call — so the dependency ' +
        `becomes one-directional. Where the cycle exists only for types, switch those imports to \`import type\`, which removes the ` +
        'runtime edge entirely. Only if the cycle is genuinely bidirectional behaviour should you consider inverting it with a ' +
        'parameter or callback passed in by the caller.',
      effort: twoNode ? 'medium' : 'large',
      verificationSteps: [
        'Re-run the import graph (or a cycle checker in the build) and confirm this loop is gone, not merely deferred.',
        `Import ${files[0]} first in a fresh process and confirm every module-scope binding it reads is defined.`,
        'Add a build-time cycle check so a reintroduced edge fails CI rather than being found in production.',
      ],
      references: [REF.cwe1047, 'Robert C. Martin — the Acyclic Dependencies Principle'],
    }));
  }
  return out;
}

// --------------------------------------------------------------- dead code ---

const ENTRY_POINT_PATTERNS: RegExp[] = [
  /(^|\/)index\.[cm]?[jt]sx?$/,
  /(^|\/)main\.[cm]?[jt]sx?$/,
  /(^|\/)(page|layout|template|loading|error|global-error|not-found|default|route|middleware|instrumentation|sitemap|robots|manifest|opengraph-image|twitter-image|icon|apple-icon|head)\.[cm]?[jt]sx?$/,
  /(^|\/)_(app|document|middleware|error)\.[cm]?[jt]sx?$/,
  /(^|\/)(server|app|worker|cli|entry|entry-server|entry-client|bootstrap|register)\.[cm]?[jt]sx?$/,
  /(^|\/)bin\//,
  /(^|\/)scripts?\//,
  /(^|\/)migrations?\//,
  /\.config\.[cm]?[jt]sx?$/,
  /\.d\.ts$/,
  /(^|\/)(__init__|conftest|manage|wsgi|asgi|settings|urls|views|admin|apps|models|setup)\.py$/,
  /(^|\/)main\.(py|go|rs|java|rb)$/,
];

function isEntryPoint(map: RepoMap, idx: QIndex, path: string): boolean {
  if (ENTRY_POINT_PATTERNS.some((re) => re.test(path))) return true;
  if (idx.referencedInConfig.has(path)) return true;
  const role = map.filesByPath.get(path)?.role;
  return role === 'route' || role === 'config' || role === 'manifest'
    || role === 'ci' || role === 'infrastructure' || role === 'migration' || role === 'schema';
}

const SERVER_FACTORY_RE =
  /\b(?:express|fastify|Fastify|Koa|Hono|Flask|FastAPI|Sanic|restify|polka|connect)\s*\(|\bnew\s+(?:Koa|Hono|Server|WebSocketServer|ApolloServer)\s*\(|\bcreateServer\s*\(/;
const SERVER_REGISTER_RE =
  /\b\w+\.(?:get|post|put|patch|delete|options|head|all|use|route|register|addHook|router)\s*\(/;
const SERVER_START_RE =
  /\.(?:listen|start|serve|run|fire)\s*\(|\bserve\s*\(|\brun\s*\(\s*(?:app|server)\b|\bcreateServer\s*\([^)]*\)\s*\.listen/;

function deadCode(ctx: AnalyzerContext, idx: QIndex): Finding[] {
  const { map } = ctx;
  const out: Finding[] = [];

  for (const mod of idx.analysable) {
    if (out.length >= T.deadCodeMaxFindings) break;
    if (isEntryPoint(map, idx, mod.path)) continue;

    const exported = mod.symbols.filter((s) => s.exported);
    if (exported.length === 0) continue;

    const file = map.filesByPath.get(mod.path);
    const codeLines = strippedLinesOf(map, idx, mod.path).filter((l) => l.trim().length > 0).length;
    if (codeLines < T.deadCodeMinCodeLines) continue;

    // A name that appears as a string literal somewhere may be resolved
    // through a registry or a dynamic import, which this analysis cannot see.
    if (exported.some((s) => idx.literals.has(s.name))) continue;

    const all = idx.importers.get(mod.path) ?? new Set<string>();
    const prod = idx.prodImporters.get(mod.path) ?? new Set<string>();

    const source = maskedLinesOf(map, idx, mod.path).join('\n');
    const buildsServer = SERVER_FACTORY_RE.test(source) && SERVER_REGISTER_RE.test(source);
    const startsServer = SERVER_START_RE.test(source);

    // --- an HTTP surface that nothing starts and nothing in production imports
    if (buildsServer && !startsServer && prod.size === 0) {
      const factoryLine = findLine(map, idx, mod.path, SERVER_FACTORY_RE);
      const registerLine = findLine(map, idx, mod.path, SERVER_REGISTER_RE);
      const ev: Evidence[] = [];
      const e1 = map.evidenceLine(mod.path, factoryLine ?? 1, 'a server application object is constructed here');
      if (e1.verified) ev.push(e1);
      if (registerLine && registerLine !== factoryLine) {
        const e2 = map.evidenceLine(mod.path, registerLine, 'a request handler is registered on it');
        if (e2.verified) ev.push(e2);
      }
      if (ev.length === 0) continue;

      const testOnlyImporters = [...all].filter((p) => isTestLike(map, p));
      const confidence: Confidence = idx.dynamicSpecifiers ? 'moderate' : 'strong';

      out.push(ctx.finding({
        ruleId: 'quality.dead_code.unstarted_server',
        title: `${mod.path} builds an HTTP server that nothing starts`,
        severity: 'medium',
        confidence,
        detectionSource: 'graph',
        files: [mod.path],
        evidence: ev,
        trace: {
          kind: 'import',
          steps: [
            { file: mod.path, line: factoryLine ?? 1, detail: 'server application object constructed at module scope' },
            { file: mod.path, line: registerLine ?? factoryLine ?? 1, detail: 'request handler(s) registered on that object' },
            { file: mod.path, detail: 'no listen/serve/start call anywhere in this module' },
            ...(testOnlyImporters.length > 0
              ? testOnlyImporters.map((p) => ({ file: p, detail: 'the only importer of this module, and it is a test file' }))
              : [{ file: mod.path, detail: 'no module in the snapshot imports this file' }]),
          ],
          complete: !idx.dynamicSpecifiers,
        },
        explanation:
          `${mod.path} constructs a server application and registers request handler(s) on it, but the module never calls listen, ` +
          `serve or start, and ` +
          (testOnlyImporters.length > 0
            ? `the only module that imports it is ${testOnlyImporters.join(', ')}, which is test code. `
            : 'no other module in the snapshot imports it. ') +
          'No manifest script or configuration file names this file either. The handlers in it are therefore not served by anything: ' +
          'the routes exist in the repository and not in the running system. This matters more than ordinary unused code because the ' +
          'file reads as live infrastructure — anyone auditing the application\'s HTTP surface, or its authorisation, will count these ' +
          'routes as real.' +
          (idx.dynamicSpecifiers
            ? ' Note: some module in this repository builds an import specifier at runtime, which this analysis cannot resolve, so ' +
              'confirm there is no dynamic loader for this file before deleting it.'
            : ''),
        userImpact:
          'No user can reach anything defined here, so any feature this file appears to provide is simply absent — a request to one of ' +
          'these paths fails rather than being served. The reverse risk is just as real: the code looks like a live endpoint, so a ' +
          'security or behaviour review of the application\'s surface can be drawn to the wrong file while the real handler goes ' +
          'unexamined.',
        likelyRootCause:
          'A server implementation was superseded by another framework or routing layer and left in place, with its start-up call ' +
          'removed or never written.',
        downstreamConsequences: [
          'Dependencies exist in the manifest only to support code that never runs, enlarging the install and the vulnerability surface.',
          'Any defect in these handlers is unexploitable today and becomes exploitable the moment somebody wires the file up.',
          'Readers and audits treat the routes as part of the live API.',
        ],
        remediation:
          'Decide whether this surface is wanted. If it is not, delete the file and drop the dependencies that existed only for it — ' +
          'deletion is the only change that removes the maintenance and audit cost. If it is wanted, add the start-up call and an entry ' +
          `point that runs it (a manifest script or a process definition), then give the handlers the same authentication, validation ` +
          'and logging as the rest of the API before exposing them. If it is kept only for the tests that import it, move it under the ' +
          'test tree so its status is unambiguous.',
        effort: 'small',
        verificationSteps: [
          'Search the repository and deployment configuration for this path and confirm nothing other than tests references it.',
          'Confirm no process definition, container entry point or manifest script starts this module.',
          'After deleting it, confirm the build and the test suite still pass and that no route disappears from the live API.',
        ],
        references: [REF.cwe561, REF.cleanCode],
      }));
      continue;
    }

    // --- an exported surface with no importer at all
    if (all.size > 0) continue;

    const names = exported.map((s) => s.name);
    const ev = map.evidenceLine(mod.path, exported[0]!.startLine,
      `${names.slice(0, 4).join(', ')}${names.length > 4 ? `, +${names.length - 4} more` : ''} exported here; no module in the snapshot imports this file`);
    if (!ev.verified) continue;

    const looksLikeComponent = (file?.language === 'tsx' || file?.language === 'jsx')
      && mod.jsx.length > 0;
    const confidence: Confidence = idx.dynamicSpecifiers ? 'moderate' : 'strong';

    out.push(ctx.finding({
      ruleId: 'quality.dead_code.unreferenced_module',
      title: `${mod.path} exports ${names.length} symbol(s) that nothing imports`,
      severity: 'low',
      confidence,
      detectionSource: 'graph',
      files: [mod.path],
      symbol: names[0],
      evidence: [ev],
      trace: {
        kind: 'import',
        steps: [
          { file: mod.path, line: exported[0]!.startLine, detail: `exports ${names.join(', ')}` },
          { file: mod.path, detail: 'the resolved import graph, including re-export edges, contains no edge pointing at this file' },
          { file: mod.path, detail: 'the path does not match a framework entry-point convention and is not named by any manifest, CI or infrastructure file' },
        ],
        complete: !idx.dynamicSpecifiers,
      },
      explanation:
        `Nothing in this snapshot imports ${mod.path}. The importer index was built from resolved imports and from \`export … from\` ` +
        're-export edges, so a barrel file would have counted; none points here. The path is not a framework convention entry point ' +
        '(a page, route, layout, config or binary) and no manifest script, CI definition or infrastructure file names it, so there is ' +
        `no non-import route into it either. ${names.length === 1 ? 'The exported symbol is' : 'The exported symbols are'} ` +
        `${names.slice(0, 6).join(', ')}.` +
        (looksLikeComponent
          ? ' It renders UI, so the practical reading is that this component is never mounted — the markup and behaviour in it are not ' +
            'part of any screen a user can open.'
          : '') +
        (idx.dynamicSpecifiers
          ? ' Confidence is held down because some module here builds an import specifier at runtime, which cannot be resolved ' +
            'statically; check for a dynamic loader before deleting.'
          : ''),
      userImpact:
        (looksLikeComponent
          ? 'Users never see this interface. If it is the intended path for an action, the feature is missing rather than broken, which ' +
            'is why it will not show up as an error anywhere — there is simply nothing to click.'
          : 'No user behaviour depends on this code today, so the direct impact is nil.') +
        ' The indirect cost is borne by everyone who reads the repository afterwards: this code is kept compiling, kept passing review, ' +
        'and counted as part of the system when effort is estimated and when behaviour is reasoned about.',
      likelyRootCause:
        'A module was written ahead of the call site that was meant to use it, or its last caller was removed without removing it.',
      downstreamConsequences: [
        'Refactors must keep this code type-correct even though no behaviour depends on it.',
        'Any defect inside it is unreachable now and lands fully formed whenever it is wired up.',
        'Its imports keep dependencies in the manifest that nothing running needs.',
      ],
      remediation:
        'Confirm the intent, then act on it rather than leaving it ambiguous. If the code is obsolete, delete it — version control is ' +
        'the archive, and a commented-out or merely unreferenced file is not. If it was written for a call site that was never built, ' +
        'either wire it up now or remove it and reinstate it from history when the caller exists. If it is genuinely reachable through ' +
        'a dynamic import or a registry keyed by string, make that reference explicit (a static import in a registry module) so both ' +
        'tooling and readers can see it.',
      effort: 'trivial',
      verificationSteps: [
        `Search the whole repository, including configuration and templates, for '${names[0]}' and for the module path.`,
        'Confirm no dynamic import or string-keyed registry resolves to this module.',
        'Delete it on a branch and confirm the build, type check and test suite all still pass.',
      ],
      references: [REF.cwe561],
    }));
  }
  return out;
}

/** First line of a file whose comment-free, literal-masked text matches. */
function findLine(map: RepoMap, idx: QIndex, path: string, re: RegExp): number | undefined {
  const lines = maskedLinesOf(map, idx, path);
  for (let i = 0; i < lines.length; i++) if (re.test(lines[i]!)) return i + 1;
  return undefined;
}

// -------------------------------------------------------- layer separation ---

const DB_PACKAGE_RE =
  /^(?:@prisma\/client|prisma|pg|mysql2?|mongoose|mongodb|sequelize|typeorm|knex|drizzle-orm|better-sqlite3|sqlite3|ioredis|redis|@planetscale\/database|@neondatabase\/serverless|cassandra-driver|@aws-sdk\/client-dynamodb|psycopg2?|sqlalchemy|pymongo)(?:\/|$)/;
const DB_CLIENT_CONSTRUCT_RE =
  /\bnew\s+(?:PrismaClient|Pool|Client|Sequelize|DataSource|MongoClient|Redis|DynamoDBClient)\s*\(|\bcreatePool\s*\(|\bdrizzle\s*\(|\bknex\s*\(/;

function isClientSide(map: RepoMap, idx: QIndex, mod: ParsedModule): boolean {
  const lines = strippedLinesOf(map, idx, mod.path);
  const head = lines.slice(0, 5).join('\n');
  if (/^\s*['"]use client['"]/m.test(head)) return true;
  if (/^\s*['"]use server['"]/m.test(head)) return false;
  const language = map.filesByPath.get(mod.path)?.language;
  const isView = language === 'tsx' || language === 'jsx' || language === 'vue' || language === 'svelte';
  return idx.clientOnlyReact && isView && mod.jsx.length > 0;
}

function layerViolations(ctx: AnalyzerContext, idx: QIndex): Finding[] {
  const { map } = ctx;
  const out: Finding[] = [];

  for (const mod of idx.analysable) {
    if (!isClientSide(map, idx, mod)) continue;

    for (const imp of mod.imports) {
      // Direct dependency on a database driver from browser code.
      const directDriver = DB_PACKAGE_RE.test(imp.specifier);
      // Or on a first-party module whose job is to hold the database client.
      let viaModule: ParsedModule | undefined;
      if (!directDriver && imp.resolvedPath) {
        const target = map.modules.get(imp.resolvedPath);
        if (target?.parsed) {
          const targetSource = maskedLinesOf(map, idx, target.path).join('\n');
          const ownsClient = target.imports.some((i) => DB_PACKAGE_RE.test(i.specifier))
            && DB_CLIENT_CONSTRUCT_RE.test(targetSource);
          if (ownsClient) viaModule = target;
        }
      }
      if (!directDriver && !viaModule) continue;

      const ev: Evidence[] = [];
      const e1 = map.evidenceLine(mod.path, imp.line,
        directDriver
          ? `browser-side module imports the database driver '${imp.specifier}' directly`
          : `browser-side module imports ${viaModule!.path}, which constructs the database client`);
      if (!e1.verified) continue;
      ev.push(e1);

      if (viaModule) {
        const line = findLine(map, idx, viaModule.path, DB_CLIENT_CONSTRUCT_RE);
        const e2 = map.evidenceLine(viaModule.path, line ?? 1, 'the database client is constructed here, at module scope');
        if (e2.verified) ev.push(e2);
      }

      const files = viaModule ? [mod.path, viaModule.path] : [mod.path];

      out.push(ctx.finding({
        ruleId: 'quality.architecture.layer_violation',
        title: `Browser-side ${mod.path} depends on the database layer`,
        severity: 'high',
        confidence: 'strong',
        detectionSource: 'graph',
        files,
        evidence: ev,
        trace: {
          kind: 'import',
          steps: [
            { file: mod.path, line: 1, detail: 'module runs in the browser (client directive, or a view component in a framework with no server-component boundary)' },
            { file: mod.path, line: imp.line, detail: `imports '${imp.specifier}'` },
            ...(viaModule
              ? [{ file: viaModule.path, detail: 'that module imports a database driver and constructs a client at module scope' }]
              : [{ file: mod.path, detail: 'the specifier is a database driver package' }]),
          ],
          complete: true,
        },
        explanation:
          `${mod.path} executes in the browser, and its import chain reaches the database layer. This crosses the one boundary a web ` +
          'application cannot blur: data access belongs behind a request, where the credential lives and where the query can be ' +
          'authorised. Pulled into client code, the module is either bundled — taking its connection string and driver with it — or it ' +
          'breaks the build when the driver\'s Node-only dependencies are resolved for the browser. Either way the layering that lets ' +
          'the server decide what a given caller may read has been bypassed at the import level, which is where it is easiest to fix ' +
          'and hardest to notice.',
        userImpact:
          'Depending on how the bundler resolves this, users either receive a bundle that contains database connection details and ' +
          'driver code, or the page fails to build and nobody can use the feature at all. In the first case any user can read the ' +
          'credential out of the shipped JavaScript and reach the database directly, with no authorisation in the way.',
        likelyRootCause:
          'A helper or a type was needed in a component and the nearest module that had it also owned the database client, so the ' +
          'import was added without noticing what else came with it.',
        downstreamConsequences: [
          'Server-only secrets can reach the client bundle through this edge even if no query is ever executed there.',
          'The boundary is now easy to cross again, because the precedent and the import both exist.',
          'Build-time failures from this pattern are often "fixed" with bundler aliases or polyfills, which hides the layering problem.',
        ],
        remediation:
          'Keep data access on the server and give the client a request-shaped interface instead: expose an endpoint, server action or ' +
          'loader that performs the query with the caller\'s identity applied, and have the component call that. If only a type or a ' +
          'constant was wanted, move it to a module that imports no driver and import it with `import type` where applicable. Add a ' +
          'build-time rule (an import boundary lint rule, or the framework\'s server-only marker) so this edge fails CI rather than ' +
          'depending on review.',
        effort: 'medium',
        verificationSteps: [
          'Build for production and confirm no database driver or connection string appears in any client chunk.',
          'Confirm the component still works through the server-side interface.',
          'Add an import-boundary check that fails the build if client code imports the data layer again.',
        ],
        references: [REF.rscBoundary, 'OWASP A05:2021 Security Misconfiguration'],
      }));
      break; // one finding per client module is enough to act on
    }
  }
  return out;
}

// ---------------------------------------------------------- testability -----

const EXTERNAL_CLIENT_RE =
  /\bnew\s+(?:PrismaClient|Pool|Client|Sequelize|DataSource|MongoClient|Redis|IORedis|Stripe|OpenAI|Anthropic|S3Client|DynamoDBClient|SQSClient|KafkaJS|Kafka|Twilio|Algoliasearch|ElasticClient)\s*\(|\bcreateClient\s*\(|\bcreatePool\s*\(|\bdrizzle\s*\(|\bknex\s*\(/;

function moduleScopeClients(ctx: AnalyzerContext, idx: QIndex): Finding[] {
  const { map } = ctx;
  const out: Finding[] = [];

  for (const mod of idx.analysable) {
    const importers = idx.importers.get(mod.path) ?? new Set<string>();
    if (importers.size < 2) continue;

    const topLevel = topLevelSymbols(mod).filter((s) => s.kind === 'const' || s.kind === 'class');
    const constructed = topLevel.filter((s) => EXTERNAL_CLIENT_RE.test(maskLiterals(s.text)));
    if (constructed.length === 0) continue;

    // A factory function that returns the client is the seam this rule is about.
    const hasFactory = mod.symbols.some(
      (s) => FUNCTION_KINDS.has(s.kind) && s.exported && EXTERNAL_CLIENT_RE.test(maskLiterals(s.text)),
    );
    if (hasFactory) continue;

    const ev: Evidence[] = [];
    for (const s of constructed.slice(0, 3)) {
      const e = map.evidenceLine(mod.path, s.startLine,
        `${s.name} is constructed at module scope, so importing this file performs the construction`);
      if (e.verified) ev.push(e);
    }
    if (ev.length === 0) continue;

    const readsEnv = mod.envVars.length > 0;
    const names = constructed.map((s) => s.name).join(', ');
    const importerList = [...importers].slice(0, 5);

    out.push(ctx.finding({
      ruleId: 'quality.testability.module_scope_external_client',
      title: `${mod.path} constructs ${names} at import time, with no seam for tests`,
      severity: 'medium',
      confidence: 'strong',
      detectionSource: 'graph',
      files: [mod.path],
      symbol: constructed[0]!.name,
      evidence: ev,
      trace: {
        kind: 'import',
        steps: [
          { file: mod.path, line: constructed[0]!.startLine, detail: `${names} constructed at module scope` },
          ...importerList.map((p) => ({ file: p, detail: 'imports this module, so it inherits that construction' })),
          { file: mod.path, detail: 'no exported factory or injection point returns the client, so a caller cannot substitute one' },
        ],
        complete: true,
      },
      explanation:
        `${mod.path} creates ${names} as a module-scope value, and ${importers.size} module(s) import this file. Because the ` +
        'construction happens on import rather than on first use, every one of those modules — and anything that imports them — runs ' +
        'it merely by being loaded. There is no exported factory and nothing is passed in, so there is no point at which a caller or a ' +
        'test can supply a different implementation. The consequence is that a unit test for any of the importers is not a unit test: ' +
        'it needs the real client to be constructible in the test process, which usually means it needs the real service.' +
        (readsEnv
          ? ` The construction also reads configuration (${mod.envVars.slice(0, 4).join(', ')}) at import time, so a missing or wrong ` +
            'value fails at module load, before any code can report a useful error.'
          : ''),
      userImpact:
        'Users feel this as untested code paths reaching production: the handlers that depend on this module are the expensive ones to ' +
        'test, so in practice they are tested least, and regressions in them are found by users rather than by CI. ' +
        (readsEnv
          ? 'It also changes how failures present: a configuration problem takes the process down at start-up instead of producing a ' +
            'clear error on the one feature that needs the service.'
          : ''),
      likelyRootCause:
        'A shared singleton was the quickest way to avoid reconnecting per request, and the trade-off against substitutability was ' +
        'never revisited.',
      downstreamConsequences: [
        'Tests of the importing modules are integration tests whether or not they are labelled as such.',
        'Teams reach for module mocking to work around this, which couples tests to import paths and breaks on refactor.',
        'Connections are opened by any process that imports the module, including scripts and build steps that never query.',
      ],
      remediation:
        'Introduce a seam without giving up the singleton: export a function that returns the client and creates it on first call, and ' +
        'let callers accept the client (or that function) as a parameter with the shared instance as the default. Keep configuration ' +
        'reading inside that function so a missing value is reported when the feature is used, with the variable name in the message. ' +
        'Tests then pass a fake in directly, and no module-mocking framework is needed.',
      effort: 'medium',
      verificationSteps: [
        'Import this module in a process with no database or service reachable and confirm nothing connects until the client is used.',
        'Write a unit test for one importer that passes a fake client and confirm it runs with no service available.',
        'Confirm production still reuses a single instance rather than creating one per call.',
      ],
      references: ['Michael Feathers, Working Effectively with Legacy Code — seams', REF.twelveFactor],
    }));
  }
  return out;
}

// ------------------------------------------------------------- coupling -----

function couplingPressure(ctx: AnalyzerContext, idx: QIndex): Finding[] {
  const { map } = ctx;
  const out: Finding[] = [];

  for (const mod of idx.analysable) {
    const internal = new Set(
      mod.imports.filter((i) => i.resolvedPath && i.resolvedPath !== mod.path).map((i) => i.resolvedPath!),
    );
    const isBarrel = /(^|\/)index\.[cm]?[jt]sx?$/.test(mod.path);

    // --- fan-out: this module depends on a great many others
    if (!isBarrel && internal.size >= T.fanOutInternal) {
      const first = mod.imports.find((i) => i.resolvedPath);
      const ev = map.evidenceLine(mod.path, first?.line ?? 1,
        `this module imports ${internal.size} other first-party modules`);
      if (ev.verified) {
        out.push(ctx.finding({
          ruleId: 'quality.coupling.excessive_fan_out',
          title: `${mod.path} depends directly on ${internal.size} other modules`,
          severity: internal.size >= T.fanOutHigh ? 'medium' : 'low',
          confidence: 'strong',
          detectionSource: 'graph',
          files: [mod.path],
          evidence: [ev],
          trace: {
            kind: 'import',
            steps: [
              { file: mod.path, line: first?.line ?? 1, detail: `${internal.size} resolved first-party imports` },
              ...[...internal].slice(0, 8).map((p) => ({ file: p, detail: 'imported directly by this module' })),
            ],
            complete: true,
          },
          explanation:
            `${mod.path} imports ${internal.size} first-party modules directly. Fan-out of this size means the module has no single ` +
            'responsibility it can be described by: it is the place where many unrelated things are coordinated. The practical cost is ' +
            'that a change to any of those modules can break this one, so this file appears in the blast radius of changes all over the ' +
            'codebase, and nobody editing those modules has a reason to look here.',
          userImpact:
            'Users see this as unrelated breakage: a change made for one feature takes out another, because both paths run through this ' +
            'module. It also slows fixes, since the file that fails is rarely the file that changed.',
          likelyRootCause:
            'A coordinating module grew by accretion — each new feature added one more import rather than a boundary.',
          downstreamConsequences: [
            'This module cannot be tested without standing up most of the system, so it tends to be covered only end to end.',
            'Build and type-check times for this file grow with every dependency added anywhere beneath it.',
          ],
          remediation:
            'Group the dependencies by the reason they are here and give each group a boundary: one module per concern that exposes the ' +
            'few operations this file actually needs, so this file imports a handful of interfaces rather than a long list of ' +
            'implementations. Where the module is an entry point whose job really is wiring, keep the wiring and move every decision ' +
            'and transformation out of it, so what remains is a list of connections with no logic to regress.',
          effort: 'large',
          verificationSteps: [
            'Confirm the direct first-party import count has fallen and that the removed dependencies are not simply re-exported through one new module.',
            'Confirm a test of this module can run with the new boundaries substituted.',
          ],
          references: [REF.cleanCode, REF.cwe1109],
        }));
      }
    }

    // --- fan-in: a large behavioural module that most of the system depends on
    const importers = idx.importers.get(mod.path) ?? new Set<string>();
    const exportedFunctions = mod.symbols.filter((s) => s.exported && FUNCTION_KINDS.has(s.kind)).length;
    const fileLines = map.filesByPath.get(mod.path)?.lines ?? 0;
    if (importers.size >= T.fanInHub && exportedFunctions >= T.hubExportedFunctions && fileLines >= T.hubLines) {
      const sym = mod.symbols.find((s) => s.exported && FUNCTION_KINDS.has(s.kind));
      const ev = map.evidenceLine(mod.path, sym?.startLine ?? 1,
        `${importers.size} modules import this file, which exports ${exportedFunctions} functions across ${fileLines} lines`);
      if (!ev.verified) continue;

      out.push(ctx.finding({
        ruleId: 'quality.coupling.change_risk_hub',
        title: `${importers.size} modules depend on ${mod.path}, which holds ${exportedFunctions} exported functions`,
        severity: 'medium',
        confidence: 'strong',
        detectionSource: 'graph',
        files: [mod.path],
        evidence: [ev],
        trace: {
          kind: 'import',
          steps: [
            { file: mod.path, line: sym?.startLine ?? 1, detail: `${exportedFunctions} exported functions in ${fileLines} lines` },
            ...[...importers].slice(0, 8).map((p) => ({ file: p, detail: 'imports this module' })),
          ],
          complete: true,
        },
        explanation:
          `${importers.size} modules import ${mod.path}, and it contains behaviour rather than only types or constants ` +
          `(${exportedFunctions} exported functions, ${fileLines} lines). High fan-in is not itself a defect — shared code is the point ` +
          'of modules. It becomes one when the shared module is large and mixed, because then every dependant is coupled to all of it: ' +
          'a change made for one caller is loaded by every caller, and the set of things that must be re-tested after a small edit here ' +
          'is the whole dependant set. Nobody editing this file can see that set from inside it.',
        userImpact:
          'A small change here can degrade unrelated features at once, so incidents originating in this file are broad rather than ' +
          'contained. Teams respond by avoiding changes to it, which means problems inside it stay unfixed and are worked around ' +
          'elsewhere — users keep meeting the same underlying defect in different shapes.',
        likelyRootCause: 'A utility module became the default home for anything more than one caller needed.',
        downstreamConsequences: [
          'The real test scope for any edit here is every dependant, which is rarely what gets run.',
          'Splitting it later is costly precisely because so many modules import it.',
        ],
        remediation:
          'Split by consumer need rather than by topic: identify the clusters of exports that are used together and move each into its ' +
          'own module, then update the dependants to import the narrower module. Keep the old path as a re-export only while the ' +
          'migration is in flight, and remove it afterwards so the coupling genuinely goes away instead of being hidden behind a barrel.',
        effort: 'large',
        verificationSteps: [
          'Confirm each dependant now imports only the narrower module it needs.',
          'Confirm the old aggregate module no longer re-exports everything once the migration is complete.',
        ],
        references: [REF.cleanCode],
      }));
    }
  }
  return out;
}

// ------------------------------------------------------------ modularity ----

function godModules(ctx: AnalyzerContext, idx: QIndex): Finding[] {
  const { map } = ctx;
  const out: Finding[] = [];

  for (const mod of idx.analysable) {
    const file = map.filesByPath.get(mod.path);
    const lines = file?.lines ?? 0;
    if (lines < T.godModuleLines) continue;
    const exported = mod.symbols.filter((s) => s.exported);
    if (exported.length < T.godModuleExports) continue;
    const exportedFunctions = exported.filter((s) => FUNCTION_KINDS.has(s.kind));
    if (exportedFunctions.length < T.godModuleFunctions) continue;
    if (/(^|\/)index\.[cm]?[jt]sx?$/.test(mod.path)) continue;

    const ev = map.evidenceLine(mod.path, exportedFunctions[0]!.startLine,
      `${exported.length} exported symbols (${exportedFunctions.length} of them functions) in a ${lines}-line module`);
    if (!ev.verified) continue;

    out.push(ctx.finding({
      ruleId: 'quality.modularity.oversized_module',
      title: `${mod.path} exports ${exported.length} symbols from ${lines} lines`,
      severity: 'low',
      confidence: 'strong',
      files: [mod.path],
      evidence: [ev],
      explanation:
        `${mod.path} is ${lines} lines long and exports ${exported.length} symbols, ${exportedFunctions.length} of which are ` +
        'functions. A module this wide has no boundary left: an importer that needs one function takes a dependency on all of it, so ' +
        'the import graph stops describing what actually depends on what. That is what makes a change here hard to scope — the ' +
        'dependency list says every importer might be affected, and nothing in the module distinguishes the parts that are genuinely ' +
        'related from the parts that merely share a file.',
      userImpact:
        'Indirect: changes in this area are harder to scope and review, so defects that reach users take longer to trace back here, and ' +
        'a fix for one caller carries avoidable risk for the others.',
      likelyRootCause: 'The module was the obvious place to add each new piece, and no split was ever forced.',
      downstreamConsequences: [
        'Import-graph analysis over-reports dependencies, which blunts impact analysis and test selection.',
        'The file becomes a merge-conflict hotspot, because unrelated work lands in it.',
      ],
      remediation:
        'Split it along the lines its callers already imply: group the exports by which importers use them together, move each group to ' +
        'its own module, and update the importers. Do it in one pass per group with the type checker as the guide rather than all at ' +
        'once, and avoid replacing the file with a barrel that re-exports everything — that keeps the coupling while adding indirection.',
      effort: 'large',
      verificationSteps: [
        'Confirm each new module has a describable single purpose and that no importer pulls in a group it does not use.',
        'Confirm the type check and test suite pass after each group is moved.',
      ],
      references: [REF.cleanCode],
    }));
  }
  return out;
}

// ------------------------------------------------------------ type safety ---

function stripJsonComments(text: string): string {
  return codeText(text, 'json');
}

function parseLooseJson(text: string): unknown {
  const cleaned = stripJsonComments(text).replace(/,(\s*[}\]])/g, '$1');
  try {
    return JSON.parse(cleaned);
  } catch {
    return undefined;
  }
}

function typeSafety(ctx: AnalyzerContext, idx: QIndex): Finding[] {
  const { map } = ctx;
  const out: Finding[] = [];

  const tsFiles = map.files.filter(
    (f) => (f.language === 'typescript' || f.language === 'tsx')
      && !f.generated && !f.vendored && !isTestLike(map, f.path) && !/\.d\.ts$/.test(f.path),
  );
  if (tsFiles.length === 0) return out;

  // --- strict mode disabled in a TypeScript project
  for (const f of map.files) {
    if (!/(^|\/)tsconfig(?:\.[\w.-]+)?\.json$/.test(f.path) || !f.text) continue;
    // A configuration under a fixture or test tree is test data, not the
    // project's build setup.
    if (isTestLike(map, f.path)) continue;
    const config = parseLooseJson(f.text);
    if (!config || typeof config !== 'object') continue;
    const options = (config as Record<string, unknown>).compilerOptions;
    const opts = (options && typeof options === 'object' ? options : {}) as Record<string, unknown>;
    const extendsBase = (config as Record<string, unknown>).extends !== undefined;

    const explicitlyOff = opts.strict === false;
    const familyFlags = ['strictNullChecks', 'noImplicitAny', 'strictFunctionTypes', 'strictBindCallApply', 'strictPropertyInitialization', 'alwaysStrict', 'useUnknownInCatchVariables'];
    const anyFamilyOn = familyFlags.some((k) => opts[k] === true);
    const absent = opts.strict === undefined && !extendsBase && !anyFamilyOn;

    if (!explicitlyOff && !absent) continue;

    const ev = solidEvidence(map, f.path, [
      explicitlyOff ? map.evidenceAt(f.path, '"strict"', 'strict checking is switched off here') : undefined,
      map.evidenceAt(f.path, '"compilerOptions"', 'no strict-family option is enabled in this configuration'),
    ], 'TypeScript configuration with strict checking not in force');
    if (!ev.verified) continue;

    const anyLikeFlagsOff = familyFlags.filter((k) => opts[k] === false);

    out.push(ctx.finding({
      ruleId: 'quality.types.strict_mode_disabled',
      title: explicitlyOff
        ? `TypeScript strict mode is switched off in ${f.path}`
        : `TypeScript strict mode is not enabled in ${f.path}`,
      severity: 'medium',
      confidence: explicitlyOff ? 'confirmed' : 'strong',
      files: [f.path],
      evidence: [ev],
      explanation:
        (explicitlyOff
          ? `${f.path} sets "strict": false.`
          : `${f.path} enables no option from the strict family and extends no base configuration, which leaves strict checking off.`) +
        ` ${tsFiles.length} TypeScript source file(s) are compiled under it. With strict off, the two checks that catch the most ` +
        'real defects are both inactive: `strictNullChecks`, so every type silently includes `null` and `undefined` and the compiler ' +
        'accepts reading a property off a value that may not be there; and `noImplicitAny`, so a parameter or variable the compiler ' +
        'cannot infer becomes `any` and stops being checked at all, along with everything derived from it. The project therefore pays ' +
        'the cost of type annotations without getting the guarantee they imply — reviewers reading a signature reasonably assume the ' +
        'compiler is enforcing it, and here it is not.' +
        (anyLikeFlagsOff.length ? ` These options are explicitly disabled: ${anyLikeFlagsOff.join(', ')}.` : '') +
        ' A compiler flag passed on the command line could override this; check the build invocation before concluding how the ' +
        'production build is actually compiled.',
      userImpact:
        'The failures this allows through are the ones users meet as a blank screen or a 500: a value that was absent at runtime is ' +
        'read as if it were present, and the error surfaces far from the code that let it through. Because the type system is not ' +
        'enforcing the contract, these defects are found by users rather than by the build.',
      likelyRootCause:
        'Strict mode was left off (or switched off) to get an existing codebase compiling, and enabling it later became a bigger task ' +
        'than any one change could absorb.',
      downstreamConsequences: [
        'Every file added while strict is off accumulates more code that will not compile when it is turned on.',
        'Editor tooling and type-aware lint rules are weaker across the whole project, not just in the unsound files.',
        '`any` introduced at a boundary spreads through inference into code that looks fully typed.',
      ],
      remediation:
        'Turn strict on at the project level and work the errors down rather than suppressing them. The migration that works in a live ' +
        'codebase: enable `strict` in the base configuration, then add the narrowest possible per-directory override (or a short ' +
        'include/exclude list) for the areas that cannot be fixed immediately, so new code is checked from today. Fix ' +
        '`strictNullChecks` errors by handling the absent case explicitly at the boundary where the value enters, not by adding `!`. ' +
        'Treat each remaining override as a tracked item with an owner, since an override with no end date is the same as leaving the ' +
        'flag off.',
      effort: 'large',
      verificationSteps: [
        'Run the type check with strict enabled and record the error count, so the migration has a baseline rather than an impression.',
        'Confirm new files are covered by strict checking, by adding a deliberate null-dereference to a scratch file and seeing it fail.',
        'Confirm CI fails on type errors — a strict configuration that CI does not enforce changes nothing.',
      ],
      references: [REF.tsStrict, 'CWE-704 Incorrect Type Conversion or Cast'],
    }));
  }

  // --- `any` used widely enough to be the project's effective type discipline
  const perFile: Array<{ path: string; count: number; line: number }> = [];
  let total = 0;
  const ANY_RE = /(?::\s*any\b|\bas\s+any\b|<any>|\bany\[\]|Array<any>|Map<[^>]*\bany\b|Record<[^>]*\bany\b|Promise<any>)/g;
  for (const f of tsFiles) {
    const lines = strippedLinesOf(map, idx, f.path);
    let count = 0;
    let firstLine = 0;
    for (let i = 0; i < lines.length; i++) {
      const hits = (lines[i]!.match(ANY_RE) ?? []).length;
      if (hits > 0 && firstLine === 0) firstLine = i + 1;
      count += hits;
    }
    if (count > 0) perFile.push({ path: f.path, count, line: firstLine });
    total += count;
  }

  if (tsFiles.length >= T.anyMinTsFiles && total >= T.anyTotal && total / tsFiles.length >= T.anyPerFile) {
    perFile.sort((a, b) => b.count - a.count);
    const ev: Evidence[] = [];
    for (const f of perFile.slice(0, 4)) {
      const e = map.evidenceLine(f.path, f.line, `${f.count} explicit \`any\` annotation(s) in this file`);
      if (e.verified) ev.push(e);
    }
    if (ev.length > 0) {
      const perFileAvg = (total / tsFiles.length).toFixed(1);
      out.push(ctx.finding({
        ruleId: 'quality.types.pervasive_any',
        title: `\`any\` is used ${total} times across ${perFile.length} files, averaging ${perFileAvg} per TypeScript file`,
        severity: 'medium',
        confidence: 'strong',
        // Anchored to the heaviest file: this is an aggregate measurement, not a
        // traced relationship, so it must not present itself as a cross-file finding.
        files: [perFile[0]!.path],
        evidence: ev,
        explanation:
          `There are ${total} explicit \`any\` annotations in ${perFile.length} of ${tsFiles.length} TypeScript source files ` +
          `(heaviest: ${perFile.slice(0, 3).map((f) => `${f.path} with ${f.count}`).join(', ')}) ` +
          `(${perFileAvg} per file on average), counted from comment-stripped source. \`any\` is not a weaker type; it switches ` +
          'checking off. Every value that flows out of one of these positions is unchecked, as is every expression derived from it, so ' +
          'a misspelled property or a changed shape produces no error at the point of use and no error anywhere downstream. At this ' +
          'density the type system is not describing the program: it is describing the parts of the program somebody had time to type, ' +
          'which is the opposite of the guarantee a reader takes from seeing TypeScript.',
        userImpact:
          'Shape mismatches that a type checker exists to catch reach users instead: a field that was renamed or removed reads as ' +
          '`undefined`, and the page renders empty or the request fails. These are also the defects that are hardest to attribute, ' +
          'because the failure happens wherever the value is finally used rather than where the typing was abandoned.',
        likelyRootCause:
          '`any` was used to get past a difficult third-party type or an incomplete API shape, and became the local convention.',
        downstreamConsequences: [
          'Inference spreads `any` into code that appears to be fully typed, so the unchecked region is larger than the count suggests.',
          'Refactoring tools cannot find all usages through an `any`, so renames and signature changes silently miss call sites.',
        ],
        remediation:
          'Replace `any` with `unknown` at the boundaries where data enters — a fetch response, a parsed body, a third-party callback — ' +
          'and narrow it once, with a validator or a type guard, so the shape is checked where it is first known. Inside the codebase, ' +
          'replace `any` with the real type, generating types from the schema where one exists. Then stop the growth: enable the lint ' +
          'rule that reports explicit `any` as an error for new code, and record the remaining uses rather than letting them accumulate.',
        effort: 'large',
        verificationSteps: [
          'Confirm the explicit `any` count has fallen and that the replacements are narrowed types rather than `unknown` casts followed by assertions.',
          'Confirm each boundary that previously used `any` now validates the value and rejects a malformed one in a test.',
          'Confirm CI fails when a new explicit `any` is added.',
        ],
        references: ['TypeScript handbook — `unknown` versus `any`', 'CWE-704 Incorrect Type Conversion or Cast'],
      }));
    }
  }

  return out;
}

// --------------------------------------------------------- configuration ----

function scatteredConfiguration(ctx: AnalyzerContext, idx: QIndex): Finding[] {
  const { map } = ctx;
  const usages = map.env.usages;
  if (usages.length < T.envVars) return [];

  const readingModules = new Set<string>();
  for (const u of usages) for (const r of u.readIn) if (!isTestLike(map, r.file)) readingModules.add(r.file);
  if (readingModules.size < T.envModules) return [];

  // A central configuration module would be the thing this rule asks for.
  const central = map.files.find(
    (f) => /(^|\/)(config|configuration|settings|env|environment)(\.\w+)?\.[cm]?[jt]sx?$/.test(f.path)
      && !isTestLike(map, f.path),
  );
  if (central) {
    const centralModule = map.modules.get(central.path);
    if (centralModule?.parsed && centralModule.envVars.length >= Math.ceil(usages.length / 2)) return [];
  }

  const withFallback = usages.filter((u) => u.hasFallback);
  const undocumented = usages.filter((u) => !u.documented);

  const ev: Evidence[] = [];
  for (const u of usages.slice(0, 4)) {
    const read = u.readIn.find((r) => !isTestLike(map, r.file));
    if (!read) continue;
    const e = map.evidenceLine(read.file, read.line,
      `${u.name} is read here, directly from the environment${u.hasFallback ? ', with an inline fallback' : ''}`);
    if (e.verified) ev.push(e);
  }
  if (ev.length === 0) return [];

  return [ctx.finding({
    ruleId: 'quality.configuration.no_central_validation',
    title: `${usages.length} environment variables are read ad hoc across ${readingModules.size} modules`,
    severity: 'low',
    confidence: 'strong',
    detectionSource: 'graph',
    files: [...readingModules].slice(0, 6),
    evidence: ev,
    trace: {
      kind: 'env_var',
      steps: [
        ...usages.slice(0, 6).flatMap((u) => {
          const read = u.readIn.find((r) => !isTestLike(map, r.file));
          return read ? [{ file: read.file, line: read.line, detail: `${u.name} read directly from the environment` }] : [];
        }),
        { file: [...readingModules][0]!, detail: 'no module in the project reads and validates the configuration in one place' },
      ],
      complete: true,
    },
    explanation:
      `${usages.length} environment variables are read at ${readingModules.size} separate points in the source, and no module ` +
      'collects and validates them. Two specific things follow. First, nothing checks that a required value is present or well formed, ' +
      'so a missing or malformed variable is not detected at start-up — it is detected when some code path finally reads it and gets ' +
      '`undefined`, which is a request-time failure in whichever feature touched it first. Second, each read site decides for itself ' +
      `what the value means: ${withFallback.length} of these reads supply their own inline default, so the same variable can behave ` +
      'differently in two places, and a reader cannot tell what the application requires without finding every read.' +
      (undocumented.length
        ? ` ${undocumented.length} of the variables are not listed in any example or template file, so the required set is not ` +
          'written down anywhere either.'
        : ''),
    userImpact:
      'A deployment with a missing or wrong configuration value starts successfully and then fails for users on the specific feature ' +
      'that needs it — often intermittently, and often long after the deployment that caused it, which makes it hard to connect the ' +
      'two. Where a read supplies its own default, the failure is worse than an error: the feature works, quietly, with the wrong ' +
      'value.',
    likelyRootCause:
      'Each variable was read where it was needed, which is the path of least resistance, and no module ever took ownership of ' +
      'configuration as a whole.',
    downstreamConsequences: [
      'The set of variables a deployment needs can only be discovered by searching the code, so it drifts from the documented set.',
      'Inline defaults mask absent configuration in production, which is the hardest class of configuration bug to find.',
      'Tests and local development diverge from deployment because nothing asserts the same required set in both.',
    ],
    remediation:
      'Read configuration in one module, once, at start-up: parse every variable there, coerce it to the type the application wants, ' +
      'fail immediately with a message naming the variable when a required one is absent or invalid, and export the resulting typed ' +
      'object. Have the rest of the code import that object instead of touching the environment. Keep the example or template file ' +
      'generated from the same declaration so it cannot drift, and keep defaults in that one place where they can be reviewed — a ' +
      'default buried at a read site is indistinguishable from working configuration.',
    effort: 'medium',
    verificationSteps: [
      'Start the application with a required variable removed and confirm it refuses to start, naming the variable.',
      'Confirm no module outside the configuration module reads the environment directly.',
      'Confirm the example or template file lists exactly the variables the configuration module declares.',
    ],
    references: [REF.twelveFactor, 'CWE-1188 Insecure Default Initialization of Resource'],
  })];
}

// ------------------------------------------------------- documentation ------

function documentedAbove(map: RepoMap, path: string, startLine: number): boolean {
  const file = map.filesByPath.get(path);
  if (!file?.text) return false;
  const lines = file.text.split('\n');
  for (let i = startLine - 2; i >= 0 && i >= startLine - 4; i--) {
    const l = lines[i]?.trim() ?? '';
    if (l === '') continue;
    if (l.startsWith('*/') || l.startsWith('*') || l.startsWith('//') || l.startsWith('/*') || l.startsWith('#')) return true;
    if (/^(?:export\s+)?(?:async\s+)?(?:function|const|class|def)\b/.test(l)) return false;
    return false;
  }
  return false;
}

function undocumentedSharedApi(ctx: AnalyzerContext, idx: QIndex): Finding[] {
  const { map } = ctx;
  const out: Finding[] = [];

  for (const mod of idx.analysable) {
    const importers = idx.prodImporters.get(mod.path) ?? new Set<string>();
    if (importers.size < T.docImporters) continue;

    const fns = mod.symbols.filter((s) => s.exported && FUNCTION_KINDS.has(s.kind));
    if (fns.length < T.docExportedFunctions) continue;
    // Only report when none of them carries any explanatory comment: a partly
    // documented module is a judgement call, not a finding.
    if (fns.some((s) => documentedAbove(map, mod.path, s.startLine))) continue;

    const nonTrivial = fns.filter((s) => s.params.length >= 2 || s.async);
    if (nonTrivial.length === 0) continue;

    const ev = map.evidenceLine(mod.path, fns[0]!.startLine,
      `${fns[0]!.name}(${fns[0]!.params.join(', ')}) — exported, imported by ${importers.size} modules, no comment on any export in this file`);
    if (!ev.verified) continue;

    out.push(ctx.finding({
      ruleId: 'quality.documentation.undocumented_shared_api',
      title: `${mod.path} is imported by ${importers.size} modules and none of its ${fns.length} exported functions is documented`,
      severity: 'low',
      confidence: 'moderate',
      detectionSource: 'graph',
      files: [mod.path],
      symbol: fns[0]!.name,
      evidence: [ev],
      trace: {
        kind: 'import',
        steps: [
          { file: mod.path, line: fns[0]!.startLine, detail: `${fns.length} exported functions, none preceded by a comment` },
          ...[...importers].slice(0, 6).map((p) => ({ file: p, detail: 'imports this module and must infer the contract from the signatures' })),
        ],
        complete: true,
      },
      explanation:
        `${mod.path} is a shared surface — ${importers.size} modules import it — and carries ${fns.length} exported functions with no ` +
        `comment on any of them (${nonTrivial.length} take two or more parameters or are asynchronous). The gap is not politeness. ` +
        'A signature cannot express the parts callers actually get wrong: which arguments are interchangeable, what unit or currency a ' +
        'number is in, whether a failure throws or returns a falsy value, whether the call has a side effect, and what happens on a ' +
        'second identical call. With nothing written down, each caller settles those questions by reading the implementation at the ' +
        'moment they integrate, and their conclusions differ — which is how two call sites come to rely on contradictory behaviour and ' +
        'why a later change to this module breaks one of them.',
      userImpact:
        'Indirect but real: the misreadings compound into defects users meet — a value treated as the wrong unit, an error swallowed ' +
        'because the caller expected a thrown exception, a duplicate action because the caller assumed the call was idempotent. They ' +
        'are also slow to diagnose, since every caller looks locally correct.',
      likelyRootCause:
        'The module began as internal, where reading the implementation was reasonable, and acquired callers without ever acquiring a ' +
        'stated contract.',
      downstreamConsequences: [
        'Every change to this module requires reading all its callers to find out what they relied on.',
        'New callers repeat the integration work, and sometimes repeat the mistake.',
      ],
      remediation:
        'Write the contract where callers will see it, on the exported function, and keep it to what the signature cannot say: units ' +
        'and ranges, which failures throw versus return, side effects, idempotency, and anything a caller must do first. Where the ' +
        'contract is load-bearing, encode it instead of describing it — a branded type for a unit, a result type instead of a nullable ' +
        'return — so the compiler enforces what the comment would only assert. A test named after each guarantee keeps the stated ' +
        'contract and the real one from diverging.',
      effort: 'medium',
      verificationSteps: [
        'Confirm each exported function states its failure mode and any side effect, not just its parameter names.',
        'Pick one caller and confirm its usage matches the contract now written down; where it does not, one of the two is a defect.',
      ],
      references: [REF.cleanCode],
    }));
  }
  return out;
}

// ------------------------------------------------------------- naming -------

const SNAKE_RE = /^[a-z][a-z0-9]*(?:_[a-z0-9]+)+$/;
const CAMEL_RE = /^[a-z][a-z0-9]*(?:[A-Z][a-z0-9]*)+$/;

function inconsistentNaming(ctx: AnalyzerContext, idx: QIndex): Finding[] {
  const { map } = ctx;
  const out: Finding[] = [];

  for (const mod of idx.analysable) {
    const language = mod.language;
    const isJsFamily = ['typescript', 'tsx', 'javascript', 'jsx'].includes(language);
    const isPython = language === 'python';
    if (!isJsFamily && !isPython) continue;

    const candidates = mod.symbols.filter(
      (s) => s.exported && (FUNCTION_KINDS.has(s.kind) || s.kind === 'const'),
    );
    if (candidates.length < T.namingMinTotal) continue;

    const snake = candidates.filter((s) => SNAKE_RE.test(s.name));
    const camel = candidates.filter((s) => CAMEL_RE.test(s.name));
    if (snake.length < T.namingMinEach || camel.length < T.namingMinEach) continue;

    const dominant = isPython ? 'snake_case' : 'camelCase';
    const minority = isPython ? camel : snake;
    const minorityStyle = isPython ? 'camelCase' : 'snake_case';

    const ev: Evidence[] = [];
    const first = map.evidenceLine(mod.path, (isPython ? snake : camel)[0]!.startLine,
      `${(isPython ? snake : camel)[0]!.name} follows ${dominant}, the convention of this language`);
    if (first.verified) ev.push(first);
    const second = map.evidenceLine(mod.path, minority[0]!.startLine,
      `${minority[0]!.name} follows ${minorityStyle} in the same public surface`);
    if (second.verified) ev.push(second);
    if (ev.length < 2) continue;

    out.push(ctx.finding({
      ruleId: 'quality.naming.mixed_conventions',
      title: `${mod.path} exports names in two different conventions`,
      severity: 'low',
      confidence: 'strong',
      files: [mod.path],
      symbol: minority[0]!.name,
      evidence: ev,
      explanation:
        `The exported surface of ${mod.path} mixes ${dominant} (${(isPython ? snake : camel).length} names) with ${minorityStyle} ` +
        `(${minority.length} names), for example ${(isPython ? snake : camel)[0]!.name} alongside ${minority[0]!.name}. The cost is ` +
        'specific: a caller cannot predict the name of a function they have not yet used, so every call starts with a lookup, and ' +
        'misspellings land on names that do not exist. It also removes a signal readers rely on — in a codebase with one convention, ' +
        'a name in a different style marks a boundary (generated code, an external payload, a wire format). Where both styles appear ' +
        'without meaning, that signal reads as noise and real boundaries stop standing out.',
      userImpact:
        'No direct user-visible effect. It shows up as time: slower integration against this module, and occasional defects where a ' +
        'name was assumed rather than checked — particularly where a value crosses into a payload whose field names follow the other ' +
        'convention.',
      likelyRootCause:
        'Names were mirrored from an external payload, a database column set, or another language\'s code, and kept their original ' +
        'style on the way in.',
      downstreamConsequences: [
        'Each new export has to choose a convention, so the inconsistency propagates.',
        'Automated renames and codemods have to handle both forms.',
      ],
      remediation:
        `Settle on ${dominant} for this surface and rename the ${minority.length} exception(s), keeping a deprecated alias only if ` +
        'external callers depend on the old names. Where a name is in the other style because it mirrors a wire format or a database ' +
        'column, do the mapping once at that boundary — in the module that parses or serialises — so the external naming does not ' +
        'propagate inwards. Then make the convention enforceable with a lint rule, so this does not have to be caught in review.',
      effort: 'small',
      verificationSteps: [
        'Confirm every export in this module follows one convention, and that call sites were updated rather than aliased indefinitely.',
        'Confirm a naming lint rule now covers this directory.',
      ],
      references: [REF.cleanCode],
    }));
  }
  return out;
}
