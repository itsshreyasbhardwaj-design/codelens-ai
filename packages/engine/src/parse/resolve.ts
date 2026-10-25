import type { ParsedModule } from './types.ts';

/**
 * Import resolution against the real file list.
 *
 * Only relative specifiers and a small set of conventional aliases are
 * resolved. A specifier that does not resolve stays unresolved rather than
 * being guessed at, because a cross-file finding must be able to cite both
 * ends of the relationship.
 */

const TS_EXTENSIONS = ['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs', '.mts', '.cts'];
const INDEX_FILES = TS_EXTENSIONS.map((e) => `/index${e}`);

/** Normalise `a/b/../c` to `a/c`. */
export function normalizePath(path: string): string {
  const out: string[] = [];
  for (const seg of path.split('/')) {
    if (seg === '' || seg === '.') continue;
    if (seg === '..') { out.pop(); continue; }
    out.push(seg);
  }
  return out.join('/');
}

function dirOf(path: string): string {
  const i = path.lastIndexOf('/');
  return i === -1 ? '' : path.slice(0, i);
}

/** Try a base path with each known extension and index file. */
function tryCandidates(base: string, files: Set<string>): string | undefined {
  if (files.has(base)) return base;
  for (const ext of TS_EXTENSIONS) if (files.has(base + ext)) return base + ext;
  for (const idx of INDEX_FILES) if (files.has(base + idx)) return base + idx;
  return undefined;
}

/**
 * Resolve a specifier from `fromPath`.
 *
 * Handles relative imports, `@/x` and `~/x` aliases (resolved against common
 * source roots), and Python's dotted relative imports.
 */
export function resolveSpecifier(
  specifier: string, fromPath: string, files: Set<string>, language: string,
): string | undefined {
  if (language === 'python') return resolvePythonSpecifier(specifier, fromPath, files);

  if (specifier.startsWith('.')) {
    return tryCandidates(normalizePath(`${dirOf(fromPath)}/${specifier}`), files);
  }
  // Conventional path aliases. Only accepted when they actually hit a file.
  const aliasMatch = /^[@~]\/(.+)$/.exec(specifier);
  if (aliasMatch) {
    const rest = aliasMatch[1]!;
    for (const root of ['src', 'app', 'lib', '']) {
      const hit = tryCandidates(normalizePath(root ? `${root}/${rest}` : rest), files);
      if (hit) return hit;
    }
  }
  return undefined;
}

function resolvePythonSpecifier(specifier: string, fromPath: string, files: Set<string>): string | undefined {
  const leadingDots = /^\.+/.exec(specifier)?.[0].length ?? 0;
  if (leadingDots === 0) {
    // An absolute-looking Python import may still be a first-party package.
    const asPath = specifier.replace(/\./g, '/');
    return files.has(`${asPath}.py`) ? `${asPath}.py`
      : files.has(`${asPath}/__init__.py`) ? `${asPath}/__init__.py`
      : undefined;
  }
  let dir = dirOf(fromPath);
  for (let i = 1; i < leadingDots; i++) dir = dirOf(dir);
  const rest = specifier.slice(leadingDots).replace(/\./g, '/');
  const base = normalizePath(dir ? `${dir}/${rest}` : rest);
  if (files.has(`${base}.py`)) return `${base}.py`;
  if (files.has(`${base}/__init__.py`)) return `${base}/__init__.py`;
  return undefined;
}

/** Fill in `resolvedPath` on every import of every module, in place. */
export function resolveImports(modules: Map<string, ParsedModule>, files: Set<string>): void {
  for (const mod of modules.values()) {
    for (const imp of mod.imports) {
      const resolved = resolveSpecifier(imp.specifier, mod.path, files, mod.language);
      if (resolved) {
        imp.resolvedPath = resolved;
        imp.external = false;
      }
    }
  }
}

/** Reverse index: path -> paths that import it. */
export function buildImporterIndex(modules: Map<string, ParsedModule>): Map<string, string[]> {
  const index = new Map<string, string[]>();
  for (const mod of modules.values()) {
    for (const imp of mod.imports) {
      if (!imp.resolvedPath) continue;
      const list = index.get(imp.resolvedPath) ?? [];
      list.push(mod.path);
      index.set(imp.resolvedPath, list);
    }
  }
  return index;
}
