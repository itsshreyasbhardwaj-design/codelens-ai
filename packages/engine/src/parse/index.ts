import type { SourceFile, Snapshot } from '../ingest/normalize.ts';
import { DEFAULT_LIMITS, type IngestLimits } from '../ingest/limits.ts';
import type { ParsedModule } from './types.ts';
import { emptyModule } from './types.ts';
import { parseTypeScript } from './ts.ts';
import { findPython, parsePython } from './py.ts';
import { resolveImports } from './resolve.ts';

export * from './types.ts';
export { parseTypeScript } from './ts.ts';
export { parsePython, findPython } from './py.ts';

const TS_LANGUAGES = new Set(['typescript', 'tsx', 'javascript', 'jsx']);

export interface ParseReport {
  modules: Map<string, ParsedModule>;
  parsedCount: number;
  unparsed: Array<{ path: string; reason: string }>;
  /** Parsers that were unavailable, so coverage can say so plainly. */
  unavailableParsers: string[];
}

/**
 * Stage 4 — code indexing.
 *
 * Parses every file a parser exists for, resolves import specifiers against the
 * real file list, and records why each unparsed file was not parsed. A file we
 * could not parse is never treated as a file with no problems.
 */
export function parseSnapshot(snapshot: Snapshot, limits: IngestLimits = DEFAULT_LIMITS): ParseReport {
  const modules = new Map<string, ParsedModule>();
  const unparsed: Array<{ path: string; reason: string }> = [];
  const unavailableParsers: string[] = [];

  const hasPython = snapshot.files.some((f) => f.language === 'python');
  const pythonAvailable = hasPython ? findPython() !== null : true;
  if (hasPython && !pythonAvailable) unavailableParsers.push('python');

  for (const file of snapshot.files) {
    const skipReason = shouldSkipParse(file, limits);
    if (skipReason) {
      file.parsed = false;
      file.unparsedReason = skipReason;
      unparsed.push({ path: file.path, reason: skipReason });
      continue;
    }

    let mod: ParsedModule;
    if (TS_LANGUAGES.has(file.language!)) {
      mod = parseTypeScript(file.path, file.text!, file.language!);
    } else if (file.language === 'python') {
      mod = pythonAvailable
        ? parsePython(file.path, file.text!)
        : emptyModule(file.path, 'python', 'no usable python3 on PATH');
    } else {
      const reason = `no parser for language '${file.language}'`;
      file.parsed = false;
      file.unparsedReason = reason;
      unparsed.push({ path: file.path, reason });
      continue;
    }

    file.parsed = mod.parsed;
    if (!mod.parsed) {
      file.unparsedReason = mod.parseError;
      unparsed.push({ path: file.path, reason: mod.parseError ?? 'parse failed' });
    }
    modules.set(file.path, mod);
  }

  resolveImports(modules, new Set(snapshot.files.map((f) => f.path)));

  return {
    modules,
    parsedCount: [...modules.values()].filter((m) => m.parsed).length,
    unparsed,
    unavailableParsers,
  };
}

function shouldSkipParse(file: SourceFile, limits: IngestLimits): string | undefined {
  if (file.binary) return 'binary file';
  if (file.text === null) return 'file could not be decoded as text';
  if (file.generated) return 'generated file';
  if (file.vendored) return 'vendored dependency';
  if (file.bytes > limits.maxParseBytes) {
    return `file larger than the ${limits.maxParseBytes}-byte parse limit`;
  }
  if (!file.language) return 'unrecognised file type';
  if (!TS_LANGUAGES.has(file.language) && file.language !== 'python') {
    return `no parser for language '${file.language}'`;
  }
  return undefined;
}
