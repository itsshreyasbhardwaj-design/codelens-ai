import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { ParsedModule } from './types.ts';
import { emptyModule } from './types.ts';

/**
 * Python parsing via the interpreter's own `ast` module.
 *
 * Safety: the extractor runs with `-I` (isolated mode), which ignores
 * PYTHONPATH and does not put the script's directory on sys.path, so a file
 * named `ast.py` inside an analysed project cannot hijack the import. The
 * analysed source is copied to a private temp directory and passed as an
 * argument; the interpreter is never started from inside the project tree.
 *
 * This only ever *parses* the file. The analysed project's code is never
 * imported or executed.
 */

const HERE = dirname(fileURLToPath(import.meta.url));
const SCRIPT = join(HERE, 'py_ast.py');
const TIMEOUT_MS = 10_000;
const MAX_OUTPUT = 32 * 1024 * 1024;

let pythonBin: string | null | undefined;

/** Locate a usable python3 once per process. */
export function findPython(): string | null {
  if (pythonBin !== undefined) return pythonBin;
  for (const candidate of ['python3', 'python']) {
    const probe = spawnSync(candidate, ['-I', '-c', 'import ast,sys;print(sys.version_info[0])'], {
      encoding: 'utf8', timeout: 5000,
    });
    if (probe.status === 0 && probe.stdout.trim() === '3') {
      pythonBin = candidate;
      return pythonBin;
    }
  }
  pythonBin = null;
  return pythonBin;
}

export function parsePython(path: string, source: string): ParsedModule {
  const bin = findPython();
  if (!bin) {
    return emptyModule(path, 'python',
      'no usable python3 found on PATH, so Python files were indexed but not parsed');
  }

  const dir = mkdtempSync(join(tmpdir(), 'codelens-py-'));
  const tmpFile = join(dir, 'source.py');
  try {
    writeFileSync(tmpFile, source, 'utf8');
    const res = spawnSync(bin, ['-I', SCRIPT, tmpFile], {
      encoding: 'utf8',
      timeout: TIMEOUT_MS,
      maxBuffer: MAX_OUTPUT,
      // No environment is inherited: the extractor needs none.
      env: { PATH: process.env.PATH ?? '' },
    });

    if (res.error) {
      return emptyModule(path, 'python', `python extractor failed: ${res.error.message}`);
    }
    if (res.status !== 0) {
      return emptyModule(path, 'python',
        `python extractor exited ${res.status}: ${(res.stderr || '').trim().slice(0, 300)}`);
    }

    let data: Record<string, unknown>;
    try {
      data = JSON.parse(res.stdout) as Record<string, unknown>;
    } catch {
      return emptyModule(path, 'python', 'python extractor produced unreadable output');
    }
    if (data.parsed !== true) {
      return emptyModule(path, 'python', String(data.parseError ?? 'unparseable Python source'));
    }

    return {
      path,
      language: 'python',
      parsed: true,
      imports: (data.imports as ParsedModule['imports']) ?? [],
      exports: (data.exports as string[]) ?? [],
      symbols: (data.symbols as ParsedModule['symbols']) ?? [],
      calls: (data.calls as ParsedModule['calls']) ?? [],
      jsx: [],
      memberAccesses: (data.memberAccesses as ParsedModule['memberAccesses']) ?? [],
      objectLiterals: (data.objectLiterals as ParsedModule['objectLiterals']) ?? [],
      envVars: (data.envVars as string[]) ?? [],
      stringLiterals: (data.stringLiterals as ParsedModule['stringLiterals']) ?? [],
      hasTryCatch: Boolean(data.hasTryCatch),
      lines: Number(data.lines ?? 0),
    };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}
