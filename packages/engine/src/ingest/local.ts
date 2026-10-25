import { createHash } from 'node:crypto';
import { readFileSync, readdirSync, statSync, lstatSync } from 'node:fs';
import { join, relative, resolve, sep } from 'node:path';
import { DEFAULT_LIMITS, IngestRejected, type IngestLimits } from './limits.ts';
import { isExcludedDir } from './ignore.ts';

export interface RawEntry {
  path: string;
  bytes: number;
  sha256: string;
  content: Buffer;
}

export interface LocalReadResult {
  entries: RawEntry[];
  skipped: Array<{ path: string; reason: string }>;
  totalUncompressedBytes: number;
}

/**
 * Read a local directory into the same shape as an archive.
 *
 * Symlinks are not followed: a link pointing outside the root would let a scan
 * read arbitrary files on the host.
 */
export function readLocalDir(root: string, limits: IngestLimits = DEFAULT_LIMITS): LocalReadResult {
  const absRoot = resolve(root);
  const st = statSync(absRoot, { throwIfNoEntry: false });
  if (!st || !st.isDirectory()) {
    throw new IngestRejected('not_a_directory', `${root} is not a directory`);
  }

  const entries: RawEntry[] = [];
  const skipped: LocalReadResult['skipped'] = [];
  let total = 0;

  const walk = (dir: string): void => {
    let names: string[];
    try {
      names = readdirSync(dir);
    } catch (e) {
      skipped.push({ path: toRel(absRoot, dir), reason: `unreadable directory: ${(e as Error).message}` });
      return;
    }
    for (const name of names) {
      const abs = join(dir, name);
      const rel = toRel(absRoot, abs);

      let ls;
      try {
        ls = lstatSync(abs);
      } catch {
        skipped.push({ path: rel, reason: 'unreadable entry' });
        continue;
      }

      if (ls.isSymbolicLink()) {
        skipped.push({ path: rel, reason: 'symlinks are not followed' });
        continue;
      }
      if (ls.isDirectory()) {
        if (isExcludedDir(name)) continue;
        walk(abs);
        continue;
      }
      if (!ls.isFile()) {
        skipped.push({ path: rel, reason: 'not a regular file' });
        continue;
      }
      if (ls.size > limits.maxEntryBytes) {
        skipped.push({ path: rel, reason: `exceeds per-file limit (${ls.size} bytes)` });
        continue;
      }
      if (entries.length >= limits.maxEntries) {
        throw new IngestRejected('too_many_entries', `directory exceeds the ${limits.maxEntries}-file limit`);
      }
      if (total + ls.size > limits.maxTotalUncompressedBytes) {
        throw new IngestRejected('uncompressed_total_exceeded',
          `directory exceeds the ${limits.maxTotalUncompressedBytes}-byte total limit`, { atEntry: rel });
      }

      let content: Buffer;
      try {
        content = readFileSync(abs);
      } catch (e) {
        skipped.push({ path: rel, reason: `unreadable file: ${(e as Error).message}` });
        continue;
      }
      total += content.length;
      entries.push({
        path: rel, bytes: content.length,
        sha256: createHash('sha256').update(content).digest('hex'),
        content,
      });
    }
  };

  walk(absRoot);
  return { entries, skipped, totalUncompressedBytes: total };
}

function toRel(root: string, abs: string): string {
  return relative(root, abs).split(sep).join('/');
}
