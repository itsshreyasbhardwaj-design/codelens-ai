import { createHash } from 'node:crypto';
import type { FileRole } from '@codelens/core';
import { DEFAULT_LIMITS, type IngestLimits } from './limits.ts';
import { isBinaryPath, isExcludedPath, looksGenerated, looksVendored } from './ignore.ts';
import { languageOf, roleOf } from '../index/classify.ts';
import type { RawEntry } from './local.ts';

/**
 * Stage 2 — source normalisation.
 *
 * Turns raw archive/directory entries into the canonical file set every later
 * stage reads. Exclusions are recorded with reasons so coverage reporting can
 * state exactly what was not looked at.
 */

export interface SourceFile {
  path: string;
  bytes: number;
  sha256: string;
  language?: string;
  role: FileRole;
  generated: boolean;
  vendored: boolean;
  binary: boolean;
  content: Buffer;
  /** Decoded text, or null for binary/undecodable files. */
  text: string | null;
  lines: number;
  /** Set by the indexing stage once an AST has (or has not) been produced. */
  parsed: boolean;
  unparsedReason?: string;
}

export interface Snapshot {
  files: SourceFile[];
  skipped: Array<{ path: string; reason: string }>;
  /** Hash of the normalised file set; equal hashes mean genuinely comparable scans. */
  contentHash: string;
  totalBytes: number;
  truncated: boolean;
  truncationNote?: string;
}

const NUL = 0x00;

/** Treat a buffer as binary if it contains a NUL in the first 8 KiB. */
function isBinaryContent(buf: Buffer): boolean {
  const n = Math.min(buf.length, 8192);
  for (let i = 0; i < n; i++) if (buf[i] === NUL) return true;
  return false;
}

function countLines(text: string): number {
  if (text.length === 0) return 0;
  let n = 1;
  for (let i = 0; i < text.length; i++) if (text.charCodeAt(i) === 10) n++;
  return n;
}

export function normalizeEntries(
  entries: RawEntry[],
  limits: IngestLimits = DEFAULT_LIMITS,
  preSkipped: Array<{ path: string; reason: string }> = [],
): Snapshot {
  const files: SourceFile[] = [];
  const skipped = [...preSkipped];
  let totalBytes = 0;
  let truncated = false;
  let truncationNote: string | undefined;

  for (const e of entries) {
    const ex = isExcludedPath(e.path);
    if (ex.excluded) {
      skipped.push({ path: e.path, reason: ex.reason ?? 'excluded' });
      continue;
    }

    const binary = isBinaryPath(e.path) || isBinaryContent(e.content);
    const text = binary ? null : e.content.toString('utf8');
    const head = text ? text.slice(0, 2000) : '';
    const generated = !binary && looksGenerated(e.path, head);
    const vendored = looksVendored(e.path);
    const language = languageOf(e.path);
    const role = roleOf(e.path, { generated, vendored, binary });

    files.push({
      path: e.path,
      bytes: e.bytes,
      sha256: e.sha256,
      language,
      role,
      generated,
      vendored,
      binary,
      content: e.content,
      text,
      lines: text ? countLines(text) : 0,
      parsed: false,
      unparsedReason: binary
        ? 'binary file'
        : e.bytes > limits.maxParseBytes
          ? `file larger than parse limit (${e.bytes} > ${limits.maxParseBytes} bytes)`
          : undefined,
    });
    totalBytes += e.bytes;
  }

  if (entries.length >= limits.maxEntries) {
    truncated = true;
    truncationNote =
      `the ${limits.maxEntries}-file ingestion limit was reached; some files were not read. ` +
      'Results describe only the files listed in coverage.';
  }

  files.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  const h = createHash('sha256');
  for (const f of files) { h.update(f.path); h.update('\u0000'); h.update(f.sha256); h.update('\u0000'); }

  return { files, skipped, contentHash: h.digest('hex'), totalBytes, truncated, truncationNote };
}
