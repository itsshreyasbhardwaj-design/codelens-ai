import { gunzipSync } from 'node:zlib';
import { createHash } from 'node:crypto';
import { DEFAULT_LIMITS, IngestRejected, type IngestLimits } from './limits.ts';
import { safeArchivePath, stripTopLevelDir } from './paths.ts';

/**
 * Minimal tar(.gz) reader for provider tarballs (GitHub serves repository
 * archives this way). Same safety posture as the ZIP reader: path validation,
 * symlink rejection, and enforced size bounds.
 */

export interface TarEntry {
  path: string;
  bytes: number;
  sha256: string;
  content: Buffer;
}

export interface TarReadResult {
  entries: TarEntry[];
  skipped: Array<{ path: string; reason: string }>;
  totalUncompressedBytes: number;
}

function octal(buf: Buffer): number {
  const s = buf.toString('ascii').replace(/\0.*$/, '').trim();
  if (s === '') return 0;
  const n = parseInt(s, 8);
  return Number.isNaN(n) ? 0 : n;
}

/**
 * @param stripRoot drop the single wrapping directory provider tarballs add
 *                  (e.g. `owner-repo-<sha>/`).
 */
export function readTarGz(gz: Buffer, limits: IngestLimits = DEFAULT_LIMITS, stripRoot = true): TarReadResult {
  if (gz.length > limits.maxArchiveBytes) {
    throw new IngestRejected('archive_too_large', `archive is ${gz.length} bytes, limit is ${limits.maxArchiveBytes}`);
  }
  let buf: Buffer;
  try {
    buf = gunzipSync(gz, { maxOutputLength: limits.maxTotalUncompressedBytes });
  } catch (e) {
    throw new IngestRejected('gunzip_failed', `tarball could not be decompressed: ${(e as Error).message}`);
  }
  return readTar(buf, limits, stripRoot);
}

export function readTar(buf: Buffer, limits: IngestLimits = DEFAULT_LIMITS, stripRoot = true): TarReadResult {
  const entries: TarEntry[] = [];
  const skipped: TarReadResult['skipped'] = [];
  let total = 0;
  let offset = 0;
  let pendingLongName: string | undefined;

  while (offset + 512 <= buf.length) {
    const header = buf.subarray(offset, offset + 512);
    // Two consecutive zero blocks mark the end of the archive.
    if (header.every((b) => b === 0)) break;

    const rawName = pendingLongName ?? header.subarray(0, 100).toString('utf8').replace(/\0.*$/, '');
    const prefix = header.subarray(345, 500).toString('utf8').replace(/\0.*$/, '');
    const size = octal(header.subarray(124, 136));
    const typeflag = String.fromCharCode(header[156] ?? 0);
    pendingLongName = undefined;

    const dataStart = offset + 512;
    const padded = Math.ceil(size / 512) * 512;
    offset = dataStart + padded;

    if (dataStart + size > buf.length) {
      throw new IngestRejected('corrupt_archive', `tar entry ${rawName} extends past end of archive`);
    }

    // GNU long name: the next header's name comes from this entry's body.
    if (typeflag === 'L') {
      pendingLongName = buf.subarray(dataStart, dataStart + size).toString('utf8').replace(/\0.*$/, '');
      continue;
    }
    // pax extended headers and global headers carry metadata we do not need.
    if (typeflag === 'x' || typeflag === 'g') continue;
    if (typeflag === '5') continue; // directory
    if (typeflag === '2' || typeflag === '1') {
      skipped.push({ path: rawName, reason: 'symlink and hardlink entries are not extracted' });
      continue;
    }
    if (typeflag !== '0' && typeflag !== '\0' && typeflag !== '') {
      skipped.push({ path: rawName, reason: `unsupported tar entry type '${typeflag}'` });
      continue;
    }

    const joined = prefix ? `${prefix}/${rawName}` : rawName;
    const relative = stripRoot ? stripTopLevelDir(joined) : joined;
    if (relative === '') continue;
    const path = safeArchivePath(relative, limits.maxPathDepth);
    if (path === '') continue;

    if (size > limits.maxEntryBytes) {
      skipped.push({ path, reason: `entry exceeds per-file limit (${size} > ${limits.maxEntryBytes} bytes)` });
      continue;
    }
    if (total + size > limits.maxTotalUncompressedBytes) {
      throw new IngestRejected('uncompressed_total_exceeded',
        `archive expands past the ${limits.maxTotalUncompressedBytes}-byte total limit`, { atEntry: path });
    }
    if (entries.length >= limits.maxEntries) {
      throw new IngestRejected('too_many_entries', `archive exceeds the ${limits.maxEntries}-entry limit`);
    }

    const content = Buffer.from(buf.subarray(dataStart, dataStart + size));
    total += content.length;
    entries.push({
      path, bytes: content.length,
      sha256: createHash('sha256').update(content).digest('hex'),
      content,
    });
  }

  return { entries, skipped, totalUncompressedBytes: total };
}
