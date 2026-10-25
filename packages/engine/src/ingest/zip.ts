import { inflateRawSync } from 'node:zlib';
import { createHash } from 'node:crypto';
import * as zlib from 'node:zlib';
import { DEFAULT_LIMITS, IngestRejected, type IngestLimits } from './limits.ts';
import { safeArchivePath } from './paths.ts';

/**
 * Minimal, hardened ZIP reader.
 *
 * Implemented directly rather than taken from a library so that every bound in
 * `IngestLimits` is actually enforced at parse time: entry count, per-entry
 * size, total uncompressed size, compression ratio, path safety, and symlink
 * rejection. Nothing is written to disk by this reader — entries are returned
 * in memory and the caller decides what to persist.
 */

const SIG_EOCD = 0x06054b50;
const SIG_CENTRAL = 0x02014b50;
const SIG_LOCAL = 0x04034b50;
const SIG_EOCD64_LOCATOR = 0x07064b50;

const METHOD_STORE = 0;
const METHOD_DEFLATE = 8;

export interface ZipEntry {
  path: string;
  bytes: number;
  sha256: string;
  content: Buffer;
}

export interface ZipReadResult {
  entries: ZipEntry[];
  /** Entries deliberately not extracted, with the reason. Reported, never hidden. */
  skipped: Array<{ path: string; reason: string }>;
  totalUncompressedBytes: number;
}

function findEocd(buf: Buffer): number {
  // The EOCD is at the end, after a comment of up to 64 KiB.
  const minOffset = Math.max(0, buf.length - (0xffff + 22));
  for (let i = buf.length - 22; i >= minOffset; i--) {
    if (buf.readUInt32LE(i) === SIG_EOCD) return i;
  }
  throw new IngestRejected('not_a_zip', 'file does not contain a ZIP end-of-central-directory record');
}

export function readZip(buf: Buffer, limits: IngestLimits = DEFAULT_LIMITS): ZipReadResult {
  if (buf.length > limits.maxArchiveBytes) {
    throw new IngestRejected('archive_too_large',
      `archive is ${buf.length} bytes, limit is ${limits.maxArchiveBytes}`,
      { bytes: buf.length, limit: limits.maxArchiveBytes });
  }

  const eocd = findEocd(buf);

  // ZIP64 archives are refused rather than mis-parsed. A source repository that
  // needs ZIP64 also exceeds our size limits.
  if (eocd >= 20 && buf.readUInt32LE(eocd - 20) === SIG_EOCD64_LOCATOR) {
    throw new IngestRejected('zip64_unsupported',
      'ZIP64 archives are not supported; export a smaller archive or connect the repository directly');
  }

  const entryCount = buf.readUInt16LE(eocd + 10);
  const centralDirOffset = buf.readUInt32LE(eocd + 16);
  if (entryCount > limits.maxEntries) {
    throw new IngestRejected('too_many_entries',
      `archive declares ${entryCount} entries, limit is ${limits.maxEntries}`);
  }
  if (centralDirOffset >= buf.length) {
    throw new IngestRejected('corrupt_archive', 'central directory offset points outside the file');
  }

  const entries: ZipEntry[] = [];
  const skipped: ZipReadResult['skipped'] = [];
  let total = 0;
  let p = centralDirOffset;

  for (let i = 0; i < entryCount; i++) {
    if (p + 46 > buf.length || buf.readUInt32LE(p) !== SIG_CENTRAL) {
      throw new IngestRejected('corrupt_archive', `central directory entry ${i} is malformed`);
    }
    const method = buf.readUInt16LE(p + 10);
    const crcExpected = buf.readUInt32LE(p + 16);
    const compSize = buf.readUInt32LE(p + 20);
    const uncompSize = buf.readUInt32LE(p + 24);
    const nameLen = buf.readUInt16LE(p + 28);
    const extraLen = buf.readUInt16LE(p + 30);
    const commentLen = buf.readUInt16LE(p + 32);
    const externalAttr = buf.readUInt32LE(p + 38);
    const localOffset = buf.readUInt32LE(p + 42);
    const rawName = buf.subarray(p + 46, p + 46 + nameLen).toString('utf8');
    p += 46 + nameLen + extraLen + commentLen;

    if (compSize === 0xffffffff || uncompSize === 0xffffffff) {
      throw new IngestRejected('zip64_unsupported', `entry ${rawName} requires ZIP64 size fields`);
    }

    // Directory entry.
    if (rawName.endsWith('/')) continue;

    // Reject symlinks: following one during extraction is a write-outside-root
    // primitive, and we have no use for them in analysis.
    const unixMode = (externalAttr >>> 16) & 0xffff;
    if ((unixMode & 0xf000) === 0xa000) {
      skipped.push({ path: rawName, reason: 'symlink entries are not extracted' });
      continue;
    }

    const path = safeArchivePath(rawName, limits.maxPathDepth);
    if (path === '') continue;

    if (uncompSize > limits.maxEntryBytes) {
      skipped.push({ path, reason: `entry exceeds per-file limit (${uncompSize} > ${limits.maxEntryBytes} bytes)` });
      continue;
    }
    if (compSize > 0 && uncompSize / compSize > limits.maxCompressionRatio) {
      throw new IngestRejected('compression_bomb',
        `entry ${path} expands ${Math.round(uncompSize / compSize)}x, limit is ${limits.maxCompressionRatio}x`,
        { path, ratio: uncompSize / compSize });
    }
    if (total + uncompSize > limits.maxTotalUncompressedBytes) {
      throw new IngestRejected('uncompressed_total_exceeded',
        `archive expands past the ${limits.maxTotalUncompressedBytes}-byte total limit`,
        { atEntry: path });
    }

    // Read the local header to find the data offset.
    if (localOffset + 30 > buf.length || buf.readUInt32LE(localOffset) !== SIG_LOCAL) {
      throw new IngestRejected('corrupt_archive', `local header for ${path} is malformed`);
    }
    const lNameLen = buf.readUInt16LE(localOffset + 26);
    const lExtraLen = buf.readUInt16LE(localOffset + 28);
    const dataStart = localOffset + 30 + lNameLen + lExtraLen;
    if (dataStart + compSize > buf.length) {
      throw new IngestRejected('corrupt_archive', `entry ${path} data extends past end of file`);
    }
    const raw = buf.subarray(dataStart, dataStart + compSize);

    let content: Buffer;
    if (method === METHOD_STORE) {
      content = Buffer.from(raw);
    } else if (method === METHOD_DEFLATE) {
      try {
        // maxOutputLength is a hard stop: a lying size header cannot make us
        // allocate without bound.
        content = inflateRawSync(raw, { maxOutputLength: limits.maxEntryBytes });
      } catch (e) {
        throw new IngestRejected('inflate_failed', `entry ${path} could not be decompressed: ${(e as Error).message}`, { path });
      }
    } else {
      skipped.push({ path, reason: `unsupported compression method ${method}` });
      continue;
    }

    if (content.length !== uncompSize) {
      throw new IngestRejected('size_mismatch',
        `entry ${path} declared ${uncompSize} bytes but produced ${content.length}`, { path });
    }
    // Verify integrity when the runtime exposes crc32.
    const crc32 = (zlib as unknown as { crc32?: (b: Buffer) => number }).crc32;
    if (typeof crc32 === 'function' && (crc32(content) >>> 0) !== crcExpected) {
      throw new IngestRejected('crc_mismatch', `entry ${path} failed its CRC check`, { path });
    }

    total += content.length;
    entries.push({
      path,
      bytes: content.length,
      sha256: createHash('sha256').update(content).digest('hex'),
      content,
    });
  }

  return { entries, skipped, totalUncompressedBytes: total };
}
