import { deflateRawSync } from 'node:zlib';
import * as zlib from 'node:zlib';

/**
 * Minimal ZIP writer used by tests to build both well-formed and deliberately
 * malicious archives. Not used in production code paths.
 */
export interface WriteEntry {
  name: string;
  content: Buffer | string;
  /** Store uncompressed instead of deflating. */
  store?: boolean;
  /** Raw external attributes; use 0xA1FF0000 to mark a symlink. */
  externalAttr?: number;
  /** Override the declared uncompressed size, to simulate a lying header. */
  declaredUncompressedSize?: number;
}

function crc32of(b: Buffer): number {
  const fn = (zlib as unknown as { crc32?: (x: Buffer) => number }).crc32;
  if (typeof fn === 'function') return fn(b) >>> 0;
  // Fallback table-based CRC32 so tests work on runtimes without zlib.crc32.
  let c = ~0;
  for (const byte of b) {
    c ^= byte;
    for (let k = 0; k < 8; k++) c = (c >>> 1) ^ (0xedb88320 & -(c & 1));
  }
  return ~c >>> 0;
}

export function writeZip(entries: WriteEntry[]): Buffer {
  const locals: Buffer[] = [];
  const centrals: Buffer[] = [];
  let offset = 0;

  for (const e of entries) {
    const content = Buffer.isBuffer(e.content) ? e.content : Buffer.from(e.content, 'utf8');
    const name = Buffer.from(e.name, 'utf8');
    const method = e.store ? 0 : 8;
    const data = e.store ? content : deflateRawSync(content);
    const crc = crc32of(content);
    const uncompSize = e.declaredUncompressedSize ?? content.length;

    const lh = Buffer.alloc(30);
    lh.writeUInt32LE(0x04034b50, 0);
    lh.writeUInt16LE(20, 4);
    lh.writeUInt16LE(0, 6);
    lh.writeUInt16LE(method, 8);
    lh.writeUInt32LE(crc, 14);
    lh.writeUInt32LE(data.length, 18);
    lh.writeUInt32LE(uncompSize, 22);
    lh.writeUInt16LE(name.length, 26);
    lh.writeUInt16LE(0, 28);
    locals.push(lh, name, data);

    const ch = Buffer.alloc(46);
    ch.writeUInt32LE(0x02014b50, 0);
    ch.writeUInt16LE(20, 4);
    ch.writeUInt16LE(20, 6);
    ch.writeUInt16LE(0, 8);
    ch.writeUInt16LE(method, 10);
    ch.writeUInt32LE(crc, 16);
    ch.writeUInt32LE(data.length, 20);
    ch.writeUInt32LE(uncompSize, 24);
    ch.writeUInt16LE(name.length, 28);
    ch.writeUInt16LE(0, 30);
    ch.writeUInt16LE(0, 32);
    ch.writeUInt32LE(e.externalAttr ?? 0, 38);
    ch.writeUInt32LE(offset, 42);
    centrals.push(ch, name);

    offset += lh.length + name.length + data.length;
  }

  const localBuf = Buffer.concat(locals);
  const centralBuf = Buffer.concat(centrals);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(entries.length, 8);
  eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(centralBuf.length, 12);
  eocd.writeUInt32LE(localBuf.length, 16);
  return Buffer.concat([localBuf, centralBuf, eocd]);
}
