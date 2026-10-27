import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readZip } from './zip.ts';
import { writeZip } from './zipwriter.ts';
import { safeArchivePath } from './paths.ts';
import { DEFAULT_LIMITS, IngestRejected } from './limits.ts';
import { isExcludedDir, isExcludedPath } from './ignore.ts';

const L = DEFAULT_LIMITS;

function expectRejected(fn: () => unknown, code: string) {
  try {
    fn();
  } catch (e) {
    assert.ok(e instanceof IngestRejected, `expected IngestRejected, got ${e}`);
    assert.equal((e as IngestRejected).code, code);
    return;
  }
  assert.fail(`expected rejection with code ${code}, but nothing was thrown`);
}

describe('archive path safety', () => {
  it('accepts a normal nested path', () => {
    assert.equal(safeArchivePath('src/app/page.tsx', 40), 'src/app/page.tsx');
  });
  it('normalises ./ segments', () => {
    assert.equal(safeArchivePath('./src/./a.ts', 40), 'src/a.ts');
  });
  it('rejects parent traversal', () => {
    expectRejected(() => safeArchivePath('../../etc/passwd', 40), 'path_traversal');
  });
  it('rejects backslash-smuggled traversal', () => {
    expectRejected(() => safeArchivePath('..\\..\\Windows\\system32', 40), 'path_traversal');
  });
  it('rejects absolute paths', () => {
    expectRejected(() => safeArchivePath('/etc/shadow', 40), 'absolute_path');
  });
  it('rejects drive-letter paths', () => {
    expectRejected(() => safeArchivePath('C:/Windows/evil.dll', 40), 'drive_path');
  });
  it('rejects null bytes', () => {
    expectRejected(() => safeArchivePath('a\u0000b.ts', 40), 'null_byte_path');
  });
  it('rejects excessive nesting', () => {
    expectRejected(() => safeArchivePath('a/'.repeat(50) + 'f.ts', 40), 'path_too_deep');
  });
});

describe('zip reader', () => {
  it('reads a well-formed archive and hashes contents', () => {
    const zip = writeZip([
      { name: 'package.json', content: '{"name":"demo"}' },
      { name: 'src/index.ts', content: 'export const x = 1;\n' },
      { name: 'src/', content: '' },
    ]);
    const out = readZip(zip, L);
    assert.equal(out.entries.length, 2);
    const paths = out.entries.map((e) => e.path).sort();
    assert.deepEqual(paths, ['package.json', 'src/index.ts']);
    assert.match(out.entries[0]!.sha256, /^[0-9a-f]{64}$/);
    assert.equal(out.totalUncompressedBytes, 15 + 20);
  });

  it('reads stored (uncompressed) entries', () => {
    const out = readZip(writeZip([{ name: 'a.txt', content: 'hello', store: true }]), L);
    assert.equal(out.entries[0]!.content.toString(), 'hello');
  });

  it('refuses a traversal entry', () => {
    expectRejected(() => readZip(writeZip([{ name: '../../../etc/passwd', content: 'x' }]), L), 'path_traversal');
  });

  it('skips symlink entries instead of extracting them', () => {
    // 0xA1FF0000 >>> 16 = 0xA1FF, and 0xA1FF & 0xF000 === 0xA000 (S_IFLNK).
    const out = readZip(writeZip([
      { name: 'link', content: '/etc/passwd', externalAttr: 0xa1ff0000 },
      { name: 'real.ts', content: 'ok' },
    ]), L);
    assert.equal(out.entries.length, 1);
    assert.equal(out.entries[0]!.path, 'real.ts');
    assert.match(out.skipped[0]!.reason, /symlink/);
  });

  it('refuses a decompression bomb by compression ratio', () => {
    // 4 MiB of zeros deflates to a few KiB: ratio far above the 200x limit.
    const bomb = Buffer.alloc(4 * 1024 * 1024, 0);
    expectRejected(() => readZip(writeZip([{ name: 'bomb.bin', content: bomb }]), L), 'compression_bomb');
  });

  it('enforces a per-entry size limit', () => {
    const big = Buffer.alloc(1024, 0x41);
    const tight = { ...L, maxEntryBytes: 512 };
    const out = readZip(writeZip([{ name: 'big.txt', content: big }]), tight);
    assert.equal(out.entries.length, 0);
    assert.match(out.skipped[0]!.reason, /per-file limit/);
  });

  it('enforces a total uncompressed limit', () => {
    const chunk = 'a'.repeat(1000);
    const tight = { ...L, maxTotalUncompressedBytes: 1500, maxCompressionRatio: 10_000 };
    expectRejected(
      () => readZip(writeZip([
        { name: 'a.txt', content: chunk }, { name: 'b.txt', content: chunk },
      ]), tight),
      'uncompressed_total_exceeded',
    );
  });

  it('detects a lying size header', () => {
    expectRejected(
      () => readZip(writeZip([{ name: 'a.txt', content: 'hello', declaredUncompressedSize: 5000 }]),
        { ...L, maxCompressionRatio: 100000 }),
      'size_mismatch',
    );
  });

  it('rejects a non-zip buffer', () => {
    expectRejected(() => readZip(Buffer.from('this is not a zip file at all, not even close'), L), 'not_a_zip');
  });

  it('rejects an oversized archive before parsing', () => {
    expectRejected(() => readZip(Buffer.alloc(100), { ...L, maxArchiveBytes: 50 }), 'archive_too_large');
  });

  it('refuses an archive declaring more entries than the limit', () => {
    const zip = writeZip([{ name: 'a.txt', content: 'x' }, { name: 'b.txt', content: 'y' }]);
    expectRejected(() => readZip(zip, { ...L, maxEntries: 1 }), 'too_many_entries');
  });
});

describe('our own output is not project source', () => {
  it('excludes the directories CodeLens writes into', () => {
    // Scanning a project that uses CodeLens was ingesting CodeLens's own
    // database. The sidecars sniff as binary so nothing was mis-analysed, but
    // their bytes counted toward the snapshot and toward the plan's megabyte
    // ceiling, and grew with every scan.
    assert.equal(isExcludedDir('.codelens'), true);
    assert.equal(isExcludedDir('codelens-report'), true);
    assert.equal(isExcludedPath('.codelens/codelens.db').excluded, true);
    assert.equal(isExcludedPath('.codelens/codelens.db-wal').excluded, true);
    assert.equal(isExcludedPath('codelens-report/findings.json').excluded, true);
  });

  it('still analyses a source file whose name merely resembles them', () => {
    assert.equal(isExcludedDir('codelens'), false);
    assert.equal(isExcludedPath('src/codelens-report.ts').excluded, false);
  });
});
