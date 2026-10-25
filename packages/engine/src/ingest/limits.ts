/**
 * Ingestion bounds. Every one of these is enforced, and exceeding one produces
 * a named error the UI shows — never a silent truncation.
 */
export interface IngestLimits {
  /** Maximum compressed archive size accepted. */
  maxArchiveBytes: number;
  /** Maximum total uncompressed bytes across all entries (decompression bomb guard). */
  maxTotalUncompressedBytes: number;
  /** Maximum uncompressed bytes for a single entry. */
  maxEntryBytes: number;
  /** Maximum uncompressed:compressed ratio for a single entry. */
  maxCompressionRatio: number;
  /** Maximum number of entries. */
  maxEntries: number;
  /** Maximum path depth. */
  maxPathDepth: number;
  /** Files larger than this are indexed but not parsed. */
  maxParseBytes: number;
}

export const DEFAULT_LIMITS: IngestLimits = {
  maxArchiveBytes: 256 * 1024 * 1024,
  maxTotalUncompressedBytes: 2 * 1024 * 1024 * 1024,
  maxEntryBytes: 32 * 1024 * 1024,
  maxCompressionRatio: 200,
  maxEntries: 200_000,
  maxPathDepth: 40,
  maxParseBytes: 2 * 1024 * 1024,
};

export class IngestRejected extends Error {
  readonly code: string;
  readonly detail: Record<string, unknown>;
  constructor(code: string, message: string, detail: Record<string, unknown> = {}) {
    super(message);
    this.name = 'IngestRejected';
    this.code = code;
    this.detail = detail;
  }
}
