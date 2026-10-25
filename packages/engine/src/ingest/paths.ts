import { IngestRejected } from './limits.ts';

/**
 * Archive path safety.
 *
 * Returns a repository-relative POSIX path, or throws. Rejects anything that
 * could escape the extraction root: absolute paths, parent traversal, drive
 * letters, UNC prefixes, null bytes, and backslash separators used to smuggle
 * traversal past a naive check.
 */
export function safeArchivePath(rawName: string, maxDepth: number): string {
  if (rawName.length === 0) throw new IngestRejected('empty_path', 'archive entry has an empty name');
  if (rawName.includes('\u0000')) {
    throw new IngestRejected('null_byte_path', `archive entry name contains a null byte: ${JSON.stringify(rawName)}`);
  }

  // Treat backslashes as separators before validating, so "..\\..\\etc" cannot
  // slip through a check that only looks for forward-slash traversal.
  const name = rawName.replace(/\\/g, '/');

  if (name.startsWith('/')) {
    throw new IngestRejected('absolute_path', `archive entry uses an absolute path: ${rawName}`);
  }
  if (/^[A-Za-z]:/.test(name)) {
    throw new IngestRejected('drive_path', `archive entry uses a drive-letter path: ${rawName}`);
  }
  if (name.startsWith('//')) {
    throw new IngestRejected('unc_path', `archive entry uses a UNC path: ${rawName}`);
  }

  const segments = name.split('/').filter((s) => s.length > 0 && s !== '.');
  if (segments.some((s) => s === '..')) {
    throw new IngestRejected('path_traversal', `archive entry escapes the extraction root: ${rawName}`);
  }
  if (segments.length > maxDepth) {
    throw new IngestRejected('path_too_deep', `archive entry nests deeper than ${maxDepth} levels: ${rawName}`);
  }
  return segments.join('/');
}

/** Strip the single leading directory GitHub tarballs wrap everything in. */
export function stripTopLevelDir(path: string): string {
  const i = path.indexOf('/');
  return i === -1 ? '' : path.slice(i + 1);
}
