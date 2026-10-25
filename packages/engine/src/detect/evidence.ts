import type { Evidence } from '@codelens/core';
import type { SourceFile, Snapshot } from '../ingest/normalize.ts';

/** Locate a literal in a file and return verified evidence pointing at it. */
export function evidenceFor(file: SourceFile, needle: string, note?: string): Evidence {
  if (!file.text) {
    return { file: file.path, note, verified: false };
  }
  const idx = file.text.indexOf(needle);
  if (idx === -1) {
    return { file: file.path, note, verified: false };
  }
  const before = file.text.slice(0, idx);
  const line = before.split('\n').length;
  const lineStart = before.lastIndexOf('\n') + 1;
  const lineEnd = file.text.indexOf('\n', idx);
  const excerpt = file.text.slice(lineStart, lineEnd === -1 ? undefined : lineEnd).trim();
  return { file: file.path, startLine: line, excerpt: excerpt.slice(0, 300), note, verified: true };
}

/** Evidence for a file's existence, with its first non-empty line as the excerpt. */
export function fileEvidence(file: SourceFile, note?: string): Evidence {
  const firstLine = file.text?.split('\n').find((l) => l.trim().length > 0)?.trim();
  return {
    file: file.path,
    startLine: firstLine ? (file.text!.split('\n').findIndex((l) => l.trim().length > 0) + 1) : undefined,
    excerpt: firstLine?.slice(0, 300),
    note,
    verified: true,
  };
}

export function byPath(snapshot: Snapshot): Map<string, SourceFile> {
  return new Map(snapshot.files.map((f) => [f.path, f]));
}

export function findFiles(snapshot: Snapshot, predicate: (f: SourceFile) => boolean): SourceFile[] {
  return snapshot.files.filter(predicate);
}

export function basename(path: string): string {
  return path.slice(path.lastIndexOf('/') + 1);
}

/** Parse JSON, returning undefined rather than throwing on malformed input. */
export function safeJson<T = Record<string, unknown>>(text: string | null): T | undefined {
  if (!text) return undefined;
  try {
    return JSON.parse(text) as T;
  } catch {
    return undefined;
  }
}
