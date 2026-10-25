/**
 * Text helpers shared by analyzers.
 *
 * `stripComments` exists because matching raw file text is a real source of
 * false negatives *and* false positives: a comment saying "no CSP is set here"
 * contains the words a naive check looks for, and a commented-out call looks
 * like a live one. Analyzers that must match on text use this first.
 */

/** Remove //, /* *\/, and # comments without disturbing string literals. */
export function stripComments(source: string): string {
  let out = '';
  let i = 0;
  const n = source.length;
  type State = 'code' | 'line' | 'block' | 'single' | 'double' | 'template';
  let state: State = 'code';

  while (i < n) {
    const ch = source[i]!;
    const next = source[i + 1];

    switch (state) {
      case 'code':
        if (ch === '/' && next === '/') { state = 'line'; i += 2; continue; }
        if (ch === '#' && next !== '!') {
          // A lone '#' starts a comment in Python/YAML/shell/TOML. In JS it only
          // appears in private fields (#name) or a shebang, so require that the
          // next character is not an identifier start.
          if (!next || !/[A-Za-z_]/.test(next)) { state = 'line'; i += 1; continue; }
          // Treat `# text` (with a space) as a comment too.
          if (next === ' ') { state = 'line'; i += 1; continue; }
        }
        if (ch === '/' && next === '*') { state = 'block'; i += 2; continue; }
        if (ch === "'") { state = 'single'; out += ch; i++; continue; }
        if (ch === '"') { state = 'double'; out += ch; i++; continue; }
        if (ch === '`') { state = 'template'; out += ch; i++; continue; }
        out += ch; i++; continue;

      case 'line':
        if (ch === '\n') { state = 'code'; out += ch; }
        i++; continue;

      case 'block':
        if (ch === '*' && next === '/') { state = 'code'; i += 2; continue; }
        // Keep newlines so line numbers are preserved.
        if (ch === '\n') out += ch;
        i++; continue;

      case 'single':
      case 'double':
      case 'template': {
        const quote = state === 'single' ? "'" : state === 'double' ? '"' : '`';
        if (ch === '\\') { out += ch + (next ?? ''); i += 2; continue; }
        if (ch === quote) { state = 'code'; }
        out += ch; i++; continue;
      }
    }
  }
  return out;
}

/** Python triple-quoted docstrings read as string literals; drop them for matching. */
export function stripPythonDocstrings(source: string): string {
  return source.replace(/("""|''')[\s\S]*?\1/g, (m) => '\n'.repeat((m.match(/\n/g) ?? []).length));
}

/** Comment-free view of a file's text, suitable for presence checks. */
export function codeText(text: string | null, language?: string): string {
  if (!text) return '';
  const base = language === 'python' ? stripPythonDocstrings(text) : text;
  return stripComments(base);
}
