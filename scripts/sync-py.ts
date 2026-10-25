/**
 * Regenerate the embedded base64 copy of the Python extractor.
 *
 * `py_ast.py` is the readable source of truth; the embedded constant is what
 * ships inside a bundle. Run this after editing the Python, or the test that
 * compares the two will fail.
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const dir = join(process.cwd(), 'packages/engine/src/parse');
const source = readFileSync(join(dir, 'py_ast.py'), 'utf8');
const b64 = Buffer.from(source, 'utf8').toString('base64');
const chunks: string[] = [];
for (let i = 0; i < b64.length; i += 100) chunks.push(b64.slice(i, i + 100));

const header = readFileSync(join(dir, 'py_ast_embedded.ts'), 'utf8').split('export const')[0];
writeFileSync(
  join(dir, 'py_ast_embedded.ts'),
  `${header}export const PY_AST_SOURCE_B64 =\n  '${chunks.join("' +\n  '")}';\n\n` +
  `export function pyAstSource(): string {\n  return Buffer.from(PY_AST_SOURCE_B64, 'base64').toString('utf8');\n}\n`,
);
console.log(`embedded ${source.length} bytes of Python from py_ast.py`);
