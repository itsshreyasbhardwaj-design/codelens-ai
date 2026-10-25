import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { findPython, parsePython } from './py.ts';
import { pyAstSource } from './py_ast_embedded.ts';

const HERE = dirname(fileURLToPath(import.meta.url));

describe('python extraction', () => {
  it('keeps the embedded extractor identical to the readable source', () => {
    // py_ast.py is the canonical copy; the base64 constant is what ships in a
    // bundle. If these drift, a built deployment runs different code from the
    // one under review.
    const canonical = readFileSync(join(HERE, 'py_ast.py'), 'utf8');
    assert.equal(pyAstSource(), canonical, 'run `pnpm sync:py` after editing py_ast.py');
  });

  it('extracts imports, symbols, calls and decorators from a FastAPI module', (t) => {
    if (!findPython()) return t.skip('no python3 on PATH');

    const mod = parsePython('app/main.py', [
      'import os',
      'from fastapi import FastAPI, Depends',
      'from .db import get_session',
      '',
      'app = FastAPI()',
      'DATABASE_URL = os.environ["DATABASE_URL"]',
      'DEBUG = os.getenv("DEBUG", "false")',
      '',
      '@app.get("/items/{item_id}")',
      'async def read_item(item_id: int, user = Depends(get_session)):',
      '    try:',
      '        rows = []',
      '        for i in range(10):',
      '            rows.append(db.query(i))',
      '        return {"id": item_id, "rows": rows}',
      '    except Exception:',
      '        raise',
    ].join('\n'));

    assert.equal(mod.parsed, true, mod.parseError);
    assert.ok(mod.imports.some((i) => i.specifier === 'fastapi'));
    // A relative import must be marked as internal so it can be resolved.
    const rel = mod.imports.find((i) => i.specifier === '.db');
    assert.ok(rel, 'relative import should be captured');
    assert.equal(rel!.external, false);

    const handler = mod.symbols.find((s) => s.name === 'read_item');
    assert.ok(handler, 'the handler symbol should be captured');
    assert.equal(handler!.async, true);
    assert.ok(handler!.decorators?.some((d) => d.includes('@app.get')), 'the route decorator carries the path');

    assert.deepEqual([...mod.envVars].sort(), ['DATABASE_URL', 'DEBUG']);
    assert.equal(mod.hasTryCatch, true);

    // The loop context is what N+1 detection depends on.
    const inLoop = mod.calls.filter((c) => c.insideLoop);
    assert.ok(inLoop.some((c) => c.callee === 'db.query'), 'a call inside a for loop must be marked');

    // Dict keys give the response shape for contract analysis.
    assert.ok(mod.objectLiterals.some((o) => o.keys.includes('id') && o.keys.includes('rows')));
  });

  it('captures class attributes as a declared shape', (t) => {
    if (!findPython()) return t.skip('no python3 on PATH');
    const mod = parsePython('models.py', [
      'from django.db import models',
      '',
      'class Order(models.Model):',
      '    user_id = models.CharField(max_length=64)',
      '    total = models.IntegerField()',
    ].join('\n'));
    assert.equal(mod.parsed, true, mod.parseError);
    const shape = mod.objectLiterals.find((o) => o.inSymbol === 'Order');
    assert.ok(shape);
    assert.ok(shape!.keys.includes('user_id'));
  });

  it('reports a syntax error rather than throwing', (t) => {
    if (!findPython()) return t.skip('no python3 on PATH');
    const mod = parsePython('broken.py', 'def f(:\n  pass');
    assert.equal(mod.parsed, false);
    assert.match(mod.parseError!, /SyntaxError/);
  });

  it('never executes the analysed module', (t) => {
    if (!findPython()) return t.skip('no python3 on PATH');
    // If the extractor imported the file instead of parsing it, this would
    // raise and the parse would fail.
    const mod = parsePython('hostile.py', [
      'import sys',
      'raise RuntimeError("this module must never run")',
      'def after(): pass',
    ].join('\n'));
    assert.equal(mod.parsed, true, 'parsing must succeed even though executing would raise');
    assert.ok(mod.symbols.some((s) => s.name === 'after'));
  });
});
