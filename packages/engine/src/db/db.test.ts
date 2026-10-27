import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Db } from './index.ts';

describe('connection settings', () => {
  it('waits for a held write lock instead of failing instantly', () => {
    // SQLite's default busy_timeout is 0, which turns the documented
    // one-writer rule into an instant "database is locked" for the second
    // process — reachable from `pnpm scan` run against a database a web
    // server is holding, where it cost a completed scan.
    const dir = mkdtempSync(join(tmpdir(), 'codelens-db-'));
    const db = new Db(join(dir, 'x.db'));
    try {
      const { timeout } = db.raw.prepare('PRAGMA busy_timeout').get() as { timeout: number };
      assert.ok(timeout > 0, `busy_timeout must be set, got ${timeout}`);
    } finally {
      db.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('keeps foreign keys on, so a delete cascades rather than orphaning rows', () => {
    const db = new Db(':memory:');
    try {
      const { foreign_keys: fk } = db.raw.prepare('PRAGMA foreign_keys').get() as { foreign_keys: number };
      assert.equal(fk, 1);
    } finally {
      db.close();
    }
  });
});
