import { DatabaseSync } from 'node:sqlite';
import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

/**
 * Database access.
 *
 * All SQL lives in this directory. Callers receive narrow, tenant-scoped
 * methods so a missing organisation filter cannot leak across tenants by
 * accident — see `assertProjectInOrg`.
 */

const HERE = dirname(fileURLToPath(import.meta.url));
export const SCHEMA_VERSION = 4;

/**
 * Migrations beyond the baseline, in order. Adding one means adding a file in
 * `migrations/` and a line here — the list is explicit rather than a directory
 * scan, so a stray file cannot silently become a migration.
 */
const MIGRATIONS: Array<{ version: number; file: string }> = [
  { version: 2, file: '002_billing.sql' },
  { version: 3, file: '003_subscription_ended.sql' },
  { version: 4, file: '004_scan_billable.sql' },
];

function pendingMigrations(applied: Set<number>): Array<{ version: number; file: string }> {
  return MIGRATIONS.filter((m) => !applied.has(m.version)).sort((a, b) => a.version - b.version);
}

export type Row = Record<string, unknown>;

export class Db {
  readonly raw: DatabaseSync;

  constructor(path = ':memory:') {
    this.raw = new DatabaseSync(path);
    this.raw.exec('PRAGMA foreign_keys = ON');
    this.raw.exec('PRAGMA journal_mode = WAL');
    // SQLite's default is 0: a writer that finds the lock held fails instantly
    // rather than waiting — measured at 0.03 ms, with errcode 5. That is
    // reachable in the flow the README and the landing page both recommend,
    // `pnpm scan` from the repository root while the dev server holds the same
    // file, and it cost a completed scan: saveScan's transaction (persist.ts)
    // is a ~26 ms window for a 24-file project and grows with the repository.
    // Waiting fixes the cross-process case — measured 787 ms, then success.
    //
    // It is NOT a fix for two connections inside one process. node:sqlite is
    // synchronous, so a blocked call owns the only thread and the holder can
    // never reach its COMMIT: the wait expires and fails anyway, five seconds
    // later than before. One connection per process is the rule — store.ts
    // caches a single Db — and this pragma is not permission to open a second.
    this.raw.exec('PRAGMA busy_timeout = 5000');
  }

  /**
   * Apply every migration this build carries that the database has not seen.
   *
   * Version 1 is `schema.sql`, which is written with IF NOT EXISTS throughout
   * and is safe to re-run. Later migrations are numbered files in `migrations/`
   * and are applied exactly once each, inside a transaction, so a statement
   * that cannot be repeated — an ALTER TABLE, say — runs only on the upgrade
   * that introduces it.
   */
  migrate(): void {
    // The baseline also creates schema_migrations itself.
    this.raw.exec(readFileSync(join(HERE, 'schema.sql'), 'utf8'));
    this.recordVersion(1);

    for (const { version, file } of pendingMigrations(this.appliedVersions())) {
      const sql = readFileSync(join(HERE, 'migrations', file), 'utf8');
      this.raw.exec('BEGIN');
      try {
        this.raw.exec(sql);
        this.recordVersion(version);
        this.raw.exec('COMMIT');
      } catch (e) {
        this.raw.exec('ROLLBACK');
        throw new Error(`migration ${file} failed: ${(e as Error).message}`);
      }
    }
  }

  private appliedVersions(): Set<number> {
    return new Set(
      (this.raw.prepare('SELECT version FROM schema_migrations').all() as Array<{ version: number }>)
        .map((r) => Number(r.version)),
    );
  }

  private recordVersion(version: number): void {
    this.raw
      .prepare('INSERT OR IGNORE INTO schema_migrations (version, applied_at) VALUES (?, ?)')
      .run(version, new Date().toISOString());
  }

  /** Versions this build carries, for a health check or a deploy gate. */
  schemaStatus(): { applied: number[]; pending: number[]; current: number } {
    const applied = [...this.appliedVersions()].sort((a, b) => a - b);
    return {
      applied,
      pending: pendingMigrations(new Set(applied)).map((m) => m.version),
      current: applied.length ? Math.max(...applied) : 0,
    };
  }

  get<T = Row>(sql: string, ...params: unknown[]): T | undefined {
    return this.raw.prepare(sql).get(...(params as never[])) as T | undefined;
  }

  all<T = Row>(sql: string, ...params: unknown[]): T[] {
    return this.raw.prepare(sql).all(...(params as never[])) as T[];
  }

  run(sql: string, ...params: unknown[]): void {
    this.raw.prepare(sql).run(...(params as never[]));
  }

  private txDepth = 0;

  /**
   * Run `fn` in a transaction, rolling back on any throw.
   *
   * Re-entrant: a transactional function calling another one is ordinary —
   * applying a payment event grants credits, and both want atomicity — and
   * SQLite rejects a nested BEGIN. Only the outermost call opens and closes the
   * transaction; an inner throw propagates and the outer rollback undoes
   * everything, which is the semantics every caller here wants.
   */
  tx<T>(fn: () => T): T {
    if (this.txDepth > 0) {
      this.txDepth++;
      try {
        return fn();
      } finally {
        this.txDepth--;
      }
    }

    this.raw.exec('BEGIN');
    this.txDepth = 1;
    try {
      const out = fn();
      this.raw.exec('COMMIT');
      return out;
    } catch (e) {
      this.raw.exec('ROLLBACK');
      throw e;
    } finally {
      this.txDepth = 0;
    }
  }

  close(): void {
    this.raw.close();
  }

  // ----------------------------------------------------------- tenancy ----

  /**
   * Throws unless the project belongs to the organisation. Every read path that
   * accepts a project id from a request must call this first.
   */
  assertProjectInOrg(projectId: string, organizationId: string): void {
    const row = this.get<{ organization_id: string; deleted_at: string | null }>(
      'SELECT organization_id, deleted_at FROM projects WHERE id = ?',
      projectId,
    );
    if (!row || row.deleted_at) throw new NotFoundError(`project ${projectId} not found`);
    if (row.organization_id !== organizationId) {
      // Deliberately the same error as "not found": existence is not leaked
      // across tenants.
      throw new NotFoundError(`project ${projectId} not found`);
    }
  }

  /** Resolve the organisation that owns a scan, for authorisation checks. */
  orgForScan(scanId: string): string | undefined {
    return this.get<{ organization_id: string }>(
      `SELECT p.organization_id AS organization_id
         FROM scan_jobs s JOIN projects p ON p.id = s.project_id
        WHERE s.id = ?`,
      scanId,
    )?.organization_id;
  }

  audit(entry: {
    organizationId?: string; actorUserId?: string; action: string;
    targetKind?: string; targetId?: string; detail?: unknown; ip?: string;
  }): void {
    this.run(
      `INSERT INTO audit_logs (id, organization_id, actor_user_id, action, target_kind, target_id, detail_json, ip_address, created_at)
       VALUES (?,?,?,?,?,?,?,?,?)`,
      randomUUID(), entry.organizationId ?? null, entry.actorUserId ?? null, entry.action,
      entry.targetKind ?? null, entry.targetId ?? null,
      entry.detail === undefined ? null : JSON.stringify(entry.detail),
      entry.ip ?? null, new Date().toISOString(),
    );
  }
}

export class NotFoundError extends Error {
  constructor(message: string) { super(message); this.name = 'NotFoundError'; }
}

export function newId(): string { return randomUUID(); }
export function now(): string { return new Date().toISOString(); }
