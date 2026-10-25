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
export const SCHEMA_VERSION = 1;

export type Row = Record<string, unknown>;

export class Db {
  readonly raw: DatabaseSync;

  constructor(path = ':memory:') {
    this.raw = new DatabaseSync(path);
    this.raw.exec('PRAGMA foreign_keys = ON');
    this.raw.exec('PRAGMA journal_mode = WAL');
  }

  migrate(): void {
    const sql = readFileSync(join(HERE, 'schema.sql'), 'utf8');
    this.raw.exec(sql);
    const applied = this.raw.prepare('SELECT version FROM schema_migrations WHERE version = ?').get(SCHEMA_VERSION);
    if (!applied) {
      this.raw
        .prepare('INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)')
        .run(SCHEMA_VERSION, new Date().toISOString());
    }
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

  /** Run `fn` in a transaction, rolling back on any throw. */
  tx<T>(fn: () => T): T {
    this.raw.exec('BEGIN');
    try {
      const out = fn();
      this.raw.exec('COMMIT');
      return out;
    } catch (e) {
      this.raw.exec('ROLLBACK');
      throw e;
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
