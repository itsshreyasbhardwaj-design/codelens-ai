import { randomUUID } from 'node:crypto';
import { Db, now } from '../db/index.ts';
import { planForOrganization } from './plans.ts';

/**
 * Credit ledger with atomic reservation.
 *
 * The shape the brief asks for: estimate a ceiling, reserve it, run the job
 * inside that ceiling, settle the real cost, release the remainder. That is
 * what stops a job that turns out expensive from spending money the customer
 * does not have, and what stops a crashed worker from stranding the charge.
 *
 * Three invariants, each enforced in more than one place:
 *
 *  1. **A balance never goes negative.** Checked before the write, and the
 *     column carries `CHECK (balance >= 0)` so a bug in this file still cannot
 *     produce one.
 *  2. **Every mutation is idempotent.** `credit_ledger.idempotency_key` is
 *     UNIQUE, so a retried webhook, a redelivered job, or a double-clicked
 *     button applies once.
 *  3. **Reads and writes of a balance happen in one transaction.** SQLite gives
 *     a single writer, so a reservation cannot interleave with another.
 */

export class InsufficientCredits extends Error {
  readonly balance: number;
  readonly required: number;
  constructor(balance: number, required: number) {
    super(`not enough credits: ${required} required, ${balance} available`);
    this.name = 'InsufficientCredits';
    this.balance = balance;
    this.required = required;
  }
}

export class ReservationNotFound extends Error {
  constructor(id: string) { super(`no held reservation ${id}`); this.name = 'ReservationNotFound'; }
}

export interface Reservation {
  id: string;
  organizationId: string;
  amount: number;
  status: 'held' | 'settled' | 'released';
  settledAmount?: number;
}

function ensureAccount(db: Db, organizationId: string): void {
  if (db.get('SELECT organization_id FROM credit_accounts WHERE organization_id = ?', organizationId)) return;
  db.run(
    'INSERT INTO credit_accounts (organization_id, balance, lifetime_granted, lifetime_spent, updated_at) VALUES (?,0,0,0,?)',
    organizationId, now(),
  );
}

export function balance(db: Db, organizationId: string): number {
  const row = db.get<{ balance: number }>(
    'SELECT balance FROM credit_accounts WHERE organization_id = ?', organizationId,
  );
  return Number(row?.balance ?? 0);
}

/** Credits currently held by in-flight reservations. Spendable = balance. */
export function held(db: Db, organizationId: string): number {
  const row = db.get<{ total: number | null }>(
    "SELECT SUM(amount) AS total FROM credit_reservations WHERE organization_id = ? AND status = 'held'",
    organizationId,
  );
  return Number(row?.total ?? 0);
}

/**
 * Write one ledger entry and move the balance, in a single statement pair.
 * Returns false when the idempotency key was already used, which is a success:
 * the effect the caller wanted is already in place.
 */
function applyDelta(
  db: Db,
  organizationId: string,
  delta: number,
  reason: string,
  idempotencyKey: string,
  opts: { scanId?: string; reservationId?: string } = {},
): boolean {
  ensureAccount(db, organizationId);

  if (db.get('SELECT id FROM credit_ledger WHERE idempotency_key = ?', idempotencyKey)) {
    return false;
  }

  const current = balance(db, organizationId);
  const next = current + delta;
  if (next < 0) throw new InsufficientCredits(current, -delta);

  db.run(
    `UPDATE credit_accounts
        SET balance = ?,
            lifetime_granted = lifetime_granted + ?,
            lifetime_spent = lifetime_spent + ?,
            updated_at = ?
      WHERE organization_id = ?`,
    next, delta > 0 ? delta : 0, delta < 0 ? -delta : 0, now(), organizationId,
  );
  db.run(
    `INSERT INTO credit_ledger
       (id, organization_id, delta, balance_after, reason, scan_id, reservation_id, idempotency_key, created_at)
     VALUES (?,?,?,?,?,?,?,?,?)`,
    randomUUID(), organizationId, delta, next, reason,
    opts.scanId ?? null, opts.reservationId ?? null, idempotencyKey, now(),
  );
  return true;
}

/** Add credits. Idempotent on `idempotencyKey`. */
export function grant(
  db: Db, organizationId: string, amount: number, reason: string, idempotencyKey: string,
): number {
  if (amount <= 0) throw new Error('a grant must be positive');
  return db.tx(() => {
    applyDelta(db, organizationId, amount, reason, idempotencyKey);
    return balance(db, organizationId);
  });
}

/**
 * Grant the plan's monthly allowance, once per calendar period.
 *
 * The period is part of the idempotency key, so calling this on every request
 * is safe and the allowance lands exactly once per month without a scheduler.
 */
export function grantMonthlyAllowance(db: Db, organizationId: string, atIso: string): number {
  const plan = planForOrganization(db, organizationId);
  if (plan.monthlyCredits <= 0) return balance(db, organizationId);

  const period = atIso.slice(0, 7); // YYYY-MM
  // The plan code is part of the key, for two reasons. An organisation that
  // upgrades mid-month is topped up to its new plan's allowance instead of
  // being stuck on the one it already took. And the subscription webhook grants
  // through this same function, so it lands on this key rather than granting a
  // second, separate allowance of its own.
  const key = `allowance:${organizationId}:${plan.code}:${period}`;

  return db.tx(() => {
    const applied = applyDelta(
      db, organizationId, plan.monthlyCredits, `${plan.name} monthly allowance (${period})`, key,
    );
    if (applied) {
      db.run('UPDATE credit_accounts SET period_started_at = ? WHERE organization_id = ?', atIso, organizationId);
    }
    return balance(db, organizationId);
  });
}

/**
 * Hold credits against work about to start.
 *
 * The amount is the estimated ceiling, not the expected cost: the job runs
 * inside it and `settle` charges what was actually used.
 */
export function reserve(
  db: Db,
  organizationId: string,
  amount: number,
  opts: { scanId?: string; idempotencyKey?: string } = {},
): Reservation {
  if (amount <= 0) throw new Error('a reservation must be positive');
  const key = opts.idempotencyKey ?? `reserve:${randomUUID()}`;

  return db.tx(() => {
    // A repeated key returns the existing reservation rather than holding twice.
    const existing = db.get<Record<string, unknown>>(
      'SELECT * FROM credit_reservations WHERE idempotency_key = ?', key,
    );
    if (existing) return rowToReservation(existing);

    const id = randomUUID();
    // Throws InsufficientCredits before anything is written.
    applyDelta(db, organizationId, -amount, 'reserved for analysis', `${key}:hold`, {
      scanId: opts.scanId, reservationId: id,
    });
    db.run(
      `INSERT INTO credit_reservations
         (id, organization_id, scan_id, amount, status, idempotency_key, created_at)
       VALUES (?,?,?,?,'held',?,?)`,
      id, organizationId, opts.scanId ?? null, amount, key, now(),
    );
    return { id, organizationId, amount, status: 'held' as const };
  });
}

/**
 * Charge what was actually used and return the rest.
 *
 * `actualAmount` above the reserved ceiling is clamped: the ceiling is the
 * promise made to the customer when the job started, and exceeding it is a bug
 * in estimation, not a licence to charge more.
 */
export function settle(db: Db, reservationId: string, actualAmount: number): { charged: number; refunded: number } {
  if (actualAmount < 0) throw new Error('settlement cannot be negative');

  return db.tx(() => {
    const row = db.get<Record<string, unknown>>(
      "SELECT * FROM credit_reservations WHERE id = ? AND status = 'held'", reservationId,
    );
    if (!row) throw new ReservationNotFound(reservationId);

    const reserved = Number(row.amount);
    const organizationId = String(row.organization_id);
    const charged = Math.min(actualAmount, reserved);
    const refunded = reserved - charged;

    if (refunded > 0) {
      applyDelta(db, organizationId, refunded, 'unused reservation returned', `${row.idempotency_key}:release`, {
        scanId: row.scan_id ? String(row.scan_id) : undefined,
        reservationId,
      });
    }
    db.run(
      "UPDATE credit_reservations SET status = 'settled', settled_amount = ?, settled_at = ? WHERE id = ?",
      charged, now(), reservationId,
    );
    return { charged, refunded };
  });
}

/** Return the whole hold — for a cancelled or failed job. */
export function release(db: Db, reservationId: string, reason = 'analysis did not complete'): number {
  return db.tx(() => {
    const row = db.get<Record<string, unknown>>(
      "SELECT * FROM credit_reservations WHERE id = ? AND status = 'held'", reservationId,
    );
    if (!row) throw new ReservationNotFound(reservationId);

    const amount = Number(row.amount);
    applyDelta(db, String(row.organization_id), amount, reason, `${row.idempotency_key}:release`, {
      scanId: row.scan_id ? String(row.scan_id) : undefined,
      reservationId,
    });
    db.run("UPDATE credit_reservations SET status = 'released', settled_at = ? WHERE id = ?", now(), reservationId);
    return amount;
  });
}

/**
 * Return holds for jobs that are no longer running.
 *
 * A worker that crashes mid-scan leaves credits held forever otherwise. Called
 * on startup and periodically; safe to run at any time because `release` only
 * touches reservations still marked held.
 */
export function releaseStaleReservations(db: Db, olderThanIso: string): number {
  const stale = db.all<{ id: string }>(
    `SELECT r.id FROM credit_reservations r
       LEFT JOIN scan_jobs s ON s.id = r.scan_id
      WHERE r.status = 'held'
        AND r.created_at < ?
        AND (s.id IS NULL OR s.status IN ('completed','partial','failed','cancelled'))`,
    olderThanIso,
  );
  let released = 0;
  for (const { id } of stale) {
    try {
      release(db, id, 'reservation outlived its scan');
      released++;
    } catch { /* already settled by a racing settle(); nothing to do */ }
  }
  return released;
}

function rowToReservation(r: Record<string, unknown>): Reservation {
  return {
    id: String(r.id),
    organizationId: String(r.organization_id),
    amount: Number(r.amount),
    status: String(r.status) as Reservation['status'],
    settledAmount: r.settled_amount === null ? undefined : Number(r.settled_amount),
  };
}

export interface LedgerEntry {
  delta: number;
  balanceAfter: number;
  reason: string;
  scanId?: string;
  createdAt: string;
}

export function ledger(db: Db, organizationId: string, limit = 50): LedgerEntry[] {
  return db.all<Record<string, unknown>>(
    'SELECT delta, balance_after, reason, scan_id, created_at FROM credit_ledger WHERE organization_id = ? ORDER BY created_at DESC, rowid DESC LIMIT ?',
    organizationId, limit,
  ).map((r) => ({
    delta: Number(r.delta),
    balanceAfter: Number(r.balance_after),
    reason: String(r.reason),
    scanId: r.scan_id ? String(r.scan_id) : undefined,
    createdAt: String(r.created_at),
  }));
}
