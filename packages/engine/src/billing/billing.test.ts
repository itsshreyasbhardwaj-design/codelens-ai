import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { Db } from '../db/index.ts';
import { register } from '../db/auth.ts';
import {
  balance, grant, grantMonthlyAllowance, held, InsufficientCredits, ledger,
  release, releaseStaleReservations, reserve, ReservationNotFound, settle,
} from './credits.ts';
import {
  canAddSeat, canCreateProject, canStartScan, canUseAi, creditsForUsage,
  estimateScanCredits, usageSummary,
} from './entitlements.ts';
import { DEFAULT_PLANS, listPlans, planByCode, planForOrganization, seedPlans } from './plans.ts';

const KEY = 'billing-test-secret-key-at-least-32-chars';

function setup(): { db: Db; org: string } {
  const prior = process.env.CODELENS_SECRET_KEY;
  process.env.CODELENS_SECRET_KEY = KEY;
  const db = new Db(':memory:');
  db.migrate();
  seedPlans(db);
  const account = register(db, { email: `u${Math.random()}@example.com`, password: 'a-good-password' });
  if (prior === undefined) delete process.env.CODELENS_SECRET_KEY;
  else process.env.CODELENS_SECRET_KEY = prior;
  return { db, org: account.organizationId };
}

describe('plan catalogue', () => {
  it('seeds every default plan', (t) => {
    const { db } = setup();
    t.after(() => db.close());
    assert.equal(listPlans(db).length, DEFAULT_PLANS.length);
    assert.equal(planByCode(db, 'pro')?.priceCents, 4900);
  });

  it('does not overwrite a price edited in the database', (t) => {
    const { db } = setup();
    t.after(() => db.close());
    db.run("UPDATE subscription_plans SET price_cents = 2500 WHERE code = 'solo'");
    seedPlans(db); // a redeploy
    assert.equal(planByCode(db, 'solo')?.priceCents, 2500);
  });

  it('puts a new organisation on the free plan', (t) => {
    const { db, org } = setup();
    t.after(() => db.close());
    assert.equal(planForOrganization(db, org).code, 'free');
  });

  it('follows an active subscription over the organisation default', (t) => {
    const { db, org } = setup();
    t.after(() => db.close());
    const pro = planByCode(db, 'pro')!;
    db.run(
      `INSERT INTO subscriptions (id, organization_id, plan_id, status, created_at, updated_at)
       VALUES ('s1',?,?,'active','n','n')`, org, pro.id,
    );
    assert.equal(planForOrganization(db, org).code, 'pro');
  });

  it('keeps a past-due customer on their plan rather than silently downgrading', (t) => {
    const { db, org } = setup();
    t.after(() => db.close());
    const pro = planByCode(db, 'pro')!;
    db.run(
      `INSERT INTO subscriptions (id, organization_id, plan_id, status, created_at, updated_at)
       VALUES ('s1',?,?,'past_due','n','n')`, org, pro.id,
    );
    assert.equal(planForOrganization(db, org).code, 'pro');
  });

  it('allows only one active subscription per organisation', (t) => {
    const { db, org } = setup();
    t.after(() => db.close());
    const pro = planByCode(db, 'pro')!;
    const solo = planByCode(db, 'solo')!;
    db.run(`INSERT INTO subscriptions (id, organization_id, plan_id, status, created_at, updated_at) VALUES ('s1',?,?,'active','n','n')`, org, pro.id);
    assert.throws(
      () => db.run(`INSERT INTO subscriptions (id, organization_id, plan_id, status, created_at, updated_at) VALUES ('s2',?,?,'active','n','n')`, org, solo.id),
      /UNIQUE|constraint/i,
    );
  });
});

describe('credit ledger', () => {
  it('starts at zero and grants add up', (t) => {
    const { db, org } = setup();
    t.after(() => db.close());
    assert.equal(balance(db, org), 0);
    grant(db, org, 100, 'test', 'k1');
    grant(db, org, 50, 'test', 'k2');
    assert.equal(balance(db, org), 150);
  });

  it('applies a repeated grant exactly once', (t) => {
    const { db, org } = setup();
    t.after(() => db.close());
    grant(db, org, 100, 'purchase', 'payment-abc');
    grant(db, org, 100, 'purchase', 'payment-abc'); // webhook redelivery
    grant(db, org, 100, 'purchase', 'payment-abc');
    assert.equal(balance(db, org), 100);
    assert.equal(ledger(db, org).filter((e) => e.reason === 'purchase').length, 1);
  });

  it('refuses a reservation larger than the balance, and writes nothing', (t) => {
    const { db, org } = setup();
    t.after(() => db.close());
    grant(db, org, 10, 'test', 'k1');
    assert.throws(() => reserve(db, org, 50, { idempotencyKey: 'r1' }), InsufficientCredits);
    assert.equal(balance(db, org), 10);
    assert.equal(held(db, org), 0);
    assert.equal(db.get<{ n: number }>('SELECT COUNT(*) AS n FROM credit_reservations')!.n, 0);
  });

  it('never lets the balance go negative, even across many reservations', (t) => {
    const { db, org } = setup();
    t.after(() => db.close());
    grant(db, org, 100, 'test', 'k1');
    let succeeded = 0;
    for (let i = 0; i < 20; i++) {
      try { reserve(db, org, 30, { idempotencyKey: `r${i}` }); succeeded++; } catch { /* expected */ }
    }
    assert.equal(succeeded, 3, 'only three 30-credit holds fit in 100');
    assert.equal(balance(db, org), 10);
    assert.ok(balance(db, org) >= 0);
  });

  it('holds credits out of the spendable balance immediately', (t) => {
    const { db, org } = setup();
    t.after(() => db.close());
    grant(db, org, 100, 'test', 'k1');
    reserve(db, org, 40, { idempotencyKey: 'r1' });
    assert.equal(balance(db, org), 60, 'the hold leaves the balance at once');
    assert.equal(held(db, org), 40);
  });

  it('returns the same reservation for a repeated key rather than holding twice', (t) => {
    const { db, org } = setup();
    t.after(() => db.close());
    grant(db, org, 100, 'test', 'k1');
    const a = reserve(db, org, 40, { idempotencyKey: 'job-1' });
    const b = reserve(db, org, 40, { idempotencyKey: 'job-1' });
    assert.equal(a.id, b.id);
    assert.equal(balance(db, org), 60);
  });

  it('charges the actual cost and returns the remainder', (t) => {
    const { db, org } = setup();
    t.after(() => db.close());
    grant(db, org, 100, 'test', 'k1');
    const r = reserve(db, org, 40, { idempotencyKey: 'job-1' });
    const { charged, refunded } = settle(db, r.id, 12);
    assert.equal(charged, 12);
    assert.equal(refunded, 28);
    assert.equal(balance(db, org), 88);
    assert.equal(held(db, org), 0);
  });

  it('clamps a settlement above the ceiling the customer was promised', (t) => {
    const { db, org } = setup();
    t.after(() => db.close());
    grant(db, org, 100, 'test', 'k1');
    const r = reserve(db, org, 40, { idempotencyKey: 'job-1' });
    const { charged, refunded } = settle(db, r.id, 500);
    assert.equal(charged, 40, 'never more than was reserved');
    assert.equal(refunded, 0);
    assert.equal(balance(db, org), 60);
  });

  it('refuses to settle the same reservation twice', (t) => {
    const { db, org } = setup();
    t.after(() => db.close());
    grant(db, org, 100, 'test', 'k1');
    const r = reserve(db, org, 40, { idempotencyKey: 'job-1' });
    settle(db, r.id, 10);
    assert.throws(() => settle(db, r.id, 10), ReservationNotFound);
    assert.equal(balance(db, org), 90);
  });

  it('returns the whole hold when a job is cancelled', (t) => {
    const { db, org } = setup();
    t.after(() => db.close());
    grant(db, org, 100, 'test', 'k1');
    const r = reserve(db, org, 40, { idempotencyKey: 'job-1' });
    assert.equal(release(db, r.id), 40);
    assert.equal(balance(db, org), 100);
  });

  it('reclaims credits stranded by a crashed worker', (t) => {
    const { db, org } = setup();
    t.after(() => db.close());
    grant(db, org, 100, 'test', 'k1');
    // A reservation whose scan never existed, created in the past.
    const r = reserve(db, org, 40, { idempotencyKey: 'job-1' });
    db.run("UPDATE credit_reservations SET created_at = '2000-01-01T00:00:00.000Z' WHERE id = ?", r.id);
    assert.equal(balance(db, org), 60);
    assert.equal(releaseStaleReservations(db, '2020-01-01T00:00:00.000Z'), 1);
    assert.equal(balance(db, org), 100);
  });

  it('leaves a live reservation alone when reclaiming', (t) => {
    const { db, org } = setup();
    t.after(() => db.close());
    grant(db, org, 100, 'test', 'k1');
    reserve(db, org, 40, { idempotencyKey: 'job-1' });
    assert.equal(releaseStaleReservations(db, '2000-01-01T00:00:00.000Z'), 0);
    assert.equal(held(db, org), 40);
  });

  it('grants the monthly allowance once per period however often it is called', (t) => {
    const { db, org } = setup();
    t.after(() => db.close());
    const plan = planForOrganization(db, org);
    for (let i = 0; i < 5; i++) grantMonthlyAllowance(db, org, '2026-03-15T10:00:00.000Z');
    assert.equal(balance(db, org), plan.monthlyCredits);
    grantMonthlyAllowance(db, org, '2026-04-01T00:00:00.000Z');
    assert.equal(balance(db, org), plan.monthlyCredits * 2);
  });

  it('records every movement with the balance it produced', (t) => {
    const { db, org } = setup();
    t.after(() => db.close());
    grant(db, org, 100, 'purchase', 'p1');
    const r = reserve(db, org, 40, { idempotencyKey: 'job-1' });
    settle(db, r.id, 15);
    const entries = ledger(db, org);
    assert.equal(entries[entries.length - 1]!.balanceAfter, 100);
    assert.equal(entries[0]!.balanceAfter, balance(db, org));
    assert.equal(entries.reduce((s, e) => s + e.delta, 0), balance(db, org));
  });
});

describe('plan limits', () => {
  it('stops a free organisation creating a second project', (t) => {
    const { db, org } = setup();
    t.after(() => db.close());
    assert.equal(canCreateProject(db, org).allowed, true);
    db.run("INSERT INTO projects (id, organization_id, name, slug, kind, created_at, updated_at) VALUES ('p1',?,'A','a','source','n','n')", org);
    const check = canCreateProject(db, org);
    assert.equal(check.allowed, false);
    assert.match(check.reason!, /Free plan includes 1 project/);
    assert.equal(check.remedy, 'upgrade');
  });

  it('does not count a deleted project against the limit', (t) => {
    const { db, org } = setup();
    t.after(() => db.close());
    db.run("INSERT INTO projects (id, organization_id, name, slug, kind, created_at, updated_at, deleted_at) VALUES ('p1',?,'A','a','source','n','n','n')", org);
    assert.equal(canCreateProject(db, org).allowed, true);
  });

  it('enforces the monthly scan allowance and says when it resets', (t) => {
    const { db, org } = setup();
    t.after(() => db.close());
    db.run("INSERT INTO projects (id, organization_id, name, slug, kind, created_at, updated_at) VALUES ('p1',?,'A','a','source','n','n')", org);
    const at = '2026-03-15T10:00:00.000Z';
    for (let i = 0; i < 2; i++) {
      db.run("INSERT INTO scan_jobs (id, project_id, idempotency_key, status, queued_at) VALUES (?, 'p1', ?, 'completed', ?)", `s${i}`, `k${i}`, at);
    }
    const check = canStartScan(db, org, { atIso: at });
    assert.equal(check.allowed, false);
    assert.match(check.reason!, /2 scans a month/);
    assert.match(check.reason!, /2026-04-01/);
  });

  it('counts only the current month', (t) => {
    const { db, org } = setup();
    t.after(() => db.close());
    db.run("INSERT INTO projects (id, organization_id, name, slug, kind, created_at, updated_at) VALUES ('p1',?,'A','a','source','n','n')", org);
    for (let i = 0; i < 2; i++) {
      db.run("INSERT INTO scan_jobs (id, project_id, idempotency_key, status, queued_at) VALUES (?, 'p1', ?, 'completed', '2026-02-10T00:00:00.000Z')", `s${i}`, `k${i}`);
    }
    assert.equal(canStartScan(db, org, { atIso: '2026-03-01T00:00:00.000Z' }).allowed, true);
  });

  it('refuses a repository larger than the plan analyses', (t) => {
    const { db, org } = setup();
    t.after(() => db.close());
    const check = canStartScan(db, org, { atIso: '2026-03-15T10:00:00.000Z', repoSizeMb: 500 });
    assert.equal(check.allowed, false);
    assert.match(check.reason!, /500 MB/);
  });

  it('enforces seats', (t) => {
    const { db, org } = setup();
    t.after(() => db.close());
    // Registration already created the owner, filling the single free seat.
    const check = canAddSeat(db, org);
    assert.equal(check.allowed, false);
    assert.match(check.reason!, /1 seat/);
  });

  it('treats an unbounded plan limit as unlimited', (t) => {
    const { db, org } = setup();
    t.after(() => db.close());
    db.run("UPDATE organizations SET plan_code = 'enterprise' WHERE id = ?", org);
    assert.equal(canCreateProject(db, org).allowed, true);
    assert.equal(canStartScan(db, org, { atIso: '2026-03-15T10:00:00.000Z', repoSizeMb: 99999 }).allowed, true);
    assert.equal(canAddSeat(db, org).allowed, true);
  });
});

describe('AI spending', () => {
  it('never gates deterministic analysis on credits', () => {
    assert.equal(estimateScanCredits({ files: 5000, aiEnabled: false }), 0);
  });

  it('estimates a bounded ceiling that grows with the project', () => {
    const small = estimateScanCredits({ files: 20, aiEnabled: true });
    const large = estimateScanCredits({ files: 5000, aiEnabled: true });
    assert.ok(small > 0);
    assert.ok(large > small);
    assert.ok(large <= 8 * 7500 / 1000 * 2, 'the ceiling is capped, not proportional forever');
  });

  it('explains that analysis still runs when credits run out', (t) => {
    const { db, org } = setup();
    t.after(() => db.close());
    const check = canUseAi(db, org, 100);
    assert.equal(check.allowed, false);
    assert.match(check.reason!, /Deterministic analysis still runs in full/);
    assert.equal(check.remedy, 'buy_credits');
  });

  it('charges metered usage, rounded up', () => {
    assert.equal(creditsForUsage(500, 400), 2);
    assert.equal(creditsForUsage(0, 0), 0);
  });

  it('summarises usage for the billing page', (t) => {
    const { db, org } = setup();
    t.after(() => db.close());
    grant(db, org, 120, 'test', 'k1');
    const s = usageSummary(db, org, '2026-03-15T10:00:00.000Z');
    assert.equal(s.plan.code, 'free');
    assert.equal(s.credits.balance, 120);
    assert.equal(s.projects.limit, 1);
    assert.equal(s.scans.resetsOn, '2026-04-01');
  });
});
