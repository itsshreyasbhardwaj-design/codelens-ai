import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { Db } from '../db/index.ts';
import { register } from '../db/auth.ts';
import {
  balance, grant, grantMonthlyAllowance, held, InsufficientCredits, ledger,
  recoverOrphanedScans, release, releaseStaleReservations, reserve, ReservationNotFound, settle,
} from './credits.ts';
import {
  canAddSeat, canCreateProject, canStartScan, canUseAi, creditsForUsage,
  estimateScanCredits, tokensForCredits, usageSummary,
} from './entitlements.ts';
import { DEFAULT_PLANS, listPlans, planByCode, planForOrganization, seedPlans } from './plans.ts';
import { applyWebhookEvent } from './payments.ts';
import { beginScan, failScan } from '../pipeline/persist.ts';

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

  it('estimates from the work to be done, not from the file count', () => {
    // The estimate follows how many investigations the AI stage will actually
    // run. It used to scale with file count, which under-counted a small,
    // route-dense repository by 4x — and because settle() clamps the charge to
    // the reservation, that overspend was absorbed in silence rather than
    // billed. A ten-file service with eight unvalidated handlers really does
    // cost eight investigations.
    const twoTargets = estimateScanCredits({ files: 10, targets: 2, aiEnabled: true });
    const eightTargets = estimateScanCredits({ files: 10, targets: 8, aiEnabled: true });
    assert.ok(twoTargets > 0);
    assert.ok(eightTargets > twoTargets, 'more investigations must cost more');
    assert.equal(eightTargets, Math.ceil(8 * 9900 / 1000 * 2));

    // Unknown target count assumes the maximum rather than guessing low:
    // guessing low is cost the clamp hides.
    assert.equal(estimateScanCredits({ files: 10, aiEnabled: true }), eightTargets);
    // Still capped, however large the repository.
    assert.equal(estimateScanCredits({ files: 5000, targets: 50, aiEnabled: true }), eightTargets);
  });

  it('funds exactly the tokens it charges for', () => {
    // The reserved ceiling and the token budget the stage is given must be the
    // same number, or the stage can spend past what anyone is charged.
    const credits = estimateScanCredits({ files: 10, targets: 8, aiEnabled: true });
    const tokens = tokensForCredits(credits);
    assert.equal(creditsForUsage(tokens, 0), credits);
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

// ---------------------------------------------------------------------------
// Regressions from the PR #1 review. Each of these passed before the fix in the
// sense that no test exercised the path at all; each fails if the fix is undone.
// ---------------------------------------------------------------------------

describe('credit reservation needs a scan row to point at', () => {
  it('refuses to reserve against a scan that was never registered', (t) => {
    const { db, org } = setup();
    t.after(() => db.close());
    grant(db, org, 500, 'test credits', 'k1');

    // credit_ledger.scan_id is a foreign key to scan_jobs. This is the state the
    // web runner used to be in on every single scan: the orchestrator minted a
    // scan id and reserved against it while the row was still unwritten.
    assert.throws(
      () => reserve(db, org, 30, { scanId: 'scan_never_registered', idempotencyKey: 'r1' }),
      /FOREIGN KEY constraint failed/,
    );
    assert.equal(balance(db, org), 500, 'a failed reservation must not move the balance');
    assert.equal(held(db, org), 0);
  });

  it('reserves once the scan row has been registered by beginScan', (t) => {
    const { db, org } = setup();
    t.after(() => db.close());
    grant(db, org, 500, 'test credits', 'k1');

    beginScan(db, 'scan_registered', {
      organizationId: org, projectId: `${org}:demo`, projectName: 'demo', slug: 'demo',
    });

    const r = reserve(db, org, 30, { scanId: 'scan_registered', idempotencyKey: 'r1' });
    assert.equal(r.status, 'held');
    assert.equal(held(db, org), 30);
    // The audit link the billing page renders per charge.
    assert.equal(ledger(db, org, 10)[0]?.scanId, 'scan_registered');
  });
});

describe('the monthly allowance is granted once per plan per month', () => {
  function subscriptionEvent(org: string, id: string, status = 'active') {
    return {
      id,
      type: 'customer.subscription.updated',
      data: {
        id: 'sub_live_1',
        status,
        metadata: { organization_id: org, code: 'pro' },
      },
    };
  }

  it('does not grant a fresh allowance for every subscription event', (t) => {
    const { db, org } = setup();
    t.after(() => db.close());
    const pro = planByCode(db, 'pro')!;

    // Stripe sends customer.subscription.updated on every renewal, card change,
    // cancellation toggle and past_due recovery. Each one has its own event id,
    // so an event-keyed grant handed out a whole allowance every time.
    applyWebhookEvent(db, 'stripe', subscriptionEvent(org, 'evt_1'));
    const afterFirst = balance(db, org);
    applyWebhookEvent(db, 'stripe', subscriptionEvent(org, 'evt_2'));
    applyWebhookEvent(db, 'stripe', subscriptionEvent(org, 'evt_3'));

    assert.equal(afterFirst, pro.monthlyCredits);
    assert.equal(balance(db, org), pro.monthlyCredits, 'three events must grant one allowance');
  });

  it('does not grant a second allowance through the scan path in the same month', (t) => {
    const { db, org } = setup();
    t.after(() => db.close());
    const pro = planByCode(db, 'pro')!;

    applyWebhookEvent(db, 'stripe', subscriptionEvent(org, 'evt_1'));
    // The scans and registration routes both call this on every request.
    grantMonthlyAllowance(db, org, new Date().toISOString());
    grantMonthlyAllowance(db, org, new Date().toISOString());

    assert.equal(balance(db, org), pro.monthlyCredits, 'the webhook and the scan path share one key');
  });

  it('tops an organisation up when it upgrades part-way through a month', (t) => {
    const { db, org } = setup();
    t.after(() => db.close());
    const free = planByCode(db, 'free')!;
    const pro = planByCode(db, 'pro')!;

    // Took the free allowance first, then upgraded. Keying the allowance on the
    // month alone would leave this organisation on 40 credits until next month.
    grantMonthlyAllowance(db, org, new Date().toISOString());
    assert.equal(balance(db, org), free.monthlyCredits);

    applyWebhookEvent(db, 'stripe', subscriptionEvent(org, 'evt_upgrade'));
    assert.equal(balance(db, org), free.monthlyCredits + pro.monthlyCredits);
  });

  it('applies an enterprise subscription even though its allowance is zero', (t) => {
    const { db, org } = setup();
    t.after(() => db.close());
    // grant() throws on a non-positive amount, which would roll back the whole
    // event and leave a paying enterprise customer with no subscription row.
    const out = applyWebhookEvent(db, 'stripe', {
      id: 'evt_ent',
      type: 'customer.subscription.updated',
      data: { id: 'sub_ent', status: 'active', metadata: { organization_id: org, code: 'enterprise' } },
    });
    assert.equal(out.applied, true);
    assert.equal(planForOrganization(db, org).code, 'enterprise');
  });
});

describe('an unpaid subscription grants nothing', () => {
  function subEvent(org: string, id: string, status: string, code = 'pro') {
    return {
      id, type: 'customer.subscription.updated',
      data: { id: `sub_${status}`, status, metadata: { organization_id: org, code } },
    };
  }

  // Every status Stripe can actually send. The three at the end used to fall
  // through a whitelist to 'active', which stored a genuinely active
  // subscription row that planForOrganization reads directly — a paid plan,
  // granted free, unreachable by any fix to plan_code.
  for (const status of ['incomplete', 'incomplete_expired', 'unpaid', 'paused']) {
    it(`leaves the organisation on free for status '${status}'`, (t) => {
      const { db, org } = setup();
      t.after(() => db.close());

      applyWebhookEvent(db, 'stripe', subEvent(org, `evt_${status}`, status));

      assert.equal(planForOrganization(db, org).code, 'free', `${status} must not entitle`);
      // The entitlement path /api/scans runs on every request.
      grantMonthlyAllowance(db, org, new Date().toISOString());
      assert.equal(balance(db, org), planByCode(db, 'free')!.monthlyCredits,
        `${status} must not yield the paid allowance`);
    });
  }

  it('still entitles an active subscription', (t) => {
    const { db, org } = setup();
    t.after(() => db.close());
    applyWebhookEvent(db, 'stripe', subEvent(org, 'evt_ok', 'active'));
    assert.equal(planForOrganization(db, org).code, 'pro');
    assert.equal(balance(db, org), planByCode(db, 'pro')!.monthlyCredits);
  });

  it('keeps a past_due customer on their plan', (t) => {
    const { db, org } = setup();
    t.after(() => db.close());
    applyWebhookEvent(db, 'stripe', subEvent(org, 'evt_ok', 'active'));
    applyWebhookEvent(db, 'stripe', subEvent(org, 'evt_pd', 'past_due'));
    // Deliberate: access is reduced through the payment flow, not by silently
    // dropping a paying customer mid-period.
    assert.equal(planForOrganization(db, org).code, 'pro');
  });

  it('does not downgrade a paying customer when a second checkout is abandoned', (t) => {
    const { db, org } = setup();
    t.after(() => db.close());
    applyWebhookEvent(db, 'stripe', subEvent(org, 'evt_paid', 'active'));
    assert.equal(planForOrganization(db, org).code, 'pro');

    // An abandoned upgrade attempt arrives as `incomplete` with its OWN
    // subscription id. Gating plan_code without also gating the supersede
    // UPDATE cancels the subscription they are actually paying for.
    applyWebhookEvent(db, 'stripe', subEvent(org, 'evt_abandoned', 'incomplete', 'team'));

    assert.equal(planForOrganization(db, org).code, 'pro', 'the paid subscription must survive');
    const live = db.get<{ n: number }>(
      "SELECT COUNT(*) AS n FROM subscriptions WHERE organization_id = ? AND status = 'active'", org,
    );
    assert.equal(Number(live?.n), 1);
  });
});

describe('a restart returns the credits it interrupted', () => {
  it('releases a hold whose scan is still marked running, and fails that scan', (t) => {
    const { db, org } = setup();
    t.after(() => db.close());
    grant(db, org, 100, 'test credits', 'k1');
    beginScan(db, 'scan_crashed', {
      organizationId: org, projectId: `${org}:p`, projectName: 'p', slug: 'p',
    });
    reserve(db, org, 30, { scanId: 'scan_crashed', idempotencyKey: 'r1' });
    assert.equal(balance(db, org), 70);

    // releaseStaleReservations cannot see this: its predicate excludes
    // 'running', and nothing heartbeats that status.
    assert.equal(releaseStaleReservations(db, new Date(Date.now() + 86_400_000).toISOString()), 0);

    const out = recoverOrphanedScans(db);
    assert.equal(out.reservations, 1);
    assert.equal(out.scans, 1);
    assert.equal(balance(db, org), 100, 'the hold must come back');
    assert.equal(
      db.get<{ status: string }>('SELECT status FROM scan_jobs WHERE id = ?', 'scan_crashed')?.status,
      'failed',
    );
    // And the ledger says why, rather than the credits just being short.
    assert.match(ledger(db, org, 5)[0]!.reason, /interrupted by a restart/);
  });

  it('leaves a live settled scan alone', (t) => {
    const { db, org } = setup();
    t.after(() => db.close());
    grant(db, org, 100, 'test credits', 'k1');
    beginScan(db, 'scan_done', {
      organizationId: org, projectId: `${org}:p`, projectName: 'p', slug: 'p',
    });
    const r = reserve(db, org, 30, { scanId: 'scan_done', idempotencyKey: 'r1' });
    settle(db, r.id, 10);
    failScan(db, 'scan_done', 'failed');  // marks it terminal

    const out = recoverOrphanedScans(db);
    assert.equal(out.reservations, 0, 'a settled reservation must not be touched');
    assert.equal(balance(db, org), 90, '10 charged, 20 returned, nothing else');
  });
});
