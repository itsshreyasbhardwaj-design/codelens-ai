import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { Db } from '../db/index.ts';
import { register } from '../db/auth.ts';
import { balance } from './credits.ts';
import { PlanCatalogueMissing, planForOrganization, seedPlans } from './plans.ts';
import {
  applyWebhookEvent, loadPaymentProvider, loadStripeConfig, NoPaymentProvider,
  ProviderNotConfigured, StripeProvider, verifyStripeSignature, WebhookVerificationFailed,
} from './payments.ts';

const SECRET = 'whsec_test_secret';

function setup(): { db: Db; org: string } {
  const prior = process.env.CODELENS_SECRET_KEY;
  process.env.CODELENS_SECRET_KEY = 'payments-test-secret-key-at-least-32ch';
  const db = new Db(':memory:');
  db.migrate();
  seedPlans(db);
  const account = register(db, { email: `p${Math.random()}@example.com`, password: 'a-good-password' });
  if (prior === undefined) delete process.env.CODELENS_SECRET_KEY;
  else process.env.CODELENS_SECRET_KEY = prior;
  return { db, org: account.organizationId };
}

function signed(body: string, secret = SECRET, atSeconds = Math.floor(Date.now() / 1000)): string {
  const mac = createHmac('sha256', secret).update(`${atSeconds}.${body}`).digest('hex');
  return `t=${atSeconds},v1=${mac}`;
}

describe('webhook signature verification', () => {
  const body = JSON.stringify({ id: 'evt_1', type: 'checkout.session.completed' });

  it('accepts a correctly signed payload', () => {
    assert.doesNotThrow(() => verifyStripeSignature(body, signed(body), SECRET));
  });

  it('rejects a forged signature', () => {
    assert.throws(() => verifyStripeSignature(body, 't=1,v1=deadbeef', SECRET), WebhookVerificationFailed);
  });

  it('rejects a payload altered after signing', () => {
    const header = signed(body);
    const tampered = JSON.stringify({ id: 'evt_1', type: 'checkout.session.completed', amount: 999 });
    assert.throws(() => verifyStripeSignature(tampered, header, SECRET), WebhookVerificationFailed);
  });

  it('rejects a signature made with a different secret', () => {
    assert.throws(
      () => verifyStripeSignature(body, signed(body, 'whsec_someone_else'), SECRET),
      WebhookVerificationFailed,
    );
  });

  it('rejects a replayed delivery outside the tolerance window', () => {
    const old = Math.floor(Date.now() / 1000) - 3600;
    assert.throws(
      () => verifyStripeSignature(body, signed(body, SECRET, old), SECRET),
      /outside the .* tolerance/,
    );
  });

  it('accepts a delivery inside the tolerance window', () => {
    const recent = Math.floor(Date.now() / 1000) - 60;
    assert.doesNotThrow(() => verifyStripeSignature(body, signed(body, SECRET, recent), SECRET));
  });

  it('accepts either signature during a secret rotation', () => {
    const t = Math.floor(Date.now() / 1000);
    const oldMac = createHmac('sha256', 'whsec_old').update(`${t}.${body}`).digest('hex');
    const newMac = createHmac('sha256', SECRET).update(`${t}.${body}`).digest('hex');
    assert.doesNotThrow(() => verifyStripeSignature(body, `t=${t},v1=${oldMac},v1=${newMac}`, SECRET));
  });

  it('rejects a missing or malformed header', () => {
    for (const h of [null, '', 'garbage', 't=123', 'v1=abc']) {
      assert.throws(() => verifyStripeSignature(body, h, SECRET), WebhookVerificationFailed);
    }
  });

  it('refuses to verify when no signing secret is configured', () => {
    assert.throws(() => verifyStripeSignature(body, signed(body), ''), /no signing secret/);
  });
});

describe('provider configuration', () => {
  it('defaults to no provider, so nothing can be charged by accident', () => {
    const p = loadPaymentProvider({});
    assert.ok(p instanceof NoPaymentProvider);
    assert.match(p.unavailableReason()!, /stay on the free plan/);
  });

  it('refuses Stripe without a webhook secret, rather than trusting the browser', () => {
    const p = new StripeProvider({ secretKey: 'sk_test_x', priceIds: {} });
    assert.match(p.unavailableReason()!, /Refusing to run billing without webhook verification/);
  });

  it('is ready when both secrets are present', () => {
    const p = new StripeProvider({ secretKey: 'sk_test_x', webhookSecret: SECRET, priceIds: { pro: 'price_1' } });
    assert.equal(p.unavailableReason(), undefined);
  });

  it('reads price ids from the environment', () => {
    const c = loadStripeConfig({ STRIPE_PRICE_PRO: 'price_abc', STRIPE_PRICE_CREDITS_10: 'price_def' });
    assert.equal(c.priceIds.pro, 'price_abc');
    assert.equal(c.priceIds.credits_10, 'price_def');
  });

  it('explains which price is missing rather than failing opaquely', async () => {
    const p = new StripeProvider({ secretKey: 'sk_test_x', webhookSecret: SECRET, priceIds: {} });
    await assert.rejects(
      () => p.createCheckout({ organizationId: 'o', code: 'pro', kind: 'subscription', successUrl: 'u', cancelUrl: 'u' }),
      /STRIPE_PRICE_PRO/,
    );
  });

  it('refuses checkout entirely when unconfigured', async () => {
    await assert.rejects(() => new NoPaymentProvider().createCheckout(), ProviderNotConfigured);
  });
});

describe('applying verified events', () => {
  function purchase(org: string, id = 'evt_buy_1') {
    return { id, type: 'checkout.session.completed', data: { metadata: { organization_id: org, code: 'credits_10' } } };
  }

  it('grants credits for a one-time purchase', (t) => {
    const { db, org } = setup();
    t.after(() => db.close());
    const out = applyWebhookEvent(db, 'stripe', purchase(org));
    assert.equal(out.applied, true);
    assert.equal(balance(db, org), 1000);
  });

  it('applies a redelivered event exactly once', (t) => {
    const { db, org } = setup();
    t.after(() => db.close());
    applyWebhookEvent(db, 'stripe', purchase(org));
    const second = applyWebhookEvent(db, 'stripe', purchase(org));
    const third = applyWebhookEvent(db, 'stripe', purchase(org));
    assert.equal(second.applied, false);
    assert.equal(third.applied, false);
    assert.equal(balance(db, org), 1000, 'a redelivery must not grant twice');
  });

  it('upgrades the plan on a subscription event and grants its allowance', (t) => {
    const { db, org } = setup();
    t.after(() => db.close());
    const out = applyWebhookEvent(db, 'stripe', {
      id: 'evt_sub_1', type: 'customer.subscription.created',
      data: { id: 'sub_1', status: 'active', metadata: { organization_id: org, code: 'pro' } },
    });
    assert.equal(out.applied, true);
    assert.equal(planForOrganization(db, org).code, 'pro');
    assert.equal(balance(db, org), 1200);
  });

  it('moves between plans without leaving two active subscriptions', (t) => {
    const { db, org } = setup();
    t.after(() => db.close());
    applyWebhookEvent(db, 'stripe', {
      id: 'e1', type: 'customer.subscription.created',
      data: { id: 'sub_1', status: 'active', metadata: { organization_id: org, code: 'solo' } },
    });
    applyWebhookEvent(db, 'stripe', {
      id: 'e2', type: 'customer.subscription.created',
      data: { id: 'sub_2', status: 'active', metadata: { organization_id: org, code: 'team' } },
    });
    assert.equal(planForOrganization(db, org).code, 'team');
    const active = db.get<{ n: number }>(
      "SELECT COUNT(*) AS n FROM subscriptions WHERE organization_id = ? AND status = 'active'", org,
    );
    assert.equal(active!.n, 1);
  });

  it('drops to free on cancellation but keeps purchased credits', (t) => {
    const { db, org } = setup();
    t.after(() => db.close());
    applyWebhookEvent(db, 'stripe', {
      id: 'e1', type: 'customer.subscription.created',
      data: { id: 'sub_1', status: 'active', metadata: { organization_id: org, code: 'pro' } },
    });
    applyWebhookEvent(db, 'stripe', purchase(org, 'e2'));
    const before = balance(db, org);

    applyWebhookEvent(db, 'stripe', {
      id: 'e3', type: 'customer.subscription.deleted', data: { id: 'sub_1' },
    });
    assert.equal(planForOrganization(db, org).code, 'free');
    assert.equal(balance(db, org), before, 'credits already paid for are not confiscated');
  });

  it('marks a failed payment past due and notifies, without cutting access', (t) => {
    const { db, org } = setup();
    t.after(() => db.close());
    applyWebhookEvent(db, 'stripe', {
      id: 'e1', type: 'customer.subscription.created',
      data: { id: 'sub_1', status: 'active', metadata: { organization_id: org, code: 'pro' } },
    });
    applyWebhookEvent(db, 'stripe', {
      id: 'e2', type: 'invoice.payment_failed', data: { metadata: { organization_id: org } },
    });
    assert.equal(planForOrganization(db, org).code, 'pro', 'still on their plan while payment is retried');
    const n = db.get<{ n: number }>("SELECT COUNT(*) AS n FROM notifications WHERE kind = 'payment_failed'");
    assert.equal(n!.n, 1);
  });

  it('ignores an event type it does not handle, and records it', (t) => {
    const { db, org } = setup();
    t.after(() => db.close());
    const out = applyWebhookEvent(db, 'stripe', { id: 'e9', type: 'customer.created', data: {} });
    assert.equal(out.applied, false);
    assert.match(out.action, /ignored/);
    assert.equal(db.get<{ n: number }>('SELECT COUNT(*) AS n FROM payment_events')!.n, 1);
    assert.equal(balance(db, org), 0);
  });

  it('refuses an event that names no organisation', (t) => {
    const { db } = setup();
    t.after(() => db.close());
    const out = applyWebhookEvent(db, 'stripe', {
      id: 'e1', type: 'checkout.session.completed', data: { metadata: {} },
    });
    assert.equal(out.applied, false);
    assert.match(out.action, /no organisation/);
  });

  it('attributes a payment by client_reference_id when metadata is absent', (t) => {
    const { db, org } = setup();
    t.after(() => db.close());
    const out = applyWebhookEvent(db, 'stripe', {
      id: 'e1', type: 'checkout.session.completed',
      data: { client_reference_id: org, metadata: { code: 'credits_10' } },
    });
    assert.equal(out.applied, true);
    assert.equal(balance(db, org), 1000);
  });
});

describe('the signed path end to end', () => {
  // The two halves are tested separately above. This covers the join, which is
  // what the webhook route actually does: verify the raw bytes, then apply the
  // event the verifier returned. A regression here means money changes hands on
  // an unverified request, or a genuine payment grants nothing.
  it('verifies a real signature and grants from the event it returns', (t) => {
    const { db, org } = setup();
    t.after(() => db.close());

    const provider = new StripeProvider({
      secretKey: 'sk_test_x', webhookSecret: SECRET, priceIds: { pro: 'price_pro' },
    });
    const body = JSON.stringify({
      id: 'evt_join_1',
      type: 'checkout.session.completed',
      data: { object: { metadata: { organization_id: org, code: 'credits_10' } } },
    });

    const event = provider.verifyWebhook(body, signed(body));
    const out = applyWebhookEvent(db, provider.name, event);

    assert.equal(out.applied, true);
    assert.equal(out.organizationId, org);
    assert.equal(balance(db, org), 1000);
  });

  it('grants nothing when the body was altered after signing', (t) => {
    const { db, org } = setup();
    t.after(() => db.close());

    const provider = new StripeProvider({
      secretKey: 'sk_test_x', webhookSecret: SECRET, priceIds: {},
    });
    const honest = JSON.stringify({
      id: 'evt_join_2',
      type: 'checkout.session.completed',
      data: { object: { metadata: { organization_id: org, code: 'credits_10' } } },
    });
    // A forged body claiming the largest pack, carrying the honest signature.
    const forged = honest.replace('credits_10', 'credits_80');

    assert.throws(
      () => provider.verifyWebhook(forged, signed(honest)),
      WebhookVerificationFailed,
    );
    assert.equal(balance(db, org), 0, 'a rejected delivery must not credit anything');
  });
});

describe('an unseeded plan catalogue', () => {
  it('refuses to resolve an entitlement rather than inventing limits', (t) => {
    // Migrated but never seeded: the state a deployment reaches if seedPlans is
    // skipped. Guessing generous limits gives work away and guessing strict
    // ones locks out a paying customer, so neither is acceptable.
    const prior = process.env.CODELENS_SECRET_KEY;
    process.env.CODELENS_SECRET_KEY = 'payments-test-secret-key-at-least-32ch';
    const db = new Db(':memory:');
    db.migrate();
    const account = register(db, { email: `u${Math.random()}@example.com`, password: 'a-good-password' });
    if (prior === undefined) delete process.env.CODELENS_SECRET_KEY;
    else process.env.CODELENS_SECRET_KEY = prior;
    t.after(() => db.close());

    assert.throws(() => planForOrganization(db, account.organizationId), PlanCatalogueMissing);
    assert.throws(() => planForOrganization(db, account.organizationId), /seedPlans/);
  });
});

describe('a purchase is granted only once the money has arrived', () => {
  function session(org: string, eventId: string, type: string, paymentStatus?: string) {
    return {
      id: eventId, type,
      data: {
        id: 'cs_session_1',
        ...(paymentStatus ? { payment_status: paymentStatus } : {}),
        metadata: { organization_id: org, code: 'credits_10' },
      },
    };
  }

  it('grants nothing for a session that completed unpaid', (t) => {
    const { db, org } = setup();
    t.after(() => db.close());
    // Delayed-notification methods (ACH, SEPA, Boleto, OXXO…) complete the
    // session before the funds settle.
    applyWebhookEvent(db, 'stripe', session(org, 'evt_1', 'checkout.session.completed', 'unpaid'));
    assert.equal(balance(db, org), 0, 'no credits before the money arrives');
    const row = db.get<{ status: string; credits_granted: number }>(
      'SELECT status, credits_granted FROM one_time_purchases WHERE organization_id = ?', org,
    );
    assert.equal(row?.status, 'pending');
    assert.equal(Number(row?.credits_granted), 0);
  });

  it('grants when the delayed payment later succeeds', (t) => {
    const { db, org } = setup();
    t.after(() => db.close());
    applyWebhookEvent(db, 'stripe', session(org, 'evt_1', 'checkout.session.completed', 'unpaid'));
    applyWebhookEvent(db, 'stripe', session(org, 'evt_2', 'checkout.session.async_payment_succeeded', 'paid'));
    assert.equal(balance(db, org), 1000);
    assert.equal(
      db.get<{ status: string }>('SELECT status FROM one_time_purchases WHERE organization_id = ?', org)?.status,
      'paid',
    );
  });

  it('records the failure when the delayed payment never arrives', (t) => {
    const { db, org } = setup();
    t.after(() => db.close());
    applyWebhookEvent(db, 'stripe', session(org, 'evt_1', 'checkout.session.completed', 'unpaid'));
    applyWebhookEvent(db, 'stripe', session(org, 'evt_2', 'checkout.session.async_payment_failed', 'unpaid'));
    assert.equal(balance(db, org), 0);
    assert.equal(
      db.get<{ status: string }>('SELECT status FROM one_time_purchases WHERE organization_id = ?', org)?.status,
      'failed',
    );
  });

  it('still grants immediately for an ordinary card payment', (t) => {
    const { db, org } = setup();
    t.after(() => db.close());
    // The common case, and the one an unconditional defer would starve: a card
    // session is already paid at `completed` and no async event ever follows.
    applyWebhookEvent(db, 'stripe', session(org, 'evt_1', 'checkout.session.completed', 'paid'));
    assert.equal(balance(db, org), 1000);
  });

  it('grants once when both events arrive for one session', (t) => {
    const { db, org } = setup();
    t.after(() => db.close());
    // Keyed on the session, not the event: two different event ids, one payment.
    applyWebhookEvent(db, 'stripe', session(org, 'evt_1', 'checkout.session.completed', 'paid'));
    applyWebhookEvent(db, 'stripe', session(org, 'evt_2', 'checkout.session.async_payment_succeeded', 'paid'));
    assert.equal(balance(db, org), 1000, 'one session, one grant');
  });
});

describe('a cancelled subscription stays cancelled', () => {
  function sub(org: string, eventId: string, type: string, status: string, subId = 'sub_1') {
    return { id: eventId, type, data: { id: subId, status, metadata: { organization_id: org, code: 'pro' } } };
  }

  it('ignores an active update delivered after the cancellation', (t) => {
    const { db, org } = setup();
    t.after(() => db.close());
    applyWebhookEvent(db, 'stripe', sub(org, 'e1', 'customer.subscription.created', 'active'));
    applyWebhookEvent(db, 'stripe', sub(org, 'e2', 'customer.subscription.deleted', 'canceled'));
    assert.equal(planForOrganization(db, org).code, 'free');

    // Stripe does not guarantee ordering: this one was generated before the
    // cancellation and delivered after it.
    const out = applyWebhookEvent(db, 'stripe', sub(org, 'e3', 'customer.subscription.updated', 'active'));
    assert.equal(out.applied, false);
    assert.equal(planForOrganization(db, org).code, 'free', 'a dead subscription must not revive');
  });

  it('still lets a paused subscription recover', (t) => {
    const { db, org } = setup();
    t.after(() => db.close());
    // `paused` and `unpaid` are stored as 'canceled' but Stripe recovers both
    // on the SAME subscription id. Treating a stored 'canceled' as terminal
    // would lock these paying customers out — which is why the terminal test
    // reads the raw provider status, not the stored one.
    applyWebhookEvent(db, 'stripe', sub(org, 'e1', 'customer.subscription.created', 'active'));
    applyWebhookEvent(db, 'stripe', sub(org, 'e2', 'customer.subscription.updated', 'paused'));
    assert.equal(planForOrganization(db, org).code, 'free');
    applyWebhookEvent(db, 'stripe', sub(org, 'e3', 'customer.subscription.updated', 'active'));
    assert.equal(planForOrganization(db, org).code, 'pro', 'a paused subscription must be able to recover');
  });

  it('still lets an unpaid subscription recover', (t) => {
    const { db, org } = setup();
    t.after(() => db.close());
    applyWebhookEvent(db, 'stripe', sub(org, 'e1', 'customer.subscription.created', 'active'));
    applyWebhookEvent(db, 'stripe', sub(org, 'e2', 'customer.subscription.updated', 'unpaid'));
    applyWebhookEvent(db, 'stripe', sub(org, 'e3', 'customer.subscription.updated', 'active'));
    assert.equal(planForOrganization(db, org).code, 'pro');
  });

  it('allows a genuine resubscribe under a new subscription id', (t) => {
    const { db, org } = setup();
    t.after(() => db.close());
    applyWebhookEvent(db, 'stripe', sub(org, 'e1', 'customer.subscription.created', 'active', 'sub_1'));
    applyWebhookEvent(db, 'stripe', sub(org, 'e2', 'customer.subscription.deleted', 'canceled', 'sub_1'));
    applyWebhookEvent(db, 'stripe', sub(org, 'e3', 'customer.subscription.created', 'active', 'sub_2'));
    assert.equal(planForOrganization(db, org).code, 'pro', 'coming back must still work');
  });
});
