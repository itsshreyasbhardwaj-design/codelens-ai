import { createHmac, randomUUID, timingSafeEqual } from 'node:crypto';
import { Db, now } from '../db/index.ts';
import { grant, grantMonthlyAllowance } from './credits.ts';
import { DEFAULT_PRODUCTS, planByCode } from './plans.ts';

/**
 * Payment provider abstraction.
 *
 * Stripe is the adapter shipped, but nothing above this interface knows that:
 * swapping in Razorpay or Paddle means another implementation, not changes to
 * the credit engine or the entitlement checks.
 *
 * The rule the brief is firm about, and the one that matters most here: paid
 * entitlements are granted by a **verified webhook**, never because a browser
 * came back from a checkout page. A return URL is a hint that payment may have
 * happened; the webhook is the fact.
 */

export type ProviderName = 'stripe' | 'razorpay' | 'none';

export interface CheckoutRequest {
  organizationId: string;
  /** A plan code for a subscription, or a product code for a one-time purchase. */
  code: string;
  kind: 'subscription' | 'one_time';
  successUrl: string;
  cancelUrl: string;
  customerEmail?: string;
}

export interface CheckoutSession {
  /** Where to send the browser. */
  url: string;
  providerSessionId: string;
}

export interface PaymentProvider {
  readonly name: ProviderName;
  /** Why this provider cannot be used, or undefined when it is ready. */
  unavailableReason(): string | undefined;
  createCheckout(req: CheckoutRequest): Promise<CheckoutSession>;
  /** Verify the signature and return the parsed event, or throw. */
  verifyWebhook(rawBody: string, signatureHeader: string | null): WebhookEvent;
}

export interface WebhookEvent {
  id: string;
  type: string;
  /** The provider's own object, untouched. */
  data: Record<string, unknown>;
}

export class WebhookVerificationFailed extends Error {
  constructor(reason: string) {
    super(`webhook signature verification failed: ${reason}`);
    this.name = 'WebhookVerificationFailed';
  }
}

export class ProviderNotConfigured extends Error {
  constructor(reason: string) { super(reason); this.name = 'ProviderNotConfigured'; }
}

// ------------------------------------------------------------------ Stripe --

/**
 * Verify a Stripe webhook signature.
 *
 * Header shape: `t=<unix>,v1=<hex hmac>[,v1=<hex hmac>…]`, where the HMAC is
 * over `${timestamp}.${rawBody}` with the endpoint's signing secret.
 *
 * Exported and pure so the scheme can be tested without an account or a network
 * call — which is the only part of a payment integration that can be proven
 * correct offline, and the part where a mistake is most expensive.
 */
export function verifyStripeSignature(
  rawBody: string,
  header: string | null,
  secret: string,
  opts: { toleranceSeconds?: number; nowSeconds?: number } = {},
): void {
  if (!header) throw new WebhookVerificationFailed('no signature header');
  if (!secret) throw new WebhookVerificationFailed('no signing secret configured');

  const parts = new Map<string, string[]>();
  for (const piece of header.split(',')) {
    const [k, v] = piece.split('=', 2);
    if (!k || v === undefined) continue;
    const list = parts.get(k.trim()) ?? [];
    list.push(v.trim());
    parts.set(k.trim(), list);
  }

  const timestamp = parts.get('t')?.[0];
  const signatures = parts.get('v1') ?? [];
  if (!timestamp) throw new WebhookVerificationFailed('no timestamp in header');
  if (signatures.length === 0) throw new WebhookVerificationFailed('no v1 signature in header');

  // Replay window. Without it, a captured delivery stays valid forever.
  const tolerance = opts.toleranceSeconds ?? 300;
  const current = opts.nowSeconds ?? Math.floor(Date.now() / 1000);
  const age = current - Number(timestamp);
  if (!Number.isFinite(age)) throw new WebhookVerificationFailed('timestamp is not a number');
  if (Math.abs(age) > tolerance) {
    throw new WebhookVerificationFailed(`timestamp is ${age}s away, outside the ${tolerance}s tolerance`);
  }

  const expected = createHmac('sha256', secret).update(`${timestamp}.${rawBody}`).digest('hex');
  const expectedBuf = Buffer.from(expected);
  // Constant-time, and any one of the supplied signatures may match during a
  // secret rotation.
  const matched = signatures.some((sig) => {
    const given = Buffer.from(sig);
    return given.length === expectedBuf.length && timingSafeEqual(given, expectedBuf);
  });
  if (!matched) throw new WebhookVerificationFailed('no signature matched');
}

export interface StripeConfig {
  secretKey?: string;
  webhookSecret?: string;
  /** Maps our plan/product codes to Stripe price ids. */
  priceIds: Record<string, string>;
}

export function loadStripeConfig(env: Record<string, string | undefined> = process.env): StripeConfig {
  const priceIds: Record<string, string> = {};
  for (const [k, v] of Object.entries(env)) {
    // STRIPE_PRICE_PRO=price_123 -> { pro: 'price_123' }
    const m = /^STRIPE_PRICE_([A-Z0-9_]+)$/.exec(k);
    if (m && v) priceIds[m[1]!.toLowerCase()] = v;
  }
  return {
    secretKey: env.STRIPE_SECRET_KEY,
    webhookSecret: env.STRIPE_WEBHOOK_SECRET,
    priceIds,
  };
}

export class StripeProvider implements PaymentProvider {
  readonly name = 'stripe' as const;
  private readonly config: StripeConfig;

  constructor(config: StripeConfig = loadStripeConfig()) {
    this.config = config;
  }

  unavailableReason(): string | undefined {
    if (!this.config.secretKey) {
      return 'STRIPE_SECRET_KEY is not set, so checkout cannot be started. Billing is disabled and every account stays on the free plan.';
    }
    if (!this.config.webhookSecret) {
      return 'STRIPE_WEBHOOK_SECRET is not set. Refusing to run billing without webhook verification, because entitlements would then rest on an unverified request.';
    }
    return undefined;
  }

  async createCheckout(req: CheckoutRequest): Promise<CheckoutSession> {
    const unavailable = this.unavailableReason();
    if (unavailable) throw new ProviderNotConfigured(unavailable);

    const price = this.config.priceIds[req.code];
    if (!price) {
      throw new ProviderNotConfigured(
        `no Stripe price configured for '${req.code}'. Set STRIPE_PRICE_${req.code.toUpperCase()} to the price id.`,
      );
    }

    // Stripe's API takes form encoding, not JSON.
    const form = new URLSearchParams({
      mode: req.kind === 'subscription' ? 'subscription' : 'payment',
      success_url: req.successUrl,
      cancel_url: req.cancelUrl,
      'line_items[0][price]': price,
      'line_items[0][quantity]': '1',
      // Carried back on the webhook: this is how a payment is attributed to an
      // organisation without trusting anything the browser sends.
      'metadata[organization_id]': req.organizationId,
      'metadata[code]': req.code,
      client_reference_id: req.organizationId,
    });
    if (req.customerEmail) form.set('customer_email', req.customerEmail);
    if (req.kind === 'subscription') {
      form.set('subscription_data[metadata][organization_id]', req.organizationId);
      form.set('subscription_data[metadata][code]', req.code);
    }

    const res = await fetch('https://api.stripe.com/v1/checkout/sessions', {
      method: 'POST',
      headers: {
        authorization: `Bearer ${this.config.secretKey}`,
        'content-type': 'application/x-www-form-urlencoded',
        // Makes a retried request reuse the same session instead of creating a
        // second one the customer could also pay.
        'idempotency-key': `checkout:${req.organizationId}:${req.code}:${Math.floor(Date.now() / 60000)}`,
      },
      body: form,
      signal: AbortSignal.timeout(20_000),
    });
    if (!res.ok) {
      const detail = await res.text();
      throw new Error(`Stripe checkout failed (${res.status}): ${detail.slice(0, 300)}`);
    }
    const session = (await res.json()) as { id?: string; url?: string };
    if (!session.url || !session.id) throw new Error('Stripe returned a session with no URL');
    return { url: session.url, providerSessionId: session.id };
  }

  verifyWebhook(rawBody: string, signatureHeader: string | null): WebhookEvent {
    verifyStripeSignature(rawBody, signatureHeader, this.config.webhookSecret ?? '');
    const parsed = JSON.parse(rawBody) as { id?: string; type?: string; data?: { object?: Record<string, unknown> } };
    if (!parsed.id || !parsed.type) throw new WebhookVerificationFailed('event has no id or type');
    return { id: parsed.id, type: parsed.type, data: parsed.data?.object ?? {} };
  }
}

/** Used when no provider is configured: every account stays on the free plan. */
export class NoPaymentProvider implements PaymentProvider {
  readonly name = 'none' as const;
  unavailableReason(): string {
    return 'No payment provider is configured. Accounts stay on the free plan and no money can change hands.';
  }
  createCheckout(): Promise<CheckoutSession> {
    return Promise.reject(new ProviderNotConfigured(this.unavailableReason()));
  }
  verifyWebhook(): WebhookEvent {
    throw new ProviderNotConfigured(this.unavailableReason());
  }
}

export function loadPaymentProvider(env: Record<string, string | undefined> = process.env): PaymentProvider {
  const name = env.CODELENS_PAYMENT_PROVIDER ?? 'none';
  if (name === 'stripe') return new StripeProvider(loadStripeConfig(env));
  return new NoPaymentProvider();
}

/**
 * Provider subscription status -> the status we store.
 *
 * Total, and it fails closed. The previous whitelist sent anything it did not
 * recognise to `'active'`, and Stripe has three statuses it did not list —
 * `incomplete_expired`, `unpaid` and `paused` — all of which mean "this will
 * not be paid for". Each was therefore stored as a genuinely active
 * subscription that `planForOrganization` reads directly, which is a paid plan
 * granted for free and unreachable by any fix to `plan_code`.
 *
 * The `subscriptions.status` CHECK permits only the five values on the left, so
 * the three dead ones map onto `canceled` rather than being stored verbatim.
 */
const SUBSCRIPTION_STATUS: Record<string, string> = {
  active: 'active',
  trialing: 'trialing',
  past_due: 'past_due',
  canceled: 'canceled',
  incomplete: 'incomplete',
  incomplete_expired: 'canceled',
  unpaid: 'canceled',
  paused: 'canceled',
};

/**
 * The statuses a customer is entitled under.
 *
 * `past_due` is deliberately included: access is reduced through the payment
 * flow, not by silently dropping a paying customer mid-period. See
 * `planForOrganization`.
 */
const ENTITLING_STATUSES = ['active', 'trialing', 'past_due'];

// --------------------------------------------------------- event handling --

export interface WebhookOutcome {
  /** False when this event had already been processed. */
  applied: boolean;
  action: string;
  organizationId?: string;
}

/**
 * Apply a verified event, exactly once.
 *
 * The event is recorded first, with a UNIQUE constraint on the provider's id.
 * A redelivery — which every provider does, routinely — hits that constraint
 * and returns without granting anything a second time.
 */
export function applyWebhookEvent(db: Db, provider: ProviderName, event: WebhookEvent): WebhookOutcome {
  return db.tx(() => {
    const seen = db.get<{ id: string; processed_at: string | null }>(
      'SELECT id, processed_at FROM payment_events WHERE provider = ? AND provider_event_id = ?',
      provider, event.id,
    );
    if (seen?.processed_at) {
      return { applied: false, action: 'already processed' };
    }
    if (!seen) {
      db.run(
        `INSERT INTO payment_events (id, provider, provider_event_id, type, payload_json, signature_verified, created_at)
         VALUES (?,?,?,?,?,1,?)`,
        randomUUID(), provider, event.id, event.type, JSON.stringify(event.data), now(),
      );
    }

    const outcome = handle(db, provider, event);

    db.run(
      'UPDATE payment_events SET processed_at = ? WHERE provider = ? AND provider_event_id = ?',
      now(), provider, event.id,
    );
    return outcome;
  });
}

function metadataOrg(event: WebhookEvent): string | undefined {
  const meta = (event.data.metadata ?? {}) as Record<string, unknown>;
  const fromMeta = meta.organization_id;
  if (typeof fromMeta === 'string' && fromMeta) return fromMeta;
  const ref = event.data.client_reference_id;
  return typeof ref === 'string' && ref ? ref : undefined;
}

function metadataCode(event: WebhookEvent): string | undefined {
  const meta = (event.data.metadata ?? {}) as Record<string, unknown>;
  return typeof meta.code === 'string' ? meta.code : undefined;
}

function handle(db: Db, provider: ProviderName, event: WebhookEvent): WebhookOutcome {
  const organizationId = metadataOrg(event);
  const code = metadataCode(event);

  switch (event.type) {
    case 'checkout.session.completed': {
      if (!organizationId || !code) return { applied: false, action: 'event carried no organisation' };
      const product = DEFAULT_PRODUCTS.find((p) => p.code === code);
      if (product) {
        db.run(
          `INSERT OR IGNORE INTO one_time_purchases
             (id, organization_id, product_code, amount_cents, currency, credits_granted,
              provider, provider_payment_id, status, created_at)
           VALUES (?,?,?,?,?,?,?,?, 'paid', ?)`,
          randomUUID(), organizationId, product.code, product.priceCents, product.currency,
          product.credits, provider, event.id, now(),
        );
        grant(db, organizationId, product.credits, `purchase: ${product.name}`, `purchase:${event.id}`);
        return { applied: true, action: `granted ${product.credits} credits`, organizationId };
      }
      // Otherwise a subscription checkout; the subscription event carries the rest.
      return { applied: true, action: 'checkout completed', organizationId };
    }

    case 'customer.subscription.created':
    case 'customer.subscription.updated': {
      if (!organizationId || !code) return { applied: false, action: 'event carried no organisation' };
      const plan = planByCode(db, code);
      if (!plan) return { applied: false, action: `unknown plan '${code}'` };

      const status = String(event.data.status ?? 'active');
      const mapped = SUBSCRIPTION_STATUS[status] ?? 'canceled';
      const subId = String(event.data.id ?? event.id);

      // Supersede any previous active row before inserting, so the partial
      // unique index on one-active-per-organisation holds.
      //
      // Only an ENTITLING status may supersede, and never the incoming
      // subscription itself. An abandoned second checkout arrives as
      // `incomplete` carrying its own subscription id; superseding on that
      // cancelled the row of a subscription the customer is actually paying
      // for. That was previously masked by the unconditional `plan_code` write
      // below — remove one without the other and a paying customer is
      // downgraded to free.
      if (ENTITLING_STATUSES.includes(mapped)) {
        db.run(
          `UPDATE subscriptions SET status = 'canceled', updated_at = ?
            WHERE organization_id = ? AND status IN ('active','trialing','past_due')
              AND NOT (provider = ? AND provider_subscription_id = ?)`,
          now(), organizationId, provider, subId,
        );
      }
      db.run(
        `INSERT INTO subscriptions
           (id, organization_id, plan_id, status, provider, provider_subscription_id,
            current_period_start, current_period_end, cancel_at_period_end, created_at, updated_at)
         VALUES (?,?,?,?,?,?,?,?,?,?,?)
         ON CONFLICT (provider, provider_subscription_id) DO UPDATE SET
           status = excluded.status, plan_id = excluded.plan_id, updated_at = excluded.updated_at`,
        randomUUID(), organizationId, plan.id, mapped, provider, subId,
        event.data.current_period_start ? String(event.data.current_period_start) : null,
        event.data.current_period_end ? String(event.data.current_period_end) : null,
        event.data.cancel_at_period_end ? 1 : 0, now(), now(),
      );
      // Only a status the customer is entitled under may move `plan_code`.
      // `planForOrganization` falls back to this column when no entitling
      // subscription row exists, so writing the paid plan for an `incomplete`
      // subscription handed out the plan, its limits and its monthly credit
      // allowance before any payment had succeeded — a free Pro account for
      // anyone who abandoned the card challenge.
      if (ENTITLING_STATUSES.includes(mapped)) {
        db.run('UPDATE organizations SET plan_code = ? WHERE id = ?', plan.code, organizationId);
      } else if (!db.get(
        `SELECT id FROM subscriptions
          WHERE organization_id = ? AND status IN ('active','trialing','past_due')`,
        organizationId,
      )) {
        // Nothing entitling left anywhere: drop to free, as the deleted branch does.
        db.run("UPDATE organizations SET plan_code = 'free' WHERE id = ?", organizationId);
      }

      if (mapped === 'active' || mapped === 'trialing') {
        // Keyed on (organisation, plan, month) by `grantMonthlyAllowance`, not
        // on this event's id. Stripe sends customer.subscription.updated for
        // every renewal, cancellation toggle, card change and past_due
        // recovery, and a per-event key granted a whole monthly allowance for
        // each one — unbounded, silent, and on the normal monthly path for
        // every paying subscriber. It also granted a second allowance on top of
        // the one the scan and registration paths take, because those used a
        // different key that could never collide.
        //
        // This call is also what tops up an organisation that upgrades
        // mid-month: the plan is in the key, so a new plan is a new grant.
        // `monthlyCredits <= 0` returns early inside, which Enterprise needs —
        // `grant` throws on a non-positive amount and would roll the event back.
        grantMonthlyAllowance(db, organizationId, now());
      }
      return { applied: true, action: `subscription ${mapped} on ${plan.code}`, organizationId };
    }

    case 'customer.subscription.deleted': {
      const subId = String(event.data.id ?? '');
      const row = db.get<{ organization_id: string }>(
        'SELECT organization_id FROM subscriptions WHERE provider = ? AND provider_subscription_id = ?',
        provider, subId,
      );
      if (!row) return { applied: false, action: 'no matching subscription' };
      db.run(
        "UPDATE subscriptions SET status = 'canceled', updated_at = ? WHERE provider = ? AND provider_subscription_id = ?",
        now(), provider, subId,
      );
      // Drop to free. Credits already bought are deliberately left alone: they
      // were paid for separately and reports stay readable.
      db.run("UPDATE organizations SET plan_code = 'free' WHERE id = ?", row.organization_id);
      return { applied: true, action: 'subscription cancelled', organizationId: row.organization_id };
    }

    case 'invoice.payment_failed': {
      if (!organizationId) return { applied: false, action: 'event carried no organisation' };
      db.run(
        "UPDATE subscriptions SET status = 'past_due', updated_at = ? WHERE organization_id = ? AND status = 'active'",
        now(), organizationId,
      );
      db.run(
        `INSERT INTO notifications (id, organization_id, kind, title, body, link, created_at)
         VALUES (?,?,'payment_failed','Payment failed',?,'/billing',?)`,
        randomUUID(), organizationId,
        'We could not take payment for your subscription. Update your card to keep your plan.', now(),
      );
      return { applied: true, action: 'marked past due', organizationId };
    }

    default:
      return { applied: false, action: `ignored event type '${event.type}'` };
  }
}
