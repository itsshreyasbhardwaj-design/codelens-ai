import { NextResponse } from 'next/server';
import { DEFAULT_PRODUCTS, listPlans } from '@codelens/engine/billing/plans.ts';
import { loadPaymentProvider, ProviderNotConfigured } from '@codelens/engine/billing/payments.ts';
import { sessionOr401 } from '../../../lib/session.ts';
import { db } from '../../../lib/store.ts';

/**
 * POST /api/billing/checkout — start a hosted checkout session.
 *
 * Two rules govern this handler, and both are about not trusting the browser.
 *
 * **The code is never passed through.** `code` arrives from the client, so it is
 * matched against the plan codes actually present in `subscription_plans` and
 * the product codes in `DEFAULT_PRODUCTS` before the provider sees it. Anything
 * else is a 400. The provider's price lookup therefore only ever receives a
 * value this installation already published, which is what stops a crafted
 * request from buying an unlisted or mispriced line item.
 *
 * **The return URL grants nothing.** `successUrl` is where the browser is sent
 * afterwards and carries no authority whatsoever: entitlements — a plan change,
 * a credit grant — are applied only by the signature-verified webhook at
 * /api/billing/webhook, from the provider's own event. A browser arriving at
 * the success URL proves only that a browser arrived there. Nothing in this file
 * writes to the credit ledger or the subscriptions table.
 */

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

/** A code and a kind; nothing legitimate needs more. */
const MAX_BODY_BYTES = 2 * 1024;
const MAX_CODE_CHARS = 64;

const NO_STORE = { 'cache-control': 'no-store' } as const;

function fail(message: string, status: number): NextResponse {
  return NextResponse.json({ error: message }, { status, headers: NO_STORE });
}

/**
 * The origin the browser actually addressed.
 *
 * Read from the `Host` header rather than from `request.url`, because the
 * server normalises that URL and it does not reliably carry the host the
 * customer typed — measured here: a same-origin POST from a browser on
 * 127.0.0.1 was rejected when the two were compared directly. The scheme comes
 * from `X-Forwarded-Proto` when a proxy sets it, so a TLS-terminated
 * deployment does not build `http://` return URLs.
 */
function requestOrigin(request: Request): string | undefined {
  const host = request.headers.get('host');
  if (!host) return undefined;
  const forwarded = request.headers.get('x-forwarded-proto');
  let proto: string;
  if (forwarded) {
    proto = forwarded.split(',')[0]!.trim();
  } else {
    try {
      proto = new URL(request.url).protocol.replace(':', '');
    } catch {
      return undefined;
    }
  }
  if (proto !== 'http' && proto !== 'https') return undefined;
  return `${proto}://${host}`;
}

/**
 * Cross-site check.
 *
 * A browser sends `Origin` on every POST, so when it is present it must match
 * the site being addressed. A request without the header is not a cross-site
 * browser request — a command-line client, for instance — and the session
 * cookie's `SameSite=Lax` already keeps it from carrying someone else's
 * session.
 */
function sameOrigin(request: Request): boolean {
  const header = request.headers.get('origin');
  if (header === null) return true;
  return header === requestOrigin(request);
}

/**
 * The origin return URLs are built from.
 *
 * `CODELENS_PUBLIC_URL` wins where it is set, because behind a proxy or on a
 * custom domain the host in the request is not necessarily the address the
 * customer is on, and a return URL has to land back where they started.
 * Otherwise the request's own origin is used, which is what the configuration
 * documents.
 */
class MisconfiguredPublicUrl extends Error {}

function returnBase(request: Request): string | undefined {
  const configured = process.env.CODELENS_PUBLIC_URL?.trim();
  if (configured) {
    let url: URL;
    try {
      url = new URL(configured);
    } catch {
      throw new MisconfiguredPublicUrl(
        `CODELENS_PUBLIC_URL is set to '${configured}', which is not an absolute URL. Set it to an origin such as https://codelens.example.com, or unset it to use the request's own origin.`,
      );
    }
    if (url.protocol !== 'http:' && url.protocol !== 'https:') {
      throw new MisconfiguredPublicUrl(
        `CODELENS_PUBLIC_URL must be an http or https origin; it is set to '${configured}'.`,
      );
    }
    return url.origin;
  }
  return requestOrigin(request);
}

/** An absolute same-origin URL, or undefined if it would not be one. */
function returnUrl(base: string, path: string): string | undefined {
  try {
    const url = new URL(path, base);
    return url.origin === base ? url.toString() : undefined;
  } catch {
    return undefined;
  }
}

/** The organisation's current subscription, if it has a live one. */
function liveSubscription(organizationId: string): { planCode: string; status: string } | undefined {
  const row = db().get<{ status: string; code: string }>(
    `SELECT s.status AS status, p.code AS code
       FROM subscriptions s
       JOIN subscription_plans p ON p.id = s.plan_id
      WHERE s.organization_id = ? AND s.status IN ('active','trialing','past_due')
      ORDER BY s.created_at DESC
      LIMIT 1`,
    organizationId,
  );
  return row ? { planCode: String(row.code), status: String(row.status) } : undefined;
}

/** The signed-in user's email, for the provider's receipt. Optional by design. */
function emailFor(userId: string): string | undefined {
  const row = db().get<{ email: string }>('SELECT email FROM users WHERE id = ?', userId);
  return row?.email ? String(row.email) : undefined;
}

export async function POST(request: Request): Promise<NextResponse> {
  const session = await sessionOr401();
  if (!session) return fail('authentication required', 401);

  const declared = Number(request.headers.get('content-length') ?? NaN);
  if (Number.isFinite(declared) && declared > MAX_BODY_BYTES) {
    return fail(`request body is ${declared} bytes, limit is ${MAX_BODY_BYTES}`, 413);
  }

  const raw = await request.text();
  if (Buffer.byteLength(raw) > MAX_BODY_BYTES) {
    return fail(`request body exceeds ${MAX_BODY_BYTES} bytes`, 413);
  }

  let body: { code?: unknown; kind?: unknown };
  try {
    body = JSON.parse(raw) as typeof body;
  } catch {
    return fail('request body is not valid JSON', 400);
  }

  if (typeof body.code !== 'string' || body.code.trim().length === 0) {
    return fail('code is required', 400);
  }
  const code = body.code.trim();
  if (code.length > MAX_CODE_CHARS) {
    return fail(`code is longer than ${MAX_CODE_CHARS} characters`, 400);
  }
  if (body.kind !== 'subscription' && body.kind !== 'one_time') {
    return fail("kind must be 'subscription' or 'one_time'", 400);
  }
  const kind = body.kind;

  // Allow-list check. The code is compared against what this installation
  // actually publishes, so nothing user-supplied reaches the provider as a
  // price lookup. A code of the wrong kind is rejected too.
  if (kind === 'subscription') {
    const plan = listPlans(db()).find((p) => p.code === code);
    if (!plan) return fail(`'${code}' is not a plan offered by this installation`, 400);
    if (plan.priceCents === null) {
      return fail(
        `The ${plan.name} plan is not sold through checkout. Get in touch to agree terms.`,
        409,
      );
    }
    if (plan.priceCents === 0) {
      return fail(
        `The ${plan.name} plan costs nothing and needs no checkout. Every account is on it already.`,
        409,
      );
    }

    const live = liveSubscription(session.organizationId);
    if (live?.status === 'past_due') {
      return fail(
        'A payment on the current subscription has not gone through. Settle that before starting another checkout, or the two will conflict.',
        402,
      );
    }
    if (live) {
      // Any live subscription blocks a new checkout, not just one on the same
      // plan. Stripe Checkout is always `mode=subscription`, so it can only
      // CREATE a subscription — it cannot replace one. Nothing in this codebase
      // cancels or modifies a subscription at the provider: the whole surface is
      // `unavailableReason`/`createCheckout`/`verifyWebhook`, and the webhook
      // marks the old row canceled in SQLite only. So an ordinary Solo → Pro
      // upgrade used to leave BOTH subscriptions billing the customer while the
      // UI showed Pro, and the local `one active subscription` index meant the
      // database could not even represent what had happened.
      //
      // Refusing is a deliberate capability reduction: changing plan is not
      // self-serve until the Subscriptions API is wired in. Taking money twice
      // is worse than not offering the button.
      return fail(
        live.planCode === code
          ? `This organisation is already subscribed to the ${plan.name} plan.`
          : `This organisation is on the ${live.planCode} plan. Changing plan is not self-serve yet: `
            + 'starting a second checkout would create a second subscription and bill you for both. '
            + 'Get in touch and we will move you across.',
        409,
      );
    }
  } else if (!DEFAULT_PRODUCTS.some((p) => p.code === code)) {
    return fail(`'${code}' is not a product offered by this installation`, 400);
  }

  if (!sameOrigin(request)) {
    return fail('this request did not come from this site', 403);
  }

  let base: string | undefined;
  try {
    base = returnBase(request);
  } catch (e) {
    if (e instanceof MisconfiguredPublicUrl) return fail(e.message, 503);
    throw e;
  }
  if (!base) {
    return fail(
      'This request carried no host to return to, so no checkout was started. Set CODELENS_PUBLIC_URL to this installation’s public origin.',
      400,
    );
  }

  // Both return URLs are built from that origin and checked to still be on it.
  // Nothing from the request body contributes to either, which is what keeps
  // this endpoint from becoming an open redirect.
  const successUrl = returnUrl(base, '/billing?checkout=returned');
  const cancelUrl = returnUrl(base, '/billing?checkout=cancelled');
  if (!successUrl || !cancelUrl) {
    return fail('could not build a same-origin return URL for this request', 400);
  }

  const provider = loadPaymentProvider();
  const unavailable = provider.unavailableReason();
  if (unavailable) return fail(unavailable, 503);

  try {
    const checkout = await provider.createCheckout({
      organizationId: session.organizationId,
      code,
      kind,
      successUrl,
      cancelUrl,
      customerEmail: emailFor(session.userId),
    });
    return NextResponse.json({ url: checkout.url }, { headers: NO_STORE });
  } catch (e) {
    if (e instanceof ProviderNotConfigured) {
      // A deployment problem, not a user error. The provider's own message says
      // which setting is missing, and it is safe to show: it names environment
      // variables, never their values.
      return fail(e.message, 503);
    }
    // The provider's raw error can carry account detail, so it is logged rather
    // than returned. The caller gets something true and actionable instead.
    console.error('[billing] checkout failed', e);
    return fail(
      'The payment provider did not return a checkout session. Nothing has been charged. Try again, and if it keeps failing the server log has the provider error.',
      502,
    );
  }
}
