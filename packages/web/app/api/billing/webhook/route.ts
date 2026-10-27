import { NextResponse } from 'next/server';
import {
  applyWebhookEvent,
  loadPaymentProvider,
  ProviderNotConfigured,
  WebhookVerificationFailed,
} from '@codelens/engine/billing/payments.ts';
import { db } from '../../../lib/store.ts';

/**
 * The payment provider's webhook.
 *
 * This is the only place where a payment becomes an entitlement. The browser
 * returning from a checkout page grants nothing: a return URL is attacker-
 * controllable, a webhook with a verified signature is not.
 *
 * Three rules hold here:
 *  - The raw body is verified before it is parsed. Reading JSON first and
 *    re-serialising it would change the bytes the signature covers.
 *  - A failed verification is a 400 and nothing is written.
 *  - Replays are idempotent: `applyWebhookEvent` records the provider event id
 *    and a repeat returns `applied: false` without granting twice.
 *
 * This route is deliberately outside the session guard — the provider has no
 * session — so the signature is the only authentication, and it is mandatory.
 */
export const runtime = 'nodejs';

export async function POST(req: Request): Promise<NextResponse> {
  const provider = loadPaymentProvider();

  const unavailable = provider.unavailableReason();
  if (unavailable) {
    // 503 rather than 400: the request may well be valid, but this
    // installation is not configured to act on it.
    return NextResponse.json({ error: unavailable }, { status: 503 });
  }

  const raw = await req.text();
  const signature =
    req.headers.get('stripe-signature') ?? req.headers.get('x-razorpay-signature');

  let event;
  try {
    event = provider.verifyWebhook(raw, signature);
  } catch (e) {
    if (e instanceof WebhookVerificationFailed) {
      return NextResponse.json({ error: e.message }, { status: 400 });
    }
    if (e instanceof ProviderNotConfigured) {
      return NextResponse.json({ error: e.message }, { status: 503 });
    }
    return NextResponse.json(
      { error: `webhook could not be read: ${e instanceof Error ? e.message : String(e)}` },
      { status: 400 },
    );
  }

  try {
    const outcome = applyWebhookEvent(db(), provider.name, event);
    // 200 on a duplicate too: the provider must stop retrying an event that
    // has already been applied.
    return NextResponse.json({
      received: true,
      applied: outcome.applied,
      action: outcome.action,
    });
  } catch (e) {
    // A 500 here makes the provider retry, which is what we want: the event was
    // genuine and has not been applied.
    console.error('[billing] failed to apply webhook event', event.id, e);
    return NextResponse.json({ error: 'could not apply event' }, { status: 500 });
  }
}
