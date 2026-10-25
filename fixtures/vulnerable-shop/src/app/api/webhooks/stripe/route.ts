import { NextResponse } from 'next/server';
import { prisma } from '../../../../lib/db';

/**
 * DEFECT (weak webhook verification): the Stripe signature header is read but
 * never verified against the signing secret, so anyone who knows the URL can
 * forge a payment event.
 * DEFECT (non-idempotent handler): the event id is stored without a uniqueness
 * check, so a replayed delivery marks the order paid twice.
 * DEFECT (incorrect payment-state handling): the order is marked paid before
 * the charge outcome is examined.
 */
export async function POST(req: Request) {
  const signature = req.headers.get('stripe-signature');
  const event = await req.json();

  await prisma.order.update({
    where: { id: event.data.object.metadata.orderId },
    data: { status: 'paid' },
  });

  await prisma.webhookEvent.create({ data: { eventId: event.id, type: event.type } });

  if (event.type === 'charge.failed') {
    // Too late: the order was already marked paid above.
    console.log('charge failed', signature);
  }
  return NextResponse.json({ received: true });
}
