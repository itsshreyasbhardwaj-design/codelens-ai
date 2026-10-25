import { NextResponse } from 'next/server';
import { prisma } from '../../../../lib/db';

/**
 * DEFECT (missing authentication on an admin route): this endpoint exposes
 * every customer's email and order totals with no session check and no role
 * check. ADMIN_EMAILS is read but never actually used to gate access.
 */
const adminEmails = (process.env.ADMIN_EMAILS ?? '').split(',');

export async function GET() {
  const users = await prisma.user.findMany({ include: { orders: true } });

  // DEFECT (N+1 query): one additional query per user inside the loop, on top
  // of the include above.
  const rows = [];
  for (const user of users) {
    const orders = await prisma.order.findMany({ where: { userId: user.id } });
    rows.push({ email: user.email, orderCount: orders.length });
  }
  return NextResponse.json({ adminEmails, rows });
}
