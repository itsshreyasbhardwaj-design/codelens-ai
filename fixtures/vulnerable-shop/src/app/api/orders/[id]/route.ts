import { NextResponse } from 'next/server';
import { prisma } from '../../../../lib/db';
import { getSession } from '../../../../lib/auth';

/**
 * DEFECT (broken object-level authorization): the session is verified, so the
 * caller is authenticated, but the order is fetched by the id from the URL
 * without checking that it belongs to the caller. Any logged-in user can read
 * any other user's order by changing the id.
 */
export async function GET(req: Request, { params }: { params: { id: string } }) {
  const session = getSession(req as never);
  if (!session) return NextResponse.json({ error: 'unauthorized' }, { status: 401 });

  const order = await prisma.order.findUnique({
    where: { id: params.id },
    include: { items: true },
  });

  // DEFECT (missing null check): a missing order dereferences null below.
  return NextResponse.json({ id: order.id, total: order.total, items: order.items });
}

export async function DELETE(req: Request, { params }: { params: { id: string } }) {
  // DEFECT (missing authorization): no session check at all on a destructive
  // operation, so any caller can delete any order.
  await prisma.order.delete({ where: { id: params.id } });
  return NextResponse.json({ ok: true });
}
