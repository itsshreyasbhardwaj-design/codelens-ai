import { NextResponse } from 'next/server';
import { prisma } from '../../../lib/db';
import { signSession } from '../../../lib/auth';

/**
 * DEFECT (missing rate limiting): unlimited password attempts per IP or
 * account, so credentials can be brute-forced.
 * DEFECT (plaintext password comparison): passwords are compared directly
 * rather than against a hash, and the comparison is not constant-time.
 */
export async function POST(req: Request) {
  const body = await req.json();
  const user = await prisma.user.findUnique({ where: { email: body.email } });

  if (!user || user.password !== body.password) {
    // DEFECT (information leak): the error distinguishes an unknown account
    // from a wrong password, enabling account enumeration.
    return NextResponse.json(
      { error: user ? 'incorrect password' : 'no account with that email' },
      { status: 401 },
    );
  }
  return NextResponse.json({ token: signSession({ userId: user.id, role: user.role }) });
}
