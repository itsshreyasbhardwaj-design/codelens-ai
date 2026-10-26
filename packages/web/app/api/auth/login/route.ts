import { NextResponse } from 'next/server';
import { authenticate, AuthUnavailable, issueSession } from '@codelens/engine/db/auth.ts';
import { db } from '../../../lib/store.ts';
import { setSessionCookie } from '../register/route.ts';

export async function POST(request: Request): Promise<NextResponse> {
  let body: { email?: string; password?: string };
  try {
    body = (await request.json()) as typeof body;
  } catch {
    return NextResponse.json({ error: 'request body is not valid JSON' }, { status: 400 });
  }
  if (!body.email || !body.password) {
    return NextResponse.json({ error: 'email and password are required' }, { status: 400 });
  }

  try {
    const account = authenticate(db(), body.email, body.password);
    // One message for both an unknown account and a wrong password: the
    // security analyzer reports the alternative as account enumeration.
    if (!account) {
      return NextResponse.json({ error: 'those credentials are not valid' }, { status: 401 });
    }
    const res = NextResponse.json({ email: account.email });
    setSessionCookie(res, issueSession({
      userId: account.userId,
      organizationId: account.organizationId,
      role: account.role,
    }));
    return res;
  } catch (e) {
    if (e instanceof AuthUnavailable) {
      return NextResponse.json({ error: e.message }, { status: 503 });
    }
    return NextResponse.json({ error: 'sign in failed' }, { status: 500 });
  }
}
