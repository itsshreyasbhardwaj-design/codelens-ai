import { NextResponse } from 'next/server';
import { AuthUnavailable, EmailTaken, issueSession, register, SESSION_COOKIE } from '@codelens/engine/db/auth.ts';
import { db } from '../../../lib/store.ts';

export async function POST(request: Request): Promise<NextResponse> {
  let body: { email?: string; password?: string; displayName?: string };
  try {
    body = (await request.json()) as typeof body;
  } catch {
    return NextResponse.json({ error: 'request body is not valid JSON' }, { status: 400 });
  }
  if (!body.email || !body.password) {
    return NextResponse.json({ error: 'email and password are required' }, { status: 400 });
  }

  try {
    const account = register(db(), {
      email: body.email,
      password: body.password,
      displayName: body.displayName,
    });
    const token = issueSession({
      userId: account.userId,
      organizationId: account.organizationId,
      role: account.role,
    });
    const res = NextResponse.json({ email: account.email }, { status: 201 });
    setSessionCookie(res, token);
    return res;
  } catch (e) {
    if (e instanceof EmailTaken) {
      return NextResponse.json({ error: e.message }, { status: 409 });
    }
    if (e instanceof AuthUnavailable) {
      // A deployment problem, not a user error: say so plainly rather than
      // pretending the credentials were wrong.
      return NextResponse.json({ error: e.message }, { status: 503 });
    }
    return NextResponse.json({ error: e instanceof Error ? e.message : 'registration failed' }, { status: 400 });
  }
}

export function setSessionCookie(res: NextResponse, token: string): void {
  res.cookies.set(SESSION_COOKIE, token, {
    httpOnly: true,
    sameSite: 'lax',
    // Secure in production; a local http dev server would otherwise drop it.
    secure: process.env.NODE_ENV === 'production',
    path: '/',
    maxAge: 60 * 60 * 12,
  });
}
