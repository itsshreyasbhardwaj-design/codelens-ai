import { NextResponse } from 'next/server';
import { SESSION_COOKIE } from '@codelens/engine/db/auth.ts';

export function POST(): NextResponse {
  const res = NextResponse.json({ ok: true });
  // ponytail: sessions are stateless, so this clears the cookie and nothing
  // more. A stolen token stays valid until it expires; see db/auth.ts.
  res.cookies.set(SESSION_COOKIE, '', { httpOnly: true, path: '/', maxAge: 0 });
  return res;
}
