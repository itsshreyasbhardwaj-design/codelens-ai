import 'server-only';
import { cookies } from 'next/headers';
import { redirect } from 'next/navigation';
import { membership, readSession, SESSION_COOKIE, type SessionPayload } from '@codelens/engine/db/auth.ts';
import { db } from './store.ts';

/**
 * Request session.
 *
 * The cookie is verified on every read rather than trusted after middleware:
 * middleware decides routing, this decides data access, and the two must not
 * share an assumption. Membership is re-checked against the database so a user
 * removed from an organisation loses access immediately rather than at cookie
 * expiry.
 */

export interface Session {
  userId: string;
  organizationId: string;
  role: string;
}

export async function currentSession(): Promise<Session | undefined> {
  const jar = await cookies();
  const payload: SessionPayload | undefined = readSession(jar.get(SESSION_COOKIE)?.value);
  if (!payload) return undefined;

  const current = membership(db(), payload.userId, payload.organizationId);
  if (!current) return undefined;

  return { userId: payload.userId, organizationId: payload.organizationId, role: current.role };
}

/** For pages: redirects to sign-in when there is no valid session. */
export async function requireSession(): Promise<Session> {
  const session = await currentSession();
  if (!session) redirect('/sign-in');
  return session;
}

/** For route handlers: returns undefined so the caller can answer 401 itself. */
export async function sessionOr401(): Promise<Session | undefined> {
  return currentSession();
}
