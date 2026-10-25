import jwt from 'jsonwebtoken';

// DEFECT (hardcoded secret): signing key committed in source, with an env
// fallback that masks the problem in production.
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-key-change-me-in-prod-12345';

export interface Session { userId: string; role: string }

export function signSession(session: Session): string {
  // DEFECT (session management): no expiry, so a leaked token is valid forever.
  return jwt.sign(session, JWT_SECRET);
}

export function verifySession(token: string): Session | null {
  try {
    return jwt.verify(token, JWT_SECRET) as Session;
  } catch {
    return null;
  }
}

export function getSession(req: { headers: { get(name: string): string | null } }): Session | null {
  const header = req.headers.get('authorization');
  if (!header) return null;
  return verifySession(header.replace('Bearer ', ''));
}

// DEFECT (undocumented env var): SESSION_TTL_HOURS is read but absent from .env.example.
export const sessionTtlHours = Number(process.env.SESSION_TTL_HOURS ?? 24);
