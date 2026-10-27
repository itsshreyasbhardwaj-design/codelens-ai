import { createHmac, randomBytes, randomUUID, scryptSync, timingSafeEqual } from 'node:crypto';
import { Db, now } from './index.ts';

/**
 * Authentication.
 *
 * Built on node:crypto rather than an auth library: scrypt for password
 * verifiers, HMAC-SHA256 for session tokens. That is the whole requirement, and
 * a dependency here would be a dependency sitting on the most security-
 * sensitive path in the product.
 *
 * ponytail: sessions are stateless signed tokens, not rows. Revoking ONE
 * session therefore is not possible — logout clears the cookie, and the only
 * server-side revocation is rotating CODELENS_SECRET_KEY, which logs everyone
 * out. Add a sessions table when per-session revocation is actually needed.
 */

// scrypt parameters. N=2^15 is the current OWASP floor for interactive logins.
const SCRYPT_N = 32768;
const SCRYPT_R = 8;
const SCRYPT_P = 1;
const KEY_LEN = 32;
const SALT_LEN = 16;
// scrypt needs about 128 * N * r bytes — 32 MiB at these parameters, which is
// exactly Node's default ceiling, so it must be raised rather than the work
// factor lowered.
const MAX_MEM = 64 * 1024 * 1024;

export const SESSION_COOKIE = 'codelens_session';
const SESSION_TTL_SECONDS = 60 * 60 * 12;

/**
  * The floor the signing key must clear. Exported so the health check and the
  * registration pre-check cannot drift from what `secret()` actually enforces.
  */
export const MIN_SECRET_KEY_CHARS = 32;

export class AuthUnavailable extends Error {
  constructor() {
    super(
      `CODELENS_SECRET_KEY is not set (needs ${MIN_SECRET_KEY_CHARS}+ characters), so sessions cannot be signed. `
        + 'Refusing to issue unsigned tokens.',
    );
    this.name = 'AuthUnavailable';
  }
}

function secret(): Buffer {
  const s = process.env.CODELENS_SECRET_KEY;
  if (!s || s.length < MIN_SECRET_KEY_CHARS) throw new AuthUnavailable();
  return Buffer.from(s, 'utf8');
}

/**
 * Throw now if a session could not be signed later.
 *
 * Registration commits the account and its first credit grant before issuing a
 * session, so without this the one step that can fail on configuration ran
 * last: the caller got a 503 while a working account and a 40-credit ledger row
 * had already been written, and the retry they would naturally make came back
 * "email taken". Checking first means nothing is written at all.
 */
export function assertAuthAvailable(): void {
  secret();
}

/** `scrypt$N$r$p$salt$hash`, all base64url. The format carries its own parameters. */
export function hashPassword(plain: string): string {
  if (plain.length < 10) throw new Error('password must be at least 10 characters');
  const salt = randomBytes(SALT_LEN);
  const hash = scryptSync(plain, salt, KEY_LEN, { N: SCRYPT_N, r: SCRYPT_R, p: SCRYPT_P, maxmem: MAX_MEM });
  return [
    'scrypt', SCRYPT_N, SCRYPT_R, SCRYPT_P,
    salt.toString('base64url'), hash.toString('base64url'),
  ].join('$');
}

/**
 * Constant-time verification. Returns false rather than throwing on a malformed
 * stored value, so a corrupt row cannot be distinguished from a wrong password.
 */
export function verifyPassword(plain: string, stored: string | null | undefined): boolean {
  if (!stored) return false;
  const parts = stored.split('$');
  if (parts.length !== 6 || parts[0] !== 'scrypt') return false;
  const [, n, r, p, saltB64, hashB64] = parts;
  try {
    const salt = Buffer.from(saltB64!, 'base64url');
    const expected = Buffer.from(hashB64!, 'base64url');
    const actual = scryptSync(plain, salt, expected.length, {
      N: Number(n), r: Number(r), p: Number(p), maxmem: MAX_MEM,
    });
    return expected.length === actual.length && timingSafeEqual(expected, actual);
  } catch {
    return false;
  }
}

export interface SessionPayload {
  userId: string;
  organizationId: string;
  role: string;
  /** Unix seconds. */
  exp: number;
}

function sign(data: string): string {
  return createHmac('sha256', secret()).update(data).digest('base64url');
}

export function issueSession(payload: Omit<SessionPayload, 'exp'>, ttlSeconds = SESSION_TTL_SECONDS): string {
  const full: SessionPayload = { ...payload, exp: Math.floor(Date.now() / 1000) + ttlSeconds };
  const body = Buffer.from(JSON.stringify(full), 'utf8').toString('base64url');
  return `${body}.${sign(body)}`;
}

/** Returns the payload, or undefined when the token is absent, forged, or expired. */
export function readSession(token: string | undefined): SessionPayload | undefined {
  if (!token) return undefined;
  const dot = token.lastIndexOf('.');
  if (dot <= 0) return undefined;
  const body = token.slice(0, dot);
  const mac = token.slice(dot + 1);

  let expected: string;
  try {
    expected = sign(body);
  } catch {
    return undefined; // no secret configured: no session is valid
  }
  const a = Buffer.from(mac);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !timingSafeEqual(a, b)) return undefined;

  try {
    const payload = JSON.parse(Buffer.from(body, 'base64url').toString('utf8')) as SessionPayload;
    if (typeof payload.exp !== 'number' || payload.exp * 1000 < Date.now()) return undefined;
    if (!payload.userId || !payload.organizationId) return undefined;
    return payload;
  } catch {
    return undefined;
  }
}

// ---------------------------------------------------------------- accounts --

export interface Account {
  userId: string;
  email: string;
  organizationId: string;
  role: string;
}

export class EmailTaken extends Error {
  constructor() { super('an account with that email already exists'); this.name = 'EmailTaken'; }
}

function normaliseEmail(email: string): string {
  return email.trim().toLowerCase();
}

/**
 * Register a user and the personal organisation that owns their projects.
 * Every user gets an organisation, so there is no second code path for
 * "personal" versus "team" ownership.
 */
export function register(db: Db, input: { email: string; password: string; displayName?: string }): Account {
  const email = normaliseEmail(input.email);
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) throw new Error('that is not a valid email address');

  const hash = hashPassword(input.password); // throws on a short password, before any write

  return db.tx(() => {
    if (db.get('SELECT id FROM users WHERE email = ?', email)) throw new EmailTaken();

    const userId = randomUUID();
    const orgId = randomUUID();
    const stamp = now();

    db.run(
      'INSERT INTO users (id, email, display_name, password_hash, created_at, updated_at) VALUES (?,?,?,?,?,?)',
      userId, email, input.displayName ?? null, hash, stamp, stamp,
    );
    db.run(
      'INSERT INTO organizations (id, name, slug, created_at, updated_at) VALUES (?,?,?,?,?)',
      orgId, input.displayName ? `${input.displayName}'s workspace` : email, `org-${orgId.slice(0, 8)}`, stamp, stamp,
    );
    db.run(
      'INSERT INTO organization_members (id, organization_id, user_id, role, created_at) VALUES (?,?,?,?,?)',
      randomUUID(), orgId, userId, 'owner', stamp,
    );
    db.audit({ organizationId: orgId, actorUserId: userId, action: 'account.registered', targetKind: 'user', targetId: userId });

    return { userId, email, organizationId: orgId, role: 'owner' };
  });
}

/**
 * Verify credentials. Returns undefined for both an unknown account and a wrong
 * password, and hashes a dummy value in the unknown-account case so the two
 * paths take comparable time — the security analyzer reports the alternative as
 * account enumeration, and this product should not fail its own check.
 */
const DUMMY_HASH = hashPassword('not-a-real-password-placeholder');

export function authenticate(db: Db, email: string, password: string): Account | undefined {
  const row = db.get<{ id: string; email: string; password_hash: string | null }>(
    'SELECT id, email, password_hash FROM users WHERE email = ?',
    normaliseEmail(email),
  );
  if (!row) {
    verifyPassword(password, DUMMY_HASH);
    return undefined;
  }
  if (!verifyPassword(password, row.password_hash)) return undefined;

  const member = db.get<{ organization_id: string; role: string }>(
    'SELECT organization_id, role FROM organization_members WHERE user_id = ? ORDER BY created_at LIMIT 1',
    row.id,
  );
  if (!member) return undefined; // a user with no organisation cannot own anything

  db.run('UPDATE users SET last_login_at = ? WHERE id = ?', now(), row.id);
  return { userId: row.id, email: row.email, organizationId: member.organization_id, role: member.role };
}

/** Does this user belong to this organisation? Checked on every request. */
export function membership(db: Db, userId: string, organizationId: string): { role: string } | undefined {
  return db.get<{ role: string }>(
    'SELECT role FROM organization_members WHERE user_id = ? AND organization_id = ?',
    userId, organizationId,
  );
}
