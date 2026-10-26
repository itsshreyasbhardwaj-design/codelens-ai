import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { Db, NotFoundError } from './index.ts';
import {
  authenticate, AuthUnavailable, EmailTaken, hashPassword, issueSession,
  membership, readSession, register, verifyPassword,
} from './auth.ts';

const KEY = 'test-secret-key-at-least-32-characters-long';

function withKey<T>(fn: () => T): T {
  const prior = process.env.CODELENS_SECRET_KEY;
  process.env.CODELENS_SECRET_KEY = KEY;
  try {
    return fn();
  } finally {
    if (prior === undefined) delete process.env.CODELENS_SECRET_KEY;
    else process.env.CODELENS_SECRET_KEY = prior;
  }
}

function freshDb(): Db {
  const db = new Db(':memory:');
  db.migrate();
  return db;
}

describe('password verifiers', () => {
  it('never stores the password itself', () => {
    const stored = hashPassword('correct horse battery staple');
    assert.doesNotMatch(stored, /correct horse/);
    assert.match(stored, /^scrypt\$\d+\$\d+\$\d+\$/);
  });

  it('accepts the right password and rejects a wrong one', () => {
    const stored = hashPassword('correct horse battery staple');
    assert.equal(verifyPassword('correct horse battery staple', stored), true);
    assert.equal(verifyPassword('Correct horse battery staple', stored), false);
    assert.equal(verifyPassword('', stored), false);
  });

  it('produces a different verifier each time, so equal passwords are not equal rows', () => {
    assert.notEqual(hashPassword('same password here'), hashPassword('same password here'));
  });

  it('refuses a password too short to be worth hashing', () => {
    assert.throws(() => hashPassword('short'), /at least 10/);
  });

  it('returns false rather than throwing on a malformed stored value', () => {
    for (const bad of ['', 'garbage', 'scrypt$1$2', 'bcrypt$x$y$z$w$v', null, undefined]) {
      assert.equal(verifyPassword('whatever', bad as string), false);
    }
  });
});

describe('session tokens', () => {
  it('round-trips a valid session', () => withKey(() => {
    const token = issueSession({ userId: 'u1', organizationId: 'o1', role: 'owner' });
    const payload = readSession(token);
    assert.equal(payload?.userId, 'u1');
    assert.equal(payload?.organizationId, 'o1');
  }));

  it('rejects a token whose payload was edited', () => withKey(() => {
    const token = issueSession({ userId: 'u1', organizationId: 'o1', role: 'viewer' });
    const [body, mac] = token.split('.');
    // Swap in another organisation and keep the original signature.
    const forged = Buffer.from(
      JSON.stringify({ userId: 'u1', organizationId: 'SOMEONE-ELSE', role: 'owner', exp: 2_000_000_000 }),
      'utf8',
    ).toString('base64url');
    assert.equal(readSession(`${forged}.${mac}`), undefined);
    assert.ok(body);
  }));

  it('rejects a token signed with a different key', () => {
    const token = withKey(() => issueSession({ userId: 'u1', organizationId: 'o1', role: 'owner' }));
    const prior = process.env.CODELENS_SECRET_KEY;
    process.env.CODELENS_SECRET_KEY = 'a-completely-different-key-also-32-chars';
    try {
      assert.equal(readSession(token), undefined);
    } finally {
      if (prior === undefined) delete process.env.CODELENS_SECRET_KEY;
      else process.env.CODELENS_SECRET_KEY = prior;
    }
  });

  it('rejects an expired token', () => withKey(() => {
    assert.equal(readSession(issueSession({ userId: 'u', organizationId: 'o', role: 'owner' }, -1)), undefined);
  }));

  it('rejects junk', () => withKey(() => {
    for (const bad of ['', 'nodot', 'a.b', '....', undefined]) {
      assert.equal(readSession(bad as string), undefined);
    }
  }));

  it('treats every token as invalid when no key is configured', () => {
    const token = withKey(() => issueSession({ userId: 'u', organizationId: 'o', role: 'owner' }));
    const prior = process.env.CODELENS_SECRET_KEY;
    delete process.env.CODELENS_SECRET_KEY;
    try {
      assert.equal(readSession(token), undefined);
      assert.throws(() => issueSession({ userId: 'u', organizationId: 'o', role: 'owner' }), AuthUnavailable);
    } finally {
      if (prior !== undefined) process.env.CODELENS_SECRET_KEY = prior;
    }
  });
});

describe('accounts', () => {
  it('registers a user with their own organisation and owner role', (t) => {
    const db = freshDb();
    t.after(() => db.close());
    const account = register(db, { email: 'Someone@Example.com ', password: 'a-good-password' });
    // Email is normalised, so case cannot create a second account.
    assert.equal(account.email, 'someone@example.com');
    assert.equal(account.role, 'owner');
    assert.ok(membership(db, account.userId, account.organizationId));
  });

  it('refuses a duplicate email regardless of case', (t) => {
    const db = freshDb();
    t.after(() => db.close());
    register(db, { email: 'dup@example.com', password: 'a-good-password' });
    assert.throws(() => register(db, { email: 'DUP@example.com', password: 'another-password' }), EmailTaken);
  });

  it('writes no rows when registration fails validation', (t) => {
    const db = freshDb();
    t.after(() => db.close());
    assert.throws(() => register(db, { email: 'nope', password: 'a-good-password' }));
    assert.throws(() => register(db, { email: 'ok@example.com', password: 'short' }));
    assert.equal(db.get<{ n: number }>('SELECT COUNT(*) AS n FROM users')!.n, 0);
    assert.equal(db.get<{ n: number }>('SELECT COUNT(*) AS n FROM organizations')!.n, 0);
  });

  it('authenticates with the right password only', (t) => {
    const db = freshDb();
    t.after(() => db.close());
    register(db, { email: 'user@example.com', password: 'a-good-password' });
    assert.ok(authenticate(db, 'user@example.com', 'a-good-password'));
    assert.equal(authenticate(db, 'user@example.com', 'wrong-password'), undefined);
  });

  it('answers identically for an unknown account and a wrong password', (t) => {
    const db = freshDb();
    t.after(() => db.close());
    register(db, { email: 'known@example.com', password: 'a-good-password' });
    // Both return undefined: the caller cannot tell which case it hit, which is
    // what stops account enumeration at the API boundary.
    assert.equal(authenticate(db, 'known@example.com', 'wrong-password'), undefined);
    assert.equal(authenticate(db, 'unknown@example.com', 'wrong-password'), undefined);
  });

  it('records the login and an audit entry', (t) => {
    const db = freshDb();
    t.after(() => db.close());
    const account = register(db, { email: 'audit@example.com', password: 'a-good-password' });
    authenticate(db, 'audit@example.com', 'a-good-password');
    assert.ok(db.get<{ last_login_at: string | null }>('SELECT last_login_at FROM users WHERE id = ?', account.userId)!.last_login_at);
    const actions = db.all<{ action: string }>('SELECT action FROM audit_logs').map((r) => r.action);
    assert.ok(actions.includes('account.registered'));
  });
});

describe('tenant isolation with real accounts', () => {
  it('stops one account reading another account\'s project', (t) => {
    const db = freshDb();
    t.after(() => db.close());

    const alice = register(db, { email: 'alice@example.com', password: 'alice-password-1' });
    const bob = register(db, { email: 'bob@example.com', password: 'bob-password-12' });

    db.run(
      'INSERT INTO projects (id, organization_id, name, slug, kind, created_at, updated_at) VALUES (?,?,?,?,?,?,?)',
      'alice-project', alice.organizationId, 'Alice app', 'alice-app', 'source', 'n', 'n',
    );

    // Alice can reach it.
    db.assertProjectInOrg('alice-project', alice.organizationId);

    // Bob gets the same error as for a project that does not exist.
    let crossTenant: Error | undefined;
    try { db.assertProjectInOrg('alice-project', bob.organizationId); } catch (e) { crossTenant = e as Error; }
    let missing: Error | undefined;
    try { db.assertProjectInOrg('no-such-project', bob.organizationId); } catch (e) { missing = e as Error; }

    assert.ok(crossTenant instanceof NotFoundError);
    assert.ok(missing instanceof NotFoundError);
    assert.equal(
      crossTenant!.message.replace('alice-project', 'X'),
      missing!.message.replace('no-such-project', 'X'),
      'the two errors must be indistinguishable',
    );
  });

  it('revokes access as soon as membership is removed, not at token expiry', (t) => {
    const db = freshDb();
    t.after(() => db.close());
    const account = register(db, { email: 'leaver@example.com', password: 'a-good-password' });

    // The token stays cryptographically valid...
    const token = withKey(() => issueSession({
      userId: account.userId, organizationId: account.organizationId, role: 'owner',
    }));
    assert.ok(withKey(() => readSession(token)));

    db.run('DELETE FROM organization_members WHERE user_id = ?', account.userId);

    // ...but membership is re-checked per request, which is what the session
    // helper does before returning an organisation.
    assert.equal(membership(db, account.userId, account.organizationId), undefined);
  });
});
