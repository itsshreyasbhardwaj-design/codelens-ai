import { loadAiConfig, ModelClient } from '@codelens/engine/ai/provider.ts';
import { loadPaymentProvider } from '@codelens/engine/billing/payments.ts';
// The key floor is the engine's, imported rather than restated: a second copy
// of a security threshold is a divergence waiting to happen.
import { MIN_SECRET_KEY_CHARS } from '@codelens/engine/db/auth.ts';
import { databasePath, db } from '../../lib/store.ts';

/**
 * GET /api/health — liveness and readiness for the orchestrator.
 *
 * Polled by the container HEALTHCHECK, by Fly's load balancer and by whatever
 * else watches the process, so the two properties that matter are that it is
 * cheap and that it cannot throw. Every branch below returns a Response; a
 * handler that threw would surface as a 500 and be indistinguishable from the
 * application being broken.
 *
 * Readiness here means exactly one thing: the SQLite file can be opened and
 * every migration this build carries has been applied. Those are the two
 * conditions under which serving traffic is safe. `migrate()` runs when the
 * first request opens the database (see lib/store.ts), so a freshly deployed
 * machine answers 503 only while that is in flight or has failed.
 *
 * Configuration is reported, never enforced: a deployment with no secret key
 * and no payment provider is a legitimate deployment — it runs free-plan,
 * sessionless and offline — and the load balancer must not take it out of
 * rotation for that. It is reported as `degraded` with a 200 instead.
 *
 * Secrets are reported as booleans. No value, no prefix, no length.
 */

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

interface Health {
  status: 'ok' | 'degraded' | 'unavailable';
  /** Present only when something is wrong, and always says what. */
  reason?: string;
  database: {
    path: string;
    reachable: boolean;
    schema?: { current: number; applied: number[]; pending: number[] };
  };
  secretKeyConfigured: boolean;
  ai: { configured: boolean; provider: string; reason?: string };
  payments: { configured: boolean; provider: string; reason?: string };
  uptimeSeconds: number;
}

function respond(body: Health, status: number): Response {
  return Response.json(body, {
    status,
    headers: {
      // A cached health check reports the state of a machine that may no
      // longer exist.
      'cache-control': 'no-store, max-age=0',
    },
  });
}

export function GET(): Response {
  // Resolved first and separately: the path is the single most useful thing in
  // this response when the database is NOT reachable, so it must not be lost
  // to the same failure.
  let path: string;
  try {
    path = databasePath();
  } catch {
    path = 'unresolved';
  }

  const secretKeyConfigured = (process.env.CODELENS_SECRET_KEY ?? '').length >= MIN_SECRET_KEY_CHARS;

  let ai: Health['ai'];
  try {
    const config = loadAiConfig();
    const reason = new ModelClient(config).unavailableReason();
    ai = { configured: reason === undefined, provider: config.provider, reason };
  } catch (e) {
    ai = { configured: false, provider: 'unknown', reason: message(e) };
  }

  let payments: Health['payments'];
  try {
    const provider = loadPaymentProvider();
    const reason = provider.unavailableReason();
    payments = { configured: reason === undefined, provider: provider.name, reason };
  } catch (e) {
    payments = { configured: false, provider: 'unknown', reason: message(e) };
  }

  const base = {
    secretKeyConfigured,
    ai,
    payments,
    uptimeSeconds: Math.round(process.uptime()),
  };

  let schema: { current: number; applied: number[]; pending: number[] };
  try {
    // One statement against schema_migrations. This is also the reachability
    // probe: if the file cannot be opened or read, it fails here.
    schema = db().schemaStatus();
  } catch (e) {
    return respond(
      {
        status: 'unavailable',
        reason: `database is not reachable at ${path}: ${message(e)}`,
        database: { path, reachable: false },
        ...base,
      },
      503,
    );
  }

  const database = { path, reachable: true, schema };

  if (schema.pending.length > 0) {
    return respond(
      {
        status: 'unavailable',
        reason: `schema migrations pending: ${schema.pending.join(', ')}. Migrations are applied on boot; this machine is not ready to serve.`,
        database,
        ...base,
      },
      503,
    );
  }

  // Reachable and migrated, so this machine can serve. Anything below is
  // configuration the operator may have chosen deliberately.
  if (!secretKeyConfigured) {
    return respond(
      {
        status: 'degraded',
        reason: `CODELENS_SECRET_KEY is unset or shorter than ${MIN_SECRET_KEY_CHARS} characters, so sessions cannot be signed and sign-in will fail. The database is healthy.`,
        database,
        ...base,
      },
      200,
    );
  }

  return respond({ status: 'ok', database, ...base }, 200);
}

function message(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}
