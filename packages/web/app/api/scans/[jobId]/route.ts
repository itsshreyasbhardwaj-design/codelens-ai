import { cancelJob, getJob } from '../../../lib/runner.ts';
import { sessionOr401 } from '../../../lib/session.ts';

/**
 * GET    /api/scans/:jobId — the live JobProgress, including real stage status.
 * DELETE /api/scans/:jobId — request cancellation of a running scan.
 *
 * Job state lives in the web process, so an id from a previous process is
 * genuinely unknown and answered with 404 rather than an invented status.
 *
 * Both methods re-check ownership rather than relying on the middleware. The
 * middleware proves the caller has a session; it cannot prove this job is
 * theirs. A job belonging to another organisation is answered as absent, so a
 * guessed id reveals neither the project's name nor that it exists — and
 * cannot be used to cancel someone else's scan.
 */

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

const JOB_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const NO_STORE = { 'cache-control': 'no-store' } as const;

function notFound(message: string): Response {
  return Response.json({ error: message }, { status: 404, headers: NO_STORE });
}

function unauthorized(): Response {
  return Response.json({ error: 'authentication required' }, { status: 401, headers: NO_STORE });
}

export async function GET(
  _req: Request,
  ctx: { params: Promise<{ jobId: string }> },
): Promise<Response> {
  const session = await sessionOr401();
  if (!session) return unauthorized();

  const { jobId } = await ctx.params;
  if (!JOB_ID.test(jobId)) return notFound('not a job id');

  const job = getJob(jobId, session.organizationId);
  if (!job) return notFound('no scan job with that id is known to this process');

  return Response.json(job, { headers: NO_STORE });
}

export async function DELETE(
  _req: Request,
  ctx: { params: Promise<{ jobId: string }> },
): Promise<Response> {
  const session = await sessionOr401();
  if (!session) return unauthorized();
  const { organizationId } = session;

  const { jobId } = await ctx.params;
  if (!JOB_ID.test(jobId)) return notFound('not a job id');

  // cancelJob is false for an unknown job, one owned by another organisation,
  // and one that has already finished; none can be cancelled, and all are a 404
  // on this resource.
  if (!cancelJob(jobId, organizationId)) {
    return notFound(
      getJob(jobId, organizationId)
        ? 'that scan has already finished and cannot be cancelled'
        : 'no scan job with that id is known to this process',
    );
  }

  const job = getJob(jobId, organizationId);
  return Response.json(job ?? { jobId, status: 'cancelled' }, { status: 202, headers: NO_STORE });
}
