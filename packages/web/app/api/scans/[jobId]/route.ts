import { cancelJob, getJob } from '../../../lib/runner.ts';

/**
 * GET    /api/scans/:jobId — the live JobProgress, including real stage status.
 * DELETE /api/scans/:jobId — request cancellation of a running scan.
 *
 * Job state lives in the web process, so an id from a previous process is
 * genuinely unknown and answered with 404 rather than an invented status.
 */

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

const JOB_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const NO_STORE = { 'cache-control': 'no-store' } as const;

function notFound(message: string): Response {
  return Response.json({ error: message }, { status: 404, headers: NO_STORE });
}

export async function GET(
  _req: Request,
  ctx: { params: Promise<{ jobId: string }> },
): Promise<Response> {
  const { jobId } = await ctx.params;
  if (!JOB_ID.test(jobId)) return notFound('not a job id');

  const job = getJob(jobId);
  if (!job) return notFound('no scan job with that id is known to this process');

  return Response.json(job, { headers: NO_STORE });
}

export async function DELETE(
  _req: Request,
  ctx: { params: Promise<{ jobId: string }> },
): Promise<Response> {
  const { jobId } = await ctx.params;
  if (!JOB_ID.test(jobId)) return notFound('not a job id');

  // cancelJob is false for both an unknown job and one that has already
  // finished; neither can be cancelled, and both are a 404 on this resource.
  if (!cancelJob(jobId)) {
    return notFound(
      getJob(jobId)
        ? 'that scan has already finished and cannot be cancelled'
        : 'no scan job with that id is known to this process',
    );
  }

  const job = getJob(jobId);
  return Response.json(job ?? { jobId, status: 'cancelled' }, { status: 202, headers: NO_STORE });
}
