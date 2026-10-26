import { canCreateProject, holdsProjectSlot, canStartScan } from '@codelens/engine/billing/entitlements.ts';
import { grantMonthlyAllowance } from '@codelens/engine/billing/credits.ts';
import { ScanRequestInvalid, projectIdFor, startScan, type ScanInput } from '../../lib/runner.ts';
import { sessionOr401 } from '../../lib/session.ts';
import { db } from '../../lib/store.ts';

/**
 * POST /api/scans — start a scan.
 *
 * This and the per-job route are the only endpoints in the application that
 * change anything, so every input is bounded and validated here before the
 * engine is touched. A scan itself is never run inside the request: `startScan`
 * registers a job, returns its id, and the client polls for stage progress.
 *
 * Accepts either:
 *   application/json       {kind:'local',path,name?} | {kind:'github',ref,token?,name?}
 *   multipart/form-data    file=<archive.zip>, name?=<project name>
 */

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

/** A path or a repository ref; nothing legitimate needs more. */
const MAX_JSON_BYTES = 8 * 1024;

/**
 * Upload ceiling for the ZIP path. Deliberately well below the engine's
 * 256 MiB archive limit: the engine bound protects the analysis, this one
 * protects the web process, which buffers the body in memory.
 */
const MAX_ARCHIVE_BYTES = 64 * 1024 * 1024;

const MAX_PATH_CHARS = 4096;
const MAX_REF_CHARS = 512;
const MAX_TOKEN_CHARS = 512;
const MAX_NAME_CHARS = 200;

class RequestRejected extends Error {
  readonly status: number;
  constructor(status: number, message: string) {
    super(message);
    this.name = 'RequestRejected';
    this.status = status;
  }
}

function fail(message: string, status = 400): Response {
  return Response.json({ error: message }, { status, headers: { 'cache-control': 'no-store' } });
}

function declaredBytes(req: Request): number | undefined {
  const raw = req.headers.get('content-length');
  if (raw === null) return undefined;
  const n = Number(raw);
  return Number.isInteger(n) && n >= 0 ? n : undefined;
}

function str(value: unknown, field: string, max: number, required: boolean): string | undefined {
  if (value === undefined || value === null || value === '') {
    if (required) throw new RequestRejected(400, `${field} is required`);
    return undefined;
  }
  if (typeof value !== 'string') throw new RequestRejected(400, `${field} must be a string`);
  const trimmed = value.trim();
  if (trimmed.length === 0) {
    if (required) throw new RequestRejected(400, `${field} is required`);
    return undefined;
  }
  if (trimmed.length > max) throw new RequestRejected(400, `${field} is longer than ${max} characters`);
  return trimmed;
}

async function jsonInput(req: Request): Promise<ScanInput> {
  const declared = declaredBytes(req);
  if (declared !== undefined && declared > MAX_JSON_BYTES) {
    throw new RequestRejected(413, `request body is ${declared} bytes, limit is ${MAX_JSON_BYTES}`);
  }
  const text = await req.text();
  if (Buffer.byteLength(text) > MAX_JSON_BYTES) {
    throw new RequestRejected(413, `request body exceeds ${MAX_JSON_BYTES} bytes`);
  }

  let body: unknown;
  try {
    body = JSON.parse(text);
  } catch {
    throw new RequestRejected(400, 'request body is not valid JSON');
  }
  if (typeof body !== 'object' || body === null || Array.isArray(body)) {
    throw new RequestRejected(400, 'request body must be a JSON object');
  }

  const b = body as Record<string, unknown>;
  const kind = str(b.kind, 'kind', 20, true);
  const name = str(b.name, 'name', MAX_NAME_CHARS, false);

  if (kind === 'local') {
    return { kind: 'local', path: str(b.path, 'path', MAX_PATH_CHARS, true)!, name };
  }
  if (kind === 'github') {
    return {
      kind: 'github',
      ref: str(b.ref, 'ref', MAX_REF_CHARS, true)!,
      // Never persisted: the token is handed to this one scan and nothing else.
      token: str(b.token, 'token', MAX_TOKEN_CHARS, false),
      name,
    };
  }
  if (kind === 'zip') {
    throw new RequestRejected(400, "kind 'zip' must be sent as multipart/form-data with a 'file' field");
  }
  throw new RequestRejected(400, `kind must be 'local' or 'github', got '${kind}'`);
}

async function zipInput(req: Request): Promise<ScanInput> {
  const declared = declaredBytes(req);
  if (declared !== undefined && declared > MAX_ARCHIVE_BYTES) {
    throw new RequestRejected(413, `upload is ${declared} bytes, limit is ${MAX_ARCHIVE_BYTES} bytes (64 MiB)`);
  }

  let form: FormData;
  try {
    form = await req.formData();
  } catch {
    throw new RequestRejected(400, 'multipart body could not be read');
  }

  const file = form.get('file');
  if (file === null) throw new RequestRejected(400, "no 'file' field in the upload");
  if (typeof file === 'string') throw new RequestRejected(400, "the 'file' field must be an uploaded file, not text");

  const filename = file.name ?? '';
  if (!/\.zip$/i.test(filename)) {
    throw new RequestRejected(400, `only .zip archives are accepted, got '${filename || 'a file with no name'}'`);
  }
  if (file.size > MAX_ARCHIVE_BYTES) {
    throw new RequestRejected(413, `archive is ${file.size} bytes, limit is ${MAX_ARCHIVE_BYTES} bytes (64 MiB)`);
  }

  const buffer = Buffer.from(await file.arrayBuffer());
  if (buffer.length > MAX_ARCHIVE_BYTES) {
    throw new RequestRejected(413, `archive exceeds ${MAX_ARCHIVE_BYTES} bytes (64 MiB)`);
  }
  if (buffer.length === 0) throw new RequestRejected(400, 'the uploaded archive is empty');

  return {
    kind: 'zip',
    buffer,
    filename,
    name: str(form.get('name'), 'name', MAX_NAME_CHARS, false),
  };
}

export async function POST(req: Request): Promise<Response> {
  const contentType = (req.headers.get('content-type') ?? '').split(';')[0].trim().toLowerCase();

  let input: ScanInput;
  try {
    if (contentType === 'multipart/form-data') input = await zipInput(req);
    else if (contentType === 'application/json') input = await jsonInput(req);
    else {
      return fail(
        `unsupported content-type '${contentType || 'none'}': send application/json, or multipart/form-data to upload a ZIP`,
        415,
      );
    }
  } catch (e) {
    if (e instanceof RequestRejected) return fail(e.message, e.status);
    return fail(e instanceof Error ? e.message : 'request could not be read');
  }

  // Entitlements are decided here, on the server, from the session's
  // organisation. Nothing the client sends influences which plan applies.
  const session = await sessionOr401();
  if (!session) return fail('authentication required', 401);
  const { organizationId } = session;

  // Idempotent per calendar month, so the allowance lands without a scheduler.
  grantMonthlyAllowance(db(), organizationId, new Date().toISOString());

  const projectLimit = canCreateProject(db(), organizationId);
  const scanLimit = canStartScan(db(), organizationId, {
    atIso: new Date().toISOString(),
    // No size is passed, deliberately.
    //
    // The one-sided argument for passing the compressed upload size does not
    // hold, and it was wrong in the commit that wrote it: compressed bytes
    // bound the UNCOMPRESSED TOTAL, while the plan ceiling is enforced on
    // ANALYSED bytes — `snapshot.totalBytes`, after normalisation drops
    // node_modules, build output and vendored files. A valid 54 MB archive
    // whose entries are all inside node_modules normalises to a few dozen
    // bytes, and this refused it as "about 54 MB" while the same content as a
    // local directory was accepted.
    //
    // The ceiling is enforced in the orchestrator against the real figure. The
    // upload itself stays bounded by MAX_ARCHIVE_BYTES above, which is a
    // request-size guard and not a plan limit — the two must not be merged.
  });

  // A project the organisation already has does not count against the project
  // limit — only a new one does.
  //
  // Keyed on `projects.id`, the column persistence itself dedupes on, and
  // derived through the same `projectIdFor` the runner uses. Keying on the slug
  // of the optional `name` field was wrong twice over: without a name it looked
  // up the literal slug "project" while persistence used the directory,
  // repository or archive name, and the stored slug is truncated to 24
  // characters where the id is not. Both made the lookup miss, so re-scanning
  // an existing project was refused with 402 "upgrade" on the Free plan.
  // ...and on whether it HOLDS A SLOT, not on whether a row exists. A project
  // whose only scans failed is not counted by `projectCount`, so exempting it
  // from the limit let a one-project plan analyse any number of projects: fail
  // a scan cheaply, come back next month, and the retry is waved through. Both
  // questions now share one predicate in `entitlements.ts` so they cannot drift
  // apart again.
  const reusesSlot = holdsProjectSlot(db(), organizationId, projectIdFor(organizationId, input));
  const blocked = !scanLimit.allowed
    ? scanLimit
    : (!reusesSlot && !projectLimit.allowed ? projectLimit : undefined);

  if (blocked) {
    // 402 rather than 403: this is a billing boundary, not a permission error,
    // and the client shows the remedy rather than a dead end.
    return Response.json(
      { error: blocked.reason, remedy: blocked.remedy, limit: blocked.limit, current: blocked.current },
      { status: 402, headers: { 'cache-control': 'no-store' } },
    );
  }

  try {
    // ScanRequestInvalid carries the real reason: a missing directory, an
    // unparseable repository ref, or an archive rejected by the ingest limits
    // (with its rejection code). It is shown to the user verbatim.
    const job = startScan(input, organizationId);
    return Response.json({ jobId: job.jobId }, { status: 202, headers: { 'cache-control': 'no-store' } });
  } catch (e) {
    if (e instanceof ScanRequestInvalid) return fail(e.message, 400);
    return fail(e instanceof Error ? e.message : 'the scan could not be started', 500);
  }
}
