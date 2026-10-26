import { getProject, latestScan, listScans, scanFixPacks } from '../../../../../lib/store.ts';
import { sessionOr401 } from '../../../../../lib/session.ts';

/**
 * Fix Pack markdown download.
 *
 * Returns exactly the prompt the engine generated and stored for the requested
 * agent format. Nothing is composed here: a prompt that differed between the
 * screen and the download would make the pack untraceable to its scan.
 *
 * The Fix Studio also reads this route to populate its prompt preview, which is
 * why the body is the plain markdown and not a JSON envelope.
 */

const FORMATS = ['claude_code', 'codex', 'generic'] as const;
type AgentFormat = (typeof FORMATS)[number];
const DEFAULT_FORMAT: AgentFormat = 'claude_code';

function isFormat(value: string): value is AgentFormat {
  return (FORMATS as readonly string[]).includes(value);
}

function text(body: string, status: number): Response {
  return new Response(body, {
    status,
    headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' },
  });
}

/**
 * Restrict the filename to characters that cannot terminate or extend the
 * Content-Disposition header, rather than trusting a path segment from the URL.
 */
function safeSegment(value: string): string {
  const cleaned = value.replace(/[^A-Za-z0-9._-]+/g, '-').replace(/^[-.]+|[-.]+$/g, '').slice(0, 80);
  return cleaned.length > 0 ? cleaned : 'fix-pack';
}

export async function GET(
  request: Request,
  { params }: { params: Promise<{ projectId: string; packKey: string }> },
): Promise<Response> {
  const { projectId, packKey } = await params;
  const search = new URL(request.url).searchParams;

  // Validate the format before touching the database: an unknown format is a
  // bad request, not a missing pack, and the two must not be conflated.
  const requested = search.get('format');
  if (requested !== null && !isFormat(requested)) {
    return text(
      `Unknown agent format '${requested}'. Supported formats: ${FORMATS.join(', ')}.`,
      400,
    );
  }
  const format: AgentFormat = requested === null ? DEFAULT_FORMAT : requested;

  const session = await sessionOr401();
  if (!session) return text('Authentication required.', 401);
  const { organizationId } = session;

  // getProject is organisation-scoped, so another tenant's project is reported
  // as absent rather than as forbidden: existence is not disclosed.
  if (!getProject(organizationId, projectId)) {
    return text(`No project '${projectId}'.`, 404);
  }

  const requestedScan = search.get('scan');
  let scanId: string | undefined;
  try {
    if (requestedScan) {
      scanId = listScans(organizationId, projectId).find((s) => s.id === requestedScan)?.id;
      if (!scanId) return text(`Scan '${requestedScan}' is not part of project '${projectId}'.`, 404);
    } else {
      scanId = latestScan(organizationId, projectId)?.id;
      if (!scanId) return text(`Project '${projectId}' has no scans.`, 404);
    }
  } catch {
    return text(`No project '${projectId}'.`, 404);
  }

  const pack = scanFixPacks(scanId).find((p) => p.key === packKey);
  if (!pack) {
    return text(`No Fix Pack '${packKey}' in scan '${scanId}'.`, 404);
  }

  const markdown = pack.prompts[format];
  if (!markdown) {
    const available = Object.keys(pack.prompts);
    return text(
      available.length > 0
        ? `Fix Pack '${packKey}' has no '${format}' prompt. Stored formats: ${available.join(', ')}.`
        : `Fix Pack '${packKey}' has no stored prompt.`,
      404,
    );
  }

  const filename = `${safeSegment(projectId)}-${String(pack.ordinal).padStart(2, '0')}-${safeSegment(pack.key)}-${safeSegment(format)}.md`;

  return new Response(markdown, {
    status: 200,
    headers: {
      'Content-Type': 'text/markdown; charset=utf-8',
      'Content-Disposition': `attachment; filename="${filename}"`,
      'Cache-Control': 'no-store',
    },
  });
}
