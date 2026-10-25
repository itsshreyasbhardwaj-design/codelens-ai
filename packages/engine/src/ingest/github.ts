import { IngestRejected } from './limits.ts';
import { readTarGz, type TarReadResult } from './tar.ts';
import { DEFAULT_LIMITS, type IngestLimits } from './limits.ts';

/**
 * GitHub repository ingestion.
 *
 * Least privilege: a token is optional and only ever used for reads. CodeLens
 * never requests or uses write scopes, and never pushes.
 *
 * SSRF posture: only the two GitHub hosts below are contacted. A user-supplied
 * "repository URL" is parsed into owner/repo and discarded — an arbitrary URL is
 * never fetched, so a redirect to an internal address cannot be followed.
 */

const ALLOWED_HOSTS = new Set(['api.github.com', 'codeload.github.com']);

export interface RepoRef { owner: string; repo: string; ref?: string }

export interface RepoMetadata {
  fullName: string;
  defaultBranch: string;
  isPrivate: boolean;
  description?: string;
  language?: string;
  pushedAt?: string;
  sizeKb?: number;
  htmlUrl: string;
}

const OWNER_RE = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/;
const REPO_RE = /^[A-Za-z0-9._-]{1,100}$/;

/** Parse `owner/repo`, a GitHub URL, or an `owner/repo@ref` spec. */
export function parseRepoRef(input: string): RepoRef {
  let s = input.trim();
  if (s.startsWith('git@github.com:')) s = s.slice('git@github.com:'.length);
  if (/^https?:\/\//.test(s)) {
    let url: URL;
    try {
      url = new URL(s);
    } catch {
      throw new IngestRejected('bad_repo_url', `not a valid URL: ${input}`);
    }
    if (url.hostname !== 'github.com' && url.hostname !== 'www.github.com') {
      throw new IngestRejected('unsupported_provider',
        `only github.com repositories are supported for URL import, got ${url.hostname}`);
    }
    s = url.pathname.replace(/^\//, '');
  }
  s = s.replace(/\.git$/, '');

  let ref: string | undefined;
  const at = s.lastIndexOf('@');
  if (at > 0) { ref = s.slice(at + 1); s = s.slice(0, at); }

  const parts = s.split('/').filter(Boolean);
  // A tree/blob URL carries the ref in the path.
  if (parts.length >= 4 && (parts[2] === 'tree' || parts[2] === 'blob')) {
    ref = parts[3];
  }
  const [owner, repo] = parts;
  if (!owner || !repo || !OWNER_RE.test(owner) || !REPO_RE.test(repo)) {
    throw new IngestRejected('bad_repo_ref',
      `expected owner/repo or a github.com repository URL, got: ${input}`);
  }
  return ref ? { owner, repo, ref } : { owner, repo };
}

function headers(token?: string): Record<string, string> {
  const h: Record<string, string> = {
    accept: 'application/vnd.github+json',
    'user-agent': 'codelens-ai',
    'x-github-api-version': '2022-11-28',
  };
  if (token) h.authorization = `Bearer ${token}`;
  return h;
}

async function githubFetch(url: string, token?: string): Promise<Response> {
  const parsed = new URL(url);
  if (parsed.protocol !== 'https:' || !ALLOWED_HOSTS.has(parsed.hostname)) {
    throw new IngestRejected('blocked_host', `refusing to fetch non-GitHub host: ${parsed.hostname}`);
  }
  const res = await fetch(url, { headers: headers(token), redirect: 'follow' });
  if (res.status === 404) {
    throw new IngestRejected('repo_not_found',
      'repository not found, or the configured token cannot see it');
  }
  if (res.status === 401 || res.status === 403) {
    const remaining = res.headers.get('x-ratelimit-remaining');
    if (remaining === '0') {
      throw new IngestRejected('rate_limited',
        'GitHub API rate limit reached. Set GITHUB_TOKEN to raise the limit, or retry later.');
    }
    throw new IngestRejected('repo_forbidden',
      'GitHub denied access. The token may be missing, expired, or lacking read access to this repository.');
  }
  if (!res.ok) {
    throw new IngestRejected('github_error', `GitHub responded ${res.status} ${res.statusText}`);
  }
  return res;
}

export async function fetchRepoMetadata(ref: RepoRef, token?: string): Promise<RepoMetadata> {
  const res = await githubFetch(`https://api.github.com/repos/${ref.owner}/${ref.repo}`, token);
  const j = (await res.json()) as Record<string, unknown>;
  return {
    fullName: String(j.full_name ?? `${ref.owner}/${ref.repo}`),
    defaultBranch: String(j.default_branch ?? 'main'),
    isPrivate: Boolean(j.private),
    description: j.description ? String(j.description) : undefined,
    language: j.language ? String(j.language) : undefined,
    pushedAt: j.pushed_at ? String(j.pushed_at) : undefined,
    sizeKb: typeof j.size === 'number' ? j.size : undefined,
    htmlUrl: String(j.html_url ?? `https://github.com/${ref.owner}/${ref.repo}`),
  };
}

/** Resolve a ref (branch/tag/sha) to a commit sha, so a scan records exactly what it read. */
export async function resolveCommitSha(ref: RepoRef, token?: string): Promise<string> {
  const target = ref.ref ?? (await fetchRepoMetadata(ref, token)).defaultBranch;
  const res = await githubFetch(
    `https://api.github.com/repos/${ref.owner}/${ref.repo}/commits/${encodeURIComponent(target)}`,
    token,
  );
  const j = (await res.json()) as { sha?: string };
  if (!j.sha) throw new IngestRejected('ref_not_found', `could not resolve ref '${target}'`);
  return j.sha;
}

export async function downloadRepoTarball(
  ref: RepoRef, token?: string, limits: IngestLimits = DEFAULT_LIMITS,
): Promise<TarReadResult> {
  const target = ref.ref ?? 'HEAD';
  const res = await githubFetch(
    `https://api.github.com/repos/${ref.owner}/${ref.repo}/tarball/${encodeURIComponent(target)}`,
    token,
  );
  const declared = Number(res.headers.get('content-length') ?? '0');
  if (declared > limits.maxArchiveBytes) {
    throw new IngestRejected('archive_too_large',
      `repository archive is ${declared} bytes, limit is ${limits.maxArchiveBytes}`);
  }
  const buf = Buffer.from(await res.arrayBuffer());
  return readTarGz(buf, limits, true);
}
