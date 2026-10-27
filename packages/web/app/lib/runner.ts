import 'server-only';
import { randomUUID } from 'node:crypto';
import { existsSync, statSync } from 'node:fs';
import { resolve } from 'node:path';
import type { StageResult } from '@codelens/core';
import { runScan, type ScanOutcome, type SourceSpec } from '@codelens/engine/pipeline/orchestrator.ts';
import { beginScan, failScan, saveScan } from '@codelens/engine/pipeline/persist.ts';
import { ALL_ANALYZERS } from '@codelens/engine/analyzers/all.ts';
import { loadAiConfig } from '@codelens/engine/ai/provider.ts';
import { parseRepoRef } from '@codelens/engine/ingest/github.ts';
import { readZip } from '@codelens/engine/ingest/zip.ts';
import { IngestRejected } from '@codelens/engine/ingest/limits.ts';
import { reserve, settle } from '@codelens/engine/billing/credits.ts';
import { planForOrganization } from '@codelens/engine/billing/plans.ts';
import {
  canUseAi, creditsForUsage, estimateScanCredits, tokensForCredits,
} from '@codelens/engine/billing/entitlements.ts';
import { db, LOCAL_ORG, workspaceRoot } from './store.ts';

/**
 * Background scan execution.
 *
 * A repository scan takes far longer than a request should, so the brief's rule
 * applies: never run one inside a request handler. A job is registered here,
 * started detached, and polled by the client. Progress is live stage status from
 * the orchestrator, not a fake progress bar.
 *
 * State lives in a module-level map, which is correct for the single-process
 * local deployment this release targets. Running more than one web process would
 * need the job table instead; the orchestrator already persists stages, so that
 * is a change of reader, not of design.
 */

export interface JobProgress {
  jobId: string;
  /**
   * The organisation the scan was started by.
   *
   * Authentication is not authorisation: the middleware guarantees a caller has
   * *a* session, not that this job is theirs. Without this field the job routes
   * are an object-level authorisation hole — a guessed id would expose another
   * tenant's project name and let them cancel the scan.
   */
  organizationId: string;
  projectId: string;
  projectName: string;
  status: 'queued' | 'running' | 'completed' | 'partial' | 'failed' | 'cancelled';
  stages: StageResult[];
  startedAt: string;
  finishedAt?: string;
  scanId?: string;
  error?: string;
  /** Short summary available once the scan finishes. */
  summary?: { findings: number; critical: number; fixPacks: number; score: number | null };
}

const jobs = new Map<string, JobProgress>();
const cancellations = new Set<string>();

/** Keep the map from growing without bound in a long-running process. */
const MAX_JOBS = 50;

function prune(): void {
  if (jobs.size <= MAX_JOBS) return;
  const finished = [...jobs.values()]
    .filter((j) => j.finishedAt)
    .sort((a, b) => (a.finishedAt ?? '').localeCompare(b.finishedAt ?? ''));
  for (const j of finished.slice(0, jobs.size - MAX_JOBS)) jobs.delete(j.jobId);
}

/**
 * A job, only if it belongs to this organisation.
 *
 * A job owned by someone else is reported as absent, exactly as a missing one
 * is, so existence does not leak across tenants — the same rule the store
 * applies to projects.
 */
export function getJob(jobId: string, organizationId: string): JobProgress | undefined {
  const job = jobs.get(jobId);
  if (!job || job.organizationId !== organizationId) return undefined;
  return job;
}

export function listJobs(organizationId: string): JobProgress[] {
  return [...jobs.values()]
    .filter((j) => j.organizationId === organizationId)
    .sort((a, b) => b.startedAt.localeCompare(a.startedAt));
}

export function cancelJob(jobId: string, organizationId: string): boolean {
  const job = getJob(jobId, organizationId);
  if (!job || job.finishedAt) return false;
  cancellations.add(jobId);
  return true;
}

export function slugify(s: string): string {
  return s.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 40) || 'project';
}

export class ScanRequestInvalid extends Error {
  constructor(message: string) { super(message); this.name = 'ScanRequestInvalid'; }
}

export type ScanInput =
  | { kind: 'local'; path: string; name?: string }
  | { kind: 'github'; ref: string; token?: string; name?: string }
  | { kind: 'zip'; buffer: Buffer; filename: string; name?: string };

/**
 * Resolve a user-supplied local directory path.
 *
 * Relative paths resolve against the workspace root, not `process.cwd()`. The
 * server starts in packages/web, while the CLI and every example in the README
 * run from the repository root — resolving against cwd made the one path the
 * dashboard itself recommends, `./fixtures/vulnerable-shop`, fail with "no such
 * directory" on a first run. An absolute or `~`-expanded path is returned
 * unchanged by `resolve`.
 *
 * Both callers go through this. `projectNameFor` derives the project identity
 * from the resolved path and `resolveSource` reads it, and the two have to
 * agree — see the note below on what a mismatch did.
 */
function localPath(raw: string): string {
  return resolve(workspaceRoot(), raw.replace(/^~/, process.env.HOME ?? '~'));
}

/**
 * The project name this input will be persisted under.
 *
 * Exported because the entitlement check in /api/scans has to resolve the same
 * identity this does. It used to slugify the optional `name` field alone, so a
 * scan without a name was checked against the slug "project" while persistence
 * used the directory, repository or archive name — the lookup always missed,
 * and a Free account was told to upgrade to re-scan a project it already had.
 *
 * This does no validation and never throws on a path that does not exist, so
 * it is safe to call before `resolveSource`.
 */
export function projectNameFor(input: ScanInput): string {
  if (input.name) return input.name;
  if (input.kind === 'local') {
    const path = localPath(input.path);
    return path.split('/').filter(Boolean).pop() ?? 'project';
  }
  if (input.kind === 'github') {
    // An unparseable ref is rejected by resolveSource before anything persists.
    try {
      const ref = parseRepoRef(input.ref);
      return `${ref.owner}/${ref.repo}`;
    } catch {
      return input.ref;
    }
  }
  return input.filename.replace(/\.zip$/i, '');
}

/** The tenant-scoped project id. The slug alone is a global name. */
export function projectIdFor(organizationId: string, input: ScanInput): string {
  return `${organizationId}:${slugify(projectNameFor(input))}`;
}

/**
 * Validate the request and resolve it to a source. Validation happens here, in
 * the request, so a bad input is rejected immediately rather than failing inside
 * a background job the user has to wait for.
 */
function resolveSource(input: ScanInput): { source: SourceSpec; projectName: string } {
  if (input.kind === 'local') {
    const path = localPath(input.path);
    if (!existsSync(path)) {
      throw new ScanRequestInvalid(`no such directory: ${input.path}`);
    }
    if (!statSync(path).isDirectory()) {
      throw new ScanRequestInvalid(`${input.path} is a file, not a directory`);
    }
    return {
      source: { kind: 'local', path },
      projectName: projectNameFor(input),
    };
  }

  if (input.kind === 'github') {
    // parseRepoRef rejects anything that is not a github.com repository, which
    // is also the SSRF guard: an arbitrary URL is never fetched.
    let ref;
    try {
      ref = parseRepoRef(input.ref);
    } catch (e) {
      throw new ScanRequestInvalid(e instanceof IngestRejected ? e.message : `invalid repository: ${input.ref}`);
    }
    return {
      source: { kind: 'github', ref: input.ref, token: input.token ?? process.env.GITHUB_TOKEN },
      projectName: projectNameFor(input),
    };
  }

  // A ZIP is validated eagerly: a traversal entry or a decompression bomb is
  // rejected now, with a specific reason, rather than surfacing later.
  try {
    readZip(input.buffer);
  } catch (e) {
    throw new ScanRequestInvalid(
      e instanceof IngestRejected
        ? `archive rejected (${e.code}): ${e.message}`
        : `archive could not be read: ${(e as Error).message}`,
    );
  }
  return {
    source: { kind: 'zip', buffer: input.buffer, filename: input.filename },
    projectName: projectNameFor(input),
  };
}

export function startScan(input: ScanInput, organizationId: string = LOCAL_ORG): JobProgress {
  const { source, projectName } = resolveSource(input);
  // Tenant-scoped. `projects.id` is the primary key and the slug alone is a
  // GLOBAL name: two organisations scanning a directory called "api" shared one
  // project row, and the second one's entire scan — snapshot, findings, fix
  // packs — was written under the first one's project, readable by them and not
  // by its owner. The slug stays human-facing and is unique per organisation.
  const slug = slugify(projectName);
  const projectId = `${organizationId}:${slug}`;
  const jobId = randomUUID();

  // The scan id is derived from a key we choose, rather than minted inside the
  // orchestrator, so the scan_jobs row can be registered BEFORE the pipeline
  // starts. The credit ledger's scan_id is a foreign key to that row: without a
  // referent, every AI credit reservation failed with "FOREIGN KEY constraint
  // failed" and the AI layer never ran. Must match the orchestrator's
  // `scan_${idempotencyKey}`.
  const idempotencyKey = randomUUID();
  const scanId = `scan_${idempotencyKey}`;

  const job: JobProgress = {
    jobId, organizationId, projectId, projectName,
    status: 'queued',
    stages: [],
    startedAt: new Date().toISOString(),
  };
  jobs.set(jobId, job);
  prune();

  // Registered before the job is detached, so the row exists for the whole of
  // the scan and a failure to register surfaces as a failed job rather than as
  // a silent loss of the AI layer.
  try {
    beginScan(db(), scanId, { organizationId, projectId, projectName, slug });
  } catch (e) {
    job.status = 'failed';
    job.error = `could not register the scan: ${e instanceof Error ? e.message : String(e)}`;
    job.finishedAt = new Date().toISOString();
    return job;
  }

  // Detached: the request returns immediately with the job id.
  void (async () => {
    try {
      job.status = 'running';
      // The plan ceiling, enforced against analysed bytes once ingestion knows
      // the real figure. Read here rather than in the route because the route
      // only has the compressed upload size to go on.
      const plan = planForOrganization(db(), organizationId);
      const outcome: ScanOutcome = await runScan({
        projectId,
        projectName,
        source,
        idempotencyKey,
        maxSourceBytes: plan.maxRepoMb === null ? null : plan.maxRepoMb * 1_000_000,
        analyzers: ALL_ANALYZERS,
        aiConfig: loadAiConfig(),
        aiCredits: {
          estimate: ({ files, targets }) => estimateScanCredits({ files, targets, aiEnabled: true }),
          reserve: (amount, scanId) => {
            const check = canUseAi(db(), organizationId, amount);
            if (!check.allowed) return { ok: false, reason: check.reason ?? 'insufficient credits' };
            try {
              // Keyed on the scan id so a retried scan cannot hold twice.
              const held = reserve(db(), organizationId, amount, {
                scanId, idempotencyKey: `scan-ai:${scanId}`,
              });
              // What these credits buy, so the stage cannot outspend them.
              return { ok: true, reservationId: held.id, tokenCeiling: tokensForCredits(amount) };
            } catch (e) {
              return { ok: false, reason: e instanceof Error ? e.message : String(e) };
            }
          },
          settle: (reservationId, tokensIn, tokensOut) => {
            settle(db(), reservationId, creditsForUsage(tokensIn, tokensOut));
          },
        },
        isCancelled: () => cancellations.has(jobId),
        onStageChange: (stage) => {
          const i = job.stages.findIndex((s) => s.name === stage.name);
          if (i === -1) job.stages.push({ ...stage });
          else job.stages[i] = { ...stage };
        },
      });

      job.stages = outcome.stages.map((s) => ({ ...s }));
      job.scanId = outcome.scanId;
      job.status = outcome.status === 'running' ? 'completed' : outcome.status;
      job.error = outcome.errorMessage;
      job.summary = {
        findings: outcome.findings.length,
        critical: outcome.findings.filter((f) => f.severity === 'critical').length,
        fixPacks: outcome.fixPacks.length,
        score: outcome.scorecard?.overall ?? null,
      };

      if (outcome.status !== 'failed' && outcome.status !== 'cancelled') {
        saveScan(db(), outcome, { organizationId, projectId, projectName, slug });
      } else {
        // `beginScan` registered this row before the pipeline ran, so a failed
        // or cancelled scan has to be closed out explicitly — `saveScan` has
        // nothing to save and is not called. Left alone the row stays `running`
        // with no reason, and becomes the project's latest scan on the
        // dashboard until something else succeeds.
        failScan(db(), scanId, outcome.status === 'cancelled' ? 'cancelled' : 'failed',
          outcome.errorMessage);
      }
    } catch (e) {
      job.status = 'failed';
      job.error = e instanceof Error ? e.message : String(e);
      // Same reasoning, for a throw rather than a reported failure. `failScan`
      // is a no-op once `saveScan` has finalised the row, so this cannot
      // clobber a scan that actually completed.
      try {
        failScan(db(), scanId, 'failed', job.error);
      } catch {
        // The database is the thing that failed; the in-memory job still shows why.
      }
    } finally {
      job.finishedAt = new Date().toISOString();
      cancellations.delete(jobId);
    }
  })();

  return job;
}
