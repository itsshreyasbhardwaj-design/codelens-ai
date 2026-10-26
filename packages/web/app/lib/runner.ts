import 'server-only';
import { randomUUID } from 'node:crypto';
import { existsSync, statSync } from 'node:fs';
import { resolve } from 'node:path';
import type { StageResult } from '@codelens/core';
import { runScan, type ScanOutcome, type SourceSpec } from '@codelens/engine/pipeline/orchestrator.ts';
import { saveScan } from '@codelens/engine/pipeline/persist.ts';
import { ALL_ANALYZERS } from '@codelens/engine/analyzers/all.ts';
import { loadAiConfig } from '@codelens/engine/ai/provider.ts';
import { parseRepoRef } from '@codelens/engine/ingest/github.ts';
import { readZip } from '@codelens/engine/ingest/zip.ts';
import { IngestRejected } from '@codelens/engine/ingest/limits.ts';
import { reserve, settle } from '@codelens/engine/billing/credits.ts';
import { canUseAi, creditsForUsage, estimateScanCredits } from '@codelens/engine/billing/entitlements.ts';
import { db, LOCAL_ORG } from './store.ts';

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
 * Validate the request and resolve it to a source. Validation happens here, in
 * the request, so a bad input is rejected immediately rather than failing inside
 * a background job the user has to wait for.
 */
function resolveSource(input: ScanInput): { source: SourceSpec; projectName: string } {
  if (input.kind === 'local') {
    const path = resolve(input.path.replace(/^~/, process.env.HOME ?? '~'));
    if (!existsSync(path)) {
      throw new ScanRequestInvalid(`no such directory: ${input.path}`);
    }
    if (!statSync(path).isDirectory()) {
      throw new ScanRequestInvalid(`${input.path} is a file, not a directory`);
    }
    return {
      source: { kind: 'local', path },
      projectName: input.name ?? path.split('/').filter(Boolean).pop() ?? 'project',
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
      projectName: input.name ?? `${ref.owner}/${ref.repo}`,
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
    projectName: input.name ?? input.filename.replace(/\.zip$/i, ''),
  };
}

export function startScan(input: ScanInput, organizationId: string = LOCAL_ORG): JobProgress {
  const { source, projectName } = resolveSource(input);
  const projectId = slugify(projectName);
  const jobId = randomUUID();

  const job: JobProgress = {
    jobId, organizationId, projectId, projectName,
    status: 'queued',
    stages: [],
    startedAt: new Date().toISOString(),
  };
  jobs.set(jobId, job);
  prune();

  // Detached: the request returns immediately with the job id.
  void (async () => {
    try {
      job.status = 'running';
      const outcome: ScanOutcome = await runScan({
        projectId,
        projectName,
        source,
        analyzers: ALL_ANALYZERS,
        aiConfig: loadAiConfig(),
        aiCredits: {
          estimate: (files) => estimateScanCredits({ files, aiEnabled: true }),
          reserve: (amount, scanId) => {
            const check = canUseAi(db(), organizationId, amount);
            if (!check.allowed) return { ok: false, reason: check.reason ?? 'insufficient credits' };
            try {
              // Keyed on the scan id so a retried scan cannot hold twice.
              const held = reserve(db(), organizationId, amount, {
                scanId, idempotencyKey: `scan-ai:${scanId}`,
              });
              return { ok: true, reservationId: held.id };
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
        saveScan(db(), outcome, { organizationId, projectId, projectName });
      }
    } catch (e) {
      job.status = 'failed';
      job.error = e instanceof Error ? e.message : String(e);
    } finally {
      job.finishedAt = new Date().toISOString();
      cancellations.delete(jobId);
    }
  })();

  return job;
}
