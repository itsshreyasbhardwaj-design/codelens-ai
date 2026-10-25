'use client';

import Link from 'next/link';
import { useEffect, useRef, useState, type FormEvent } from 'react';

/**
 * The scan form and live stage progress.
 *
 * This is a client component because it polls. It never imports the store or
 * the runner: everything it shows arrives as JSON from /api/scans. Progress is
 * the orchestrator's real per-stage status — there is no synthetic percentage
 * anywhere in this file, because the pipeline does not report one.
 */

type Mode = 'local' | 'github' | 'zip';

interface StageView {
  name: string;
  status: 'pending' | 'running' | 'completed' | 'failed' | 'skipped' | 'cancelled';
  durationMs?: number;
  message?: string;
  warnings?: string[];
}

interface JobView {
  jobId: string;
  projectId: string;
  projectName: string;
  status: 'queued' | 'running' | 'completed' | 'partial' | 'failed' | 'cancelled';
  stages: StageView[];
  startedAt: string;
  finishedAt?: string;
  scanId?: string;
  error?: string;
  summary?: { findings: number; critical: number; fixPacks: number; score: number | null };
}

/**
 * The twelve pipeline stages, in order, with display labels. Declared here
 * rather than imported so that no server-only module is pulled into the client
 * bundle; a stage the server reports but this list does not know is still
 * rendered, under its raw name.
 */
const STAGES: Array<{ name: string; label: string }> = [
  { name: 'ingestion_validation', label: 'Ingestion and validation' },
  { name: 'source_normalization', label: 'Source normalisation' },
  { name: 'technology_detection', label: 'Technology detection' },
  { name: 'code_indexing', label: 'Code indexing' },
  { name: 'deterministic_diagnostics', label: 'Deterministic diagnostics' },
  { name: 'architecture_reconstruction', label: 'Architecture reconstruction' },
  { name: 'dynamic_verification', label: 'Dynamic verification' },
  { name: 'ai_semantic_investigation', label: 'AI semantic investigation' },
  { name: 'finding_consolidation', label: 'Finding consolidation' },
  { name: 'risk_prioritization', label: 'Risk prioritisation' },
  { name: 'fix_pack_generation', label: 'Fix Pack generation' },
  { name: 'report_generation', label: 'Report generation' },
];

const STAGE_LOOK: Record<StageView['status'], { label: string; color: string; glyph: string }> = {
  pending: { label: 'Pending', color: 'var(--ink-3)', glyph: '·' },
  running: { label: 'Running', color: 'var(--accent)', glyph: '▸' },
  completed: { label: 'Completed', color: 'var(--good)', glyph: '✓' },
  failed: { label: 'Failed', color: 'var(--critical)', glyph: '✕' },
  skipped: { label: 'Skipped', color: 'var(--medium)', glyph: '–' },
  cancelled: { label: 'Cancelled', color: 'var(--ink-3)', glyph: '□' },
};

const JOB_STATUS_LABEL: Record<JobView['status'], string> = {
  queued: 'Queued',
  running: 'Running',
  completed: 'Completed',
  partial: 'Completed with gaps',
  failed: 'Failed',
  cancelled: 'Cancelled',
};

function duration(ms: number | undefined): string {
  if (ms === undefined) return '';
  return ms < 1000 ? `${ms}ms` : `${(ms / 1000).toFixed(1)}s`;
}

const inputStyle = {
  width: '100%',
  padding: '0.45rem 0.6rem',
  borderRadius: 6,
  border: '1px solid var(--border-strong)',
  background: 'var(--bg)',
  color: 'var(--ink)',
  font: 'inherit',
  fontSize: '0.88rem',
} as const;

const hintStyle = {
  margin: '0.25rem 0 0',
  fontSize: '0.8rem',
  color: 'var(--ink-3)',
  lineHeight: 1.5,
} as const;

function labelStyle() {
  return { display: 'block', fontSize: '0.84rem', fontWeight: 600, marginBottom: '0.3rem' } as const;
}

function buttonStyle(primary: boolean) {
  return {
    padding: '0.45rem 0.9rem',
    borderRadius: 6,
    fontSize: '0.88rem',
    fontWeight: 600,
    cursor: 'pointer',
    border: primary ? '1px solid var(--accent)' : '1px solid var(--border-strong)',
    background: primary ? 'var(--accent)' : 'var(--surface-2)',
    color: primary ? 'var(--accent-ink)' : 'var(--ink)',
  } as const;
}

export function NewScan() {
  const [mode, setMode] = useState<Mode>('local');
  const [path, setPath] = useState('');
  const [ref, setRef] = useState('');
  const [token, setToken] = useState('');
  const [zipFile, setZipFile] = useState<File | null>(null);
  const [name, setName] = useState('');

  const [submitting, setSubmitting] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);

  const [jobId, setJobId] = useState<string | null>(null);
  const [job, setJob] = useState<JobView | null>(null);
  const [pollError, setPollError] = useState<string | null>(null);
  const [cancelling, setCancelling] = useState(false);

  const fileInput = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (!jobId) return;
    let stopped = false;
    let timer: ReturnType<typeof setTimeout> | undefined;

    const tick = async () => {
      try {
        const res = await fetch(`/api/scans/${jobId}`, { cache: 'no-store' });
        if (res.status === 404) {
          if (!stopped) setPollError('This scan job is no longer known to the server.');
          return;
        }
        if (!res.ok) {
          if (!stopped) {
            setPollError(`Progress could not be read (HTTP ${res.status}). Retrying.`);
            timer = setTimeout(tick, 2000);
          }
          return;
        }
        const next = (await res.json()) as JobView;
        if (stopped) return;
        setJob(next);
        setPollError(null);
        if (!next.finishedAt) timer = setTimeout(tick, 1000);
      } catch (e) {
        if (stopped) return;
        setPollError(`${e instanceof Error ? e.message : 'Progress could not be read'}. Retrying.`);
        timer = setTimeout(tick, 2000);
      }
    };

    void tick();
    return () => {
      stopped = true;
      if (timer) clearTimeout(timer);
    };
  }, [jobId]);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setFormError(null);

    if (mode === 'zip' && !zipFile) {
      setFormError('Choose a .zip archive to upload.');
      return;
    }

    setSubmitting(true);
    try {
      let res: Response;
      if (mode === 'zip' && zipFile) {
        const body = new FormData();
        body.append('file', zipFile);
        if (name.trim()) body.append('name', name.trim());
        res = await fetch('/api/scans', { method: 'POST', body });
      } else {
        const body =
          mode === 'local'
            ? { kind: 'local', path: path.trim(), name: name.trim() || undefined }
            : { kind: 'github', ref: ref.trim(), token: token.trim() || undefined, name: name.trim() || undefined };
        res = await fetch('/api/scans', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify(body),
        });
      }

      const payload = (await res.json().catch(() => null)) as { jobId?: string; error?: string } | null;
      if (!res.ok || !payload?.jobId) {
        setFormError(payload?.error ?? `The scan could not be started (HTTP ${res.status}).`);
        return;
      }

      // The token has been handed to the scan; drop it from component state.
      setToken('');
      setJob(null);
      setPollError(null);
      setJobId(payload.jobId);
    } catch (e) {
      setFormError(e instanceof Error ? e.message : 'The scan could not be started.');
    } finally {
      setSubmitting(false);
    }
  }

  async function cancel() {
    if (!jobId) return;
    setCancelling(true);
    try {
      const res = await fetch(`/api/scans/${jobId}`, { method: 'DELETE' });
      if (!res.ok) {
        const payload = (await res.json().catch(() => null)) as { error?: string } | null;
        setPollError(payload?.error ?? `Cancellation was refused (HTTP ${res.status}).`);
      }
    } catch (e) {
      setPollError(e instanceof Error ? e.message : 'Cancellation could not be requested.');
    } finally {
      setCancelling(false);
    }
  }

  function reset() {
    setJobId(null);
    setJob(null);
    setPollError(null);
    setZipFile(null);
    if (fileInput.current) fileInput.current.value = '';
  }

  const byName = new Map(job?.stages.map((s) => [s.name, s]) ?? []);
  const known = new Set(STAGES.map((s) => s.name));
  const rows: Array<{ label: string; stage: StageView }> = STAGES.map((s) => ({
    label: s.label,
    stage: byName.get(s.name) ?? { name: s.name, status: 'pending', warnings: [] },
  }));
  for (const s of job?.stages ?? []) {
    if (!known.has(s.name)) rows.push({ label: s.name, stage: s });
  }
  const completed = rows.filter((r) => r.stage.status === 'completed').length;
  const settled = rows.filter((r) => r.stage.status !== 'pending' && r.stage.status !== 'running').length;

  if (jobId) {
    return (
      <div>
        <div
          style={{
            display: 'flex', flexWrap: 'wrap', alignItems: 'baseline',
            gap: '0.5rem 0.75rem', marginBottom: '0.85rem',
          }}
        >
          <h3 style={{ margin: 0, fontSize: '0.98rem', fontWeight: 650 }}>
            {job?.projectName ?? 'Scan'}
          </h3>
          <span style={{ fontSize: '0.84rem', color: 'var(--ink-2)' }}>
            {job ? JOB_STATUS_LABEL[job.status] : 'Starting'}
          </span>
          <div style={{ flex: 1 }} />
          {job && !job.finishedAt ? (
            <button type="button" onClick={cancel} disabled={cancelling} style={buttonStyle(false)}>
              {cancelling ? 'Cancelling…' : 'Cancel scan'}
            </button>
          ) : (
            <button type="button" onClick={reset} style={buttonStyle(false)}>
              Start another scan
            </button>
          )}
        </div>

        <p role="status" style={{ margin: '0 0 0.85rem', fontSize: '0.84rem', color: 'var(--ink-2)' }}>
          {settled} of {rows.length} stages have finished; {completed} completed.
          {job?.finishedAt ? '' : ' Stage status updates as the pipeline runs.'}
        </p>

        {pollError ? (
          <p
            aria-live="polite"
            style={{
              margin: '0 0 0.85rem', padding: '0.5rem 0.7rem', borderRadius: 6,
              background: 'var(--medium-soft)', border: '1px solid var(--border)',
              color: 'var(--ink-2)', fontSize: '0.84rem',
            }}
          >
            {pollError}
          </p>
        ) : null}

        <ol style={{ listStyle: 'none', margin: 0, padding: 0, display: 'grid', gap: '0.3rem' }}>
          {rows.map(({ label, stage }, i) => {
            const look = STAGE_LOOK[stage.status] ?? STAGE_LOOK.pending;
            const pending = stage.status === 'pending';
            return (
              <li
                key={stage.name}
                style={{
                  display: 'grid',
                  gridTemplateColumns: 'auto 1fr auto',
                  alignItems: 'start',
                  gap: '0.5rem',
                  padding: '0.4rem 0.55rem',
                  borderRadius: 6,
                  background: stage.status === 'running' ? 'var(--accent-soft)' : 'var(--surface-2)',
                  border: '1px solid var(--border)',
                  opacity: pending ? 0.7 : 1,
                }}
              >
                <span
                  aria-hidden="true"
                  style={{
                    color: look.color, fontFamily: 'var(--font-mono)', fontSize: '0.8rem',
                    width: '1.1rem', textAlign: 'center', paddingTop: '0.1rem',
                  }}
                >
                  {look.glyph}
                </span>

                <div style={{ minWidth: 0 }}>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.4rem', alignItems: 'baseline' }}>
                    <span style={{ fontSize: '0.86rem', fontWeight: 550 }}>
                      <span style={{ color: 'var(--ink-3)', fontFamily: 'var(--font-mono)', fontSize: '0.76rem' }}>
                        {String(i + 1).padStart(2, '0')}
                      </span>{' '}
                      {label}
                    </span>
                    <span style={{ fontSize: '0.76rem', fontWeight: 650, color: look.color }}>{look.label}</span>
                  </div>

                  {stage.status === 'running' ? (
                    <div className="skeleton" style={{ height: 4, marginTop: '0.4rem', maxWidth: '12rem' }} />
                  ) : null}

                  {stage.message ? (
                    <p style={{ ...hintStyle, color: 'var(--ink-2)' }}>
                      <span style={{ fontWeight: 600 }}>
                        {stage.status === 'skipped' ? 'Skipped because: ' : stage.status === 'failed' ? 'Failure: ' : ''}
                      </span>
                      {stage.message}
                    </p>
                  ) : null}

                  {stage.warnings && stage.warnings.length > 0 ? (
                    <ul style={{ ...hintStyle, paddingLeft: '1.1rem' }}>
                      {stage.warnings.map((w, wi) => (
                        <li key={wi}>Warning: {w}</li>
                      ))}
                    </ul>
                  ) : null}
                </div>

                <span
                  style={{
                    fontFamily: 'var(--font-mono)', fontSize: '0.76rem', color: 'var(--ink-3)',
                    whiteSpace: 'nowrap', paddingTop: '0.1rem',
                  }}
                >
                  {duration(stage.durationMs)}
                </span>
              </li>
            );
          })}
        </ol>

        {job?.error ? (
          <p
            style={{
              marginTop: '0.85rem', padding: '0.6rem 0.8rem', borderRadius: 6,
              background: 'var(--critical-soft)', border: '1px solid var(--border)',
              borderLeft: '3px solid var(--critical)', color: 'var(--ink-2)', fontSize: '0.85rem',
            }}
          >
            {job.error}
          </p>
        ) : null}

        {job?.finishedAt && (job.status === 'completed' || job.status === 'partial') ? (
          <div
            style={{
              marginTop: '0.9rem', padding: '0.8rem 0.9rem', borderRadius: 8,
              background: 'var(--surface-2)', border: '1px solid var(--border)',
            }}
          >
            <p style={{ margin: '0 0 0.5rem', fontSize: '0.86rem' }}>
              {job.summary
                ? `${job.summary.findings} findings, ${job.summary.critical} of them critical, and ${job.summary.fixPacks} Fix Packs. Overall score: ${job.summary.score === null ? 'insufficient evidence' : job.summary.score}.`
                : 'The scan finished. No summary was returned.'}
            </p>
            <Link href={`/projects/${encodeURIComponent(job.projectId)}`} style={{ fontSize: '0.88rem', fontWeight: 600 }}>
              Open {job.projectName}
            </Link>
          </div>
        ) : null}
      </div>
    );
  }

  return (
    <form onSubmit={submit} style={{ display: 'grid', gap: '1rem' }}>
      <fieldset style={{ border: 0, margin: 0, padding: 0 }}>
        <legend style={{ ...labelStyle(), padding: 0 }}>Where is the code?</legend>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.4rem 1rem' }}>
          {(
            [
              ['local', 'Local directory'],
              ['github', 'GitHub repository'],
              ['zip', 'ZIP upload'],
            ] as Array<[Mode, string]>
          ).map(([value, label]) => (
            <label key={value} style={{ display: 'flex', alignItems: 'center', gap: '0.35rem', fontSize: '0.88rem' }}>
              <input
                type="radio"
                name="scan-mode"
                value={value}
                checked={mode === value}
                onChange={() => setMode(value)}
              />
              {label}
            </label>
          ))}
        </div>
      </fieldset>

      {mode === 'local' ? (
        <div>
          <label htmlFor="scan-path" style={labelStyle()}>Directory path</label>
          <input
            id="scan-path"
            name="path"
            type="text"
            required
            value={path}
            onChange={(e) => setPath(e.target.value)}
            placeholder="./fixtures/vulnerable-shop"
            aria-describedby="scan-path-hint"
            spellCheck={false}
            autoComplete="off"
            style={inputStyle}
          />
          <p id="scan-path-hint" style={hintStyle}>
            A directory on this machine, absolute or relative to where the server was started. A leading{' '}
            <code style={{ fontFamily: 'var(--font-mono)' }}>~</code> is expanded.
          </p>
        </div>
      ) : null}

      {mode === 'github' ? (
        <>
          <div>
            <label htmlFor="scan-ref" style={labelStyle()}>Repository</label>
            <input
              id="scan-ref"
              name="ref"
              type="text"
              required
              value={ref}
              onChange={(e) => setRef(e.target.value)}
              placeholder="owner/repo"
              aria-describedby="scan-ref-hint"
              spellCheck={false}
              autoComplete="off"
              style={inputStyle}
            />
            <p id="scan-ref-hint" style={hintStyle}>
              <code style={{ fontFamily: 'var(--font-mono)' }}>owner/repo</code>, or{' '}
              <code style={{ fontFamily: 'var(--font-mono)' }}>owner/repo@branch-or-tag-or-sha</code> to pin a ref. A
              github.com repository URL also works. Only github.com is accepted.
            </p>
          </div>
          <div>
            <label htmlFor="scan-token" style={labelStyle()}>
              Access token <span style={{ fontWeight: 400, color: 'var(--ink-3)' }}>(optional)</span>
            </label>
            <input
              id="scan-token"
              name="token"
              type="password"
              value={token}
              onChange={(e) => setToken(e.target.value)}
              aria-describedby="scan-token-hint"
              autoComplete="off"
              spellCheck={false}
              style={inputStyle}
            />
            <p id="scan-token-hint" style={hintStyle}>
              Needed only for a private repository. Use a token with <strong>read-only scopes</strong>. It is used for
              this one scan and is <strong>never written to the database</strong>; it is cleared from this form as soon
              as the scan starts. Leave it empty to use a token from the server environment, if one is configured.
            </p>
          </div>
        </>
      ) : null}

      {mode === 'zip' ? (
        <div>
          <label htmlFor="scan-zip" style={labelStyle()}>Archive</label>
          <input
            id="scan-zip"
            name="file"
            type="file"
            accept=".zip"
            ref={fileInput}
            required
            onChange={(e) => setZipFile(e.target.files?.[0] ?? null)}
            aria-describedby="scan-zip-hint"
            style={{ ...inputStyle, padding: '0.35rem' }}
          />
          <p id="scan-zip-hint" style={hintStyle}>
            A <code style={{ fontFamily: 'var(--font-mono)' }}>.zip</code> of the source tree, up to 64 MiB. Archives
            are validated before analysis: path traversal, excessive compression ratios, and ZIP64 are refused with the
            specific reason.
          </p>
        </div>
      ) : null}

      <div>
        <label htmlFor="scan-name" style={labelStyle()}>
          Project name <span style={{ fontWeight: 400, color: 'var(--ink-3)' }}>(optional)</span>
        </label>
        <input
          id="scan-name"
          name="name"
          type="text"
          value={name}
          onChange={(e) => setName(e.target.value)}
          aria-describedby="scan-name-hint"
          autoComplete="off"
          style={inputStyle}
        />
        <p id="scan-name-hint" style={hintStyle}>
          Defaults to the directory name, the repository name, or the archive filename.
        </p>
      </div>

      <div aria-live="polite">
        {formError ? (
          <p
            style={{
              margin: 0, padding: '0.6rem 0.8rem', borderRadius: 6,
              background: 'var(--critical-soft)', border: '1px solid var(--border)',
              borderLeft: '3px solid var(--critical)', color: 'var(--ink-2)', fontSize: '0.85rem',
            }}
          >
            {formError}
          </p>
        ) : null}
      </div>

      <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: '0.75rem' }}>
        <button type="submit" disabled={submitting} style={buttonStyle(true)}>
          {submitting ? 'Starting…' : 'Start scan'}
        </button>
        <span style={{ fontSize: '0.8rem', color: 'var(--ink-3)' }}>
          Dynamic verification and the AI layer are disabled unless the server is configured for them; the stage list
          will say so.
        </span>
      </div>
    </form>
  );
}
