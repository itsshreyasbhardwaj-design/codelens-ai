'use client';

import Link from 'next/link';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  Caveat,
  ConfidencePill,
  Mono,
  PriorityPill,
  SectionHeading,
  SeverityPill,
  StatusPill,
  Tag,
} from '../../../components/ui.tsx';
import { CATEGORY_LABEL, formatRelative, pluralize, SEVERITY_ORDER, severityStyle } from '../../../lib/format.ts';

/**
 * Fix Studio, client half.
 *
 * Responsible only for interaction: which pack is selected, which agent format
 * is shown, copying, exporting, and the verification checklist. Every value it
 * renders was read from the store on the server and passed down as plain data.
 *
 * Prompts are never assembled here. The engine generated one markdown document
 * per pack per agent format; this component displays the stored text and, for a
 * pack it has not seen yet, fetches it from the download route. Composing a
 * prompt in the browser would produce something that does not match the
 * download and cannot be traced back to the scan.
 */

// ------------------------------------------------------------------- types --

export interface StudioFinding {
  displayId: string;
  title: string;
  severity: string;
  confidence: string;
  status: string;
  priority?: string;
  effort: string;
  category: string;
  files: string[];
  affectedFeatures: string[];
  verificationSteps: string[];
}

export interface StudioPrerequisite {
  key: string;
  title?: string;
  ordinal?: number;
  appliedAt?: string;
  /** True when the declared prerequisite sits later in the roadmap than this pack. */
  outOfOrder: boolean;
}

export interface StudioPack {
  id: string;
  key: string;
  ordinal: number;
  title: string;
  family: string;
  objective: string;
  effort: string;
  appliedAt?: string;
  baselineCommit?: string;
  prerequisites: StudioPrerequisite[];
  /** Agent formats with a stored prompt, in display order. */
  formats: string[];
  findings: StudioFinding[];
  affectedFiles: string[];
  affectedFeatures: string[];
  severityMix: Array<{ severity: string; count: number }>;
  topPriority?: string;
  verificationSteps: string[];
  validation: {
    presentable: boolean;
    checksRun: string[];
    issues: Array<{ level: string; check: string; detail: string }>;
  };
}

export interface StudioProps {
  projectId: string;
  scanId: string;
  packs: StudioPack[];
  initialPackKey: string;
  initialFormat: string;
  /** Pre-loaded prompts, keyed `${packKey}::${format}`, for the first pack shown. */
  initialPrompts: Record<string, string>;
  /** Persists the "marked applied" note. Returns a result rather than throwing. */
  setApplied: (projectId: string, packId: string, applied: boolean) => Promise<{ ok: boolean; message?: string }>;
}

// ------------------------------------------------------------------ labels --

const FORMAT_LABEL: Record<string, string> = {
  claude_code: 'Claude Code',
  codex: 'Codex',
  generic: 'Generic agent',
};

const FORMAT_HINT: Record<string, string> = {
  claude_code: 'Written for Claude Code, with its working conventions and a working-notes section.',
  codex: 'Written for Codex, with its working conventions and a working-notes section.',
  generic: 'No agent-specific conventions. Use this for any other agent, or for a human engineer.',
};

const EFFORT_LABEL: Record<string, string> = {
  trivial: 'trivial effort',
  small: 'small effort',
  medium: 'medium effort',
  large: 'large effort',
};

/** Plain-language names for the engine's pre-flight checks. */
const CHECK_LABEL: Record<string, string> = {
  referenced_files_exist: 'Every referenced file exists in the analysed snapshot',
  findings_belong_to_scan: 'Every cited finding belongs to this scan',
  dependencies_valid: 'Prerequisites exist and do not form a cycle',
  evidence_verified: 'Each finding carries evidence re-checked against the snapshot',
  no_contradictions: 'No two instructions in the pack contradict each other',
  no_redundancy: 'No finding is included twice',
  acceptance_criteria_present: 'Acceptance criteria are present and cover the findings',
  no_destructive_operations: 'The instructions request no destructive operation',
  scope_reasonable: 'Scope fits one reviewable change',
  uncertainty_marked: 'Findings short of confirmed are marked as uncertain',
  baseline_recorded: 'The scan and its file-set baseline are recorded in the prompt',
  no_overclaiming: 'The prompt makes no security or completeness guarantee',
};

function familyLabel(family: string): string {
  if (CATEGORY_LABEL[family]) return CATEGORY_LABEL[family];
  const words = family.split(/[-_]/).filter(Boolean);
  if (words.length === 0) return family;
  return words.join(' ').replace(/^./, (c) => c.toUpperCase());
}

function effortLabel(effort: string): string {
  return EFFORT_LABEL[effort] ?? `${effort} effort`;
}

function checkLabel(check: string): string {
  return CHECK_LABEL[check] ?? check.replace(/_/g, ' ');
}

// ------------------------------------------------------------ prompt parts --

interface PromptSection {
  id: string;
  heading?: string;
  /** The `A`–`J` prefix when the heading carries one. */
  letter?: string;
  body: string;
}

/**
 * Split the prompt on its level-two headings so the sections can be labelled
 * and jumped to. The body is kept verbatim — what is on screen is what the
 * copy button and the download produce.
 */
function parsePrompt(markdown: string): PromptSection[] {
  const sections: PromptSection[] = [];
  let heading: string | undefined;
  let buffer: string[] = [];
  let index = 0;

  const flush = () => {
    const body = buffer.join('\n').replace(/^\n+|\n+$/g, '');
    if (heading === undefined && body.length === 0) return;
    const slug = (heading ?? 'start').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 40);
    sections.push({
      id: `fs-prompt-${index}-${slug || 'section'}`,
      heading,
      letter: heading ? /^([A-Z])\.\s/.exec(heading)?.[1] : undefined,
      body,
    });
    index += 1;
  };

  for (const line of markdown.split('\n')) {
    const match = /^##[ \t]+(.+)$/.exec(line);
    if (match) {
      flush();
      heading = match[1].trim();
      buffer = [];
    } else {
      buffer.push(line);
    }
  }
  flush();
  return sections;
}

// ------------------------------------------------------------------- chips --

function SeverityCount({ severity, count }: { severity: string; count: number }) {
  const { color, bg } = severityStyle(severity);
  return (
    <span
      aria-label={`${count} ${severity}`}
      style={{
        color,
        background: bg,
        border: `1px solid ${color}33`,
        borderRadius: 999,
        padding: '0.02rem 0.4rem',
        fontSize: '0.72rem',
        fontWeight: 650,
        whiteSpace: 'nowrap',
        fontVariantNumeric: 'tabular-nums',
      }}
    >
      <span aria-hidden="true">{count} {severity}</span>
    </span>
  );
}

function FieldList({ label, items, mono }: { label: string; items: string[]; mono?: boolean }) {
  return (
    <div>
      <h4 style={{ margin: '0 0 0.25rem', fontSize: '0.78rem', fontWeight: 650, color: 'var(--ink-3)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
        {label}
      </h4>
      {items.length === 0 ? (
        <p style={{ margin: 0, fontSize: '0.85rem', color: 'var(--ink-3)', fontStyle: 'italic' }}>not recorded</p>
      ) : (
        <ul style={{ margin: 0, paddingLeft: '1.1rem', display: 'grid', gap: '0.12rem' }}>
          {items.map((item) => (
            <li key={item} style={{ fontSize: '0.85rem', lineHeight: 1.5 }}>
              {mono ? <Mono>{item}</Mono> : item}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

// -------------------------------------------------------------------- copy --

type CopyTarget = 'pack' | 'all';

type CopyState =
  | { kind: 'idle' }
  | { kind: 'working'; target: CopyTarget; note: string }
  | { kind: 'copied'; target: CopyTarget; note: string }
  | { kind: 'manual'; target: CopyTarget; note: string; text: string }
  | { kind: 'failed'; target: CopyTarget; note: string };

const BUTTON: React.CSSProperties = {
  font: 'inherit',
  fontSize: '0.84rem',
  fontWeight: 550,
  padding: '0.35rem 0.7rem',
  borderRadius: 6,
  border: '1px solid var(--border-strong)',
  background: 'var(--surface-2)',
  color: 'var(--ink)',
  cursor: 'pointer',
};

const BUTTON_PRIMARY: React.CSSProperties = {
  ...BUTTON,
  background: 'var(--accent)',
  borderColor: 'var(--accent)',
  color: 'var(--accent-ink)',
  fontWeight: 650,
};

// -------------------------------------------------------------------- main --

export function Studio({
  projectId,
  scanId,
  packs,
  initialPackKey,
  initialFormat,
  initialPrompts,
  setApplied,
}: StudioProps) {
  const [selectedKey, setSelectedKey] = useState(initialPackKey);
  const [preferredFormat, setPreferredFormat] = useState(initialFormat);
  const [copy, setCopy] = useState<CopyState>({ kind: 'idle' });
  const [checked, setChecked] = useState<Record<string, boolean>>({});
  const [applyPending, setApplyPending] = useState(false);
  const [applyError, setApplyError] = useState<string | null>(null);

  const promptCache = useRef<Map<string, string>>(new Map(Object.entries(initialPrompts)));
  const promptPane = useRef<HTMLDivElement | null>(null);
  const manualArea = useRef<HTMLTextAreaElement | null>(null);

  const pack = useMemo(
    () => packs.find((p) => p.key === selectedKey) ?? packs[0],
    [packs, selectedKey],
  );

  // A pack may not have been generated in every format. Fall back to one it has
  // rather than showing a format switch that leads nowhere.
  const format = pack.formats.includes(preferredFormat) ? preferredFormat : pack.formats[0];

  const [prompt, setPrompt] = useState<
    { state: 'ready'; text: string } | { state: 'loading' } | { state: 'error'; message: string } | { state: 'none' }
  >(() => {
    const seeded = promptCache.current.get(`${initialPackKey}::${initialFormat}`);
    return seeded === undefined ? { state: 'loading' } : { state: 'ready', text: seeded };
  });

  const promptUrl = useCallback(
    (packKey: string, agentFormat: string) =>
      `/api/projects/${encodeURIComponent(projectId)}/fix-packs/${encodeURIComponent(packKey)}` +
      `?format=${encodeURIComponent(agentFormat)}&scan=${encodeURIComponent(scanId)}`,
    [projectId, scanId],
  );

  const loadPrompt = useCallback(
    async (packKey: string, agentFormat: string, signal?: AbortSignal): Promise<string> => {
      const cacheKey = `${packKey}::${agentFormat}`;
      const hit = promptCache.current.get(cacheKey);
      if (hit !== undefined) return hit;
      const response = await fetch(promptUrl(packKey, agentFormat), { signal });
      if (!response.ok) throw new Error(`the server returned ${response.status}`);
      const text = await response.text();
      promptCache.current.set(cacheKey, text);
      return text;
    },
    [promptUrl],
  );

  // Load the selected prompt. Nothing is generated here: the response body is
  // the markdown the engine stored for this pack and format.
  useEffect(() => {
    if (format === undefined) {
      setPrompt({ state: 'none' });
      return;
    }
    const cached = promptCache.current.get(`${pack.key}::${format}`);
    if (cached !== undefined) {
      setPrompt({ state: 'ready', text: cached });
      return;
    }
    const controller = new AbortController();
    setPrompt({ state: 'loading' });
    loadPrompt(pack.key, format, controller.signal)
      .then((text) => setPrompt({ state: 'ready', text }))
      .catch((error: unknown) => {
        if (controller.signal.aborted) return;
        setPrompt({ state: 'error', message: error instanceof Error ? error.message : 'the prompt could not be loaded' });
      });
    return () => controller.abort();
  }, [pack.key, format, loadPrompt]);

  // Reading position belongs to the document being read, not the one before it.
  useEffect(() => {
    if (promptPane.current) promptPane.current.scrollTop = 0;
  }, [pack.key, format]);

  // Keep the address bar in step with the selection so a pack can be linked to,
  // without a navigation that would discard the loaded prompt.
  useEffect(() => {
    if (format === undefined) return;
    try {
      const url = new URL(window.location.href);
      url.searchParams.set('pack', pack.key);
      url.searchParams.set('format', format);
      window.history.replaceState(window.history.state, '', url.toString());
    } catch {
      /* history is unavailable in some embedded contexts; selection still works */
    }
  }, [pack.key, format]);

  useEffect(() => {
    if (copy.kind !== 'copied') return;
    const timer = window.setTimeout(() => setCopy({ kind: 'idle' }), 4000);
    return () => window.clearTimeout(timer);
  }, [copy]);

  // When the clipboard is unavailable or refused, put the text somewhere the
  // user can copy it by hand, selected and ready.
  useEffect(() => {
    if (copy.kind !== 'manual') return;
    const area = manualArea.current;
    if (!area) return;
    area.focus();
    area.select();
  }, [copy]);

  const sections = useMemo(
    () => (prompt.state === 'ready' ? parsePrompt(prompt.text) : []),
    [prompt],
  );
  const jumpTargets = useMemo(() => sections.filter((s) => s.heading), [sections]);

  const appliedCount = packs.filter((p) => p.appliedAt).length;

  async function writeToClipboard(target: CopyTarget, note: string, text: string): Promise<void> {
    try {
      if (typeof navigator === 'undefined' || !navigator.clipboard?.writeText) {
        throw new Error('clipboard unavailable');
      }
      await navigator.clipboard.writeText(text);
      setCopy({ kind: 'copied', target, note });
    } catch {
      // Never report success for a write that did not happen.
      setCopy({ kind: 'manual', target, note, text });
    }
  }

  async function copySelectedPrompt(): Promise<void> {
    if (prompt.state !== 'ready' || format === undefined) return;
    await writeToClipboard('pack', `the ${FORMAT_LABEL[format] ?? format} prompt for pack ${pack.ordinal}`, prompt.text);
  }

  async function copyEveryPack(): Promise<void> {
    const note = `all ${packs.length} prompts`;
    setCopy({ kind: 'working', target: 'all', note });
    const parts: string[] = [];
    try {
      for (const candidate of packs) {
        const candidateFormat = candidate.formats.includes(preferredFormat)
          ? preferredFormat
          : candidate.formats[0];
        if (candidateFormat === undefined) continue;
        parts.push((await loadPrompt(candidate.key, candidateFormat)).trim());
      }
    } catch (error: unknown) {
      setCopy({ kind: 'failed', target: 'all', note: error instanceof Error ? error.message : 'the prompts could not be loaded' });
      return;
    }
    if (parts.length === 0) {
      setCopy({ kind: 'failed', target: 'all', note: 'no pack in this scan has a stored prompt' });
      return;
    }
    await writeToClipboard('all', note, `${parts.join('\n\n---\n\n')}\n`);
  }

  async function toggleApplied(): Promise<void> {
    setApplyPending(true);
    setApplyError(null);
    try {
      const result = await setApplied(projectId, pack.id, !pack.appliedAt);
      if (!result.ok) setApplyError(result.message ?? 'The note could not be saved.');
    } catch {
      setApplyError('The note could not be saved. Nothing was changed.');
    } finally {
      setApplyPending(false);
    }
  }

  function jumpTo(id: string): void {
    const pane = promptPane.current;
    if (!pane) return;
    const target = pane.querySelector<HTMLElement>(`[id="${id}"]`);
    if (!target) return;
    pane.scrollTop += target.getBoundingClientRect().top - pane.getBoundingClientRect().top - 8;
  }

  const warnings = pack.validation.issues.filter((i) => i.level === 'warning');
  const otherIssues = pack.validation.issues.filter((i) => i.level !== 'warning');
  const checkedCount = pack.verificationSteps.filter((_, i) => checked[`${pack.key}::${i}`]).length;

  return (
    <>
      <style>{CSS}</style>

      <div className="fs-layout">
        {/* ------------------------------------------------------ roadmap -- */}
        <div className="fs-roadmap">
          <SectionHeading hint={`In dependency order. ${appliedCount} of ${packs.length} marked applied.`}>
            Roadmap
          </SectionHeading>

          <ol className="fs-packlist">
            {packs.map((candidate) => {
              const current = candidate.key === pack.key;
              return (
                <li key={candidate.key}>
                  <button
                    type="button"
                    className="fs-pack"
                    aria-current={current ? 'true' : undefined}
                    data-applied={candidate.appliedAt ? 'true' : undefined}
                    onClick={() => setSelectedKey(candidate.key)}
                  >
                    <span className="fs-pack-top">
                      <span className="fs-ordinal" aria-hidden="true">
                        {String(candidate.ordinal).padStart(2, '0')}
                      </span>
                      <span className="fs-pack-title">
                        <span className="sr-only">Pack {candidate.ordinal}. </span>
                        {candidate.title}
                      </span>
                    </span>

                    <span className="fs-chips">
                      {candidate.topPriority ? <PriorityPill priority={candidate.topPriority} /> : null}
                      {candidate.severityMix.map((m) => (
                        <SeverityCount key={m.severity} severity={m.severity} count={m.count} />
                      ))}
                      <Tag>{pluralize(candidate.findings.length, 'finding')}</Tag>
                      <Tag>{effortLabel(candidate.effort)}</Tag>
                    </span>

                    {candidate.prerequisites.length > 0 ? (
                      <span className="fs-prereq">
                        <span aria-hidden="true">↑</span> after{' '}
                        {candidate.prerequisites
                          .map((p) => (p.ordinal === undefined ? p.key : `pack ${p.ordinal}`))
                          .join(', ')}
                        {candidate.prerequisites.some((p) => p.outOfOrder)
                          ? ' — one prerequisite is listed later, see the pack detail'
                          : ''}
                      </span>
                    ) : (
                      <span className="fs-prereq fs-prereq-free">no prerequisites</span>
                    )}

                    {candidate.appliedAt ? (
                      <span className="fs-applied">
                        <span aria-hidden="true">✓</span> Marked applied {formatRelative(candidate.appliedAt)}
                      </span>
                    ) : null}
                  </button>
                </li>
              );
            })}
          </ol>

          <p className="fs-roadmap-foot">
            Work top to bottom. Each pack&rsquo;s prerequisites appear above it, because a pack applied out of
            order edits behaviour the earlier pack is about to replace.
          </p>
        </div>

        {/* ------------------------------------------------------- detail -- */}
        <div className="fs-detail">
          <p aria-live="polite" className="sr-only">
            Pack {pack.ordinal} of {packs.length} selected: {pack.title}.
          </p>

          <section className="fs-card" aria-labelledby="fs-pack-heading">
            <div className="fs-detail-head">
              <p className="fs-eyebrow">
                Pack {pack.ordinal} of {packs.length} · {familyLabel(pack.family)}
              </p>
              <h2 id="fs-pack-heading" className="fs-h2">{pack.title}</h2>
              <div className="fs-chips">
                {pack.topPriority ? <PriorityPill priority={pack.topPriority} /> : null}
                {pack.severityMix.map((m) => (
                  <SeverityCount key={m.severity} severity={m.severity} count={m.count} />
                ))}
                <Tag>{pluralize(pack.findings.length, 'finding')}</Tag>
                <Tag>{effortLabel(pack.effort)}</Tag>
                {pack.appliedAt ? <Tag tone="good">Marked applied {formatRelative(pack.appliedAt)}</Tag> : null}
              </div>
            </div>

            <h3 className="fs-h3">Objective</h3>
            <p className="fs-body">{pack.objective}</p>

            <h3 className="fs-h3">Prerequisites</h3>
            {pack.prerequisites.length === 0 ? (
              <p className="fs-body fs-muted">
                None. This pack can be applied first.
              </p>
            ) : (
              <ul className="fs-prereq-list">
                {pack.prerequisites.map((p) => (
                  <li key={p.key}>
                    {p.ordinal === undefined || p.title === undefined ? (
                      <>
                        <Mono>{p.key}</Mono>{' '}
                        <span className="fs-muted">— declared, but no such pack is present in this scan</span>
                      </>
                    ) : (
                      <>
                        <button type="button" className="fs-link-button" onClick={() => setSelectedKey(p.key)}>
                          Pack {p.ordinal} — {p.title}
                        </button>{' '}
                        {p.appliedAt ? (
                          <Tag tone="good">marked applied</Tag>
                        ) : (
                          <Tag tone="warn">not marked applied</Tag>
                        )}
                        {p.outOfOrder ? <> <Tag tone="warn">listed after this pack</Tag></> : null}
                      </>
                    )}
                  </li>
                ))}
              </ul>
            )}

            <div className="fs-two">
              <FieldList label="Affected features" items={pack.affectedFeatures} />
              <FieldList label="Affected files" items={pack.affectedFiles} mono />
            </div>
          </section>

          {/* ------------------------------------------------- the prompt -- */}
          <section className="fs-card" aria-labelledby="fs-prompt-heading">
            <SectionHeading
              id="fs-prompt-heading"
              hint="The prompt below was generated when the scan ran and is stored as it stands. Switching format shows a different stored document; nothing is rewritten in your browser."
            >
              Agent prompt
            </SectionHeading>

            {pack.formats.length === 0 ? (
              <p className="fs-body fs-muted">No prompt is stored for this pack in any agent format.</p>
            ) : (
              <>
                <fieldset className="fs-formats">
                  <legend className="fs-legend">Agent format</legend>
                  {pack.formats.map((candidate) => {
                    const active = candidate === format;
                    return (
                      <label key={candidate} className="fs-format" data-active={active ? 'true' : undefined}>
                        <input
                          type="radio"
                          name="fs-agent-format"
                          value={candidate}
                          checked={active}
                          onChange={() => setPreferredFormat(candidate)}
                        />
                        <span>{FORMAT_LABEL[candidate] ?? candidate}</span>
                      </label>
                    );
                  })}
                </fieldset>
                {format ? <p className="fs-format-hint">{FORMAT_HINT[format] ?? null}</p> : null}

                {pack.formats.length < 3 ? (
                  <p className="fs-body fs-muted">
                    Stored formats for this pack: {pack.formats.map((f) => FORMAT_LABEL[f] ?? f).join(', ')}. The
                    others were not generated.
                  </p>
                ) : null}

                {jumpTargets.length > 0 ? (
                  <nav className="fs-jump" aria-label="Prompt sections">
                    <span className="fs-jump-label" aria-hidden="true">Jump to</span>
                    {jumpTargets.map((s) => (
                      <button
                        key={s.id}
                        type="button"
                        className="fs-jump-button"
                        title={s.heading}
                        aria-label={`Jump to section ${s.heading}`}
                        onClick={() => jumpTo(s.id)}
                      >
                        {s.letter ?? s.heading?.slice(0, 12)}
                      </button>
                    ))}
                  </nav>
                ) : null}

                {prompt.state === 'loading' ? (
                  <div className="fs-prompt-placeholder">
                    <p className="fs-body fs-muted">Loading the stored prompt…</p>
                    <div className="skeleton" style={{ height: '1rem', width: '70%' }} />
                    <div className="skeleton" style={{ height: '1rem', width: '90%' }} />
                    <div className="skeleton" style={{ height: '1rem', width: '55%' }} />
                  </div>
                ) : null}

                {prompt.state === 'error' ? (
                  <Caveat>
                    The prompt for this pack could not be loaded ({prompt.message}). The download link below
                    requests the same document directly.
                  </Caveat>
                ) : null}

                {prompt.state === 'none' ? (
                  <p className="fs-body fs-muted">No prompt is stored for this pack in any agent format.</p>
                ) : null}

                {prompt.state === 'ready' && format ? (
                  <>
                    <div
                      className="fs-prompt"
                      ref={promptPane}
                      tabIndex={0}
                      role="region"
                      aria-label={`${FORMAT_LABEL[format] ?? format} prompt for pack ${pack.ordinal}, ${pack.title}`}
                    >
                      {sections.map((s) => (
                        <div key={s.id} className="fs-prompt-section">
                          {s.heading ? (
                            <h4 id={s.id} className="fs-prompt-heading">{s.heading}</h4>
                          ) : null}
                          {s.body ? <pre className="fs-prompt-body">{s.body}</pre> : null}
                        </div>
                      ))}
                    </div>
                    <p className="fs-prompt-meta">
                      {prompt.text.length.toLocaleString()} characters ·{' '}
                      {pluralize(jumpTargets.length, 'section')} · markdown, shown verbatim
                    </p>
                  </>
                ) : null}

                <div className="fs-actions">
                  <button
                    type="button"
                    style={BUTTON_PRIMARY}
                    disabled={prompt.state !== 'ready'}
                    onClick={() => void copySelectedPrompt()}
                  >
                    Copy this prompt
                  </button>
                  {format ? (
                    <a
                      href={promptUrl(pack.key, format)}
                      download
                      style={{ ...BUTTON, textDecoration: 'none', display: 'inline-block' }}
                    >
                      Download markdown
                    </a>
                  ) : null}
                  <button
                    type="button"
                    style={BUTTON}
                    disabled={copy.kind === 'working'}
                    onClick={() => void copyEveryPack()}
                  >
                    {copy.kind === 'working' && copy.target === 'all' ? 'Collecting prompts…' : 'Copy all packs'}
                  </button>
                </div>

                <p role="status" aria-live="polite" className="fs-status">
                  {copy.kind === 'copied' ? `Copied ${copy.note} to the clipboard.` : null}
                  {copy.kind === 'working' ? `Collecting ${copy.note}…` : null}
                  {copy.kind === 'failed' ? `Nothing was copied: ${copy.note}.` : null}
                  {copy.kind === 'manual'
                    ? `The clipboard was not available, so ${copy.note} is selected below for you to copy by hand.`
                    : null}
                </p>

                {copy.kind === 'manual' ? (
                  <div className="fs-manual">
                    <label className="fs-legend" htmlFor="fs-manual-copy">
                      Copy by hand: the text is selected — press Command-C, or Ctrl-C
                    </label>
                    <textarea
                      id="fs-manual-copy"
                      ref={manualArea}
                      className="fs-manual-area"
                      readOnly
                      value={copy.text}
                      spellCheck={false}
                      onFocus={(e) => e.currentTarget.select()}
                    />
                    <button type="button" style={BUTTON} onClick={() => setCopy({ kind: 'idle' })}>
                      Close
                    </button>
                  </div>
                ) : null}

                <Caveat>
                  <strong>Copy all packs</strong> is for handing the whole roadmap to a person, or for keeping a
                  record. Do not give several packs to an agent in one session: when more than one pack is applied
                  between scans, the next scan cannot attribute what changed to any one of them.
                </Caveat>
              </>
            )}
          </section>

          {/* ---------------------------------------------------- findings -- */}
          <section className="fs-card" aria-labelledby="fs-findings-heading">
            <SectionHeading
              id="fs-findings-heading"
              hint="Severity is how much it matters. Confidence is how sure the analysis is. They are independent: a critical finding can rest on moderate evidence."
            >
              Findings in this pack
            </SectionHeading>

            {pack.findings.length === 0 ? (
              <p className="fs-body fs-muted">No findings are attached to this pack.</p>
            ) : (
              <ul className="fs-findings">
                {pack.findings.map((f) => (
                  <li key={f.displayId} className="fs-finding">
                    <div className="fs-finding-head">
                      <Link
                        href={`/projects/${encodeURIComponent(projectId)}/findings?finding=${encodeURIComponent(f.displayId)}`}
                        className="fs-finding-id"
                      >
                        {f.displayId}
                      </Link>
                      <span className="fs-finding-title">{f.title}</span>
                    </div>
                    <div className="fs-chips">
                      <SeverityPill severity={f.severity} />
                      <ConfidencePill confidence={f.confidence} />
                      <StatusPill status={f.status} />
                      {f.priority ? <PriorityPill priority={f.priority} /> : null}
                      <Tag>{CATEGORY_LABEL[f.category] ?? f.category}</Tag>
                      <Tag>{effortLabel(f.effort)}</Tag>
                    </div>
                    {f.files.length > 0 ? (
                      <p className="fs-finding-files">
                        {f.files.map((file) => (
                          <span key={file} style={{ marginRight: '0.6rem' }}>
                            <Mono>{file}</Mono>
                          </span>
                        ))}
                      </p>
                    ) : null}
                  </li>
                ))}
              </ul>
            )}
          </section>

          {/* ------------------------------------------------ verification -- */}
          <section className="fs-card" aria-labelledby="fs-verify-heading">
            <SectionHeading
              id="fs-verify-heading"
              hint="Every verification step from the findings in this pack, with duplicates removed. Work through it after the pack has been applied, then re-scan."
            >
              Verification checklist
            </SectionHeading>

            {pack.verificationSteps.length === 0 ? (
              <p className="fs-body fs-muted">
                None of the findings in this pack records a verification step.
              </p>
            ) : (
              <>
                <p className="fs-body fs-muted">
                  {checkedCount} of {pack.verificationSteps.length} ticked. Ticks are for this visit only — they
                  are not saved.
                </p>
                <ul className="fs-checklist">
                  {pack.verificationSteps.map((step, i) => {
                    const key = `${pack.key}::${i}`;
                    return (
                      <li key={key}>
                        <label className="fs-check">
                          <input
                            type="checkbox"
                            checked={checked[key] ?? false}
                            onChange={(e) => setChecked((prior) => ({ ...prior, [key]: e.currentTarget.checked }))}
                          />
                          <span data-done={checked[key] ? 'true' : undefined}>{step}</span>
                        </label>
                      </li>
                    );
                  })}
                </ul>
              </>
            )}
          </section>

          {/* -------------------------------------------------- validation -- */}
          <section className="fs-card" aria-labelledby="fs-validation-heading">
            <SectionHeading
              id="fs-validation-heading"
              hint="Checks the engine ran on this pack before it was allowed on screen. A pack with an error-level issue is withheld, so no pack you can see here failed one."
            >
              Pre-flight validation
            </SectionHeading>

            {warnings.length > 0 ? (
              <Caveat>
                <strong>{pluralize(warnings.length, 'warning')}.</strong> The pack is still presentable, but read
                these before handing it to an agent.
                <ul style={{ margin: '0.4rem 0 0', paddingLeft: '1.1rem' }}>
                  {warnings.map((w, i) => (
                    <li key={`${w.check}-${i}`} style={{ marginBottom: '0.2rem' }}>
                      <strong>{checkLabel(w.check)}:</strong> {w.detail}
                    </li>
                  ))}
                </ul>
              </Caveat>
            ) : (
              <p className="fs-body fs-muted">No warnings were raised on this pack.</p>
            )}

            {otherIssues.length > 0 ? (
              <Caveat>
                <ul style={{ margin: 0, paddingLeft: '1.1rem' }}>
                  {otherIssues.map((issue, i) => (
                    <li key={`${issue.check}-${i}`}>
                      <strong>{issue.level}</strong> — {checkLabel(issue.check)}: {issue.detail}
                    </li>
                  ))}
                </ul>
              </Caveat>
            ) : null}

            {pack.validation.checksRun.length === 0 ? (
              <p className="fs-body fs-muted">No record of which checks ran was stored with this pack.</p>
            ) : (
              <>
                <h3 className="fs-h3">{pluralize(pack.validation.checksRun.length, 'check')} ran</h3>
                <ul className="fs-checks">
                  {pack.validation.checksRun.map((check) => {
                    const flagged = pack.validation.issues.some((i) => i.check === check);
                    return (
                      <li key={check} data-flagged={flagged ? 'true' : undefined}>
                        <span aria-hidden="true" className="fs-check-glyph">{flagged ? '!' : '✓'}</span>
                        <span>
                          {checkLabel(check)}
                          {flagged ? <span className="fs-flagged-note"> — raised an issue above</span> : null}
                        </span>
                      </li>
                    );
                  })}
                </ul>
              </>
            )}
          </section>

          {/* ----------------------------------------------------- applied -- */}
          <section className="fs-card" aria-labelledby="fs-applied-heading">
            <SectionHeading
              id="fs-applied-heading"
              hint="A note for your own tracking. It records that you consider this pack handled; it does not inspect your repository, does not verify the fix, and changes no code."
            >
              Applied state
            </SectionHeading>

            <p className="fs-body">
              {pack.appliedAt
                ? `Marked applied ${formatRelative(pack.appliedAt)}.`
                : 'Not marked applied.'}
              {pack.baselineCommit ? (
                <>
                  {' '}Baseline commit <Mono>{pack.baselineCommit}</Mono>.
                </>
              ) : null}
            </p>

            <div className="fs-actions">
              <button type="button" style={BUTTON} disabled={applyPending} onClick={() => void toggleApplied()}>
                {applyPending
                  ? 'Saving…'
                  : pack.appliedAt
                    ? `Clear the applied note on pack ${pack.ordinal}`
                    : `Mark pack ${pack.ordinal} as applied`}
              </button>
            </div>

            <p role="status" aria-live="polite" className="fs-status">
              {applyError}
            </p>

            <Caveat tone="neutral">
              Apply one pack, re-scan, then move to the next. The re-scan is what tells you whether the findings
              in this pack are gone, and it can only tell you that for one pack at a time.
            </Caveat>
          </section>
        </div>
      </div>
    </>
  );
}

// --------------------------------------------------------------------- css --

/**
 * Component styles.
 *
 * Kept with the component rather than in globals.css, which other surfaces
 * share. Media queries are the reason this is not inline `style`: the roadmap
 * and detail panes must stack below 60rem and hold together at 380px.
 */
const CSS = `
.fs-layout { display: grid; gap: 1.1rem; align-items: start; grid-template-columns: minmax(0, 1fr); }
@media (min-width: 60rem) {
  .fs-layout { grid-template-columns: minmax(15rem, 21rem) minmax(0, 1fr); }
  .fs-roadmap { position: sticky; top: 4rem; max-height: calc(100vh - 5rem); overflow-y: auto; padding-right: 0.3rem; }
}
.fs-detail { display: grid; gap: 1.1rem; min-width: 0; }
.fs-card {
  background: var(--surface); border: 1px solid var(--border); border-radius: 10px;
  padding: 1.1rem 1.25rem; min-width: 0; display: grid; gap: 0.7rem;
}
@media (max-width: 26rem) { .fs-card { padding: 0.9rem; } }

.fs-packlist { list-style: none; margin: 0; padding: 0; display: grid; gap: 0.4rem; }
.fs-pack {
  font: inherit; color: var(--ink); text-align: left; width: 100%; cursor: pointer;
  background: var(--surface); border: 1px solid var(--border); border-left: 3px solid var(--border);
  border-radius: 8px; padding: 0.55rem 0.65rem; display: grid; gap: 0.3rem;
}
.fs-pack:hover { border-color: var(--border-strong); border-left-color: var(--border-strong); }
.fs-pack[aria-current="true"] {
  border-color: var(--accent); border-left-color: var(--accent); background: var(--accent-soft);
}
.fs-pack[data-applied="true"] { border-left-color: var(--good); }
.fs-pack-top { display: flex; gap: 0.45rem; align-items: baseline; }
.fs-ordinal {
  font-family: var(--font-mono); font-size: 0.74rem; font-weight: 650; color: var(--ink-3);
  font-variant-numeric: tabular-nums; flex: none;
}
.fs-pack-title { font-weight: 600; font-size: 0.9rem; line-height: 1.35; }
.fs-chips { display: flex; flex-wrap: wrap; gap: 0.3rem; align-items: center; }
.fs-prereq { font-size: 0.76rem; color: var(--ink-2); line-height: 1.4; }
.fs-prereq-free { color: var(--ink-3); }
.fs-applied { font-size: 0.76rem; color: var(--good); font-weight: 600; }
.fs-roadmap-foot { margin: 0.7rem 0 0; font-size: 0.78rem; color: var(--ink-3); line-height: 1.5; }

.fs-detail-head { display: grid; gap: 0.35rem; }
.fs-eyebrow {
  margin: 0; font-size: 0.76rem; color: var(--ink-3); text-transform: uppercase;
  letter-spacing: 0.05em; font-weight: 600;
}
.fs-h2 { margin: 0; font-size: 1.22rem; font-weight: 680; letter-spacing: -0.015em; line-height: 1.25; }
.fs-h3 { margin: 0.3rem 0 0; font-size: 0.82rem; font-weight: 650; color: var(--ink-3); text-transform: uppercase; letter-spacing: 0.05em; }
.fs-body { margin: 0; font-size: 0.9rem; line-height: 1.6; color: var(--ink-2); }
.fs-muted { color: var(--ink-3); }
.fs-two { display: grid; gap: 0.8rem; grid-template-columns: minmax(0, 1fr); }
@media (min-width: 42rem) { .fs-two { grid-template-columns: minmax(0, 1fr) minmax(0, 1fr); } }

.fs-prereq-list { margin: 0; padding-left: 1.1rem; display: grid; gap: 0.3rem; font-size: 0.88rem; }
.fs-link-button {
  font: inherit; background: none; border: none; padding: 0; cursor: pointer;
  color: var(--accent); text-decoration: underline; text-underline-offset: 2px; text-align: left;
}

.fs-formats { display: flex; flex-wrap: wrap; gap: 0.4rem; border: none; margin: 0; padding: 0; }
.fs-legend { font-size: 0.78rem; font-weight: 650; color: var(--ink-3); text-transform: uppercase; letter-spacing: 0.05em; padding: 0; }
.fs-formats .fs-legend { width: 100%; margin-bottom: 0.35rem; }
.fs-format {
  display: inline-flex; align-items: center; gap: 0.35rem; cursor: pointer;
  border: 1px solid var(--border-strong); border-radius: 999px; padding: 0.25rem 0.65rem;
  font-size: 0.84rem; background: var(--surface-2); color: var(--ink-2);
}
.fs-format[data-active="true"] {
  background: var(--accent-soft); border-color: var(--accent); color: var(--ink); font-weight: 650;
}
.fs-format-hint { margin: 0; font-size: 0.82rem; color: var(--ink-3); line-height: 1.5; }

.fs-jump {
  display: flex; gap: 0.25rem; align-items: center; overflow-x: auto;
  padding: 0.3rem 0; border-top: 1px solid var(--border); border-bottom: 1px solid var(--border);
}
.fs-jump-label { font-size: 0.74rem; color: var(--ink-3); text-transform: uppercase; letter-spacing: 0.05em; flex: none; }
.fs-jump-button {
  font: inherit; font-family: var(--font-mono); font-size: 0.76rem; font-weight: 650;
  min-width: 1.75rem; padding: 0.15rem 0.35rem; flex: none; cursor: pointer;
  background: var(--surface-2); color: var(--ink-2);
  border: 1px solid var(--border); border-radius: 4px;
}
.fs-jump-button:hover { color: var(--ink); border-color: var(--border-strong); }

.fs-prompt {
  max-height: 60vh; min-height: 14rem; overflow: auto;
  background: var(--surface-2); border: 1px solid var(--border); border-radius: 8px;
  padding: 0.8rem 0.9rem; display: grid; gap: 0.2rem;
}
.fs-prompt-section { display: grid; gap: 0.25rem; }
.fs-prompt-heading {
  margin: 0.8rem 0 0; font-family: var(--font-mono); font-size: 0.82rem; font-weight: 700;
  color: var(--ink); background: var(--surface-3); border-left: 3px solid var(--accent);
  border-radius: 0 4px 4px 0; padding: 0.3rem 0.5rem; position: sticky; top: -0.8rem;
}
.fs-prompt-section:first-child .fs-prompt-heading { margin-top: 0; }
.fs-prompt-body {
  margin: 0; padding: 0 0.1rem; font-family: var(--font-mono); font-size: 0.78rem;
  line-height: 1.6; color: var(--ink-2); white-space: pre-wrap; overflow-wrap: anywhere;
}
.fs-prompt-placeholder { display: grid; gap: 0.5rem; }
.fs-prompt-meta { margin: 0; font-size: 0.76rem; color: var(--ink-3); font-variant-numeric: tabular-nums; }

.fs-actions { display: flex; flex-wrap: wrap; gap: 0.45rem; align-items: center; }
.fs-status { margin: 0; font-size: 0.84rem; color: var(--ink-2); min-height: 1.2rem; }
.fs-manual { display: grid; gap: 0.35rem; }
.fs-manual-area {
  width: 100%; min-height: 8rem; resize: vertical; font-family: var(--font-mono); font-size: 0.76rem;
  background: var(--surface-2); color: var(--ink); border: 1px solid var(--border-strong); border-radius: 6px;
  padding: 0.5rem;
}

.fs-findings { list-style: none; margin: 0; padding: 0; display: grid; gap: 0.6rem; }
.fs-finding {
  display: grid; gap: 0.35rem; padding: 0.6rem 0.7rem;
  border: 1px solid var(--border); border-radius: 8px; background: var(--surface-2);
}
.fs-finding-head { display: flex; flex-wrap: wrap; gap: 0.45rem; align-items: baseline; }
.fs-finding-id { font-family: var(--font-mono); font-size: 0.78rem; font-weight: 650; flex: none; }
.fs-finding-title { font-size: 0.9rem; font-weight: 600; line-height: 1.4; }
.fs-finding-files { margin: 0; line-height: 1.7; }

.fs-checklist { list-style: none; margin: 0; padding: 0; display: grid; gap: 0.3rem; }
.fs-check { display: flex; gap: 0.5rem; align-items: start; font-size: 0.88rem; line-height: 1.5; cursor: pointer; }
.fs-check input { margin-top: 0.3rem; flex: none; }
.fs-check span[data-done="true"] { color: var(--ink-3); text-decoration: line-through; }

.fs-checks { list-style: none; margin: 0; padding: 0; display: grid; gap: 0.2rem; font-size: 0.85rem; }
.fs-checks li { display: flex; gap: 0.45rem; align-items: baseline; color: var(--ink-2); line-height: 1.5; }
.fs-check-glyph { font-family: var(--font-mono); color: var(--good); font-weight: 700; flex: none; }
.fs-checks li[data-flagged="true"] .fs-check-glyph { color: var(--medium); }
.fs-flagged-note { color: var(--medium); }
`;
