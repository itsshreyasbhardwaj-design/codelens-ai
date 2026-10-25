'use client';

import { useId, useRef, useState } from 'react';
import {
  Card, Caveat, CodeBlock, ConfidencePill, Mono, PriorityPill, SectionHeading,
  SeverityPill, StatusPill, Table, Td,
} from '../../../components/ui.tsx';
import { CATEGORY_LABEL } from '../../../lib/format.ts';

/**
 * The question surface.
 *
 * This component is interactive (it submits questions and keeps a transcript),
 * so it is a client component and holds no data access of its own. Every answer
 * is computed on the server from the stored scan and arrives as plain data.
 *
 * The wire types below are the single source of truth for the answer shape: the
 * POST handler at app/api/projects/[projectId]/chat/route.ts imports them with a
 * type-only import, so the two cannot drift.
 */

// ------------------------------------------------------------------ wire types

export interface Citation {
  file: string;
  line?: number;
  endLine?: number;
  symbol?: string;
  excerpt?: string;
  note?: string;
  /** Whether the excerpt was re-checked against the snapshot when it was stored. */
  verified: boolean;
  /** What this location is evidence of, e.g. "route handler" or "SEC-002". */
  label?: string;
}

/**
 * A finding referenced by an answer. Severity and confidence travel as separate
 * fields and render as separate indicators — they are never combined.
 */
export interface FindingRef {
  displayId: string;
  title: string;
  category: string;
  severity: string;
  confidence: string;
  status: string;
  priority?: string;
  userImpact?: string;
  remediation?: string;
  citations: Citation[];
}

export interface AnswerBlock {
  heading?: string;
  text?: string;
  bullets?: string[];
  table?: { caption: string; head: string[]; rows: string[][] };
  findings?: FindingRef[];
  citations?: Citation[];
}

export interface ChatAnswer {
  question: string;
  intent: string;
  intentLabel: string;
  /** False when the question matched no supported query; then `answerable` is the reply. */
  matched: boolean;
  scanId: string;
  scanLabel: string;
  summary: string;
  blocks: AnswerBlock[];
  caveats: string[];
  /** 'stored-evidence' means no model was involved at any point. */
  composedBy: 'stored-evidence' | 'model-phrased';
  /** Present when a model was configured but phrasing failed; the stored answer stands. */
  modelNote?: string;
  answerable: Array<{ id: string; question: string }>;
}

export interface SuggestedQuestion { id: string; question: string }

// ------------------------------------------------------------------- rendering

function CitationList({ citations }: { citations: Citation[] }) {
  if (citations.length === 0) return null;
  return (
    <ul style={{ listStyle: 'none', margin: '0.4rem 0 0', padding: 0, display: 'grid', gap: '0.35rem' }}>
      {citations.map((c, i) => {
        const loc = `${c.file}${c.line ? `:${c.line}${c.endLine && c.endLine !== c.line ? `-${c.endLine}` : ''}` : ''}`;
        return (
          <li key={`${loc}-${i}`} style={{ fontSize: '0.84rem' }}>
            <span style={{ display: 'flex', flexWrap: 'wrap', gap: '0.4rem', alignItems: 'baseline' }}>
              <Mono>{loc}</Mono>
              {c.label ? <span style={{ color: 'var(--ink-3)', fontSize: '0.8rem' }}>{c.label}</span> : null}
              {c.verified ? null : (
                <span style={{ color: 'var(--medium)', fontSize: '0.78rem' }}>evidence not re-verified</span>
              )}
            </span>
            {c.note ? (
              <span style={{ display: 'block', color: 'var(--ink-3)', fontSize: '0.8rem' }}>{c.note}</span>
            ) : null}
            {c.excerpt ? (
              <details style={{ marginTop: '0.2rem' }}>
                <summary style={{ cursor: 'pointer', fontSize: '0.8rem', color: 'var(--ink-2)' }}>
                  Excerpt from {loc}
                </summary>
                <CodeBlock>{c.excerpt}</CodeBlock>
              </details>
            ) : null}
          </li>
        );
      })}
    </ul>
  );
}

function FindingCard({ f }: { f: FindingRef }) {
  return (
    <li
      style={{
        border: '1px solid var(--border)', borderRadius: 8, padding: '0.7rem 0.8rem',
        background: 'var(--surface-2)',
      }}
    >
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.4rem', alignItems: 'center' }}>
        <Mono>{f.displayId}</Mono>
        {f.priority ? <PriorityPill priority={f.priority} /> : null}
        <SeverityPill severity={f.severity} />
        <ConfidencePill confidence={f.confidence} />
        <StatusPill status={f.status} />
        <span style={{ fontSize: '0.78rem', color: 'var(--ink-3)' }}>
          {CATEGORY_LABEL[f.category] ?? f.category}
        </span>
      </div>
      <p style={{ margin: '0.4rem 0 0', fontWeight: 600, lineHeight: 1.45 }}>{f.title}</p>
      {f.userImpact ? (
        <p style={{ margin: '0.3rem 0 0', fontSize: '0.86rem', color: 'var(--ink-2)' }}>{f.userImpact}</p>
      ) : null}
      {f.remediation ? (
        <p style={{ margin: '0.3rem 0 0', fontSize: '0.86rem', color: 'var(--ink-2)' }}>
          <span style={{ fontWeight: 600 }}>Remediation. </span>
          {f.remediation}
        </p>
      ) : null}
      <CitationList citations={f.citations} />
    </li>
  );
}

function Block({ block }: { block: AnswerBlock }) {
  return (
    <div style={{ display: 'grid', gap: '0.45rem' }}>
      {block.heading ? (
        <h4 style={{ margin: '0.5rem 0 0', fontSize: '0.92rem', fontWeight: 650 }}>{block.heading}</h4>
      ) : null}
      {block.text ? <p style={{ margin: 0, lineHeight: 1.6 }}>{block.text}</p> : null}
      {block.bullets && block.bullets.length > 0 ? (
        <ul style={{ margin: 0, paddingLeft: '1.1rem', display: 'grid', gap: '0.25rem' }}>
          {block.bullets.map((b, i) => (
            <li key={i} style={{ lineHeight: 1.55 }}>{b}</li>
          ))}
        </ul>
      ) : null}
      {block.table ? (
        <Table head={block.table.head} caption={block.table.caption}>
          {block.table.rows.map((row, i) => (
            <tr key={i}>
              {row.map((cell, j) => (
                <Td key={j} mono={j === row.length - 1}>{cell}</Td>
              ))}
            </tr>
          ))}
        </Table>
      ) : null}
      {block.findings && block.findings.length > 0 ? (
        <ul style={{ listStyle: 'none', margin: 0, padding: 0, display: 'grid', gap: '0.5rem' }}>
          {block.findings.map((f) => <FindingCard key={f.displayId} f={f} />)}
        </ul>
      ) : null}
      {block.citations ? <CitationList citations={block.citations} /> : null}
    </div>
  );
}

function AnswerView({ answer }: { answer: ChatAnswer }) {
  return (
    <div style={{ display: 'grid', gap: '0.6rem' }}>
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.4rem', alignItems: 'baseline' }}>
        <span style={{ fontSize: '0.78rem', color: 'var(--ink-3)', textTransform: 'uppercase', letterSpacing: '0.05em', fontWeight: 600 }}>
          {answer.matched ? answer.intentLabel : 'No matching query'}
        </span>
        <span style={{ fontSize: '0.78rem', color: 'var(--ink-3)' }}>
          · from {answer.scanLabel}
          {answer.composedBy === 'model-phrased' ? ' · wording generated by a model' : ' · composed from stored evidence'}
        </span>
      </div>

      <p style={{ margin: 0, lineHeight: 1.6 }}>{answer.summary}</p>

      {answer.blocks.map((b, i) => <Block key={i} block={b} />)}

      {!answer.matched && answer.answerable.length > 0 ? (
        <ul style={{ margin: 0, paddingLeft: '1.1rem', display: 'grid', gap: '0.25rem' }}>
          {answer.answerable.map((a) => <li key={a.id}>{a.question}</li>)}
        </ul>
      ) : null}

      {answer.modelNote ? (
        <Caveat tone="neutral">{answer.modelNote}</Caveat>
      ) : null}

      {answer.caveats.length > 0 ? (
        <Caveat>
          <span style={{ fontWeight: 650 }}>What this answer does not cover. </span>
          <ul style={{ margin: '0.3rem 0 0', paddingLeft: '1.1rem', display: 'grid', gap: '0.2rem' }}>
            {answer.caveats.map((c, i) => <li key={i}>{c}</li>)}
          </ul>
        </Caveat>
      ) : null}
    </div>
  );
}

// -------------------------------------------------------------------- the panel

interface Entry {
  id: number;
  question: string;
  answer?: ChatAnswer;
  error?: string;
}

export function ChatPanel({ projectId, scanLabel, suggested, modelUnavailableReason }: {
  projectId: string;
  scanLabel: string;
  suggested: SuggestedQuestion[];
  /** Why no model is available. Undefined means one is configured. */
  modelUnavailableReason?: string;
}) {
  const [entries, setEntries] = useState<Entry[]>([]);
  const [value, setValue] = useState('');
  const [pending, setPending] = useState(false);
  const nextId = useRef(1);
  const inputId = useId();

  async function ask(question: string) {
    const q = question.trim();
    if (!q || pending) return;
    const id = nextId.current++;
    setEntries((prev) => [...prev, { id, question: q }]);
    setPending(true);
    setValue('');
    try {
      const res = await fetch(`/api/projects/${encodeURIComponent(projectId)}/chat`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ question: q }),
      });
      const body = (await res.json()) as ChatAnswer | { error: string };
      setEntries((prev) => prev.map((e) => (
        e.id === id
          ? 'error' in body ? { ...e, error: body.error } : { ...e, answer: body }
          : e
      )));
    } catch (err) {
      setEntries((prev) => prev.map((e) => (
        e.id === id ? { ...e, error: err instanceof Error ? err.message : 'the request failed' } : e
      )));
    } finally {
      setPending(false);
    }
  }

  return (
    <div style={{ display: 'grid', gap: '1.25rem' }}>
      <Card>
        <SectionHeading hint="Answers are assembled from this scan's stored findings, routes, models, features and architecture. Each one cites the file and line it came from.">
          Ask about this codebase
        </SectionHeading>

        {modelUnavailableReason ? (
          <Caveat tone="neutral">
            <span style={{ fontWeight: 650 }}>No language model is configured, which is the default. </span>
            Answers below are composed from stored scan evidence rather than generated, so they are
            reproducible and nothing leaves this machine. The engine reported:{' '}
            <Mono>{modelUnavailableReason}</Mono>
          </Caveat>
        ) : (
          <Caveat tone="neutral">
            A model is configured, so it may be used to phrase an answer. The facts and citations are
            still taken from the stored scan; the model is given the assembled answer as fenced,
            untrusted data and cannot add, remove or alter a finding or a citation.
          </Caveat>
        )}

        <form
          onSubmit={(e) => { e.preventDefault(); void ask(value); }}
          style={{ marginTop: '0.9rem', display: 'grid', gap: '0.5rem' }}
        >
          <label htmlFor={inputId} style={{ fontSize: '0.86rem', fontWeight: 600 }}>
            Your question
          </label>
          <textarea
            id={inputId}
            value={value}
            onChange={(e) => setValue(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); void ask(value); }
            }}
            rows={2}
            placeholder="How does authentication work in this project?"
            style={{
              width: '100%', resize: 'vertical', padding: '0.5rem 0.6rem',
              background: 'var(--surface-2)', color: 'var(--ink)',
              border: '1px solid var(--border-strong)', borderRadius: 6,
              font: 'inherit', fontSize: '0.92rem',
            }}
          />
          <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center', flexWrap: 'wrap' }}>
            <button
              type="submit"
              disabled={pending || value.trim().length === 0}
              style={{
                font: 'inherit', fontSize: '0.88rem', fontWeight: 600,
                padding: '0.4rem 0.9rem', borderRadius: 6,
                border: '1px solid var(--accent)',
                background: pending || value.trim().length === 0 ? 'var(--surface-3)' : 'var(--accent)',
                color: pending || value.trim().length === 0 ? 'var(--ink-3)' : 'var(--accent-ink)',
                cursor: pending || value.trim().length === 0 ? 'not-allowed' : 'pointer',
              }}
            >
              {pending ? 'Looking up evidence…' : 'Ask'}
            </button>
            <span style={{ fontSize: '0.8rem', color: 'var(--ink-3)' }}>
              Enter to send, Shift+Enter for a new line.
            </span>
          </div>
        </form>

        <h3 style={{ fontSize: '0.86rem', fontWeight: 650, margin: '1.1rem 0 0.4rem' }}>
          Questions this scan can answer
        </h3>
        <ul style={{ listStyle: 'none', margin: 0, padding: 0, display: 'flex', flexWrap: 'wrap', gap: '0.4rem' }}>
          {suggested.map((s) => (
            <li key={s.id}>
              <button
                type="button"
                onClick={() => void ask(s.question)}
                disabled={pending}
                style={{
                  font: 'inherit', fontSize: '0.82rem', textAlign: 'left',
                  padding: '0.3rem 0.6rem', borderRadius: 999,
                  border: '1px solid var(--border-strong)',
                  background: 'var(--surface-2)', color: 'var(--ink-2)',
                  cursor: pending ? 'not-allowed' : 'pointer',
                }}
              >
                {s.question}
              </button>
            </li>
          ))}
        </ul>
      </Card>

      <div aria-live="polite" className="sr-only">
        {pending ? 'Looking up evidence' : entries.length > 0 ? 'Answer ready' : ''}
      </div>

      {entries.length === 0 ? null : (
        <section aria-label="Questions and answers" style={{ display: 'grid', gap: '1rem' }}>
          {[...entries].reverse().map((e) => (
            <Card key={e.id} as="article">
              <h3 style={{ margin: 0, fontSize: '1rem', fontWeight: 650, letterSpacing: '-0.01em' }}>
                {e.question}
              </h3>
              <div style={{ marginTop: '0.7rem' }}>
                {e.error ? (
                  <p style={{ margin: 0, color: 'var(--critical)' }}>
                    That question could not be answered: {e.error}
                  </p>
                ) : e.answer ? (
                  <AnswerView answer={e.answer} />
                ) : (
                  <p style={{ margin: 0, color: 'var(--ink-3)' }}>Looking up evidence…</p>
                )}
              </div>
            </Card>
          ))}
        </section>
      )}
    </div>
  );
}
