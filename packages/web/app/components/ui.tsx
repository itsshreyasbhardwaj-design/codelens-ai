import type { ReactNode } from 'react';
import { CONFIDENCE_MEANING, severityStyle, STATUS_LABEL } from '../lib/format.ts';

/**
 * Shared presentation primitives.
 *
 * Severity and confidence render as two separate indicators everywhere, never
 * combined into a single score or colour. A critical finding that is only
 * suspected must look exactly like that.
 */

export function Card({ children, className = '', as: As = 'section' }: {
  children: ReactNode; className?: string; as?: 'section' | 'div' | 'article' | 'li';
}) {
  return (
    <As
      className={className}
      style={{
        background: 'var(--surface)',
        border: '1px solid var(--border)',
        borderRadius: 10,
        padding: '1.1rem 1.25rem',
      }}
    >
      {children}
    </As>
  );
}

export function SectionHeading({ children, hint, id }: { children: ReactNode; hint?: ReactNode; id?: string }) {
  return (
    <div style={{ marginBottom: '0.85rem' }}>
      <h2 id={id} style={{ fontSize: '1.02rem', fontWeight: 650, margin: 0, letterSpacing: '-0.01em' }}>
        {children}
      </h2>
      {hint ? (
        <p style={{ margin: '0.3rem 0 0', color: 'var(--ink-3)', fontSize: '0.84rem', lineHeight: 1.5 }}>{hint}</p>
      ) : null}
    </div>
  );
}

export function SeverityPill({ severity }: { severity: string }) {
  const { color, bg } = severityStyle(severity);
  return (
    <span
      style={{
        color, background: bg, border: `1px solid ${color}33`,
        padding: '0.08rem 0.45rem', borderRadius: 999,
        fontSize: '0.72rem', fontWeight: 650, textTransform: 'uppercase',
        letterSpacing: '0.04em', whiteSpace: 'nowrap',
      }}
    >
      {severity}
    </span>
  );
}

export function ConfidencePill({ confidence }: { confidence: string }) {
  return (
    <span
      title={CONFIDENCE_MEANING[confidence]}
      style={{
        color: 'var(--ink-2)', background: 'var(--surface-2)', border: '1px solid var(--border)',
        padding: '0.08rem 0.45rem', borderRadius: 999, fontSize: '0.72rem',
        fontWeight: 550, whiteSpace: 'nowrap',
      }}
    >
      {confidence} confidence
    </span>
  );
}

export function StatusPill({ status }: { status: string }) {
  const emphasise = status === 'needs_runtime_verification' || status === 'suspected';
  return (
    <span
      style={{
        color: emphasise ? 'var(--medium)' : 'var(--ink-3)',
        background: emphasise ? 'var(--medium-soft)' : 'var(--surface-2)',
        border: '1px solid var(--border)',
        padding: '0.08rem 0.45rem', borderRadius: 4, fontSize: '0.72rem', whiteSpace: 'nowrap',
      }}
    >
      {STATUS_LABEL[status] ?? status}
    </span>
  );
}

export function PriorityPill({ priority }: { priority: string }) {
  const colors: Record<string, string> = {
    P0: 'var(--critical)', P1: 'var(--high)', P2: 'var(--low)', P3: 'var(--info)',
  };
  const color = colors[priority] ?? 'var(--info)';
  return (
    <span
      style={{
        color, border: `1px solid ${color}55`, background: 'transparent',
        padding: '0.05rem 0.4rem', borderRadius: 4,
        fontFamily: 'var(--font-mono)', fontSize: '0.72rem', fontWeight: 650,
      }}
    >
      {priority}
    </span>
  );
}

export function Tag({ children, tone = 'neutral' }: { children: ReactNode; tone?: 'neutral' | 'accent' | 'warn' | 'good' }) {
  const tones = {
    neutral: { color: 'var(--ink-3)', bg: 'var(--surface-2)', border: 'var(--border)' },
    accent: { color: 'var(--accent)', bg: 'var(--accent-soft)', border: 'var(--accent)' },
    warn: { color: 'var(--medium)', bg: 'var(--medium-soft)', border: 'var(--medium)' },
    good: { color: 'var(--good)', bg: 'var(--good-soft)', border: 'var(--good)' },
  }[tone];
  return (
    <span
      style={{
        color: tones.color, background: tones.bg, border: `1px solid ${tones.border}33`,
        padding: '0.05rem 0.4rem', borderRadius: 4, fontSize: '0.74rem', whiteSpace: 'nowrap',
      }}
    >
      {children}
    </span>
  );
}

export function Mono({ children }: { children: ReactNode }) {
  return (
    <code style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem', color: 'var(--ink-2)', wordBreak: 'break-all' }}>
      {children}
    </code>
  );
}

export function CodeBlock({ children, label }: { children: ReactNode; label?: string }) {
  return (
    <figure style={{ margin: '0.5rem 0' }}>
      {label ? (
        <figcaption
          style={{
            fontFamily: 'var(--font-mono)', fontSize: '0.74rem', color: 'var(--ink-3)',
            padding: '0.25rem 0.5rem', background: 'var(--surface-2)',
            border: '1px solid var(--border)', borderBottom: 'none',
            borderRadius: '6px 6px 0 0',
          }}
        >
          {label}
        </figcaption>
      ) : null}
      <pre
        style={{
          margin: 0, padding: '0.6rem 0.7rem', background: 'var(--surface-2)',
          border: '1px solid var(--border)', borderRadius: label ? '0 0 6px 6px' : 6,
          overflowX: 'auto', fontFamily: 'var(--font-mono)', fontSize: '0.8rem',
          lineHeight: 1.5, color: 'var(--ink)',
        }}
      >
        <code>{children}</code>
      </pre>
    </figure>
  );
}

export function Stat({ label, value, hint, tone }: {
  label: string; value: ReactNode; hint?: string; tone?: 'critical' | 'good' | 'neutral';
}) {
  const color = tone === 'critical' ? 'var(--critical)' : tone === 'good' ? 'var(--good)' : 'var(--ink)';
  return (
    <div>
      <div style={{ fontSize: '0.76rem', color: 'var(--ink-3)', textTransform: 'uppercase', letterSpacing: '0.05em', fontWeight: 600 }}>
        {label}
      </div>
      <div style={{ fontSize: '1.5rem', fontWeight: 650, color, letterSpacing: '-0.02em', lineHeight: 1.25, fontVariantNumeric: 'tabular-nums' }}>
        {value}
      </div>
      {hint ? <div style={{ fontSize: '0.78rem', color: 'var(--ink-3)', lineHeight: 1.45 }}>{hint}</div> : null}
    </div>
  );
}

/**
 * The limitations callout.
 *
 * Shown wherever findings or scores are displayed. A report that travels without
 * its caveats is how static analysis gets mistaken for proof.
 */
export function Caveat({ children, tone = 'warn' }: { children: ReactNode; tone?: 'warn' | 'neutral' }) {
  const color = tone === 'warn' ? 'var(--medium)' : 'var(--ink-3)';
  const bg = tone === 'warn' ? 'var(--medium-soft)' : 'var(--surface-2)';
  return (
    <aside
      style={{
        background: bg, borderLeft: `3px solid ${color}`, border: '1px solid var(--border)',
        borderLeftWidth: 3, borderRadius: 6, padding: '0.7rem 0.9rem',
        fontSize: '0.85rem', color: 'var(--ink-2)', lineHeight: 1.55,
      }}
    >
      {children}
    </aside>
  );
}

export function EmptyState({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div
      style={{
        textAlign: 'center', padding: '2.5rem 1.5rem', color: 'var(--ink-3)',
        border: '1px dashed var(--border-strong)', borderRadius: 10, background: 'var(--surface)',
      }}
    >
      <p style={{ margin: 0, fontWeight: 600, color: 'var(--ink-2)' }}>{title}</p>
      {children ? <div style={{ marginTop: '0.4rem', fontSize: '0.86rem' }}>{children}</div> : null}
    </div>
  );
}

export function Table({ head, children, caption }: { head: ReactNode[]; children: ReactNode; caption?: string }) {
  return (
    <div style={{ overflowX: 'auto', border: '1px solid var(--border)', borderRadius: 8 }}>
      <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.86rem' }}>
        {caption ? <caption className="sr-only">{caption}</caption> : null}
        <thead>
          <tr>
            {head.map((h, i) => (
              <th
                key={i}
                scope="col"
                style={{
                  textAlign: 'left', padding: '0.5rem 0.65rem', background: 'var(--surface-2)',
                  borderBottom: '1px solid var(--border)', fontWeight: 600,
                  fontSize: '0.78rem', color: 'var(--ink-2)', whiteSpace: 'nowrap',
                }}
              >
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>{children}</tbody>
      </table>
    </div>
  );
}

export function Td({ children, mono, nowrap }: { children: ReactNode; mono?: boolean; nowrap?: boolean }) {
  return (
    <td
      style={{
        padding: '0.5rem 0.65rem', borderBottom: '1px solid var(--border)',
        verticalAlign: 'top',
        fontFamily: mono ? 'var(--font-mono)' : undefined,
        fontSize: mono ? '0.78rem' : undefined,
        whiteSpace: nowrap ? 'nowrap' : undefined,
      }}
    >
      {children}
    </td>
  );
}

/** A labelled meter. `value` of null renders as "not assessed", never as zero. */
export function ScoreBar({ value, weight }: { value: number | null; weight?: number }) {
  if (value === null) {
    return (
      <div style={{ fontSize: '0.8rem', color: 'var(--ink-3)', fontStyle: 'italic' }}>
        not assessed
      </div>
    );
  }
  const color = value >= 90 ? 'var(--good)' : value >= 75 ? 'var(--low)' : value >= 60 ? 'var(--medium)' : value >= 40 ? 'var(--high)' : 'var(--critical)';
  return (
    <div
      role="meter"
      aria-valuenow={value}
      aria-valuemin={0}
      aria-valuemax={100}
      aria-label={`score ${value} of 100${weight ? `, weighted ${Math.round(weight * 100)}%` : ''}`}
      style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}
    >
      <div style={{ flex: 1, height: 6, background: 'var(--surface-3)', borderRadius: 999, overflow: 'hidden', minWidth: 60 }}>
        <div style={{ width: `${value}%`, height: '100%', background: color }} />
      </div>
      <span style={{ fontVariantNumeric: 'tabular-nums', fontWeight: 650, fontSize: '0.86rem', minWidth: '2.2rem', textAlign: 'right' }}>
        {value}
      </span>
    </div>
  );
}
