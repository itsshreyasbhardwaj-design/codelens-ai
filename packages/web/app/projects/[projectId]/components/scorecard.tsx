import { DIMENSION_LABEL, SEVERITY_ORDER, gradeLabel, severityStyle } from '../../../lib/format.ts';
import { Card, Caveat, ScoreBar, SectionHeading } from '../../../components/ui.tsx';
import type { ScoreRow } from '../../../lib/store.ts';

/**
 * Health scorecard.
 *
 * Server component. Every number arrives as a plain prop computed by the store
 * from counted findings; nothing here is estimated. A dimension whose score is
 * null renders as "Insufficient evidence" with the recorded reason — never as a
 * zero and never as an empty bar.
 */

/**
 * Mirrors `toGrade` in @codelens/core. The store persists a grade per dimension
 * but not for the weighted total, so the total's letter is derived here from the
 * same thresholds.
 */
function letterGrade(score: number): 'A' | 'B' | 'C' | 'D' | 'F' {
  if (score >= 90) return 'A';
  if (score >= 75) return 'B';
  if (score >= 60) return 'C';
  if (score >= 40) return 'D';
  return 'F';
}

/** Mirrors MIN_ASSESSED_WEIGHT in @codelens/core. */
const MIN_ASSESSED_WEIGHT = 0.5;

function gradeColour(grade: string): string {
  switch (grade) {
    case 'A': return 'var(--good)';
    case 'B': return 'var(--low)';
    case 'C': return 'var(--medium)';
    case 'D': return 'var(--high)';
    case 'F': return 'var(--critical)';
    default: return 'var(--ink-3)';
  }
}

function GradePill({ grade }: { grade: string }) {
  const colour = gradeColour(grade);
  return (
    <span
      style={{
        color: colour,
        background: 'var(--surface)',
        border: `1px solid ${colour}66`,
        borderRadius: 4,
        padding: '0.08rem 0.45rem',
        fontSize: '0.76rem',
        fontWeight: 650,
        whiteSpace: 'nowrap',
      }}
    >
      {gradeLabel(grade)}
    </span>
  );
}

/** Finding counts per severity. The number and the severity word carry the meaning; colour is additional. */
function FindingCounts({ counts }: { counts: Record<string, number> }) {
  const present = SEVERITY_ORDER.filter((s) => (counts[s] ?? 0) > 0);
  if (present.length === 0) {
    return (
      <p style={{ margin: 0, fontSize: '0.8rem', color: 'var(--ink-3)' }}>
        No findings in this category.
      </p>
    );
  }
  return (
    <ul style={{ margin: 0, padding: 0, listStyle: 'none', display: 'flex', flexWrap: 'wrap', gap: '0.3rem' }}>
      {present.map((s) => {
        const { color, bg } = severityStyle(s);
        return (
          <li
            key={s}
            style={{
              color, background: bg, border: `1px solid ${color}33`,
              borderRadius: 4, padding: '0 0.35rem',
              fontSize: '0.78rem', fontVariantNumeric: 'tabular-nums', whiteSpace: 'nowrap',
            }}
          >
            {counts[s]} {s}
          </li>
        );
      })}
    </ul>
  );
}

function endWithStop(text: string): string {
  return /[.!?]$/.test(text.trim()) ? text.trim() : `${text.trim()}.`;
}

export function Scorecard({ overall, assessedWeight, dimensions }: {
  /** Weighted total, or null when too little could be graded to total one. */
  overall: number | null;
  /** Share of the configured weight that was gradeable, 0..1. */
  assessedWeight: number;
  dimensions: ScoreRow[];
}) {
  const ungraded = dimensions.filter((d) => d.score === null);
  const assessedPct = Math.round(assessedWeight * 100);

  return (
    <Card>
      <SectionHeading
        id="scorecard"
        hint="Each dimension starts at 100 and loses points per finding, weighted by severity and confidence. No score on this page is model-generated."
      >
        Health scorecard
      </SectionHeading>

      <div
        style={{
          display: 'flex', alignItems: 'center', gap: '1rem', flexWrap: 'wrap',
          padding: '0.85rem 0', borderBottom: '1px solid var(--border)', marginBottom: '0.9rem',
        }}
      >
        {overall === null ? (
          <div style={{ flex: 1, minWidth: 220 }}>
            <p style={{ margin: 0, fontWeight: 650, color: 'var(--ink)' }}>Overall score withheld</p>
            <p style={{ margin: '0.25rem 0 0', fontSize: '0.86rem', color: 'var(--ink-2)', lineHeight: 1.5 }}>
              Only {assessedPct}% of the configured weight could be graded, below the{' '}
              {Math.round(MIN_ASSESSED_WEIGHT * 100)}% minimum this product requires before it will total a
              score. Too little of this project was assessed for a single number to mean anything, so none is
              shown. Read the dimensions below individually.
            </p>
          </div>
        ) : (
          <>
            <div>
              <div
                style={{
                  fontSize: '0.76rem', color: 'var(--ink-3)', textTransform: 'uppercase',
                  letterSpacing: '0.05em', fontWeight: 600,
                }}
              >
                Overall
              </div>
              <div style={{ display: 'flex', alignItems: 'baseline', gap: '0.4rem' }}>
                <span
                  style={{
                    fontSize: '2.4rem', fontWeight: 650, lineHeight: 1.05,
                    letterSpacing: '-0.03em', fontVariantNumeric: 'tabular-nums',
                    color: gradeColour(letterGrade(overall)),
                  }}
                >
                  {overall}
                </span>
                <span style={{ color: 'var(--ink-3)', fontSize: '0.9rem' }}>/ 100</span>
                <GradePill grade={letterGrade(overall)} />
              </div>
            </div>
            <div style={{ flex: 1, minWidth: '12rem' }}>
              <ScoreBar value={overall} />
              <p style={{ margin: '0.4rem 0 0', fontSize: '0.82rem', color: 'var(--ink-2)', lineHeight: 1.5 }}>
                Graded on {assessedPct}% of the configured weight
                {ungraded.length > 0
                  ? `; the remaining ${100 - assessedPct}% was not assessed and is excluded rather than counted as full marks.`
                  : '.'}
              </p>
            </div>
          </>
        )}
      </div>

      <p style={{ margin: '0 0 0.9rem', fontSize: '0.84rem', color: 'var(--ink-3)', lineHeight: 1.5 }}>
        The eight weights below are configurable product weights, not scientific guarantees — they express how
        this product ranks the dimensions, not a measured relationship to real-world risk.
      </p>

      {ungraded.length > 0 ? (
        <div style={{ marginBottom: '0.9rem' }}>
          <Caveat>
            {ungraded.length} of {dimensions.length} dimensions could not be graded
            {' '}({ungraded.map((d) => DIMENSION_LABEL[d.dimension] ?? d.dimension).join(', ')}). An ungraded
            dimension is not a clean one: nothing was assessed there.
          </Caveat>
        </div>
      ) : null}

      {dimensions.length === 0 ? (
        <p style={{ margin: 0, color: 'var(--ink-2)', lineHeight: 1.6 }}>
          This scan recorded no dimension scores at all, so there is nothing to grade in any category. That is
          an absence of assessment, not a clean result.
        </p>
      ) : null}

      <ul
        style={{
          margin: 0, padding: 0, listStyle: 'none',
          display: 'grid', gap: '0.6rem', gridTemplateColumns: 'repeat(auto-fit, minmax(16rem, 1fr))',
        }}
      >
        {dimensions.map((d) => (
          <li
            key={d.dimension}
            style={{
              background: 'var(--surface-2)', border: '1px solid var(--border)', borderRadius: 8,
              padding: '0.7rem 0.8rem', display: 'grid', gap: '0.45rem', alignContent: 'start',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'baseline', justifyContent: 'space-between', gap: '0.5rem', flexWrap: 'wrap' }}>
              <h3 style={{ margin: 0, fontSize: '0.92rem', fontWeight: 650, letterSpacing: '-0.01em' }}>
                {DIMENSION_LABEL[d.dimension] ?? d.dimension}
              </h3>
              <span style={{ fontSize: '0.76rem', color: 'var(--ink-3)', whiteSpace: 'nowrap', fontVariantNumeric: 'tabular-nums' }}>
                weight {Math.round(d.weight * 100)}%
              </span>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '0.55rem', flexWrap: 'wrap' }}>
              <GradePill grade={d.grade} />
              <div style={{ flex: 1, minWidth: '7rem' }}>
                <ScoreBar value={d.score} weight={d.weight} />
              </div>
            </div>

            {d.score === null ? (
              <p style={{ margin: 0, fontSize: '0.82rem', color: 'var(--ink-2)', lineHeight: 1.5 }}>
                Why it could not be graded:{' '}
                {d.reason ? endWithStop(d.reason) : 'no reason was recorded with this scan.'}
              </p>
            ) : null}

            <FindingCounts counts={d.counts} />
          </li>
        ))}
      </ul>
    </Card>
  );
}
