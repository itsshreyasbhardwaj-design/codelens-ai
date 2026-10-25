import type { ReactNode } from 'react';
import {
  CATEGORY_LABEL,
  CONFIDENCE_MEANING,
  DETECTION_SOURCE_LABEL,
  PRIORITY_MEANING,
} from '../../../lib/format.ts';
import {
  Caveat,
  CodeBlock,
  ConfidencePill,
  Mono,
  PriorityPill,
  SeverityPill,
  StatusPill,
  Tag,
} from '../../../components/ui.tsx';

/**
 * Full evidence inspection for one finding.
 *
 * This component is the reason the explorer exists: a user decides whether a
 * finding is real, so every claim is shown next to the excerpt it rests on,
 * whether that excerpt was verified against the snapshot, and — for a
 * cross-file finding — the ordered chain that was traced. Severity and
 * confidence are rendered as two separate indicators with their own
 * explanations; they are never merged.
 *
 * The props mirror `FindingRow` in app/lib/store.ts rather than importing it,
 * because store.ts is server-only and this component renders inside the client
 * explorer.
 */

export interface Evidence {
  file: string;
  startLine?: number;
  endLine?: number;
  symbol?: string;
  excerpt?: string;
  note?: string;
  verified: boolean;
}

export interface TraceStep {
  file: string;
  line?: number;
  symbol?: string;
  detail: string;
}

export interface Trace {
  kind: string;
  complete: boolean;
  steps: TraceStep[];
}

export interface Finding {
  displayId: string;
  ruleId: string;
  title: string;
  category: string;
  severity: string;
  confidence: string;
  status: string;
  detectionSource: string;
  priority?: string;
  priorityScore?: number;
  priorityRationale?: string;
  files: string[];
  explanation: string;
  userImpact: string;
  likelyRootCause?: string;
  downstream: string[];
  remediation: string;
  effort: string;
  verificationSteps: string[];
  references: string[];
  affectedFeatures: string[];
  relatedTests: string[];
  trace?: Trace;
  evidence: Evidence[];
  firstDetectedScanId?: string;
}

/**
 * Plain-language gloss for each status value.
 *
 * format.ts exports STATUS_LABEL but no meaning map, and the brief requires the
 * status to be explained, so the glosses live here rather than in the shared
 * module (which other surfaces are editing concurrently).
 */
const STATUS_MEANING: Record<string, string> = {
  confirmed: 'The evidence settles this; no further confirmation is needed.',
  strongly_supported: 'The evidence is clear, but nothing was executed to confirm it.',
  suspected: 'Consistent with the evidence rather than established by it.',
  needs_runtime_verification: 'Source alone cannot settle this; run the verification steps below.',
  resolved: 'Recorded as fixed.',
  accepted_risk: 'Reviewed and accepted as it stands.',
  false_positive: 'Reviewed and rejected as a mis-detection.',
};

const EFFORT_LABEL: Record<string, string> = {
  trivial: 'Trivial',
  small: 'Small',
  medium: 'Medium',
  large: 'Large',
};

const TRACE_KIND_LABEL: Record<string, string> = {
  import: 'Import chain',
  call: 'Call chain',
  data_flow: 'Data flow',
  route_handler: 'Route to handler',
  unused_integration: 'Unreachable integration',
};

/** `file:line` for an evidence entry or trace step, with no invented line number. */
export function atLine(file: string, line?: number, endLine?: number): string {
  if (line === undefined) return file;
  if (endLine !== undefined && endLine !== line) return `${file}:${line}-${endLine}`;
  return `${file}:${line}`;
}

function Heading({ children, level = 3 }: { children: ReactNode; level?: 3 | 4 }) {
  const Tag_ = level === 3 ? 'h3' : 'h4';
  return (
    <Tag_
      style={{
        margin: '0 0 0.5rem',
        fontSize: level === 3 ? '0.95rem' : '0.86rem',
        fontWeight: 650,
        letterSpacing: '-0.005em',
        color: 'var(--ink)',
      }}
    >
      {children}
    </Tag_>
  );
}

function Label({ children }: { children: ReactNode }) {
  return (
    <dt
      style={{
        fontSize: '0.72rem',
        textTransform: 'uppercase',
        letterSpacing: '0.05em',
        fontWeight: 650,
        color: 'var(--ink-3)',
        marginTop: '0.7rem',
      }}
    >
      {children}
    </dt>
  );
}

function Value({ children }: { children: ReactNode }) {
  return (
    <dd style={{ margin: '0.15rem 0 0', color: 'var(--ink-2)', fontSize: '0.88rem', lineHeight: 1.6 }}>
      {children}
    </dd>
  );
}

function Absent({ children }: { children: ReactNode }) {
  return <span style={{ fontStyle: 'italic', color: 'var(--ink-3)' }}>{children}</span>;
}

function Prose({ children }: { children: ReactNode }) {
  return (
    <p style={{ margin: '0.15rem 0 0', color: 'var(--ink-2)', fontSize: '0.88rem', lineHeight: 1.6 }}>
      {children}
    </p>
  );
}

function Block({ children }: { children: ReactNode }) {
  return <div style={{ marginTop: '1.1rem' }}>{children}</div>;
}

function Bullets({ items }: { items: string[] }) {
  return (
    <ul style={{ margin: '0.2rem 0 0', paddingLeft: '1.15rem', color: 'var(--ink-2)', fontSize: '0.88rem', lineHeight: 1.6 }}>
      {items.map((item, i) => (
        <li key={i} style={{ marginTop: '0.15rem' }}>{item}</li>
      ))}
    </ul>
  );
}

function TagRow({ children }: { children: ReactNode }) {
  return <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.3rem', marginTop: '0.25rem' }}>{children}</div>;
}

/** One evidence entry: the location, the excerpt, why it matters, and whether it was verified. */
function EvidenceEntry({ entry, index }: { entry: Evidence; index: number }) {
  const location = atLine(entry.file, entry.startLine, entry.endLine);
  return (
    <li style={{ marginTop: index === 0 ? 0 : '1rem', listStyle: 'none' }}>
      <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: '0.4rem' }}>
        <Mono>{location}</Mono>
        {entry.symbol ? <Tag>in {entry.symbol}</Tag> : null}
        {entry.verified ? (
          <Tag tone="good">Verified against the snapshot</Tag>
        ) : (
          <Tag tone="warn">Not verified against the snapshot</Tag>
        )}
      </div>
      {entry.excerpt ? (
        <CodeBlock label={location}>{entry.excerpt}</CodeBlock>
      ) : (
        <Prose><Absent>No excerpt was recorded for this location.</Absent></Prose>
      )}
      {entry.note ? <Prose>{entry.note}</Prose> : <Prose><Absent>No note explains this excerpt.</Absent></Prose>}
      {entry.verified ? null : (
        <div style={{ marginTop: '0.4rem' }}>
          <Caveat>
            This excerpt was not matched back against the stored snapshot, so the quotation itself is
            unconfirmed. Open the file before acting on it.
          </Caveat>
        </div>
      )}
    </li>
  );
}

/** The traced chain. Its prominence is the point: it is what makes a cross-file finding checkable. */
function TraceSection({ trace }: { trace: Trace }) {
  return (
    <Block>
      <div
        style={{
          border: '1px solid var(--border)',
          borderLeft: '3px solid var(--accent)',
          borderRadius: 8,
          padding: '0.9rem 1rem',
          background: 'var(--surface-2)',
        }}
      >
        <Heading level={4}>
          Traced relationship
          <span style={{ fontWeight: 500, color: 'var(--ink-3)' }}>
            {' '}&middot; {TRACE_KIND_LABEL[trace.kind] ?? trace.kind}
          </span>
        </Heading>
        <Prose>
          {trace.complete
            ? 'Every step below was resolved statically from the snapshot. Read it end to end to check the claim.'
            : 'The chain below is the part that could be resolved.'}
        </Prose>
        {trace.complete ? null : (
          <div style={{ marginTop: '0.6rem' }}>
            <Caveat>
              <strong>This chain is incomplete.</strong> At least one step could not be resolved
              statically — dynamic imports, reflection, and string-built routes are not traceable — so
              the connection needs manual confirmation before you act on it.
            </Caveat>
          </div>
        )}
        {trace.steps.length === 0 ? (
          <Prose><Absent>No steps were recorded for this trace.</Absent></Prose>
        ) : (
          <ol style={{ margin: '0.7rem 0 0', paddingLeft: '1.4rem', color: 'var(--ink-2)', fontSize: '0.88rem', lineHeight: 1.6 }}>
            {trace.steps.map((step, i) => (
              <li key={i} style={{ marginTop: i === 0 ? 0 : '0.5rem' }}>
                <Mono>{atLine(step.file, step.line)}</Mono>
                {step.symbol ? <> <Tag>in {step.symbol}</Tag></> : null}
                <div style={{ marginTop: '0.1rem' }}>{step.detail}</div>
              </li>
            ))}
          </ol>
        )}
      </div>
    </Block>
  );
}

export function FindingDetail({ finding, currentScanId }: { finding: Finding; currentScanId: string }) {
  const f = finding;
  const firstElsewhere = f.firstDetectedScanId !== undefined && f.firstDetectedScanId !== currentScanId;

  return (
    <div
      style={{
        borderTop: '1px solid var(--border)',
        padding: '1rem 0.1rem 0.4rem',
        display: 'grid',
        gap: 0,
      }}
    >
      {/* --------------------------------------------------- assessment --- */}
      <Heading>How this was assessed</Heading>
      <dl style={{ margin: 0 }}>
        <Label>Severity &mdash; the consequence if it is real</Label>
        <Value>
          <SeverityPill severity={f.severity} />
        </Value>

        <Label>Confidence &mdash; how well the evidence supports it</Label>
        <Value>
          <ConfidencePill confidence={f.confidence} />{' '}
          {CONFIDENCE_MEANING[f.confidence] ?? <Absent>No gloss is defined for this confidence level.</Absent>}
        </Value>

        <Label>Status</Label>
        <Value>
          <StatusPill status={f.status} />{' '}
          {STATUS_MEANING[f.status] ?? <Absent>No gloss is defined for this status.</Absent>}
        </Value>

        <Label>Priority</Label>
        <Value>
          {f.priority ? (
            <>
              <PriorityPill priority={f.priority} />{' '}
              {PRIORITY_MEANING[f.priority] ?? ''}
              {f.priorityScore === undefined ? null : (
                <>
                  {' '}
                  <span style={{ color: 'var(--ink-3)' }}>
                    Priority score {f.priorityScore.toFixed(2)} of 100.
                  </span>
                </>
              )}
              {f.priorityRationale ? <div style={{ marginTop: '0.25rem' }}>{f.priorityRationale}</div> : (
                <div style={{ marginTop: '0.25rem' }}><Absent>No rationale was recorded.</Absent></div>
              )}
            </>
          ) : (
            <Absent>Not prioritised.</Absent>
          )}
        </Value>

        <Label>Detection source</Label>
        <Value>{DETECTION_SOURCE_LABEL[f.detectionSource] ?? f.detectionSource}</Value>

        <Label>Category</Label>
        <Value>{CATEGORY_LABEL[f.category] ?? f.category}</Value>

        <Label>Identifiers</Label>
        <Value>
          <Mono>{f.displayId}</Mono> &middot; rule <Mono>{f.ruleId}</Mono>
        </Value>

        <Label>Files</Label>
        <Value>
          {f.files.length === 0 ? (
            <Absent>No file was recorded on the finding itself; see the evidence below.</Absent>
          ) : (
            <TagRow>{f.files.map((file) => <Mono key={file}>{file}</Mono>)}</TagRow>
          )}
        </Value>
      </dl>

      {/* ----------------------------------------------------- evidence --- */}
      <Block>
        <Heading>
          Evidence
          <span style={{ fontWeight: 500, color: 'var(--ink-3)' }}>
            {' '}&middot; {f.evidence.length} {f.evidence.length === 1 ? 'entry' : 'entries'}
          </span>
        </Heading>
        {f.evidence.length === 0 ? (
          <Prose><Absent>No evidence entries were recorded for this finding.</Absent></Prose>
        ) : (
          <ul style={{ margin: 0, padding: 0 }}>
            {f.evidence.map((entry, i) => (
              <EvidenceEntry key={`${entry.file}:${entry.startLine ?? i}:${i}`} entry={entry} index={i} />
            ))}
          </ul>
        )}
      </Block>

      {/* -------------------------------------------------------- trace --- */}
      {f.trace ? <TraceSection trace={f.trace} /> : null}

      {/* ------------------------------------------------- explanation --- */}
      <Block>
        <Heading>What is happening and why it matters</Heading>
        <dl style={{ margin: 0 }}>
          <Label>Technical explanation</Label>
          <Value>{f.explanation}</Value>

          <Label>What a user would experience</Label>
          <Value>{f.userImpact}</Value>

          <Label>Likely root cause</Label>
          <Value>
            {f.likelyRootCause ?? <Absent>Not determined from the snapshot.</Absent>}
          </Value>

          <Label>Downstream consequences</Label>
          <Value>
            {f.downstream.length === 0
              ? <Absent>None recorded.</Absent>
              : <Bullets items={f.downstream} />}
          </Value>
        </dl>
      </Block>

      {/* ------------------------------------------------- remediation --- */}
      <Block>
        <Heading>Putting it right</Heading>
        <dl style={{ margin: 0 }}>
          <Label>Remediation</Label>
          <Value>{f.remediation}</Value>

          <Label>Remediation effort</Label>
          <Value>{EFFORT_LABEL[f.effort] ?? f.effort}</Value>

          <Label>Verification steps</Label>
          <Value>
            {f.verificationSteps.length === 0
              ? <Absent>None recorded.</Absent>
              : <ol style={{ margin: '0.2rem 0 0', paddingLeft: '1.3rem', lineHeight: 1.6 }}>
                  {f.verificationSteps.map((step, i) => <li key={i} style={{ marginTop: '0.15rem' }}>{step}</li>)}
                </ol>}
          </Value>
        </dl>
      </Block>

      {/* ------------------------------------------------------ context --- */}
      <Block>
        <Heading>References and context</Heading>
        <dl style={{ margin: 0 }}>
          <Label>References</Label>
          <Value>
            {f.references.length === 0
              ? <Absent>None recorded.</Absent>
              : <TagRow>{f.references.map((r) => <Tag key={r}>{r}</Tag>)}</TagRow>}
          </Value>

          <Label>Affected features</Label>
          <Value>
            {f.affectedFeatures.length === 0
              ? <Absent>No feature was attributed to this finding.</Absent>
              : <TagRow>{f.affectedFeatures.map((x) => <Tag key={x} tone="accent">{x}</Tag>)}</TagRow>}
          </Value>

          <Label>Related tests</Label>
          <Value>
            {f.relatedTests.length === 0
              ? <Absent>No test in the snapshot covers this.</Absent>
              : <TagRow>{f.relatedTests.map((t) => <Mono key={t}>{t}</Mono>)}</TagRow>}
          </Value>

          {firstElsewhere ? (
            <>
              <Label>First detected</Label>
              <Value>
                An earlier scan reported this first: <Mono>{f.firstDetectedScanId}</Mono>. It is not new in
                the scan shown here.
              </Value>
            </>
          ) : null}
        </dl>
      </Block>
    </div>
  );
}
