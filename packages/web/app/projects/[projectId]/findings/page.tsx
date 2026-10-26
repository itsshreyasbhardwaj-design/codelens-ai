import type { ReactNode } from 'react';
import {
  getProject,
  listScans,
  scanFeatures,
  scanFindings,
  scanStages,
} from '../../../lib/store.ts';
import {
  CONFIDENCE_MEANING,
  CONFIDENCE_ORDER,
  PRIORITY_ORDER,
  SEVERITY_ORDER,
  formatRelative,
  pluralize,
  severityStyle,
} from '../../../lib/format.ts';
import { Card, Caveat, EmptyState, Mono, SectionHeading } from '../../../components/ui.tsx';
import { Shell, TopBar, projectTabs } from '../../../components/nav.tsx';
import { EMPTY_FILTERS, FindingsExplorer } from './explorer.tsx';
import type { Filters, GroupKey } from './explorer.tsx';
import type { Finding } from './finding-detail.tsx';
import { requireSession } from '../../../lib/session.ts';

/**
 * Findings explorer, server side.
 *
 * Loads one scan (the latest by default, or `?scan=<id>`), summarises it along
 * the three independent axes a reader needs — severity, priority, confidence —
 * and hands the findings to the client explorer as plain props. The confidence
 * breakdown is not decoration: it is how a reader sees how much of the report
 * is confirmed rather than suspected.
 */

export const dynamic = 'force-dynamic';

const GROUP_KEYS: GroupKey[] = ['priority', 'category', 'severity', 'file', 'feature'];

const PRIORITY_COLOR: Record<string, string> = {
  P0: 'var(--critical)', P1: 'var(--high)', P2: 'var(--low)', P3: 'var(--info)',
};

/** Cooler as the evidence gets stronger. Every segment is labelled, so colour is never the only signal. */
const CONFIDENCE_COLOR: Record<string, string> = {
  confirmed: 'var(--good)', strong: 'var(--low)', moderate: 'var(--medium)', weak: 'var(--high)',
};

function first(value: string | string[] | undefined): string | undefined {
  return Array.isArray(value) ? value[0] : value;
}

interface BreakdownRow { key: string; label: string; count: number; color: string }

/**
 * One axis of the summary: a proportional bar plus the real numbers.
 *
 * The bar is decorative; the list underneath carries every count, so nothing
 * depends on reading a colour or estimating a width.
 */
function Breakdown({ title, note, rows, total }: {
  title: string; note: string; rows: BreakdownRow[]; total: number;
}) {
  return (
    <div>
      <h3 style={{ margin: 0, fontSize: '0.78rem', textTransform: 'uppercase', letterSpacing: '0.05em', fontWeight: 650, color: 'var(--ink-3)' }}>
        {title}
      </h3>
      <p style={{ margin: '0.15rem 0 0.5rem', fontSize: '0.8rem', color: 'var(--ink-3)', lineHeight: 1.45 }}>
        {note}
      </p>
      {total > 0 ? (
        <div
          aria-hidden="true"
          style={{ display: 'flex', height: 8, borderRadius: 999, overflow: 'hidden', background: 'var(--surface-3)' }}
        >
          {rows.filter((r) => r.count > 0).map((r) => (
            <div key={r.key} style={{ width: `${(r.count / total) * 100}%`, background: r.color }} />
          ))}
        </div>
      ) : null}
      <ul style={{ listStyle: 'none', margin: '0.5rem 0 0', padding: 0, display: 'grid', gap: '0.15rem' }}>
        {rows.map((r) => (
          <li key={r.key} style={{ display: 'flex', alignItems: 'baseline', gap: '0.4rem', fontSize: '0.86rem' }}>
            <span
              aria-hidden="true"
              style={{ width: 9, height: 9, borderRadius: 2, background: r.color, flex: 'none', transform: 'translateY(-1px)' }}
            />
            <span style={{ color: 'var(--ink-2)', flex: 1, minWidth: 0 }}>{r.label}</span>
            <span style={{ fontVariantNumeric: 'tabular-nums', fontWeight: 650 }}>{r.count}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

function PageFrame({ projectId, children }: { projectId: string; children: ReactNode }) {
  const base = `/projects/${encodeURIComponent(projectId)}`;
  return (
    <>
      <TopBar tabs={projectTabs(projectId)} current={`${base}/findings`} context={projectId} />
      <Shell>
        {/*
          A grid column of `minmax(0, 1fr)` rather than the default `auto`: a
          code excerpt or a long path must scroll inside its own box instead of
          widening the page, which is what forces a horizontal scrollbar on a
          narrow screen.
        */}
        <div style={{ display: 'grid', gap: '1.25rem', gridTemplateColumns: 'minmax(0, 1fr)' }}>
          {children}
        </div>
      </Shell>
    </>
  );
}

export default async function FindingsPage({ params, searchParams }: {
  params: Promise<{ projectId: string }>;
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const { projectId } = await params;
  const query = await searchParams;

  const { organizationId } = await requireSession();
  const project = getProject(organizationId, projectId);
  if (!project) {
    return (
      <PageFrame projectId={projectId}>
        <h1 style={{ margin: 0, fontSize: '1.5rem', letterSpacing: '-0.02em' }}>Findings</h1>
        <EmptyState title="No such project">
          <p style={{ margin: 0 }}>
            Nothing is stored under the identifier <Mono>{projectId}</Mono>. Check the address, or scan
            the codebase first.
          </p>
        </EmptyState>
      </PageFrame>
    );
  }

  const scans = listScans(organizationId, projectId);
  if (scans.length === 0) {
    return (
      <PageFrame projectId={projectId}>
        <h1 style={{ margin: 0, fontSize: '1.5rem', letterSpacing: '-0.02em' }}>Findings</h1>
        <EmptyState title="This project has not been scanned">
          <p style={{ margin: 0 }}>
            {project.name} exists but holds no scan, so there is nothing to report. Run a scan to
            produce findings.
          </p>
        </EmptyState>
      </PageFrame>
    );
  }

  const requestedScan = first(query.scan);
  const scan = (requestedScan ? scans.find((s) => s.id === requestedScan) : undefined) ?? scans[0];
  const scanNotFound = requestedScan !== undefined && requestedScan !== scan.id;

  const findings: Finding[] = scanFindings(scan.id).map((f) => ({
    displayId: f.displayId,
    ruleId: f.ruleId,
    title: f.title,
    category: f.category,
    severity: f.severity,
    confidence: f.confidence,
    status: f.status,
    detectionSource: f.detectionSource,
    priority: f.priority,
    priorityScore: f.priorityScore,
    priorityRationale: f.priorityRationale,
    files: f.files,
    explanation: f.explanation,
    userImpact: f.userImpact,
    likelyRootCause: f.likelyRootCause,
    downstream: f.downstream,
    remediation: f.remediation,
    effort: f.effort,
    verificationSteps: f.verificationSteps,
    references: f.references,
    affectedFeatures: f.affectedFeatures,
    relatedTests: f.relatedTests,
    trace: f.trace
      ? { kind: f.trace.kind, complete: f.trace.complete, steps: f.trace.steps }
      : undefined,
    evidence: f.evidence,
    firstDetectedScanId: f.firstDetectedScanId,
  }));

  const featureNames = scanFeatures(scan.id).map((x) => x.name).sort((a, b) => a.localeCompare(b));
  const stages = scanStages(scan.id);

  /**
   * The number of findings the evidence gate refused.
   *
   * store.ts does not expose the refusal count directly, so it is derived from
   * the consolidation stage's warnings — the pipeline records exactly one
   * `refused "<title>": <reason>` warning per refused finding. When that stage
   * is absent nothing is claimed.
   */
  const consolidation = stages.find((s) => s.name === 'finding_consolidation');
  const refusals = consolidation
    ? consolidation.warnings.filter((w) => w.startsWith('refused "'))
    : undefined;

  const dynamicStage = stages.find((s) => s.name === 'dynamic_verification');
  const aiStage = stages.find((s) => s.name === 'ai_semantic_investigation');

  // ----------------------------------------------- filters from the URL -----
  const valueSets: Record<string, Set<string>> = {
    category: new Set(findings.map((f) => f.category)),
    severity: new Set(findings.map((f) => f.severity)),
    confidence: new Set(findings.map((f) => f.confidence)),
    status: new Set(findings.map((f) => f.status)),
    priority: new Set(findings.flatMap((f) => (f.priority ? [f.priority] : []))),
    source: new Set(findings.map((f) => f.detectionSource)),
    feature: new Set([...featureNames, ...findings.flatMap((f) => f.affectedFeatures)]),
    effort: new Set(findings.map((f) => f.effort)),
  };

  const filters: Filters = { ...EMPTY_FILTERS, q: first(query.q) ?? '' };
  for (const key of Object.keys(valueSets) as Array<keyof typeof valueSets>) {
    const requested = first(query[key]);
    // A value that is not in this scan is dropped rather than shown as a
    // filter that silently matches nothing.
    if (requested && valueSets[key].has(requested)) {
      filters[key as keyof Filters] = requested;
    }
  }

  const requestedGroup = first(query.group);
  const group: GroupKey = GROUP_KEYS.includes(requestedGroup as GroupKey)
    ? (requestedGroup as GroupKey)
    : 'priority';

  // ------------------------------------------------------- breakdowns -------
  const total = findings.length;
  const bySeverity: BreakdownRow[] = SEVERITY_ORDER.map((s) => ({
    key: s,
    label: `${s.charAt(0).toUpperCase()}${s.slice(1)}`,
    count: findings.filter((f) => f.severity === s).length,
    color: severityStyle(s).color,
  }));
  const byPriority: BreakdownRow[] = [
    ...PRIORITY_ORDER.map((p) => ({
      key: p,
      label: p,
      count: findings.filter((f) => f.priority === p).length,
      color: PRIORITY_COLOR[p],
    })),
    {
      key: 'none',
      label: 'Not prioritised',
      count: findings.filter((f) => !f.priority).length,
      color: 'var(--border-strong)',
    },
  ].filter((r) => r.key !== 'none' || r.count > 0);
  const byConfidence: BreakdownRow[] = CONFIDENCE_ORDER.map((c) => ({
    key: c,
    label: `${c.charAt(0).toUpperCase()}${c.slice(1)}`,
    count: findings.filter((f) => f.confidence === c).length,
    color: CONFIDENCE_COLOR[c],
  }));

  const base = `/projects/${encodeURIComponent(projectId)}`;

  return (
    <PageFrame projectId={projectId}>
      <div>
        <h1 style={{ margin: 0, fontSize: '1.5rem', letterSpacing: '-0.02em' }}>Findings</h1>
        <p style={{ margin: '0.3rem 0 0', color: 'var(--ink-3)', fontSize: '0.88rem' }}>
          {project.name} &middot; {pluralize(total, 'finding')} in scan{' '}
          <Mono>{scan.id}</Mono> &middot; {scan.status} &middot; {formatRelative(scan.finishedAt ?? scan.queuedAt)}
          {scans.length > 1 ? <> &middot; {pluralize(scans.length, 'scan')} on record</> : null}
        </p>
      </div>

      {scanNotFound ? (
        <Caveat>
          No scan with the identifier <Mono>{requestedScan}</Mono> belongs to this project. The latest
          scan is shown instead.
        </Caveat>
      ) : null}

      {scans.length > 1 ? (
        <Card>
          <SectionHeading hint="Findings below belong to the selected scan only.">Scan</SectionHeading>
          <ul style={{ listStyle: 'none', margin: 0, padding: 0, display: 'flex', flexWrap: 'wrap', gap: '0.4rem' }}>
            {scans.map((s) => (
              <li key={s.id}>
                <a
                  href={`${base}/findings?scan=${encodeURIComponent(s.id)}`}
                  aria-current={s.id === scan.id ? 'true' : undefined}
                  style={{
                    display: 'inline-block', padding: '0.25rem 0.5rem', borderRadius: 6,
                    border: '1px solid var(--border)', fontSize: '0.8rem',
                    fontFamily: 'var(--font-mono)',
                    background: s.id === scan.id ? 'var(--surface-3)' : 'transparent',
                    color: s.id === scan.id ? 'var(--ink)' : 'var(--accent)',
                    textDecoration: s.id === scan.id ? 'none' : undefined,
                  }}
                >
                  {s.id} &middot; {formatRelative(s.finishedAt ?? s.queuedAt)}
                  {s.id === scan.id ? <span className="sr-only"> (showing)</span> : null}
                </a>
              </li>
            ))}
          </ul>
        </Card>
      ) : null}

      {total === 0 ? (
        <>
          <EmptyState title="This scan reported no findings">
            <p style={{ margin: 0 }}>
              The analysers that ran produced nothing for this snapshot. That means these checks found
              nothing — not that the code is free of defects.
            </p>
          </EmptyState>
          {refusals && refusals.length > 0 ? (
            <Caveat>
              {pluralize(refusals.length, 'candidate finding')} {refusals.length === 1 ? 'was' : 'were'}{' '}
              refused by the evidence gate before this report and {refusals.length === 1 ? 'is' : 'are'} not
              counted above.
            </Caveat>
          ) : null}
        </>
      ) : (
        <>
          <Card>
            <SectionHeading hint="Severity, priority and confidence are independent. A critical finding can still be only suspected, and this is where you see how many are.">
              What this scan found
            </SectionHeading>
            <div
              style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
                gap: '1.2rem',
              }}
            >
              <Breakdown
                title="By severity"
                note="The consequence if the finding is real."
                rows={bySeverity}
                total={total}
              />
              <Breakdown
                title="By priority"
                note="Severity, confidence, reach and effort combined into an order of work."
                rows={byPriority}
                total={total}
              />
              <Breakdown
                title="By confidence"
                note="How much of this report is established by the evidence rather than suspected from it."
                rows={byConfidence}
                total={total}
              />
            </div>
            <dl style={{ margin: '1.1rem 0 0', fontSize: '0.84rem', color: 'var(--ink-3)', lineHeight: 1.55 }}>
              {CONFIDENCE_ORDER.filter((c) => findings.some((f) => f.confidence === c)).map((c) => (
                <div key={c} style={{ display: 'flex', flexWrap: 'wrap', gap: '0.35rem' }}>
                  <dt style={{ fontWeight: 650, color: 'var(--ink-2)' }}>{c}:</dt>
                  <dd style={{ margin: 0 }}>{CONFIDENCE_MEANING[c]}</dd>
                </div>
              ))}
            </dl>
            {refusals ? (
              <p style={{ margin: '0.9rem 0 0', fontSize: '0.84rem', color: 'var(--ink-3)', lineHeight: 1.55 }}>
                {refusals.length === 0
                  ? 'The evidence gate refused no candidate findings in this scan.'
                  : `The evidence gate refused ${pluralize(refusals.length, 'candidate finding')} before this report; they are not included above.`}
              </p>
            ) : null}
            {refusals && refusals.length > 0 ? (
              <ul style={{ margin: '0.4rem 0 0', paddingLeft: '1.15rem', fontSize: '0.82rem', color: 'var(--ink-3)', lineHeight: 1.5 }}>
                {refusals.map((r, i) => <li key={i}>{r.replace(/^refused /, '')}</li>)}
              </ul>
            ) : null}
          </Card>

          <Caveat>
            <p style={{ margin: 0 }}>
              These findings come from static analysis of one snapshot. They show what these checks
              matched; they cannot prove a defect is absent.
            </p>
            {dynamicStage?.status === 'skipped' && dynamicStage.message ? (
              <p style={{ margin: '0.5rem 0 0' }}>{dynamicStage.message}</p>
            ) : null}
            {aiStage?.status === 'skipped' && aiStage.message ? (
              <p style={{ margin: '0.5rem 0 0' }}>{aiStage.message}</p>
            ) : null}
          </Caveat>

          <FindingsExplorer
            findings={findings}
            featureNames={featureNames}
            scanId={scan.id}
            scanParam={requestedScan && !scanNotFound ? requestedScan : undefined}
            initialFilters={filters}
            initialGroup={group}
            initialFinding={first(query.finding)}
          />
        </>
      )}
    </PageFrame>
  );
}
