import Link from 'next/link';
import { Shell, TopBar } from '../components/nav.tsx';
import {
  Card, Caveat, EmptyState, ScoreBar, SectionHeading, SeverityPill, Stat, Table, Tag, Td,
} from '../components/ui.tsx';
import {
  DIMENSION_LABEL, formatRelative, gradeLabel, pluralize, SEVERITY_ORDER,
} from '../lib/format.ts';
import {
  assessedWeight, latestScan, listProjects, scanFindings, scanFixPacks, scanScores,
  type ProjectRow, type ScanRow,
} from '../lib/store.ts';
import { listJobs } from '../lib/runner.ts';
import { NewScan } from './new-scan.tsx';

/**
 * The dashboard.
 *
 * A server component: every number here is read from the scan database at
 * request time. Where the store has nothing — no scan yet, a score that is not
 * gradeable, a project with no findings — the page says so in words. Nothing is
 * defaulted to zero to make a tile look populated.
 */

export const dynamic = 'force-dynamic';

export const metadata = {
  title: 'Dashboard — CodeLens AI',
  description: 'Connected projects, their latest scan, and any scan in progress.',
};

const SCAN_STATUS_LABEL: Record<string, string> = {
  queued: 'Queued',
  running: 'Running',
  completed: 'Completed',
  partial: 'Completed with gaps',
  failed: 'Failed',
  cancelled: 'Cancelled',
};

/**
 * Severity counts for one scan.
 *
 * store.ts exposes no severity-count aggregate, so this is derived from
 * scanFindings. Severity is counted on its own and never mixed with the
 * confidence of a finding.
 */
function severityCounts(scanId: string): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const f of scanFindings(scanId)) counts[f.severity] = (counts[f.severity] ?? 0) + 1;
  return counts;
}

function scoreText(score: number | null): string {
  return score === null ? 'insufficient evidence' : String(score);
}

function h1Style() {
  return { fontSize: '1.45rem', fontWeight: 680, letterSpacing: '-0.02em', margin: 0 } as const;
}

function CoverageSummary({ scan }: { scan: ScanRow }) {
  const c = scan.coverage;
  if (!c) {
    return <p style={{ margin: 0, fontSize: '0.85rem', color: 'var(--ink-3)' }}>Coverage was not recorded for this scan.</p>;
  }
  const layers: Array<[string, boolean]> = [
    ['Static analysis', c.layers.static],
    ['Relationship graph', c.layers.graph],
    ['AI semantic layer', c.layers.ai],
    ['Dynamic verification', c.layers.dynamic],
  ];
  return (
    <div style={{ display: 'grid', gap: '0.45rem' }}>
      <p style={{ margin: 0, fontSize: '0.85rem', color: 'var(--ink-2)' }}>
        {c.filesParsed} of {c.filesIndexed} indexed files were parsed
        {c.filesSkipped > 0 ? `, ${c.filesSkipped} skipped` : ''}
        {' · '}
        {pluralize(c.analyzersRun.length, 'analyzer')} ran
        {c.analyzersSkipped.length > 0 ? `, ${c.analyzersSkipped.length} did not` : ''}
        {c.truncated ? ' · the repository was truncated' : ''}
      </p>
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.3rem' }}>
        {layers.map(([label, ran]) => (
          <Tag key={label} tone={ran ? 'good' : 'neutral'}>
            {label}: {ran ? 'ran' : 'did not run'}
          </Tag>
        ))}
      </div>
      {c.analyzersSkipped.length > 0 ? (
        <ul style={{ margin: 0, paddingLeft: '1.1rem', fontSize: '0.82rem', color: 'var(--ink-3)' }}>
          {c.analyzersSkipped.map((a) => (
            <li key={a.analyzer}>
              {a.analyzer}: {a.reason}
            </li>
          ))}
        </ul>
      ) : null}
      {c.truncationNote ? (
        <p style={{ margin: 0, fontSize: '0.82rem', color: 'var(--ink-3)' }}>{c.truncationNote}</p>
      ) : null}
    </div>
  );
}

function ProjectCard({ project, detailed }: { project: ProjectRow; detailed: boolean }) {
  const href = `/projects/${encodeURIComponent(project.id)}`;
  const scan = project.latestScanId ? latestScan(project.id) : undefined;
  const counts = scan ? severityCounts(scan.id) : {};
  const packs = scan ? scanFixPacks(scan.id) : [];
  const presentable = packs.filter((p) => p.validation.presentable).length;
  const scores = scan && detailed ? scanScores(scan.id) : [];
  const assessed = scan && detailed ? assessedWeight(scan.id) : undefined;

  return (
    <Card as="div">
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem 0.85rem', alignItems: 'baseline' }}>
        <h3 style={{ margin: 0, fontSize: '1.02rem', fontWeight: 650 }}>
          <Link href={href}>{project.name}</Link>
        </h3>
        <Tag>{project.kind}</Tag>
        {project.latestScanStatus ? (
          <Tag tone={project.latestScanStatus === 'completed' ? 'good' : 'warn'}>
            {SCAN_STATUS_LABEL[project.latestScanStatus] ?? project.latestScanStatus}
          </Tag>
        ) : null}
        <div style={{ flex: 1 }} />
        <span style={{ fontSize: '0.82rem', color: 'var(--ink-3)' }}>
          {project.latestScanAt ? `Last scan ${formatRelative(project.latestScanAt)}` : 'Never scanned'}
          {' · '}
          {pluralize(project.scanCount, 'scan')} stored
        </span>
      </div>

      {!scan ? (
        <p style={{ margin: '0.75rem 0 0', fontSize: '0.88rem', color: 'var(--ink-2)' }}>
          No scan has completed for this project yet, so there is nothing to report.
        </p>
      ) : (
        <>
          <div
            style={{
              display: 'grid', gap: '0.9rem', marginTop: '0.95rem',
              gridTemplateColumns: 'repeat(auto-fit, minmax(min(100%, 8.5rem), 1fr))',
            }}
          >
            <div>
              <div
                style={{
                  fontSize: '0.76rem', color: 'var(--ink-3)', textTransform: 'uppercase',
                  letterSpacing: '0.05em', fontWeight: 600,
                }}
              >
                Overall score
              </div>
              <div style={{ marginTop: '0.3rem', maxWidth: '12rem' }}>
                <ScoreBar value={scan.score} />
              </div>
            </div>
            <Stat label="Findings" value={scan.findings} />
            <Stat
              label="Critical"
              value={scan.critical}
              tone={scan.critical > 0 ? 'critical' : 'good'}
            />
            <Stat
              label="Fix Packs ready"
              value={presentable}
              hint={packs.length === presentable ? undefined : `${packs.length} generated, ${presentable} passed validation`}
            />
          </div>

          <div style={{ marginTop: '0.9rem' }}>
            <h4
              style={{
                margin: '0 0 0.35rem', fontSize: '0.78rem', color: 'var(--ink-3)',
                textTransform: 'uppercase', letterSpacing: '0.05em', fontWeight: 600,
              }}
            >
              Findings by severity
            </h4>
            {scan.findings === 0 ? (
              <p style={{ margin: 0, fontSize: '0.85rem', color: 'var(--ink-3)' }}>
                No findings were recorded in this scan.
              </p>
            ) : (
              <ul style={{ listStyle: 'none', margin: 0, padding: 0, display: 'flex', flexWrap: 'wrap', gap: '0.45rem' }}>
                {SEVERITY_ORDER.filter((s) => (counts[s] ?? 0) > 0).map((s) => (
                  <li key={s} style={{ display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
                    <SeverityPill severity={s} />
                    <span style={{ fontVariantNumeric: 'tabular-nums', fontWeight: 650, fontSize: '0.88rem' }}>
                      {counts[s]}
                    </span>
                  </li>
                ))}
              </ul>
            )}
            <p style={{ margin: '0.4rem 0 0', fontSize: '0.8rem', color: 'var(--ink-3)' }}>
              Severity is the consequence if the finding is real. How well it is evidenced is recorded separately, per
              finding, as confidence and status.
            </p>
          </div>

          <div style={{ marginTop: '0.9rem' }}>
            <h4
              style={{
                margin: '0 0 0.35rem', fontSize: '0.78rem', color: 'var(--ink-3)',
                textTransform: 'uppercase', letterSpacing: '0.05em', fontWeight: 600,
              }}
            >
              Coverage
            </h4>
            <CoverageSummary scan={scan} />
          </div>

          {detailed && scores.length > 0 ? (
            <div style={{ marginTop: '1rem' }}>
              <h4
                style={{
                  margin: '0 0 0.45rem', fontSize: '0.78rem', color: 'var(--ink-3)',
                  textTransform: 'uppercase', letterSpacing: '0.05em', fontWeight: 600,
                }}
              >
                Scorecard
              </h4>
              <Table
                head={['Dimension', 'Grade', 'Score', 'Weight']}
                caption={`Score by dimension for the latest scan of ${project.name}`}
              >
                {scores.map((s) => (
                  <tr key={s.dimension}>
                    <th
                      scope="row"
                      style={{
                        textAlign: 'left', padding: '0.5rem 0.65rem', borderBottom: '1px solid var(--border)',
                        fontWeight: 550, verticalAlign: 'top',
                      }}
                    >
                      {DIMENSION_LABEL[s.dimension] ?? s.dimension}
                      {s.reason ? (
                        <span style={{ display: 'block', fontWeight: 400, fontSize: '0.8rem', color: 'var(--ink-3)' }}>
                          {s.reason}
                        </span>
                      ) : null}
                    </th>
                    <Td nowrap>{gradeLabel(s.grade)}</Td>
                    <Td>
                      <div style={{ minWidth: '7rem' }}>
                        <ScoreBar value={s.score} weight={s.weight} />
                      </div>
                    </Td>
                    <Td nowrap>{Math.round(s.weight * 100)}%</Td>
                  </tr>
                ))}
              </Table>
              {assessed !== undefined ? (
                <p style={{ margin: '0.45rem 0 0', fontSize: '0.82rem', color: 'var(--ink-3)' }}>
                  {Math.round(assessed * 100)}% of the scoring weight was gradeable.
                  {assessed < 1
                    ? ' The overall score is renormalised over the dimensions that had enough evidence; the rest read as insufficient evidence rather than zero.'
                    : ' Every dimension had enough evidence to grade, so the overall score is the full weighted average.'}
                </p>
              ) : null}
            </div>
          ) : null}

          <p style={{ margin: '0.95rem 0 0', fontSize: '0.88rem' }}>
            <Link href={href}>Open the full report for {project.name}</Link>
          </p>
        </>
      )}
    </Card>
  );
}

export default function DashboardPage() {
  const projects = listProjects();
  const jobs = listJobs();
  const inFlight = jobs.filter((j) => !j.finishedAt);

  return (
    <>
      <TopBar context="Dashboard" />
      <Shell>
        <header style={{ display: 'grid', gap: '0.4rem' }}>
          <h1 style={h1Style()}>Dashboard</h1>
          <p style={{ margin: 0, color: 'var(--ink-2)', maxWidth: '54rem' }}>
            Every project whose scans are stored in this installation, with the result of its most recent scan. A score
            of “insufficient evidence” means the analysis did not cover enough of the code to grade that dimension.
          </p>
        </header>

        {inFlight.length > 0 ? (
          <Card>
            <SectionHeading hint="Live stage status from the running pipeline.">
              {pluralize(inFlight.length, 'scan')} in progress
            </SectionHeading>
            <ul style={{ listStyle: 'none', margin: 0, padding: 0, display: 'grid', gap: '0.45rem' }}>
              {inFlight.map((j) => {
                const running = j.stages.find((s) => s.status === 'running');
                const done = j.stages.filter((s) => s.status === 'completed').length;
                return (
                  <li
                    key={j.jobId}
                    style={{
                      display: 'flex', flexWrap: 'wrap', gap: '0.4rem 0.85rem', alignItems: 'baseline',
                      padding: '0.5rem 0.65rem', borderRadius: 6,
                      background: 'var(--surface-2)', border: '1px solid var(--border)',
                    }}
                  >
                    <span style={{ fontWeight: 600, fontSize: '0.9rem' }}>{j.projectName}</span>
                    <Tag tone="accent">{SCAN_STATUS_LABEL[j.status] ?? j.status}</Tag>
                    <span style={{ fontSize: '0.84rem', color: 'var(--ink-2)' }}>
                      {done} stages completed
                      {running ? ` · now: ${running.name.replace(/_/g, ' ')}` : ''}
                    </span>
                    <div style={{ flex: 1 }} />
                    <span style={{ fontSize: '0.82rem', color: 'var(--ink-3)' }}>
                      started {formatRelative(j.startedAt)}
                    </span>
                  </li>
                );
              })}
            </ul>
            <p style={{ margin: '0.6rem 0 0', fontSize: '0.82rem', color: 'var(--ink-3)' }}>
              Jobs are tracked in the web process that started them. Restarting the server clears this list; the stored
              scans below are unaffected.
            </p>
          </Card>
        ) : null}

        <Card>
          <div id="new-scan" style={{ scrollMarginTop: '4rem' }} />
          <SectionHeading hint="Three ingestion methods are implemented: a directory on this machine, a GitHub repository, or a ZIP of the source tree.">
            New scan
          </SectionHeading>
          <NewScan />
        </Card>

        {/*
          minWidth 0: this section is a grid item of Shell, and without it the
          scorecard table's min-content width raises the grid track above the
          viewport, giving the whole page a horizontal scroll at phone width.
        */}
        <section aria-labelledby="projects-heading" style={{ minWidth: 0 }}>
          <SectionHeading id="projects-heading" hint="Most recently scanned first.">
            Projects
          </SectionHeading>
          {projects.length === 0 ? (
            <EmptyState title="No projects yet">
              <p style={{ margin: 0 }}>
                Nothing has been scanned in this installation. Start with the form above — the quickest first run is the
                bundled demo project: enter{' '}
                <code style={{ fontFamily: 'var(--font-mono)' }}>./fixtures/vulnerable-shop</code> as a local directory
                path. It is a deliberately defective codebase, so the report will be full of real findings.
              </p>
            </EmptyState>
          ) : (
            /*
             * A block list, not a grid. An auto-sized grid track takes its floor
             * from the widest item's min-content width, which lets the scorecard
             * table inside a card push the whole page into a horizontal scroll at
             * phone width. Block flow sizes from the container instead, so the
             * table scrolls inside its own container as intended.
             */
            <ul style={{ listStyle: 'none', margin: 0, padding: 0 }}>
              {projects.map((p, i) => (
                <li key={p.id} style={{ marginBottom: i === projects.length - 1 ? 0 : '0.85rem' }}>
                  <ProjectCard project={p} detailed={i === 0} />
                </li>
              ))}
            </ul>
          )}
        </section>

        <Caveat>
          Scores and findings come from static analysis of a snapshot. They cannot prove that a defect is absent, and
          with dynamic verification disabled nothing on this page is runtime-verified. Check the coverage line on each
          project before reading a score as a verdict.
        </Caveat>
      </Shell>
    </>
  );
}
