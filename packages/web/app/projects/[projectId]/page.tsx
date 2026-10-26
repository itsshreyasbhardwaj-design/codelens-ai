import Link from 'next/link';
import { notFound } from 'next/navigation';
import { requireSession } from '../../lib/session.ts';
import { Shell, TopBar, projectTabs } from '../../components/nav.tsx';
import {
  Card, Caveat, ConfidencePill, EmptyState, Mono, PriorityPill, SectionHeading,
  SeverityPill, Stat, StatusPill, Table, Tag, Td,
} from '../../components/ui.tsx';
import {
  assessedWeight, getProject, latestScan, listScans, overallScore,
  scanFeatures, scanFindings, scanFixPacks, scanModels, scanRoutes, scanScores, scanTech,
} from '../../lib/store.ts';
import type { FeatureRow, FindingRow, ProjectRow, TechRow } from '../../lib/store.ts';
import {
  CATEGORY_LABEL, FEATURE_STATUS_LABEL, formatRelative, locationOf, pluralize,
} from '../../lib/format.ts';
import { Scorecard } from './components/scorecard.tsx';
import { CoveragePanel } from './components/coverage-panel.tsx';

/**
 * Project overview — the page a founder or a new engineer reads first.
 *
 * Server component. Every value comes from the store for the latest scan. The
 * scan database changes outside the request lifecycle, so this page is never
 * cached.
 */
export const dynamic = 'force-dynamic';

// ------------------------------------------------------------------ helpers --

function listPhrase(items: string[]): string {
  if (items.length === 0) return '';
  if (items.length === 1) return items[0];
  if (items.length === 2) return `${items[0]} and ${items[1]}`;
  return `${items.slice(0, -1).join(', ')} and ${items[items.length - 1]}`;
}

function techNames(tech: TechRow[], kind: string): string[] {
  return tech.filter((t) => t.kind === kind).map((t) => t.name);
}

/**
 * The application summary, assembled from detected values only. Where a value
 * was not detected the sentence says so rather than being dropped — an absent
 * framework and an undetected one read very differently to someone deciding
 * what to do next.
 */
function summarySentences(args: {
  project: ProjectRow; tech: TechRow[]; routeCount: number; modelCount: number; features: FeatureRow[];
}): string[] {
  const { project, tech, routeCount, modelCount, features } = args;
  const out: string[] = [];

  const kindPhrase = project.kind === 'source'
    ? 'a source-code project, read from its repository'
    : project.kind === 'website'
      ? 'a deployed website, observed only from the outside'
      : `a ${project.kind} project`;

  const languages = techNames(tech, 'language');
  out.push(languages.length > 0
    ? `${project.name} is ${kindPhrase}, written in ${listPhrase(languages)}.`
    : `${project.name} is ${kindPhrase}. No programming language could be identified from its files.`);

  const frontend = techNames(tech, 'frontend');
  const backend = techNames(tech, 'backend');
  if (frontend.length > 0 && backend.length > 0) {
    out.push(`The interface is built with ${listPhrase(frontend)}, and the server side with ${listPhrase(backend)}.`);
  } else if (frontend.length > 0) {
    out.push(`The interface is built with ${listPhrase(frontend)}. No server-side framework was detected.`);
  } else if (backend.length > 0) {
    out.push(`The server side uses ${listPhrase(backend)}. No front-end framework was detected.`);
  } else {
    out.push('No application framework was detected on either the front end or the server.');
  }

  const databases = techNames(tech, 'database');
  const orms = techNames(tech, 'orm');
  if (databases.length > 0 && orms.length > 0) {
    out.push(`Data is stored in ${listPhrase(databases)} and reached through ${listPhrase(orms)}.`);
  } else if (databases.length > 0) {
    out.push(`Data is stored in ${listPhrase(databases)}.`);
  } else if (orms.length > 0) {
    out.push(`Database access goes through ${listPhrase(orms)}; the database product itself was not identified.`);
  } else {
    out.push('No database was detected.');
  }

  out.push(
    routeCount === 0 && modelCount === 0
      ? 'No HTTP endpoint and no data model was found, so the scan could not map how requests reach stored data.'
      : `The scan mapped ${pluralize(routeCount, 'HTTP endpoint')} and ${pluralize(modelCount, 'data model')}.`,
  );

  if (features.length === 0) {
    out.push('No user-facing feature could be inventoried from the code.');
  } else {
    const byStatus = new Map<string, number>();
    for (const f of features) byStatus.set(f.status, (byStatus.get(f.status) ?? 0) + 1);
    const parts = [...byStatus.entries()]
      .sort((a, b) => b[1] - a[1])
      .map(([status, n]) => `${n} ${(FEATURE_STATUS_LABEL[status] ?? status).toLowerCase()}`);
    out.push(
      `${pluralize(features.length, 'feature')} ${features.length === 1 ? 'was' : 'were'} inventoried: ${listPhrase(parts)}.`,
    );
    if (byStatus.has('implemented_unverified')) {
      out.push('"Implemented but unverified" means the code for that feature exists and no test in this repository exercises it.');
    }
  }

  return out;
}

const TECH_KIND_ORDER = [
  'language', 'frontend', 'backend', 'orm', 'database', 'cache', 'queue', 'auth',
  'ai', 'testing', 'ci', 'build', 'infrastructure', 'hosting', 'monitoring', 'mobile',
];

const TECH_KIND_LABEL: Record<string, string> = {
  language: 'Languages', frontend: 'Front end', backend: 'Server', orm: 'Data access',
  database: 'Databases', cache: 'Caching', queue: 'Queues and messaging',
  auth: 'Authentication', ai: 'AI services', testing: 'Testing', ci: 'Continuous integration',
  build: 'Build tooling', infrastructure: 'Infrastructure', hosting: 'Hosting',
  monitoring: 'Monitoring', mobile: 'Mobile',
};

const DEPTH_LABEL: Record<string, string> = {
  deep: 'deep analysis', shallow: 'shallow analysis', detected_only: 'detected only',
};

function confidenceWord(confidence: number): string {
  if (confidence >= 0.95) return 'near-certain';
  if (confidence >= 0.85) return 'high';
  if (confidence >= 0.7) return 'moderate';
  return 'low';
}

/** Problematic statuses first, so what needs attention is not buried under what works. */
const FEATURE_STATUS_RANK: Record<string, number> = {
  broken_confirmed: 0, placeholder_or_mock: 1, partially_implemented: 2,
  implemented_unverified: 3, unknown: 4, implemented_verified: 5,
};

function featureTone(status: string): { colour: string; bg: string } {
  switch (status) {
    case 'broken_confirmed': return { colour: 'var(--critical)', bg: 'var(--critical-soft)' };
    case 'placeholder_or_mock':
    case 'partially_implemented': return { colour: 'var(--high)', bg: 'var(--high-soft)' };
    case 'implemented_unverified': return { colour: 'var(--medium)', bg: 'var(--medium-soft)' };
    case 'implemented_verified': return { colour: 'var(--good)', bg: 'var(--good-soft)' };
    default: return { colour: 'var(--info)', bg: 'var(--info-soft)' };
  }
}

function scanStatusTone(status: string): 'good' | 'warn' | 'neutral' {
  if (status === 'completed') return 'good';
  if (status === 'partial' || status === 'failed') return 'warn';
  return 'neutral';
}

function FeatureStatusPill({ status }: { status: string }) {
  const { colour, bg } = featureTone(status);
  return (
    <span
      style={{
        color: colour, background: bg, border: `1px solid ${colour}33`,
        borderRadius: 4, padding: '0.08rem 0.45rem', fontSize: '0.74rem',
        fontWeight: 600, whiteSpace: 'nowrap',
      }}
    >
      {FEATURE_STATUS_LABEL[status] ?? status}
    </span>
  );
}

/** A labelled list of file paths, capped but never silently truncated. */
function FileList({ label, files, empty }: { label: string; files: string[]; empty: string }) {
  const shown = files.slice(0, 4);
  return (
    <div style={{ fontSize: '0.82rem', lineHeight: 1.5 }}>
      <span style={{ color: 'var(--ink-3)' }}>{label}: </span>
      {files.length === 0 ? (
        <span style={{ color: 'var(--ink-3)' }}>{empty}</span>
      ) : (
        <span style={{ color: 'var(--ink-2)' }}>
          {shown.map((f, i) => (
            <span key={f}>
              {i > 0 ? ', ' : ''}
              <Mono>{f}</Mono>
            </span>
          ))}
          {files.length > shown.length ? (
            <span style={{ color: 'var(--ink-3)' }}> and {files.length - shown.length} more</span>
          ) : null}
        </span>
      )}
    </div>
  );
}

/**
 * One risk row. Severity, confidence and status render as three separate
 * indicators: a critical finding that is only suspected must look like exactly
 * that, and never like a confirmed one.
 */
function RiskRow({ finding, href }: { finding: FindingRow; href: string }) {
  return (
    <li
      style={{
        border: '1px solid var(--border)', borderRadius: 8, padding: '0.6rem 0.7rem',
        background: 'var(--surface-2)', display: 'grid', gap: '0.35rem',
      }}
    >
      <div style={{ display: 'flex', gap: '0.35rem', alignItems: 'center', flexWrap: 'wrap' }}>
        {finding.priority ? <PriorityPill priority={finding.priority} /> : null}
        <SeverityPill severity={finding.severity} />
        <ConfidencePill confidence={finding.confidence} />
        <StatusPill status={finding.status} />
      </div>
      <h3 style={{ margin: 0, fontSize: '0.92rem', fontWeight: 600, lineHeight: 1.4 }}>
        <Link href={href}>{finding.title}</Link>
      </h3>
      <p style={{ margin: 0, fontSize: '0.8rem', color: 'var(--ink-3)' }}>
        <Mono>{finding.displayId}</Mono>
        {' · '}
        {CATEGORY_LABEL[finding.category] ?? finding.category}
        {locationOf(finding) ? <> {' · '} <Mono>{locationOf(finding)}</Mono></> : null}
      </p>
    </li>
  );
}

// --------------------------------------------------------------------- page --

export default async function ProjectOverviewPage({ params }: { params: Promise<{ projectId: string }> }) {
  const { projectId } = await params;

  // The store raises the same result for another organisation's project as for
  // one that does not exist, so this reveals nothing about which it was.
  const { organizationId } = await requireSession();
  const project = getProject(organizationId, projectId);
  if (!project) notFound();

  const base = `/projects/${encodeURIComponent(projectId)}`;
  const tabs = projectTabs(projectId);
  const scans = listScans(organizationId, projectId);
  const scan = latestScan(organizationId, projectId);

  if (!scan) {
    return (
      <>
        <TopBar tabs={tabs} current={base} context={project.name} />
        <Shell>
          <header>
            <h1 style={{ margin: 0, fontSize: '1.6rem', fontWeight: 680, letterSpacing: '-0.02em' }}>
              {project.name}
            </h1>
            <p style={{ margin: '0.3rem 0 0', color: 'var(--ink-3)', fontSize: '0.9rem' }}>
              Project overview · <Mono>{project.id}</Mono>
            </p>
          </header>
          <EmptyState title="No scan has been recorded for this project">
            <p style={{ margin: 0 }}>
              Nothing about this codebase can be summarised until a scan completes. Run one with the CodeLens
              CLI against the project directory, then reload this page.
            </p>
          </EmptyState>
        </Shell>
      </>
    );
  }

  const tech = scanTech(scan.id);
  const routes = scanRoutes(scan.id);
  const models = scanModels(scan.id);
  const features = scanFeatures(scan.id);
  const findings = scanFindings(scan.id);
  const packs = scanFixPacks(scan.id);
  const scores = scanScores(scan.id);
  const overall = overallScore(scan.id);
  const assessed = assessedWeight(scan.id);

  const risks = findings.filter((f) => f.priority === 'P0' || f.priority === 'P1');
  const p0 = risks.filter((f) => f.priority === 'P0').length;
  const p1 = risks.length - p0;
  const nextPack = packs[0];

  const sortedFeatures = [...features].sort((a, b) => {
    const ra = FEATURE_STATUS_RANK[a.status] ?? 9;
    const rb = FEATURE_STATUS_RANK[b.status] ?? 9;
    return ra === rb ? a.name.localeCompare(b.name) : ra - rb;
  });

  const techKinds = [...new Set(tech.map((t) => t.kind))].sort((a, b) => {
    const ia = TECH_KIND_ORDER.indexOf(a);
    const ib = TECH_KIND_ORDER.indexOf(b);
    if (ia === -1 && ib === -1) return a.localeCompare(b);
    if (ia === -1) return 1;
    if (ib === -1) return -1;
    return ia - ib;
  });

  const summary = summarySentences({
    project, tech, routeCount: routes.length, modelCount: models.length, features,
  });

  return (
    <>
      <TopBar tabs={tabs} current={base} context={project.name} />
      <Shell>
        <header>
          <h1 style={{ margin: 0, fontSize: '1.6rem', fontWeight: 680, letterSpacing: '-0.02em' }}>
            {project.name}
          </h1>
          <p style={{ margin: '0.35rem 0 0', color: 'var(--ink-3)', fontSize: '0.88rem', lineHeight: 1.6 }}>
            Project overview · <Mono>{project.id}</Mono> · latest scan{' '}
            <Tag tone={scanStatusTone(scan.status) === 'good' ? 'good' : scanStatusTone(scan.status) === 'warn' ? 'warn' : 'neutral'}>
              {scan.status}
            </Tag>{' '}
            <time dateTime={scan.queuedAt}>{formatRelative(scan.queuedAt)}</time>
            {scan.commitSha ? <> · commit <Mono>{scan.commitSha.slice(0, 10)}</Mono></> : null}
            {' · '}
            {pluralize(scans.length, 'scan')} on record
          </p>
          {scan.errorMessage ? (
            <p style={{ margin: '0.5rem 0 0', color: 'var(--critical)', fontSize: '0.86rem' }}>
              The scan reported an error: {scan.errorMessage}
            </p>
          ) : null}
        </header>

        <Caveat>
          This report describes what a set of checks found in a snapshot of the source. It cannot prove the
          absence of bugs or vulnerabilities, and with dynamic verification disabled nothing here was measured
          at runtime — no throughput, latency or capacity figure is produced. Read the coverage section before
          treating any quiet category as clean.
        </Caveat>

        {/* ------------------------------------------------ application summary */}
        <Card>
          <SectionHeading id="summary" hint="Assembled from what the scan detected, in plain language.">
            What this project is
          </SectionHeading>
          {summary.map((sentence) => (
            <p key={sentence} style={{ margin: '0 0 0.5rem', color: 'var(--ink-2)', lineHeight: 1.65 }}>
              {sentence}
            </p>
          ))}
          <div
            style={{
              display: 'grid', gap: '0.9rem', gridTemplateColumns: 'repeat(auto-fit, minmax(8rem, 1fr))',
              marginTop: '0.9rem', paddingTop: '0.9rem', borderTop: '1px solid var(--border)',
            }}
          >
            <Stat label="HTTP endpoints" value={routes.length} />
            <Stat label="Data models" value={models.length} />
            <Stat label="Features" value={features.length} />
            <Stat
              label="Findings"
              value={findings.length}
              hint={`${p0} P0, ${p1} P1`}
              tone={p0 > 0 ? 'critical' : 'neutral'}
            />
          </div>
        </Card>

        {/* ------------------------------------------------------ health scores */}
        <Scorecard overall={overall} assessedWeight={assessed} dimensions={scores} />

        {/* ----------------------------------------------------------- coverage */}
        <CoveragePanel coverage={scan.coverage} aiProvider={scan.aiProvider} />

        {/* -------------------------------------------------------- main risks */}
        <Card>
          <SectionHeading
            id="risks"
            hint={
              risks.length > 0
                ? `${p0} P0 and ${p1} P1 ${risks.length === 1 ? 'finding' : 'findings'}, highest priority first. Severity, confidence and status are three separate judgements and are shown separately.`
                : 'The highest-priority findings from this scan.'
            }
          >
            Main risks
          </SectionHeading>
          {risks.length === 0 ? (
            <p style={{ margin: 0, color: 'var(--ink-2)' }}>
              No P0 or P1 findings in this scan. That means these checks raised nothing at those priorities —
              not that none exists. Check the coverage section above for what was not assessed.
            </p>
          ) : (
            <>
              <ul style={{ margin: 0, padding: 0, listStyle: 'none', display: 'grid', gap: '0.5rem' }}>
                {risks.map((f) => (
                  <RiskRow
                    key={f.displayId}
                    finding={f}
                    href={`${base}/findings?finding=${encodeURIComponent(f.displayId)}`}
                  />
                ))}
              </ul>
              <p style={{ margin: '0.8rem 0 0', fontSize: '0.86rem' }}>
                <Link href={`${base}/findings`}>
                  See all {pluralize(findings.length, 'finding')}, including P2 and P3
                </Link>
              </p>
            </>
          )}
        </Card>

        {/* --------------------------------------------- recommended next action */}
        <Card>
          <SectionHeading id="next" hint="The first Fix Pack in the ordered remediation plan for this scan.">
            Recommended next action
          </SectionHeading>
          {!nextPack ? (
            <p style={{ margin: 0, color: 'var(--ink-2)' }}>
              This scan produced no Fix Packs, so there is no recommended next action to show.
            </p>
          ) : (
            <>
              <h3 style={{ margin: '0 0 0.3rem', fontSize: '1rem', fontWeight: 650 }}>
                {nextPack.ordinal}. {nextPack.title}
              </h3>
              <p style={{ margin: '0 0 0.6rem', color: 'var(--ink-2)', lineHeight: 1.6 }}>
                {nextPack.objective}
              </p>
              <ul
                style={{
                  margin: '0 0 0.7rem', padding: 0, listStyle: 'none',
                  display: 'flex', flexWrap: 'wrap', gap: '0.35rem',
                }}
              >
                <li><Tag>effort: {nextPack.effort}</Tag></li>
                <li><Tag>{pluralize(nextPack.findingIds.length, 'finding')} covered</Tag></li>
                {nextPack.dependsOn.length > 0 ? (
                  <li><Tag tone="warn">depends on {nextPack.dependsOn.length} earlier pack(s)</Tag></li>
                ) : (
                  <li><Tag tone="good">no prerequisites</Tag></li>
                )}
                {nextPack.appliedAt ? <li><Tag tone="good">marked applied</Tag></li> : null}
              </ul>
              {nextPack.findingIds.length > 0 ? (
                <p style={{ margin: '0 0 0.7rem', fontSize: '0.82rem', color: 'var(--ink-3)', lineHeight: 1.7 }}>
                  Covers:{' '}
                  {nextPack.findingIds.map((id, i) => (
                    <span key={id}>
                      {i > 0 ? ', ' : ''}
                      <Link href={`${base}/findings?finding=${encodeURIComponent(id)}`}>
                        <Mono>{id}</Mono>
                      </Link>
                    </span>
                  ))}
                </p>
              ) : null}
              {!nextPack.validation.presentable ? (
                <div style={{ marginBottom: '0.7rem' }}>
                  <Caveat>
                    This pack did not pass its own validation checks and is held back from presentation.
                    {nextPack.validation.issues.length > 0 ? (
                      <ul style={{ margin: '0.4rem 0 0', paddingLeft: '1.1rem' }}>
                        {nextPack.validation.issues.map((issue, i) => (
                          <li key={`${issue.check}-${i}`}>{issue.check}: {issue.detail}</li>
                        ))}
                      </ul>
                    ) : null}
                  </Caveat>
                </div>
              ) : null}
              <p style={{ margin: 0, fontSize: '0.9rem' }}>
                <Link href={`${base}/fix-studio`}>Open this pack in the Fix Studio</Link>
              </p>
            </>
          )}
        </Card>

        {/* --------------------------------------------------- technology stack */}
        <Card>
          <SectionHeading
            id="stack"
            hint="Each detection carries its own confidence and the file and line that supports it. A detection at 0.70 is a weaker claim than one at 0.98."
          >
            Technology stack
          </SectionHeading>
          {tech.length === 0 ? (
            <p style={{ margin: 0, color: 'var(--ink-2)' }}>
              No technology was detected in this scan.
            </p>
          ) : (
            <div style={{ display: 'grid', gap: '1.1rem' }}>
              {techKinds.map((kind) => (
                <div key={kind}>
                  <h3
                    style={{
                      margin: '0 0 0.45rem', fontSize: '0.78rem', fontWeight: 600, color: 'var(--ink-3)',
                      textTransform: 'uppercase', letterSpacing: '0.05em',
                    }}
                  >
                    {TECH_KIND_LABEL[kind] ?? kind}
                  </h3>
                  <ul
                    style={{
                      margin: 0, padding: 0, listStyle: 'none', display: 'grid', gap: '0.5rem',
                      gridTemplateColumns: 'repeat(auto-fit, minmax(16rem, 1fr))',
                    }}
                  >
                    {tech.filter((t) => t.kind === kind).map((t) => {
                      const ev = t.evidence[0];
                      return (
                        <li
                          key={`${t.kind}:${t.name}`}
                          style={{
                            border: '1px solid var(--border)', borderRadius: 8, padding: '0.55rem 0.7rem',
                            background: 'var(--surface-2)', display: 'grid', gap: '0.3rem', alignContent: 'start',
                          }}
                        >
                          <div style={{ display: 'flex', gap: '0.4rem', alignItems: 'baseline', flexWrap: 'wrap' }}>
                            <span style={{ fontWeight: 650, fontSize: '0.92rem' }}>{t.name}</span>
                            {t.version ? <Mono>{t.version}</Mono> : (
                              <span style={{ fontSize: '0.78rem', color: 'var(--ink-3)' }}>version not detected</span>
                            )}
                          </div>
                          <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center', flexWrap: 'wrap' }}>
                            <span style={{ fontSize: '0.78rem', color: 'var(--ink-2)', fontVariantNumeric: 'tabular-nums' }}>
                              confidence {t.confidence.toFixed(2)} ({confidenceWord(t.confidence)})
                            </span>
                            <span
                              aria-hidden="true"
                              style={{
                                width: 44, height: 5, background: 'var(--surface-3)', borderRadius: 999,
                                overflow: 'hidden', flexShrink: 0,
                              }}
                            >
                              <span
                                style={{
                                  display: 'block', height: '100%',
                                  width: `${Math.round(t.confidence * 100)}%`, background: 'var(--accent)',
                                }}
                              />
                            </span>
                            <Tag>{DEPTH_LABEL[t.analysisDepth] ?? t.analysisDepth}</Tag>
                          </div>
                          <div style={{ fontSize: '0.78rem', color: 'var(--ink-3)', lineHeight: 1.5 }}>
                            {ev ? (
                              <>
                                Evidence:{' '}
                                <Mono>{ev.file}{ev.startLine ? `:${ev.startLine}` : ''}</Mono>
                                {ev.note ? <> — {ev.note}</> : null}
                                {t.evidence.length > 1 ? <> (and {t.evidence.length - 1} more)</> : null}
                              </>
                            ) : (
                              'No evidence was recorded for this detection.'
                            )}
                          </div>
                        </li>
                      );
                    })}
                  </ul>
                </div>
              ))}
            </div>
          )}
        </Card>

        {/* --------------------------------------------------- feature inventory */}
        <Card>
          <SectionHeading
            id="features"
            hint='Problematic statuses first. "Implemented but unverified" means the code exists and no test in this repository covers it — it is not a statement that the feature works.'
          >
            Feature inventory
          </SectionHeading>
          {sortedFeatures.length === 0 ? (
            <p style={{ margin: 0, color: 'var(--ink-2)' }}>
              No feature could be inventoried from this scan.
            </p>
          ) : (
            <ul
              style={{
                margin: 0, padding: 0, listStyle: 'none', display: 'grid', gap: '0.6rem',
                gridTemplateColumns: 'repeat(auto-fit, minmax(17rem, 1fr))',
              }}
            >
              {sortedFeatures.map((f) => (
                <li
                  key={f.key}
                  style={{
                    border: '1px solid var(--border)', borderRadius: 8, padding: '0.7rem 0.8rem',
                    background: 'var(--surface-2)', display: 'grid', gap: '0.4rem', alignContent: 'start',
                  }}
                >
                  <div style={{ display: 'flex', gap: '0.4rem', alignItems: 'baseline', justifyContent: 'space-between', flexWrap: 'wrap' }}>
                    <h3 style={{ margin: 0, fontSize: '0.95rem', fontWeight: 650 }}>{f.name}</h3>
                    <FeatureStatusPill status={f.status} />
                  </div>
                  <p style={{ margin: 0, fontSize: '0.86rem', color: 'var(--ink-2)', lineHeight: 1.55 }}>
                    {f.intendedFunction}
                  </p>
                  <FileList label="Front end" files={f.frontendFiles} empty="no front-end file detected" />
                  <FileList label="Back end" files={f.backendFiles} empty="no back-end file detected" />
                  <FileList label="Database" files={f.databaseDeps} empty="no model dependency detected" />
                  <FileList label="External services" files={f.externalServices} empty="none detected" />
                  <div style={{ fontSize: '0.82rem', lineHeight: 1.5 }}>
                    <span style={{ color: 'var(--ink-3)' }}>Authentication: </span>
                    <span style={{ color: f.authRequirement === 'public' ? 'var(--medium)' : 'var(--ink-2)' }}>
                      {f.authRequirement === 'unknown'
                        ? 'not determined'
                        : f.authRequirement === 'public'
                          ? 'public — no authentication requirement detected'
                          : f.authRequirement}
                    </span>
                  </div>
                  <FileList label="Tests" files={f.tests} empty="no test covers this feature" />
                  {f.possibleDefects.length > 0 ? (
                    <div style={{ fontSize: '0.82rem', lineHeight: 1.5 }}>
                      <span style={{ color: 'var(--ink-3)' }}>
                        Possible {f.possibleDefects.length === 1 ? 'defect' : 'defects'}:
                      </span>
                      <ul style={{ margin: '0.2rem 0 0', paddingLeft: '1.1rem', color: 'var(--medium)' }}>
                        {f.possibleDefects.map((d) => <li key={d}>{d}</li>)}
                      </ul>
                    </div>
                  ) : (
                    <div style={{ fontSize: '0.82rem', color: 'var(--ink-3)' }}>
                      Possible defects: none recorded for this feature.
                    </div>
                  )}
                </li>
              ))}
            </ul>
          )}
        </Card>

        {/*
          ------------------------------------------------------- scan history

          `minWidth: 0` on the grid item is what lets the Table primitive's own
          horizontal scroll do its job: without it the grid track grows to the
          table's min-content width and the whole page scrolls sideways instead.
        */}
        <div style={{ minWidth: 0 }}>
        <Card>
          <SectionHeading
            id="history"
            hint={
              scans.length >= 2
                ? 'Every scan recorded for this project. Two or more can be compared in Reports.'
                : 'Every scan recorded for this project.'
            }
          >
            Scan history
          </SectionHeading>
          <Table
            caption={`Scans of ${project.name}, newest first`}
            head={['Started', 'Status', 'Findings', 'Score', 'Scan id', '']}
          >
            {scans.map((s) => (
              <tr key={s.id}>
                <Td nowrap>
                  <time dateTime={s.queuedAt}>{formatRelative(s.queuedAt)}</time>
                </Td>
                <Td nowrap>
                  <Tag tone={scanStatusTone(s.status) === 'good' ? 'good' : scanStatusTone(s.status) === 'warn' ? 'warn' : 'neutral'}>
                    {s.status}
                  </Tag>
                </Td>
                <Td nowrap>
                  <span style={{ fontVariantNumeric: 'tabular-nums' }}>{s.findings}</span>
                  {s.critical > 0 ? (
                    <span style={{ color: 'var(--critical)', fontSize: '0.8rem' }}> ({s.critical} critical)</span>
                  ) : null}
                </Td>
                <Td nowrap>
                  {s.score === null ? (
                    <span style={{ color: 'var(--ink-3)', fontStyle: 'italic' }}>not scored</span>
                  ) : (
                    <span style={{ fontVariantNumeric: 'tabular-nums', fontWeight: 650 }}>{s.score}</span>
                  )}
                </Td>
                <Td mono>{s.id}</Td>
                <Td nowrap>
                  <Link href={`${base}/findings?scan=${encodeURIComponent(s.id)}`}>
                    Findings<span className="sr-only"> for the scan started {formatRelative(s.queuedAt)}</span>
                  </Link>
                </Td>
              </tr>
            ))}
          </Table>
          {scans.length >= 2 ? (
            <p style={{ margin: '0.8rem 0 0', fontSize: '0.86rem' }}>
              <Link href={`${base}/reports`}>Compare scans in Reports</Link>
            </p>
          ) : (
            <p style={{ margin: '0.8rem 0 0', fontSize: '0.84rem', color: 'var(--ink-3)' }}>
              One scan on record. A second scan makes a comparison possible in Reports.
            </p>
          )}
        </Card>
        </div>
      </Shell>
    </>
  );
}
