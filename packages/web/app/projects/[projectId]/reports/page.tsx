import type { Metadata } from 'next';
import { compareScans, type ScanComparison } from '@codelens/engine/reports/compare.ts';
import { loadScanSide } from '@codelens/engine/pipeline/persist.ts';
import { projectTabs, Shell, TopBar } from '../../../components/nav.tsx';
import {
  Card, Caveat, EmptyState, Mono, SectionHeading, SeverityPill, Stat, Table, Tag, Td,
} from '../../../components/ui.tsx';
import { formatRelative, pluralize } from '../../../lib/format.ts';
import {
  db, getProject, latestScan, listScans, scanFindings, scanFixPacks, type ScanRow,
} from '../../../lib/store.ts';
import { requireSession } from '../../../lib/session.ts';

/**
 * Exports.
 *
 * Every entry on this page is a working download produced from the stored scan
 * by /api/projects/<id>/reports/<kind>. Nothing here is a teaser for an export
 * that does not exist yet.
 *
 * The comparison block is the part that has to be got right: a finding that is
 * no longer reported is only progress if the newer scan actually looked at the
 * same ground. Verified repairs and unverified absences are therefore shown as
 * two separate figures with two separate explanations, never summed.
 */

export const dynamic = 'force-dynamic';

export const metadata: Metadata = {
  title: 'Reports — CodeLens AI',
  description: 'Download the executive summary, technical diagnostic report, findings JSON, printable reports, Fix Pack bundle and scan comparison.',
};

interface ExportEntry {
  kind: string;
  name: string;
  format: string;
  contains: string;
  audience: string;
  /** Rendered in the browser rather than downloaded. */
  inline?: boolean;
  note?: string;
}

function exportCatalogue(fixPackCount: number, findingCount: number): ExportEntry[] {
  return [
    {
      kind: 'exec-md',
      name: 'Executive summary',
      format: 'Markdown',
      contains:
        'What the project is, where it stands against the scorecard, the issues that need attention '
        + 'before release, the recommended first Fix Pack and the full remediation order, and a '
        + 'section on what was and was not examined.',
      audience: 'An owner or reviewer who needs the position in a page, without reading findings one by one.',
    },
    {
      kind: 'tech-md',
      name: 'Technical diagnostic report',
      format: 'Markdown',
      contains:
        `The stage ledger, coverage, detected technology, the architecture section, the API surface, `
        + `data models, the feature inventory, and all ${pluralize(findingCount, 'finding')} in full — `
        + 'evidence with excerpts, traced relationships, remediation and verification steps.',
      audience: 'The engineer who will do the work.',
    },
    {
      kind: 'tech-md',
      name: 'Architecture documentation',
      format: 'Markdown — the architecture section of the technical report',
      contains:
        'Components and relationships with their provenance, a Mermaid diagram of the graph, the API '
        + 'surface with authentication and validation per route, the data models, and the feature inventory.',
      audience: 'Anyone who needs to understand the shape of the system before changing it.',
      note:
        'This is a section inside the technical report rather than a separate file, so the link downloads '
        + 'that report. Splitting it out would mean shipping an architecture document without the coverage '
        + 'statement that qualifies it.',
    },
    {
      kind: 'findings-json',
      name: 'Findings JSON',
      format: 'JSON, schema-versioned',
      contains:
        'Every finding with its severity, confidence, status, priority, category and evidence, plus the '
        + 'coverage object, the scorecard, detected technology, the architecture tables and Fix Pack metadata.',
      audience: 'A CI job, a dashboard, or another tool. The limitations travel inside the document as a field.',
    },
    {
      kind: 'exec-html',
      name: 'Executive summary, printable',
      format: 'HTML, print-styled',
      contains: 'The assessment, the coverage table and the findings index, laid out for paged output.',
      audience: 'Anyone who needs a PDF to send on.',
      inline: true,
      note: 'Opens in a new tab. Use the browser\'s own Save as PDF — that is deliberate, and needs no extra dependency.',
    },
    {
      kind: 'tech-html',
      name: 'Technical report, printable',
      format: 'HTML, print-styled',
      contains: 'The same as the executive print view plus every finding in full, with page breaks between sections.',
      audience: 'A reviewer who wants the whole report as one PDF.',
      inline: true,
      note: 'Opens in a new tab. Use the browser\'s own Save as PDF.',
    },
    {
      kind: 'fix-packs-md',
      name: 'Fix Pack bundle',
      format: 'Markdown',
      contains:
        `All ${pluralize(fixPackCount, 'pack')} in dependency order, each a self-contained brief with its `
        + 'objective, the findings it closes, the files it touches and its validation warnings. Rendered '
        + 'from the stored prompts in the claude_code format.',
      audience: 'A coding agent, or an engineer working through the packs one at a time.',
    },
  ];
}

function ExportCard({ projectId, entry }: { projectId: string; entry: ExportEntry }) {
  const href = `/api/projects/${encodeURIComponent(projectId)}/reports/${entry.kind}`;
  return (
    <Card as="li">
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem', alignItems: 'baseline', justifyContent: 'space-between' }}>
        <h3 style={{ margin: 0, fontSize: '1rem', fontWeight: 650, letterSpacing: '-0.01em' }}>{entry.name}</h3>
        <Tag>{entry.format}</Tag>
      </div>
      <dl style={{ margin: '0.6rem 0 0', display: 'grid', gap: '0.35rem' }}>
        <dt style={{ fontSize: '0.78rem', fontWeight: 650, color: 'var(--ink-3)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
          What it contains
        </dt>
        <dd style={{ margin: 0, fontSize: '0.88rem', lineHeight: 1.55 }}>{entry.contains}</dd>
        <dt style={{ fontSize: '0.78rem', fontWeight: 650, color: 'var(--ink-3)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
          Who it is for
        </dt>
        <dd style={{ margin: 0, fontSize: '0.88rem', lineHeight: 1.55 }}>{entry.audience}</dd>
      </dl>
      {entry.note ? (
        <p style={{ margin: '0.5rem 0 0', fontSize: '0.82rem', color: 'var(--ink-3)', lineHeight: 1.5 }}>
          {entry.note}
        </p>
      ) : null}
      <p style={{ margin: '0.75rem 0 0' }}>
        <a
          href={href}
          {...(entry.inline
            ? { target: '_blank', rel: 'noopener noreferrer' }
            : { download: '' })}
          style={{
            display: 'inline-block', fontSize: '0.88rem', fontWeight: 600,
            padding: '0.35rem 0.8rem', borderRadius: 6,
            border: '1px solid var(--accent)', background: 'var(--accent-soft)',
            color: 'var(--accent)', textDecoration: 'none',
          }}
        >
          {entry.inline ? `Open ${entry.name.toLowerCase()} in a new tab` : `Download ${entry.name.toLowerCase()}`}
        </a>
      </p>
    </Card>
  );
}

function ComparisonBlock({ projectId, base, head, comparison }: {
  projectId: string; base: ScanRow; head: ScanRow; comparison: ScanComparison;
}) {
  const d = comparison.coverageDelta;
  const coverageShrank =
    d.filesIndexed < 0 || d.filesParsed < 0 || d.parseRatio < 0
    || d.analyzersRemoved.length > 0 || d.layersLost.length > 0;

  return (
    <Card>
      <SectionHeading
        id="comparison"
        hint={`Comparing ${base.id} (${formatRelative(base.queuedAt)}) with ${head.id} (${formatRelative(head.queuedAt)}).`}
      >
        Scan comparison
      </SectionHeading>

      <p style={{ margin: '0 0 0.9rem', lineHeight: 1.6 }}>{comparison.summary}</p>

      {/*
        The two figures that must never be added together. They are separated
        structurally, labelled in words, and each carries its own explanation —
        colour alone never carries the distinction.
      */}
      <div
        style={{
          display: 'grid', gap: '0.75rem',
          gridTemplateColumns: 'repeat(auto-fit, minmax(16rem, 1fr))',
        }}
      >
        <div
          style={{
            border: '1px solid var(--border)', borderLeft: '3px solid var(--good)',
            borderRadius: 8, padding: '0.8rem 0.9rem', background: 'var(--good-soft)',
          }}
        >
          <Stat
            label="Verified resolved"
            value={comparison.resolved.length}
            tone="good"
            hint="Gone, and the newer scan covered the same ground. This is progress."
          />
        </div>
        <div
          style={{
            border: '1px solid var(--border)', borderLeft: '3px solid var(--medium)',
            borderRadius: 8, padding: '0.8rem 0.9rem', background: 'var(--medium-soft)',
          }}
        >
          <Stat
            label="Unverified absence — not a fix"
            value={comparison.unverifiedAbsences.length}
            hint="No longer reported, but the newer scan did not cover the same ground. Do not count these as progress."
          />
        </div>
      </div>

      {coverageShrank ? (
        <div style={{ marginTop: '0.9rem' }}>
          <Caveat>
            <span style={{ fontWeight: 650 }}>Coverage shrank between these scans. </span>
            Some findings stopped being reported because less was examined, not because anything was
            repaired. A falling finding count here is not improvement.
          </Caveat>
        </div>
      ) : null}

      <div
        style={{
          display: 'grid', gap: '1rem', marginTop: '1rem',
          gridTemplateColumns: 'repeat(auto-fit, minmax(7rem, 1fr))',
        }}
      >
        <Stat label="Still present" value={comparison.persistent.length} hint="Reported by both scans, unchanged" />
        <Stat
          label="Edited, still reported"
          value={comparison.relocated.length}
          hint="Same rule, same file, new fingerprint: the edit did not remove the problem"
        />
        <Stat label="Newly reported" value={comparison.introduced.length} hint="Only in the newer scan" />
        <Stat
          label="Regressed"
          value={comparison.regressed.length}
          tone={comparison.regressed.length > 0 ? 'critical' : 'neutral'}
          hint="Resolved earlier, present again"
        />
        <Stat label="Severity changed" value={comparison.severityChanges.length} hint="Same finding, different severity" />
      </div>
      {comparison.relocated.length > 0 ? (
        <p style={{ margin: '0.75rem 0 0', fontSize: '0.86rem', color: 'var(--ink-2)', lineHeight: 1.55 }}>
          {comparison.persistent.length + comparison.relocated.length} finding(s) are still reported in
          total. {comparison.relocated.length} of them sit in code that was edited since the earlier
          scan: the fingerprint changed, so they are not the same record, but the same rule still fires
          on the same file. They are counted as present rather than resolved.
        </p>
      ) : null}

      {comparison.unverifiedAbsences.length > 0 ? (
        <section style={{ marginTop: '1.25rem' }}>
          <h3 style={{ fontSize: '0.95rem', fontWeight: 650, margin: '0 0 0.5rem' }}>
            The {comparison.unverifiedAbsences.length} unverified absence(s), and why each one is unverified
          </h3>
          <Table
            head={['Finding', 'Severity', 'Why the absence is not a fix']}
            caption="Findings no longer reported whose absence could not be attributed to a repair"
          >
            {comparison.unverifiedAbsences.map((c) => (
              <tr key={c.fingerprint}>
                <Td>{c.title}</Td>
                <Td nowrap><SeverityPill severity={c.severity} /></Td>
                <Td>{c.caveat ?? 'Coverage changed between the two scans.'}</Td>
              </tr>
            ))}
          </Table>
        </section>
      ) : null}

      {comparison.relocated.length > 0 ? (
        <section style={{ marginTop: '1.25rem' }}>
          <h3 style={{ fontSize: '0.95rem', fontWeight: 650, margin: '0 0 0.5rem' }}>
            Edited but still reported ({comparison.relocated.length})
          </h3>
          <p style={{ margin: '0 0 0.5rem', fontSize: '0.86rem', color: 'var(--ink-3)', lineHeight: 1.55 }}>
            The code around each of these changed, so the finding has a new identity, but the same
            rule still fires on the same file. Treating these as repairs would report progress that
            did not happen.
          </p>
          <Table head={['Finding', 'Severity', 'Category']} caption="Findings whose code was edited while the problem remained">
            {comparison.relocated.map((c) => (
              <tr key={c.fingerprint}>
                <Td>{c.title}</Td>
                <Td nowrap><SeverityPill severity={c.severity} /></Td>
                <Td>{c.category}</Td>
              </tr>
            ))}
          </Table>
        </section>
      ) : null}

      {comparison.resolved.length > 0 ? (
        <section style={{ marginTop: '1.25rem' }}>
          <h3 style={{ fontSize: '0.95rem', fontWeight: 650, margin: '0 0 0.5rem' }}>
            Verified as resolved ({comparison.resolved.length})
          </h3>
          <Table head={['Finding', 'Severity', 'Category']} caption="Findings absent from the newer scan under equivalent coverage">
            {comparison.resolved.map((c) => (
              <tr key={c.fingerprint}>
                <Td>{c.title}</Td>
                <Td nowrap><SeverityPill severity={c.severity} /></Td>
                <Td>{c.category}</Td>
              </tr>
            ))}
          </Table>
        </section>
      ) : null}

      <section style={{ marginTop: '1.25rem' }}>
        <h3 style={{ fontSize: '0.95rem', fontWeight: 650, margin: '0 0 0.5rem' }}>Coverage delta</h3>
        <p style={{ margin: '0 0 0.5rem', fontSize: '0.86rem', color: 'var(--ink-3)', lineHeight: 1.55 }}>
          Coverage is what decides whether an absence counts as a repair, so it is reported next to the counts.
        </p>
        <Table head={['Measure', 'Change']} caption="Change in coverage between the two scans">
          <tr><Td>Files indexed</Td><Td mono>{d.filesIndexed >= 0 ? `+${d.filesIndexed}` : d.filesIndexed}</Td></tr>
          <tr><Td>Files parsed</Td><Td mono>{d.filesParsed >= 0 ? `+${d.filesParsed}` : d.filesParsed}</Td></tr>
          <tr><Td>Parse coverage</Td><Td mono>{`${d.parseRatio >= 0 ? '+' : ''}${(d.parseRatio * 100).toFixed(0)} pp`}</Td></tr>
          <tr><Td>Analyzers added</Td><Td mono>{d.analyzersAdded.join(', ') || 'none'}</Td></tr>
          <tr><Td>Analyzers removed</Td><Td mono>{d.analyzersRemoved.join(', ') || 'none'}</Td></tr>
          <tr><Td>Layers gained</Td><Td mono>{d.layersGained.join(', ') || 'none'}</Td></tr>
          <tr><Td>Layers lost</Td><Td mono>{d.layersLost.join(', ') || 'none'}</Td></tr>
        </Table>
      </section>

      {comparison.scoreDelta ? (
        <p style={{ margin: '1rem 0 0', fontSize: '0.88rem', lineHeight: 1.6 }}>
          <span style={{ fontWeight: 650 }}>Overall score. </span>
          {comparison.scoreDelta.change === null
            ? (comparison.scoreDelta.note ?? 'No change can be stated.')
            : `${comparison.scoreDelta.overallBefore} to ${comparison.scoreDelta.overallAfter} `
              + `(${comparison.scoreDelta.change >= 0 ? '+' : ''}${comparison.scoreDelta.change}).`}
        </p>
      ) : null}

      <p style={{ margin: '1rem 0 0' }}>
        <a
          href={`/api/projects/${encodeURIComponent(projectId)}/reports/comparison-json`}
          download=""
          style={{
            display: 'inline-block', fontSize: '0.88rem', fontWeight: 600,
            padding: '0.35rem 0.8rem', borderRadius: 6,
            border: '1px solid var(--accent)', background: 'var(--accent-soft)',
            color: 'var(--accent)', textDecoration: 'none',
          }}
        >
          Download scan comparison report (JSON)
        </a>
      </p>
      <p style={{ margin: '0.5rem 0 0', fontSize: '0.82rem', color: 'var(--ink-3)', lineHeight: 1.5 }}>
        The export keeps the two groups in separate arrays, <Mono>resolved</Mono> and{' '}
        <Mono>unverifiedAbsences</Mono>, with the reason on each entry, so a consumer cannot add them
        together by accident.
      </p>
    </Card>
  );
}

export default async function ReportsPage({ params }: { params: Promise<{ projectId: string }> }) {
  const { projectId } = await params;
  const { organizationId } = await requireSession();
  const project = getProject(organizationId, projectId);
  const base = `/projects/${encodeURIComponent(projectId)}`;

  if (!project) {
    return (
      <>
        <TopBar context={projectId} />
        <Shell>
          <h1 style={{ fontSize: '1.4rem', margin: 0 }}>Project not found</h1>
          <EmptyState title={`No project '${projectId}' exists in this organisation.`}>
            <p style={{ margin: 0 }}>
              Either it was never scanned, or it belongs to another organisation. Nothing is
              disclosed about which, by design.
            </p>
          </EmptyState>
        </Shell>
      </>
    );
  }

  const tabs = projectTabs(projectId);
  const scan = latestScan(organizationId, projectId);

  if (!scan) {
    return (
      <>
        <TopBar tabs={tabs} current={`${base}/reports`} context={project.name} />
        <Shell>
          <h1 style={{ fontSize: '1.4rem', margin: 0 }}>Reports for {project.name}</h1>
          <EmptyState title="This project has no scan, so there is nothing to export.">
            <p style={{ margin: 0 }}>
              Every export is built from a stored scan. None is generated from an empty project.
            </p>
          </EmptyState>
        </Shell>
      </>
    );
  }

  const findings = scanFindings(scan.id);
  const packs = scanFixPacks(scan.id);
  const catalogue = exportCatalogue(packs.length, findings.length);

  // Two scans with recorded coverage are needed: an absence cannot be judged
  // against coverage that was never written down.
  const comparable = listScans(organizationId, projectId)
    .filter((s) => (s.status === 'completed' || s.status === 'partial') && s.coverage !== undefined);
  const head = comparable[0];
  const baseScan = comparable[1];
  const headSide = head ? loadScanSide(db(), head.id) : undefined;
  const baseSide = baseScan ? loadScanSide(db(), baseScan.id) : undefined;
  const comparison = headSide && baseSide ? compareScans(baseSide, headSide) : undefined;

  return (
    <>
      <TopBar tabs={tabs} current={`${base}/reports`} context={project.name} />
      <Shell>
        <header>
          <h1 style={{ fontSize: '1.4rem', margin: 0, letterSpacing: '-0.02em' }}>
            Reports for {project.name}
          </h1>
          <p style={{ margin: '0.35rem 0 0', color: 'var(--ink-3)', fontSize: '0.9rem', lineHeight: 1.55 }}>
            Built from scan <Mono>{scan.id}</Mono>, {formatRelative(scan.queuedAt)}, status{' '}
            <Mono>{scan.status}</Mono> — {pluralize(findings.length, 'finding')},{' '}
            {pluralize(packs.length, 'Fix Pack')}.
          </p>
        </header>

        <Caveat>
          <span style={{ fontWeight: 650 }}>Every export carries its own coverage and limitations. </span>
          Each document states what the scan parsed, which analyzers ran, which did not and why, and
          that static analysis over a snapshot cannot prove a problem is absent. A report that
          travels without its caveats is how static analysis gets mistaken for proof, so the caveats
          travel inside the file rather than on this page.
        </Caveat>

        <Card>
          <SectionHeading hint="Stated here because it changes how the documents should be read.">
            How these exports are produced
          </SectionHeading>
          <p style={{ margin: 0, lineHeight: 1.6, fontSize: '0.9rem' }}>
            The engine&rsquo;s renderers need a full in-memory scan result, including the repository
            map, which is not stored. These exports therefore rebuild the renderers&rsquo; inputs from
            the stored tables rather than re-running the scan. Re-running was not available for this
            scan in any case: the snapshot row records the source kind but not the source location,
            so the original tree cannot be found from stored state.
          </p>
          <p style={{ margin: '0.6rem 0 0', lineHeight: 1.6, fontSize: '0.9rem' }}>
            The consequence is stated inside every document: the environment-variable map, the
            findings refused by the evidence gate, and the AI layer&rsquo;s own report were never
            persisted, so their absence from a document is an absence in the stored data — not a
            statement about the project.
          </p>
        </Card>

        <section aria-labelledby="exports">
          <h2 id="exports" style={{ fontSize: '1.02rem', fontWeight: 650, margin: '0 0 0.85rem', letterSpacing: '-0.01em' }}>
            Available exports
          </h2>
          <ul style={{ listStyle: 'none', margin: 0, padding: 0, display: 'grid', gap: '0.85rem' }}>
            {catalogue.map((entry) => (
              <ExportCard key={entry.name} projectId={projectId} entry={entry} />
            ))}
          </ul>
        </section>

        {comparison && head && baseScan ? (
          <ComparisonBlock projectId={projectId} base={baseScan} head={head} comparison={comparison} />
        ) : (
          <Card>
            <SectionHeading hint="A comparison needs two scans of the same project with recorded coverage.">
              Scan comparison
            </SectionHeading>
            <p style={{ margin: 0, lineHeight: 1.6 }}>
              This project has {pluralize(comparable.length, 'comparable scan')}, so no comparison can
              be produced and no comparison export is offered. Comparing a scan with itself would
              report no change, which says nothing about the project.
            </p>
            <p style={{ margin: '0.6rem 0 0', fontSize: '0.88rem', color: 'var(--ink-3)', lineHeight: 1.55 }}>
              Once a second scan exists, the comparison separates findings verified as resolved from
              findings that are merely no longer reported, because a falling count caused by reduced
              coverage is not progress.
            </p>
          </Card>
        )}
      </Shell>
    </>
  );
}
