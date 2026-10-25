import Link from 'next/link';
import { Shell, TopBar, projectTabs } from '../../../components/nav.tsx';
import { Card, Caveat, EmptyState, SectionHeading, Stat, Tag } from '../../../components/ui.tsx';
import { formatRelative, pluralize } from '../../../lib/format.ts';
import {
  getProject,
  latestScan,
  scanComponents,
  scanFindings,
  scanModels,
  scanRelationships,
  scanRoutes,
} from '../../../lib/store.ts';
import { ArchitectureExplorer, type FindingLink, type GraphEdge, type GraphNode } from './explorer.tsx';
import { ApiSurface } from './api-surface.tsx';
import { DataModels } from './data-models.tsx';

/**
 * Architecture explorer — server surface.
 *
 * Every read happens here. The interactive graph is a client component, so this
 * page loads the scan's components, relationships, routes, models and findings
 * and hands down plain serialisable props.
 *
 * The graph payload is bounded here rather than in the browser: a repository
 * with thousands of components would otherwise be serialised into the HTML in
 * full before anything could decide not to draw it. When the bound bites, the
 * most-connected components are kept and the explorer is told exactly how many
 * were left out, so the view degrades visibly rather than silently.
 */

/** Maximum components rendered in the graph. Above this, degree decides. */
const NODE_LIMIT = 44;

export const metadata = { title: 'Architecture — CodeLens AI' };

export default async function ArchitecturePage({ params }: { params: Promise<{ projectId: string }> }) {
  const { projectId } = await params;
  const project = getProject(projectId);

  if (!project) {
    return (
      <>
        <TopBar context="Unknown project" />
        <Shell>
          <h1 style={{ fontSize: '1.4rem', margin: 0, letterSpacing: '-0.02em' }}>Architecture</h1>
          <EmptyState title="No such project">
            <p style={{ margin: 0 }}>
              Nothing is stored under the id <code style={{ fontFamily: 'var(--font-mono)' }}>{projectId}</code>.
            </p>
            <p style={{ margin: '0.5rem 0 0' }}>
              <Link href="/">Return to the project list</Link>
            </p>
          </EmptyState>
        </Shell>
      </>
    );
  }

  const tabs = projectTabs(project.id);
  const current = `/projects/${encodeURIComponent(project.id)}/architecture`;
  const scan = latestScan(project.id);

  if (!scan) {
    return (
      <>
        <TopBar tabs={tabs} current={current} context={project.name} />
        <Shell>
          <h1 style={{ fontSize: '1.4rem', margin: 0, letterSpacing: '-0.02em' }}>Architecture</h1>
          <EmptyState title="No scan has been recorded for this project">
            The architecture view is built from a completed scan. Run one, then return here.
          </EmptyState>
        </Shell>
      </>
    );
  }

  const components = scanComponents(scan.id);
  const relationships = scanRelationships(scan.id);
  const routes = scanRoutes(scan.id);
  const models = scanModels(scan.id);

  const findings: FindingLink[] = scanFindings(scan.id).map((f) => ({
    displayId: f.displayId,
    title: f.title,
    severity: f.severity,
    confidence: f.confidence,
    status: f.status,
    category: f.category,
    files: f.files,
  }));

  // Relationships whose endpoints are not both present as components cannot be
  // drawn. They are counted and reported rather than quietly dropped.
  const keys = new Set(components.map((c) => c.key));
  const resolvable = relationships.filter((r) => keys.has(r.from) && keys.has(r.to));
  const unresolvedEdges = relationships.length - resolvable.length;

  const degree = new Map<string, number>();
  for (const r of resolvable) {
    degree.set(r.from, (degree.get(r.from) ?? 0) + 1);
    if (r.to !== r.from) degree.set(r.to, (degree.get(r.to) ?? 0) + 1);
  }

  const ranked = [...components].sort((a, b) => {
    const d = (degree.get(b.key) ?? 0) - (degree.get(a.key) ?? 0);
    if (d !== 0) return d;
    if (a.kind !== b.kind) return a.kind < b.kind ? -1 : 1;
    return a.name < b.name ? -1 : 1;
  });

  const kept = ranked.slice(0, NODE_LIMIT);
  const keptKeys = new Set(kept.map((c) => c.key));
  const keptEdges = resolvable.filter((r) => keptKeys.has(r.from) && keptKeys.has(r.to));

  const nodes: GraphNode[] = kept.map((c) => ({
    key: c.key,
    name: c.name,
    kind: c.kind,
    provenance: c.provenance,
    files: c.files,
    summary: c.summary,
  }));

  const edges: GraphEdge[] = keptEdges.map((r) => ({
    from: r.from,
    to: r.to,
    kind: r.kind,
    provenance: r.provenance,
    evidence: r.evidence.map((e) => ({
      file: e.file,
      startLine: e.startLine,
      note: e.note,
      excerpt: e.excerpt,
    })),
  }));

  const inferredNodes = components.filter((c) => c.provenance === 'inferred').length;
  const inferredEdges = relationships.filter((r) => r.provenance === 'inferred').length;

  return (
    <>
      <TopBar tabs={tabs} current={current} context={project.name} />
      <Shell>
        <header>
          <h1 style={{ fontSize: '1.4rem', margin: 0, letterSpacing: '-0.02em' }}>Architecture</h1>
          <p style={{ margin: '0.35rem 0 0', color: 'var(--ink-3)', fontSize: '0.88rem' }}>
            Read from the scan finished {formatRelative(scan.finishedAt ?? scan.queuedAt)}
            {scan.commitSha ? ` at commit ${scan.commitSha.slice(0, 10)}` : ''}. Components,
            relationships, routes and data models are all extracted from source — nothing here was
            observed running.
          </p>
        </header>

        <Card>
          <div
            style={{
              display: 'grid',
              gap: '1rem',
              gridTemplateColumns: 'repeat(auto-fit, minmax(8.5rem, 1fr))',
            }}
          >
            <Stat label="Components" value={components.length} hint={`${inferredNodes} inferred from convention`} />
            <Stat label="Relationships" value={relationships.length} hint={`${inferredEdges} inferred from convention`} />
            <Stat label="API routes" value={routes.length} hint="read from handler definitions" />
            <Stat label="Data models" value={models.length} hint="schema definitions, not measured" />
          </div>
        </Card>

        <Caveat>
          <strong>Detected and inferred are not the same claim.</strong> A detected component or
          relationship was read directly out of the code — an import that resolved, a query against a
          known model, a declared handler. An inferred one was concluded from convention, such as a
          file classified as a UI component by its path and extension. Inferred items are hypotheses
          and are drawn and labelled differently throughout this page.
        </Caveat>

        <ArchitectureExplorer
          projectId={project.id}
          nodes={nodes}
          edges={edges}
          findings={findings}
          totalNodes={components.length}
          omittedNodes={components.length - kept.length}
          omittedEdges={resolvable.length - keptEdges.length}
          unresolvedEdges={unresolvedEdges}
          nodeLimit={NODE_LIMIT}
        />

        <ApiSurface projectId={project.id} routes={routes} findings={findings} />

        <DataModels models={models} />

        <Card>
          <SectionHeading hint="Where the rest of this scan lives.">Related views</SectionHeading>
          <ul style={{ margin: 0, paddingLeft: '1.1rem', display: 'grid', gap: '0.3rem', fontSize: '0.9rem' }}>
            <li>
              <Link href={`/projects/${encodeURIComponent(project.id)}/findings`}>
                All findings for this scan
              </Link>{' '}
              <Tag>{pluralize(findings.length, 'finding')}</Tag>
            </li>
            <li>
              <Link href={`/projects/${encodeURIComponent(project.id)}`}>Scan overview and coverage</Link>
            </li>
          </ul>
        </Card>
      </Shell>
    </>
  );
}
