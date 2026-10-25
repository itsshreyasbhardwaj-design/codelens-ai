'use client';

import Link from 'next/link';
import { useMemo, useState, type ReactNode } from 'react';
import {
  Card,
  Caveat,
  ConfidencePill,
  EmptyState,
  Mono,
  SectionHeading,
  SeverityPill,
  StatusPill,
  Table,
  Tag,
  Td,
} from '../../../components/ui.tsx';

/**
 * Interactive architecture graph.
 *
 * Drawn with inline SVG — no graph library, no layout engine. Components are
 * laid out in bands by kind, which for a web application is both cheap to
 * compute and genuinely readable: requests enter at the top, data and
 * third-party services sit at the bottom, and an edge that crosses the whole
 * diagram is a coupling worth looking at.
 *
 * Two rules carry most of the honesty load here:
 *
 *  - A detected relationship is drawn solid and an inferred one dashed, with a
 *    legend stating that detected was read from code and inferred was concluded
 *    from convention. They are different epistemic claims and must not look
 *    alike.
 *  - An SVG diagram is not an accessible interface on its own. Every node is a
 *    real focusable control, and the same data is published again below as
 *    tables, which is the view a screen reader or a keyboard user can actually
 *    work through.
 */

export interface GraphNode {
  key: string;
  name: string;
  kind: string;
  provenance: string;
  files: string[];
  summary?: string;
}

export interface GraphEdgeEvidence {
  file: string;
  startLine?: number;
  note?: string;
  excerpt?: string;
}

export interface GraphEdge {
  from: string;
  to: string;
  kind: string;
  provenance: string;
  evidence: GraphEdgeEvidence[];
}

export interface FindingLink {
  displayId: string;
  title: string;
  severity: string;
  confidence: string;
  status: string;
  category: string;
  files: string[];
}

export interface ExplorerProps {
  projectId: string;
  nodes: GraphNode[];
  edges: GraphEdge[];
  findings: FindingLink[];
  totalNodes: number;
  omittedNodes: number;
  omittedEdges: number;
  unresolvedEdges: number;
  nodeLimit: number;
}

// ------------------------------------------------------------------ labels --

const KIND_LABEL: Record<string, string> = {
  app: 'Application',
  page: 'Page',
  component: 'UI component',
  service: 'Service',
  api_route: 'API route',
  middleware: 'Middleware',
  job: 'Background job',
  datastore: 'Data store',
  external_service: 'External service',
  package: 'Package',
  module: 'Module',
};

const REL_LABEL: Record<string, string> = {
  imports: 'imports',
  calls: 'calls',
  renders: 'renders',
  queries: 'queries',
  publishes: 'publishes to',
  subscribes: 'subscribes to',
  deploys_to: 'deploys to',
  authenticates_with: 'authenticates with',
};

function kindLabel(kind: string): string {
  return KIND_LABEL[kind] ?? kind.replace(/_/g, ' ');
}

function relLabel(kind: string): string {
  return REL_LABEL[kind] ?? kind.replace(/_/g, ' ');
}

/** Bands, top to bottom: request enters at the top, data sits at the bottom. */
const BANDS: Array<{ id: string; label: string; kinds: string[] }> = [
  { id: 'ui', label: 'Pages and UI components', kinds: ['app', 'page', 'component'] },
  { id: 'http', label: 'HTTP surface', kinds: ['api_route', 'middleware'] },
  { id: 'code', label: 'Application modules', kinds: ['module', 'service', 'package', 'job'] },
  { id: 'data', label: 'Data stores and external services', kinds: ['datastore', 'external_service'] },
];

// ---------------------------------------------------------------- geometry --

const NODE_W = 176;
const NODE_H = 36;
const GAP_X = 16;
const ROW_GAP = 30;
const BAND_GAP = 50;
const PAD = 26;
const BAND_HEADER = 22;
const MAX_PER_ROW = 6;
/** Above this many edges the per-edge labels are hidden; selection still shows them. */
const EDGE_LABEL_LIMIT = 60;

interface Placed {
  node: GraphNode;
  x: number;
  y: number;
}

function shortLabel(name: string, max = 25): string {
  if (name.length <= max) return name;
  return `…${name.slice(-(max - 1))}`;
}

/** The point where a line to (tx, ty) leaves this node's box. */
function anchorOf(p: Placed, tx: number, ty: number): [number, number] {
  const cx = p.x + NODE_W / 2;
  const cy = p.y + NODE_H / 2;
  const dx = tx - cx;
  const dy = ty - cy;
  if (dx === 0 && dy === 0) return [cx, cy];
  const sx = dx === 0 ? Number.POSITIVE_INFINITY : NODE_W / 2 / Math.abs(dx);
  const sy = dy === 0 ? Number.POSITIVE_INFINITY : NODE_H / 2 / Math.abs(dy);
  const s = Math.min(sx, sy);
  return [cx + dx * s, cy + dy * s];
}

/** Shape per kind, drawn at the origin. Shape is the primary signal, not colour. */
function shapeFor(kind: string, fill: string, stroke: string, strokeWidth: number): ReactNode {
  const w = NODE_W;
  const h = NODE_H;
  const common = { fill, stroke, strokeWidth };

  switch (kind) {
    case 'datastore': {
      const ry = 6;
      return (
        <>
          <path
            d={`M 0 ${ry} a ${w / 2} ${ry} 0 0 1 ${w} 0 L ${w} ${h - ry} a ${w / 2} ${ry} 0 0 1 ${-w} 0 Z`}
            {...common}
          />
          <path d={`M 0 ${ry} a ${w / 2} ${ry} 0 0 0 ${w} 0`} fill="none" stroke={stroke} strokeWidth={strokeWidth} />
        </>
      );
    }
    case 'external_service': {
      const c = 13;
      return (
        <polygon
          points={`${c},0 ${w - c},0 ${w},${h / 2} ${w - c},${h} ${c},${h} 0,${h / 2}`}
          {...common}
        />
      );
    }
    case 'page': {
      const c = 11;
      return <path d={`M 0 0 L ${w - c} 0 L ${w} ${c} L ${w} ${h} L 0 ${h} Z`} {...common} />;
    }
    case 'component':
      return <rect x={0} y={0} width={w} height={h} rx={h / 2} {...common} />;
    case 'api_route':
      return (
        <>
          <rect x={0} y={0} width={w} height={h} rx={8} {...common} />
          <rect x={5} y={7} width={3.5} height={h - 14} rx={1.75} fill={stroke} stroke="none" />
        </>
      );
    case 'middleware':
      return <path d={`M 11 0 L ${w} 0 L ${w - 11} ${h} L 0 ${h} Z`} {...common} />;
    case 'service': {
      const c = 9;
      return (
        <polygon
          points={`${c},0 ${w - c},0 ${w},${c} ${w},${h - c} ${w - c},${h} ${c},${h} 0,${h - c} 0,${c}`}
          {...common}
        />
      );
    }
    case 'package':
      return <path d={`M 0 0 L ${w * 0.34} 0 L ${w * 0.4} 7 L ${w} 7 L ${w} ${h} L 0 ${h} Z`} {...common} />;
    case 'job':
      return <path d={`M 0 0 L ${w - 13} 0 L ${w} ${h / 2} L ${w - 13} ${h} L 0 ${h} Z`} {...common} />;
    case 'app':
      return (
        <>
          <rect x={0} y={0} width={w} height={h} {...common} />
          <rect x={4} y={4} width={w - 8} height={h - 8} fill="none" stroke={stroke} strokeWidth={1} />
        </>
      );
    default:
      // Module and anything the extractor adds later: a plain rectangle.
      return <rect x={0} y={0} width={w} height={h} {...common} />;
  }
}

// ----------------------------------------------------------------- helpers --

function edgeId(e: GraphEdge): string {
  return `${e.from}→${e.to}→${e.kind}`;
}

function evidenceLabel(e: GraphEdgeEvidence): string {
  return e.startLine ? `${e.file}:${e.startLine}` : e.file;
}

/**
 * Deep link to one finding on the findings surface.
 *
 * That page filters from `?q=`, which it matches against the display id among
 * other fields, and anchors each card as `finding-<displayId>`. Both were
 * verified against the running application rather than assumed.
 */
function findingHref(projectId: string, displayId: string): string {
  const base = `/projects/${encodeURIComponent(projectId)}/findings`;
  return `${base}?q=${encodeURIComponent(displayId)}#finding-${encodeURIComponent(displayId)}`;
}

// -------------------------------------------------------------- the surface --

export function ArchitectureExplorer({
  projectId,
  nodes,
  edges,
  findings,
  totalNodes,
  omittedNodes,
  omittedEdges,
  unresolvedEdges,
  nodeLimit,
}: ExplorerProps) {
  const [selected, setSelected] = useState<string | null>(null);
  const [focused, setFocused] = useState<string | null>(null);
  const [kindFilter, setKindFilter] = useState<string | null>(null);
  const [query, setQuery] = useState('');

  const byKey = useMemo(() => new Map(nodes.map((n) => [n.key, n])), [nodes]);

  const kindsPresent = useMemo(() => {
    const seen = new Map<string, number>();
    for (const n of nodes) seen.set(n.kind, (seen.get(n.kind) ?? 0) + 1);
    return [...seen.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1));
  }, [nodes]);

  const findingsByFile = useMemo(() => {
    const m = new Map<string, FindingLink[]>();
    for (const f of findings) {
      for (const file of f.files) {
        const arr = m.get(file);
        if (arr) arr.push(f);
        else m.set(file, [f]);
      }
    }
    return m;
  }, [findings]);

  /** Degree, in and out, over everything that was handed to the graph. */
  const degree = useMemo(() => {
    const m = new Map<string, { in: number; out: number }>();
    const bump = (k: string, dir: 'in' | 'out') => {
      const cur = m.get(k) ?? { in: 0, out: 0 };
      cur[dir] += 1;
      m.set(k, cur);
    };
    for (const e of edges) {
      bump(e.from, 'out');
      bump(e.to, 'in');
    }
    return m;
  }, [edges]);

  const neighbours = useMemo(() => {
    if (!selected) return new Set<string>();
    const s = new Set<string>();
    for (const e of edges) {
      if (e.from === selected) s.add(e.to);
      if (e.to === selected) s.add(e.from);
    }
    s.delete(selected);
    return s;
  }, [edges, selected]);

  const trimmedQuery = query.trim().toLowerCase();
  const visible = useMemo(
    () =>
      nodes.filter((n) => {
        if (kindFilter && n.kind !== kindFilter) return false;
        if (trimmedQuery && !n.name.toLowerCase().includes(trimmedQuery)) return false;
        return true;
      }),
    [nodes, kindFilter, trimmedQuery],
  );

  const visibleKeys = useMemo(() => new Set(visible.map((n) => n.key)), [visible]);

  // ---- layout ----
  const layout = useMemo(() => {
    const bandNodes = BANDS.map((b) => ({
      band: b,
      items: visible
        .filter((n) => b.kinds.includes(n.kind))
        .sort((a, b2) => (a.kind === b2.kind ? (a.name < b2.name ? -1 : 1) : a.kind < b2.kind ? -1 : 1)),
    }));
    const others = visible.filter((n) => !BANDS.some((b) => b.kinds.includes(n.kind)));
    const groups = [...bandNodes];
    if (others.length > 0) {
      groups.push({ band: { id: 'other', label: 'Other components', kinds: [] }, items: others });
    }
    const used = groups.filter((g) => g.items.length > 0);

    const maxBand = used.reduce((m, g) => Math.max(m, g.items.length), 0);
    const perRow = Math.min(MAX_PER_ROW, Math.max(3, maxBand));
    const contentW = perRow * NODE_W + (perRow - 1) * GAP_X;

    const placed: Placed[] = [];
    const headers: Array<{ id: string; label: string; y: number; count: number }> = [];
    let y = PAD;

    for (const g of used) {
      headers.push({ id: g.band.id, label: g.band.label, y, count: g.items.length });
      y += BAND_HEADER;
      for (let i = 0; i < g.items.length; i += perRow) {
        const row = g.items.slice(i, i + perRow);
        const rowW = row.length * NODE_W + (row.length - 1) * GAP_X;
        const x0 = PAD + (contentW - rowW) / 2;
        row.forEach((node, j) => placed.push({ node, x: x0 + j * (NODE_W + GAP_X), y }));
        y += NODE_H + ROW_GAP;
      }
      y += BAND_GAP - ROW_GAP;
    }

    return {
      placed,
      headers,
      width: contentW + PAD * 2,
      height: Math.max(y - BAND_GAP + ROW_GAP + PAD, 160),
      positions: new Map(placed.map((p) => [p.node.key, p])),
    };
  }, [visible]);

  // ---- edges that can be drawn with the current filter ----
  const drawable = useMemo(
    () => edges.filter((e) => visibleKeys.has(e.from) && visibleKeys.has(e.to)),
    [edges, visibleKeys],
  );

  const edgeGeometry = useMemo(() => {
    const groups = new Map<string, GraphEdge[]>();
    for (const e of drawable) {
      const k = [e.from, e.to].sort().join('|');
      const arr = groups.get(k);
      if (arr) arr.push(e);
      else groups.set(k, [e]);
    }

    const out: Array<{ edge: GraphEdge; d: string; lx: number; ly: number; self: boolean }> = [];
    for (const list of groups.values()) {
      list.forEach((e, i) => {
        const a = layout.positions.get(e.from);
        const b = layout.positions.get(e.to);
        if (!a || !b) return;

        if (e.from === e.to) {
          const sx = a.x + NODE_W * 0.34;
          const ex = a.x + NODE_W * 0.66;
          const top = a.y;
          out.push({
            edge: e,
            d: `M ${sx} ${top} C ${sx - 10} ${top - 36} ${ex + 10} ${top - 36} ${ex} ${top}`,
            lx: a.x + NODE_W / 2,
            ly: top - 28,
            self: true,
          });
          return;
        }

        const [ax, ay] = anchorOf(a, b.x + NODE_W / 2, b.y + NODE_H / 2);
        const [bx, by] = anchorOf(b, a.x + NODE_W / 2, a.y + NODE_H / 2);
        const spread = list.length === 1 ? 14 : (i - (list.length - 1) / 2) * 34 + 14;
        const dx = bx - ax;
        const dy = by - ay;
        const len = Math.hypot(dx, dy) || 1;
        const cx = (ax + bx) / 2 + (-dy / len) * spread;
        const cy = (ay + by) / 2 + (dx / len) * spread;
        out.push({
          edge: e,
          d: `M ${ax} ${ay} Q ${cx} ${cy} ${bx} ${by}`,
          lx: 0.25 * ax + 0.5 * cx + 0.25 * bx,
          ly: 0.25 * ay + 0.5 * cy + 0.25 * by,
          self: false,
        });
      });
    }
    return out;
  }, [drawable, layout]);

  const showEdgeLabels = drawable.length <= EDGE_LABEL_LIMIT;

  // ---- derived panels ----
  const selectedNode = selected ? byKey.get(selected) ?? null : null;

  const outgoing = useMemo(
    () => (selected ? edges.filter((e) => e.from === selected) : []),
    [edges, selected],
  );
  const incoming = useMemo(
    () => (selected ? edges.filter((e) => e.to === selected && e.from !== selected) : []),
    [edges, selected],
  );

  const selectedFindings = useMemo(() => {
    if (!selectedNode) return [];
    const seen = new Map<string, FindingLink>();
    for (const file of selectedNode.files) {
      for (const f of findingsByFile.get(file) ?? []) seen.set(f.displayId, f);
    }
    return [...seen.values()];
  }, [selectedNode, findingsByFile]);

  const mostCoupled = useMemo(
    () =>
      [...nodes]
        .map((n) => ({ node: n, d: degree.get(n.key) ?? { in: 0, out: 0 } }))
        .map((x) => ({ ...x, total: x.d.in + x.d.out }))
        .filter((x) => x.total > 0)
        .sort((a, b) => b.total - a.total || (a.node.name < b.node.name ? -1 : 1))
        .slice(0, 6),
    [nodes, degree],
  );

  const boundaries = useMemo(
    () =>
      edges.filter((e) => {
        const to = byKey.get(e.to);
        const from = byKey.get(e.from);
        return to?.kind === 'external_service' || from?.kind === 'external_service';
      }),
    [edges, byKey],
  );

  const detectedEdges = edges.filter((e) => e.provenance === 'detected').length;
  const inferredEdges = edges.length - detectedEdges;
  const inferredNodeCount = nodes.filter((n) => n.provenance === 'inferred').length;

  const select = (key: string) => setSelected((cur) => (cur === key ? null : key));

  if (nodes.length === 0) {
    return (
      <Card>
        <SectionHeading>Component graph</SectionHeading>
        <EmptyState title="No architecture components were recorded for this scan">
          The extractor found nothing it could classify as a page, route, module, data store or
          external service. That is a gap in coverage, not a verdict on the codebase.
        </EmptyState>
      </Card>
    );
  }

  return (
    <>
      <Card>
        <SectionHeading
          id="component-graph"
          hint="Components are laid out in bands by kind. Select one to see its provenance, its files, the relationships either side of it and the findings that touch it."
        >
          Component graph
        </SectionHeading>

        {/* ---- filters ---- */}
        <div
          role="group"
          aria-label="Graph filters"
          style={{ display: 'grid', gap: '0.6rem', marginBottom: '0.9rem' }}
        >
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.35rem', alignItems: 'center' }}>
            <span style={{ fontSize: '0.78rem', color: 'var(--ink-3)', fontWeight: 600 }}>Kind</span>
            <FilterButton active={kindFilter === null} onClick={() => setKindFilter(null)}>
              All ({nodes.length})
            </FilterButton>
            {kindsPresent.map(([kind, count]) => (
              <FilterButton
                key={kind}
                active={kindFilter === kind}
                onClick={() => setKindFilter((cur) => (cur === kind ? null : kind))}
              >
                {kindLabel(kind)} ({count})
              </FilterButton>
            ))}
          </div>

          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem', alignItems: 'center' }}>
            <label htmlFor="graph-name-filter" style={{ fontSize: '0.78rem', color: 'var(--ink-3)', fontWeight: 600 }}>
              Filter by name
            </label>
            <input
              id="graph-name-filter"
              type="text"
              value={query}
              onChange={(ev) => setQuery(ev.target.value)}
              placeholder="e.g. orders"
              style={{
                flex: '1 1 10rem',
                minWidth: '8rem',
                maxWidth: '20rem',
                padding: '0.32rem 0.55rem',
                borderRadius: 6,
                border: '1px solid var(--border-strong)',
                background: 'var(--surface-2)',
                color: 'var(--ink)',
                font: 'inherit',
                fontSize: '0.86rem',
              }}
            />
            {(kindFilter || trimmedQuery) && (
              <FilterButton
                active={false}
                onClick={() => {
                  setKindFilter(null);
                  setQuery('');
                }}
              >
                Clear filters
              </FilterButton>
            )}
          </div>

          <p style={{ margin: 0, fontSize: '0.82rem', color: 'var(--ink-3)' }} role="status">
            Showing {visible.length} of {nodes.length} components and {drawable.length} of{' '}
            {edges.length} relationships.
            {selectedNode ? ` Selected: ${selectedNode.name}.` : ''}
          </p>
        </div>

        {/* ---- bound notice ---- */}
        {omittedNodes > 0 || omittedEdges > 0 || unresolvedEdges > 0 ? (
          <div style={{ marginBottom: '0.9rem' }}>
            <Caveat>
              {omittedNodes > 0 ? (
                <>
                  This graph is bounded at {nodeLimit} components. {totalNodes} were extracted, so{' '}
                  <strong>{omittedNodes} are not drawn</strong> — the ones kept are those with the most
                  relationships. {omittedEdges} relationship{omittedEdges === 1 ? '' : 's'} touching an
                  omitted component {omittedEdges === 1 ? 'is' : 'are'} therefore also absent. The full
                  set is in the scan record; nothing was discarded there.{' '}
                </>
              ) : null}
              {unresolvedEdges > 0 ? (
                <>
                  {unresolvedEdges} relationship{unresolvedEdges === 1 ? '' : 's'} reference a component
                  that was not itself extracted and cannot be drawn.
                </>
              ) : null}
            </Caveat>
          </div>
        ) : null}

        {/* ---- the graph ---- */}
        {visible.length === 0 ? (
          <EmptyState title="No component matches these filters">
            Clear the filters above to see the whole graph again.
          </EmptyState>
        ) : (
          <div
            style={{
              overflowX: 'auto',
              border: '1px solid var(--border)',
              borderRadius: 8,
              background: 'var(--surface-2)',
            }}
          >
            <svg
              width={layout.width}
              height={layout.height}
              viewBox={`0 0 ${layout.width} ${layout.height}`}
              role="group"
              aria-label={`Component graph: ${visible.length} components, ${drawable.length} relationships. The same data is available as a table below.`}
              style={{ display: 'block', maxWidth: 'none' }}
            >
              <defs>
                <marker id="clx-arrow-detected" viewBox="0 0 8 6" refX={7} refY={3} markerWidth={7} markerHeight={6} orient="auto">
                  <path d="M0,0 L8,3 L0,6 Z" fill="var(--ink-3)" />
                </marker>
                <marker id="clx-arrow-inferred" viewBox="0 0 8 6" refX={7} refY={3} markerWidth={7} markerHeight={6} orient="auto">
                  <path d="M0,0 L8,3 L0,6 Z" fill="var(--medium)" />
                </marker>
                <marker id="clx-arrow-active" viewBox="0 0 8 6" refX={7} refY={3} markerWidth={7} markerHeight={6} orient="auto">
                  <path d="M0,0 L8,3 L0,6 Z" fill="var(--accent)" />
                </marker>
              </defs>

              {/* edges first, so band labels and nodes sit on top */}
              {edgeGeometry.map(({ edge, d, lx, ly }) => {
                const incident = selected ? edge.from === selected || edge.to === selected : false;
                const inferred = edge.provenance !== 'detected';
                const opacity = selected ? (incident ? 1 : 0.12) : 0.85;
                const stroke = incident ? 'var(--accent)' : inferred ? 'var(--medium)' : 'var(--ink-3)';
                const marker = incident
                  ? 'url(#clx-arrow-active)'
                  : inferred
                    ? 'url(#clx-arrow-inferred)'
                    : 'url(#clx-arrow-detected)';
                const label = `${relLabel(edge.kind)}${inferred ? ' (inferred)' : ''}`;
                const showLabel = showEdgeLabels || incident;
                return (
                  <g key={edgeId(edge)} opacity={opacity}>
                    <path
                      d={d}
                      fill="none"
                      stroke={stroke}
                      strokeWidth={incident ? 2 : 1.3}
                      strokeDasharray={inferred ? '5 4' : undefined}
                      markerEnd={marker}
                    />
                    {showLabel ? (
                      <>
                        <rect
                          x={lx - (label.length * 5.4) / 2 - 3}
                          y={ly - 7}
                          width={label.length * 5.4 + 6}
                          height={13}
                          rx={3}
                          fill="var(--surface-2)"
                        />
                        <text
                          x={lx}
                          y={ly + 3}
                          fontSize={9.5}
                          textAnchor="middle"
                          fill={incident ? 'var(--accent)' : 'var(--ink-3)'}
                        >
                          {label}
                        </text>
                      </>
                    ) : null}
                  </g>
                );
              })}

              {/* band labels, drawn over the edges that cross them so they stay legible */}
              {layout.headers.map((h) => {
                const text = `${h.label} (${h.count})`;
                return (
                  <g key={h.id}>
                    <rect
                      x={PAD - 4}
                      y={h.y + 1}
                      width={text.length * 6.6 + 8}
                      height={16}
                      rx={3}
                      fill="var(--surface-2)"
                    />
                    <text
                      x={PAD}
                      y={h.y + 13}
                      fontSize={11}
                      fontWeight={650}
                      fill="var(--ink-3)"
                      style={{ textTransform: 'uppercase', letterSpacing: '0.06em' }}
                    >
                      {text}
                    </text>
                  </g>
                );
              })}

              {/* nodes, in band order so tab order follows the diagram */}
              {layout.placed.map(({ node, x, y }) => {
                const isSelected = selected === node.key;
                const isNeighbour = neighbours.has(node.key);
                const dim = selected !== null && !isSelected && !isNeighbour;
                const inferred = node.provenance !== 'detected';
                const stroke = isSelected
                  ? 'var(--accent)'
                  : isNeighbour
                    ? 'var(--accent)'
                    : 'var(--border-strong)';
                const fill = isSelected ? 'var(--accent-soft)' : isNeighbour ? 'var(--surface-3)' : 'var(--surface)';
                const d = degree.get(node.key) ?? { in: 0, out: 0 };
                const describe =
                  `${node.name}. ${kindLabel(node.kind)}, ${node.provenance}. ` +
                  `${d.in} incoming and ${d.out} outgoing relationships. ` +
                  (isSelected ? 'Selected.' : 'Activate to select.');

                return (
                  <g
                    key={node.key}
                    transform={`translate(${x} ${y})`}
                    role="button"
                    tabIndex={0}
                    aria-pressed={isSelected}
                    aria-label={describe}
                    opacity={dim ? 0.3 : 1}
                    style={{ cursor: 'pointer' }}
                    onClick={() => select(node.key)}
                    onFocus={() => setFocused(node.key)}
                    onBlur={() => setFocused((cur) => (cur === node.key ? null : cur))}
                    onKeyDown={(ev) => {
                      if (ev.key === 'Enter' || ev.key === ' ' || ev.key === 'Spacebar') {
                        ev.preventDefault();
                        select(node.key);
                      } else if (ev.key === 'Escape') {
                        setSelected(null);
                      }
                    }}
                  >
                    <title>{`${node.name} — ${kindLabel(node.kind)} (${node.provenance})`}</title>
                    {shapeFor(node.kind, fill, stroke, isSelected ? 2.2 : 1.3)}
                    {inferred ? (
                      <rect
                        x={-2}
                        y={-2}
                        width={NODE_W + 4}
                        height={NODE_H + 4}
                        rx={6}
                        fill="none"
                        stroke="var(--medium)"
                        strokeWidth={1}
                        strokeDasharray="4 3"
                        pointerEvents="none"
                      />
                    ) : null}
                    {focused === node.key ? (
                      <rect
                        x={-6}
                        y={-6}
                        width={NODE_W + 12}
                        height={NODE_H + 12}
                        rx={9}
                        fill="none"
                        stroke="var(--accent)"
                        strokeWidth={2}
                        pointerEvents="none"
                      />
                    ) : null}
                    <text
                      x={NODE_W / 2}
                      y={NODE_H / 2 + 4}
                      textAnchor="middle"
                      fontSize={11.5}
                      fontWeight={isSelected ? 650 : 500}
                      fill="var(--ink)"
                      pointerEvents="none"
                    >
                      {shortLabel(node.name)}
                    </text>
                  </g>
                );
              })}
            </svg>
          </div>
        )}

        {/* ---- legend ---- */}
        <div style={{ marginTop: '0.9rem', display: 'grid', gap: '0.7rem' }}>
          <h3 style={{ margin: 0, fontSize: '0.88rem', fontWeight: 650 }}>Legend</h3>

          <div>
            <p style={{ margin: '0 0 0.3rem', fontSize: '0.82rem', color: 'var(--ink-3)', fontWeight: 600 }}>
              Relationship provenance
            </p>
            <ul style={{ margin: 0, padding: 0, listStyle: 'none', display: 'grid', gap: '0.35rem', fontSize: '0.85rem' }}>
              <li style={{ display: 'flex', gap: '0.55rem', alignItems: 'flex-start' }}>
                <svg width="44" height="14" aria-hidden="true" style={{ flex: '0 0 auto', marginTop: 2 }}>
                  <path d="M2,7 L38,7" stroke="var(--ink-3)" strokeWidth={1.6} markerEnd="url(#clx-legend-solid)" fill="none" />
                  <defs>
                    <marker id="clx-legend-solid" viewBox="0 0 8 6" refX={7} refY={3} markerWidth={7} markerHeight={6} orient="auto">
                      <path d="M0,0 L8,3 L0,6 Z" fill="var(--ink-3)" />
                    </marker>
                  </defs>
                </svg>
                <span>
                  <strong>Solid — detected ({detectedEdges}).</strong> Read directly from the code: an
                  import that resolved to a file in the repository, a query against a known model, a
                  call to an imported SDK. The evidence is a file and line.
                </span>
              </li>
              <li style={{ display: 'flex', gap: '0.55rem', alignItems: 'flex-start' }}>
                <svg width="44" height="14" aria-hidden="true" style={{ flex: '0 0 auto', marginTop: 2 }}>
                  <path
                    d="M2,7 L38,7"
                    stroke="var(--medium)"
                    strokeWidth={1.6}
                    strokeDasharray="5 4"
                    markerEnd="url(#clx-legend-dash)"
                    fill="none"
                  />
                  <defs>
                    <marker id="clx-legend-dash" viewBox="0 0 8 6" refX={7} refY={3} markerWidth={7} markerHeight={6} orient="auto">
                      <path d="M0,0 L8,3 L0,6 Z" fill="var(--medium)" />
                    </marker>
                  </defs>
                </svg>
                <span>
                  <strong>Dashed — inferred ({inferredEdges}).</strong> Concluded from convention
                  rather than read from code, so it is a hypothesis and may be wrong. Confirm it
                  against the source before relying on it.
                </span>
              </li>
              <li style={{ display: 'flex', gap: '0.55rem', alignItems: 'flex-start' }}>
                <svg width="44" height="18" aria-hidden="true" style={{ flex: '0 0 auto', marginTop: 2 }}>
                  <rect x="4" y="3" width="36" height="12" rx={3} fill="var(--surface)" stroke="var(--border-strong)" />
                  <rect x="2" y="1" width="40" height="16" rx={5} fill="none" stroke="var(--medium)" strokeDasharray="4 3" />
                </svg>
                <span>
                  A component drawn inside a dashed outline was itself <strong>inferred</strong> (
                  {inferredNodeCount} here) — classified by convention such as its path and extension,
                  not by a declaration found in the code.
                </span>
              </li>
            </ul>
          </div>

          <div>
            <p style={{ margin: '0 0 0.3rem', fontSize: '0.82rem', color: 'var(--ink-3)', fontWeight: 600 }}>
              Shape by kind
            </p>
            <ul
              style={{
                margin: 0,
                padding: 0,
                listStyle: 'none',
                display: 'flex',
                flexWrap: 'wrap',
                gap: '0.5rem 1.1rem',
                fontSize: '0.84rem',
              }}
            >
              {kindsPresent.map(([kind]) => (
                <li key={kind} style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                  <svg width="58" height="16" viewBox={`0 0 ${NODE_W} ${NODE_H}`} aria-hidden="true" style={{ flex: '0 0 auto' }}>
                    {shapeFor(kind, 'var(--surface)', 'var(--border-strong)', 2.4)}
                  </svg>
                  <span>{kindLabel(kind)}</span>
                </li>
              ))}
            </ul>
          </div>

          {!showEdgeLabels ? (
            <p style={{ margin: 0, fontSize: '0.82rem', color: 'var(--ink-3)' }}>
              Relationship labels are hidden because this graph has more than {EDGE_LABEL_LIMIT}{' '}
              edges. Select a component to label the edges either side of it, or read the
              relationships table below.
            </p>
          ) : null}
        </div>
      </Card>

      {/* ---- detail panel ---- */}
      <Card>
        <SectionHeading id="component-detail">Selected component</SectionHeading>
        {!selectedNode ? (
          <p style={{ margin: 0, color: 'var(--ink-3)', fontSize: '0.9rem' }}>
            No component is selected. Choose one in the graph above, or from the table below, to see
            its provenance, files, relationships and the findings that cite its files.
          </p>
        ) : (
          <div style={{ display: 'grid', gap: '0.9rem' }}>
            <div>
              <h3 style={{ margin: 0, fontSize: '1rem', fontWeight: 650, wordBreak: 'break-word' }}>
                {selectedNode.name}
              </h3>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.35rem', marginTop: '0.4rem' }}>
                <Tag>{kindLabel(selectedNode.kind)}</Tag>
                {selectedNode.provenance === 'detected' ? (
                  <Tag tone="good">detected — read from code</Tag>
                ) : (
                  <Tag tone="warn">inferred — concluded from convention</Tag>
                )}
                <Tag>
                  {incoming.length} incoming · {outgoing.length} outgoing
                </Tag>
                {!visibleKeys.has(selectedNode.key) ? <Tag tone="warn">hidden by the current filter</Tag> : null}
              </div>
              <p style={{ margin: '0.5rem 0 0', fontSize: '0.9rem', color: 'var(--ink-2)' }}>
                {selectedNode.summary ?? 'No summary was recorded for this component.'}
              </p>
            </div>

            <div>
              <h4 style={{ margin: '0 0 0.3rem', fontSize: '0.84rem', fontWeight: 650 }}>Files covered</h4>
              {selectedNode.files.length === 0 ? (
                <p style={{ margin: 0, fontSize: '0.85rem', color: 'var(--ink-3)' }}>No files recorded.</p>
              ) : (
                <ul style={{ margin: 0, paddingLeft: '1.1rem', display: 'grid', gap: '0.15rem' }}>
                  {selectedNode.files.map((f) => (
                    <li key={f}>
                      <Mono>{f}</Mono>
                    </li>
                  ))}
                </ul>
              )}
            </div>

            <RelationshipList
              title="Outgoing relationships"
              empty="This component depends on nothing else that was extracted."
              rows={outgoing.map((e) => ({ edge: e, other: byKey.get(e.to), direction: 'to' as const }))}
              onSelect={setSelected}
            />
            <RelationshipList
              title="Incoming relationships"
              empty="Nothing that was extracted depends on this component."
              rows={incoming.map((e) => ({ edge: e, other: byKey.get(e.from), direction: 'from' as const }))}
              onSelect={setSelected}
            />

            <div>
              <h4 style={{ margin: '0 0 0.3rem', fontSize: '0.84rem', fontWeight: 650 }}>
                Findings citing these files
              </h4>
              {selectedFindings.length === 0 ? (
                <p style={{ margin: 0, fontSize: '0.85rem', color: 'var(--ink-3)' }}>
                  No findings in this scan cite a file covered by this component. That is not a
                  guarantee the component is sound — it means these checks found nothing here.
                </p>
              ) : (
                <ul style={{ margin: 0, padding: 0, listStyle: 'none', display: 'grid', gap: '0.45rem' }}>
                  {selectedFindings.map((f) => (
                    <li key={f.displayId} style={{ display: 'grid', gap: '0.2rem' }}>
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.3rem', alignItems: 'center' }}>
                        <SeverityPill severity={f.severity} />
                        <ConfidencePill confidence={f.confidence} />
                        <StatusPill status={f.status} />
                      </div>
                      <Link href={findingHref(projectId, f.displayId)} style={{ fontSize: '0.88rem' }}>
                        <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem' }}>{f.displayId}</span>{' '}
                        {f.title}
                      </Link>
                    </li>
                  ))}
                </ul>
              )}
            </div>

            <div>
              <button
                type="button"
                onClick={() => setSelected(null)}
                style={{
                  justifySelf: 'start',
                  padding: '0.3rem 0.7rem',
                  borderRadius: 6,
                  border: '1px solid var(--border-strong)',
                  background: 'var(--surface-2)',
                  color: 'var(--ink-2)',
                  font: 'inherit',
                  fontSize: '0.84rem',
                  cursor: 'pointer',
                }}
              >
                Clear selection
              </button>
            </div>
          </div>
        )}
      </Card>

      {/* ---- coupling and integration boundaries ---- */}
      <Card>
        <SectionHeading hint="Degree counts relationships drawn in this graph, in both directions. A high count means many parts of the codebase move together when this one changes.">
          Most tightly coupled components
        </SectionHeading>
        {mostCoupled.length === 0 ? (
          <p style={{ margin: 0, fontSize: '0.88rem', color: 'var(--ink-3)' }}>
            No relationships were extracted, so coupling cannot be ranked.
          </p>
        ) : (
          <Table head={['Component', 'Kind', 'Incoming', 'Outgoing', 'Total']} caption="Components ranked by relationship count">
            {mostCoupled.map(({ node, d, total }) => (
              <tr key={node.key}>
                <Td>
                  <RowSelect name={node.name} onClick={() => select(node.key)} selected={selected === node.key} />
                </Td>
                <Td>{kindLabel(node.kind)}</Td>
                <Td nowrap>{d.in}</Td>
                <Td nowrap>{d.out}</Td>
                <Td nowrap>
                  <strong>{total}</strong>
                </Td>
              </tr>
            ))}
          </Table>
        )}
      </Card>

      <Card>
        <SectionHeading hint="Every edge that crosses into a third-party service. These are the points where data leaves the codebase, and where an outage or a credential is someone else's problem to cause and yours to absorb.">
          Integration boundaries
        </SectionHeading>
        {boundaries.length === 0 ? (
          <p style={{ margin: 0, fontSize: '0.88rem', color: 'var(--ink-3)' }}>
            No relationship to an external service was extracted from this scan.
          </p>
        ) : (
          <Table
            head={['From', 'Relationship', 'External service', 'Provenance', 'Evidence']}
            caption="Relationships that cross into an external service"
          >
            {boundaries.map((e) => {
              const from = byKey.get(e.from);
              const to = byKey.get(e.to);
              return (
                <tr key={edgeId(e)}>
                  <Td>
                    {from ? <RowSelect name={from.name} onClick={() => select(from.key)} selected={selected === from.key} /> : e.from}
                  </Td>
                  <Td nowrap>{relLabel(e.kind)}</Td>
                  <Td>
                    {to ? <RowSelect name={to.name} onClick={() => select(to.key)} selected={selected === to.key} /> : e.to}
                  </Td>
                  <Td nowrap>
                    {e.provenance === 'detected' ? <Tag tone="good">detected</Tag> : <Tag tone="warn">inferred</Tag>}
                  </Td>
                  <Td mono>
                    {e.evidence.length === 0 ? (
                      <span style={{ color: 'var(--ink-3)' }}>none recorded</span>
                    ) : (
                      e.evidence.map((ev) => <div key={`${ev.file}:${ev.startLine ?? ''}`}>{evidenceLabel(ev)}</div>)
                    )}
                  </Td>
                </tr>
              );
            })}
          </Table>
        )}
      </Card>

      {/* ---- accessible parallel view ---- */}
      <Card>
        <SectionHeading
          id="graph-tables"
          hint="The same components and relationships as the diagram, in a form a screen reader and a keyboard can work through. Selecting a component here drives the diagram above."
        >
          Components and relationships as tables
        </SectionHeading>

        <h3 style={{ margin: '0 0 0.5rem', fontSize: '0.9rem', fontWeight: 650 }}>
          Components ({nodes.length})
        </h3>
        <Table
          head={['Component', 'Kind', 'Provenance', 'In', 'Out', 'Files', 'Summary']}
          caption="Every component in the graph"
        >
          {nodes.map((n) => {
            const d = degree.get(n.key) ?? { in: 0, out: 0 };
            return (
              <tr key={n.key}>
                <Td>
                  <RowSelect name={n.name} onClick={() => select(n.key)} selected={selected === n.key} />
                </Td>
                <Td nowrap>{kindLabel(n.kind)}</Td>
                <Td nowrap>
                  {n.provenance === 'detected' ? <Tag tone="good">detected</Tag> : <Tag tone="warn">inferred</Tag>}
                </Td>
                <Td nowrap>{d.in}</Td>
                <Td nowrap>{d.out}</Td>
                <Td mono>
                  {n.files.length === 0 ? (
                    <span style={{ color: 'var(--ink-3)' }}>none</span>
                  ) : (
                    n.files.map((f) => <div key={f}>{f}</div>)
                  )}
                </Td>
                <Td>{n.summary ?? <span style={{ color: 'var(--ink-3)' }}>no summary recorded</span>}</Td>
              </tr>
            );
          })}
        </Table>

        <h3 style={{ margin: '1.2rem 0 0.5rem', fontSize: '0.9rem', fontWeight: 650 }}>
          Relationships ({edges.length})
        </h3>
        {edges.length === 0 ? (
          <p style={{ margin: 0, fontSize: '0.88rem', color: 'var(--ink-3)' }}>
            No relationships were extracted between these components.
          </p>
        ) : (
          <Table
            head={['From', 'Relationship', 'To', 'Provenance', 'Evidence']}
            caption="Every relationship in the graph, with the evidence behind it"
          >
            {edges.map((e) => {
              const from = byKey.get(e.from);
              const to = byKey.get(e.to);
              return (
                <tr key={edgeId(e)}>
                  <Td>
                    {from ? <RowSelect name={from.name} onClick={() => select(from.key)} selected={selected === from.key} /> : e.from}
                  </Td>
                  <Td nowrap>{relLabel(e.kind)}</Td>
                  <Td>
                    {to ? <RowSelect name={to.name} onClick={() => select(to.key)} selected={selected === to.key} /> : e.to}
                  </Td>
                  <Td nowrap>
                    {e.provenance === 'detected' ? <Tag tone="good">detected</Tag> : <Tag tone="warn">inferred</Tag>}
                  </Td>
                  <Td mono>
                    {e.evidence.length === 0 ? (
                      <span style={{ color: 'var(--ink-3)' }}>none recorded</span>
                    ) : (
                      e.evidence.map((ev) => (
                        <div key={`${ev.file}:${ev.startLine ?? ''}`}>
                          {evidenceLabel(ev)}
                          {ev.excerpt ? ` — ${ev.excerpt}` : ''}
                        </div>
                      ))
                    )}
                  </Td>
                </tr>
              );
            })}
          </Table>
        )}
      </Card>
    </>
  );
}

// ---------------------------------------------------------------- partials --

function FilterButton({
  active,
  onClick,
  children,
}: {
  active: boolean;
  onClick: () => void;
  children: ReactNode;
}) {
  return (
    <button
      type="button"
      aria-pressed={active}
      onClick={onClick}
      style={{
        padding: '0.22rem 0.55rem',
        borderRadius: 999,
        border: `1px solid ${active ? 'var(--accent)' : 'var(--border-strong)'}`,
        background: active ? 'var(--accent-soft)' : 'var(--surface-2)',
        color: active ? 'var(--accent)' : 'var(--ink-2)',
        font: 'inherit',
        fontSize: '0.8rem',
        fontWeight: active ? 650 : 500,
        cursor: 'pointer',
      }}
    >
      {children}
    </button>
  );
}

function RowSelect({ name, onClick, selected }: { name: string; onClick: () => void; selected: boolean }) {
  return (
    <button
      type="button"
      aria-pressed={selected}
      onClick={onClick}
      style={{
        padding: 0,
        border: 'none',
        background: 'none',
        color: 'var(--accent)',
        font: 'inherit',
        fontSize: '0.86rem',
        fontWeight: selected ? 650 : 500,
        textAlign: 'left',
        textDecoration: 'underline',
        textUnderlineOffset: 2,
        cursor: 'pointer',
        wordBreak: 'break-word',
      }}
    >
      {name}
      {selected ? <span className="sr-only"> (selected)</span> : null}
    </button>
  );
}

function RelationshipList({
  title,
  empty,
  rows,
  onSelect,
}: {
  title: string;
  empty: string;
  rows: Array<{ edge: GraphEdge; other: GraphNode | undefined; direction: 'to' | 'from' }>;
  onSelect: (key: string) => void;
}) {
  return (
    <div>
      <h4 style={{ margin: '0 0 0.3rem', fontSize: '0.84rem', fontWeight: 650 }}>{title}</h4>
      {rows.length === 0 ? (
        <p style={{ margin: 0, fontSize: '0.85rem', color: 'var(--ink-3)' }}>{empty}</p>
      ) : (
        <ul style={{ margin: 0, padding: 0, listStyle: 'none', display: 'grid', gap: '0.5rem' }}>
          {rows.map(({ edge, other, direction }) => (
            <li key={edgeId(edge)} style={{ display: 'grid', gap: '0.15rem' }}>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.35rem', alignItems: 'center', fontSize: '0.88rem' }}>
                <span style={{ color: 'var(--ink-3)' }}>
                  {direction === 'to' ? '→' : '←'} {relLabel(edge.kind)}
                </span>
                {other ? (
                  <RowSelect name={other.name} onClick={() => onSelect(other.key)} selected={false} />
                ) : (
                  <span>{direction === 'to' ? edge.to : edge.from}</span>
                )}
                {edge.provenance === 'detected' ? (
                  <Tag tone="good">detected</Tag>
                ) : (
                  <Tag tone="warn">inferred</Tag>
                )}
              </div>
              {edge.evidence.length === 0 ? (
                <span style={{ fontSize: '0.8rem', color: 'var(--ink-3)' }}>
                  No file-and-line evidence was recorded for this relationship.
                </span>
              ) : (
                <ul style={{ margin: 0, paddingLeft: '1.1rem', display: 'grid', gap: '0.1rem' }}>
                  {edge.evidence.map((ev) => (
                    <li key={`${ev.file}:${ev.startLine ?? ''}`} style={{ fontSize: '0.8rem' }}>
                      <Mono>{evidenceLabel(ev)}</Mono>
                      {ev.excerpt ? <span style={{ color: 'var(--ink-3)' }}> — {ev.excerpt}</span> : null}
                      {ev.note ? <span style={{ color: 'var(--ink-3)' }}> ({ev.note})</span> : null}
                    </li>
                  ))}
                </ul>
              )}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
