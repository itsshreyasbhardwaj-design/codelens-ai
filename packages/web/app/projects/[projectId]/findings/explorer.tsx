'use client';

import { useEffect, useMemo, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import {
  CATEGORY_LABEL,
  CONFIDENCE_ORDER,
  DETECTION_SOURCE_LABEL,
  PRIORITY_MEANING,
  PRIORITY_ORDER,
  SEVERITY_ORDER,
  STATUS_LABEL,
  locationOf,
} from '../../../lib/format.ts';
import {
  Card,
  Caveat,
  ConfidencePill,
  EmptyState,
  Mono,
  PriorityPill,
  SectionHeading,
  SeverityPill,
  StatusPill,
} from '../../../components/ui.tsx';
import { FindingDetail } from './finding-detail.tsx';
import type { Finding } from './finding-detail.tsx';

/**
 * Client-side filtering, grouping and selection over one scan's findings.
 *
 * The server hands down plain findings (already ordered by priority) and the
 * filter state parsed out of the query string. State is held locally so typing
 * does not round-trip, and mirrored back into the URL with `replaceState` so a
 * filtered view can be shared and reloaded.
 *
 * Whenever a filter is active the header states "N of M", because a filtered
 * list that looks like the whole report is how a partial view gets mistaken for
 * a complete one.
 */

export type GroupKey = 'priority' | 'category' | 'severity' | 'file' | 'feature';

const GROUP_LABEL: Record<GroupKey, string> = {
  priority: 'Priority',
  category: 'Category',
  severity: 'Severity',
  file: 'File',
  feature: 'Affected feature',
};

const EFFORT_ORDER = ['trivial', 'small', 'medium', 'large'] as const;

const EFFORT_LABEL: Record<string, string> = {
  trivial: 'Trivial', small: 'Small', medium: 'Medium', large: 'Large',
};

export type FacetKey =
  | 'category' | 'severity' | 'confidence' | 'status'
  | 'priority' | 'source' | 'feature' | 'effort';

export type Filters = Record<FacetKey, string> & { q: string };

export const EMPTY_FILTERS: Filters = {
  q: '', category: '', severity: '', confidence: '', status: '',
  priority: '', source: '', feature: '', effort: '',
};

interface Facet {
  key: FacetKey;
  label: string;
  /** Every value of this facet that the finding carries; [] means it has none. */
  valuesOf: (f: Finding) => string[];
  /** Canonical display order, where the domain has one. */
  order?: readonly string[];
  labelOf: (value: string) => string;
}

const FACETS: Facet[] = [
  { key: 'category', label: 'Category', valuesOf: (f) => [f.category], labelOf: (v) => CATEGORY_LABEL[v] ?? v },
  { key: 'severity', label: 'Severity', valuesOf: (f) => [f.severity], order: SEVERITY_ORDER, labelOf: (v) => v },
  { key: 'confidence', label: 'Confidence', valuesOf: (f) => [f.confidence], order: CONFIDENCE_ORDER, labelOf: (v) => v },
  { key: 'status', label: 'Status', valuesOf: (f) => [f.status], labelOf: (v) => STATUS_LABEL[v] ?? v },
  { key: 'priority', label: 'Priority', valuesOf: (f) => (f.priority ? [f.priority] : []), order: PRIORITY_ORDER, labelOf: (v) => v },
  { key: 'source', label: 'Detection source', valuesOf: (f) => [f.detectionSource], labelOf: (v) => DETECTION_SOURCE_LABEL[v] ?? v },
  { key: 'feature', label: 'Affected feature', valuesOf: (f) => f.affectedFeatures, labelOf: (v) => v },
  { key: 'effort', label: 'Remediation effort', valuesOf: (f) => [f.effort], order: EFFORT_ORDER, labelOf: (v) => EFFORT_LABEL[v] ?? v },
];

const NO_FILE = '\u0000no-file';
const NO_FEATURE = '\u0000no-feature';
const NO_PRIORITY = '\u0000no-priority';

function primaryFile(f: Finding): string {
  return f.files[0] ?? f.evidence[0]?.file ?? NO_FILE;
}

const controlStyle = {
  width: '100%',
  padding: '0.35rem 0.45rem',
  borderRadius: 6,
  border: '1px solid var(--border-strong)',
  background: 'var(--surface)',
  color: 'var(--ink)',
  font: 'inherit',
  fontSize: '0.86rem',
  minWidth: 0,
} as const;

const buttonStyle = {
  padding: '0.35rem 0.7rem',
  borderRadius: 6,
  border: '1px solid var(--border-strong)',
  background: 'var(--surface-2)',
  color: 'var(--ink)',
  font: 'inherit',
  fontSize: '0.84rem',
  fontWeight: 550,
  cursor: 'pointer',
} as const;

function FieldLabel({ htmlFor, children }: { htmlFor: string; children: ReactNode }) {
  return (
    <label
      htmlFor={htmlFor}
      style={{
        display: 'block', fontSize: '0.72rem', textTransform: 'uppercase',
        letterSpacing: '0.05em', fontWeight: 650, color: 'var(--ink-3)', marginBottom: '0.2rem',
      }}
    >
      {children}
    </label>
  );
}

/** One finding row: a real button that expands the full evidence beneath it. */
function Row({
  finding, open, onToggle, currentScanId,
}: {
  finding: Finding; open: boolean; onToggle: () => void; currentScanId: string;
}) {
  const detailId = `detail-${finding.displayId}`;
  const location = locationOf(finding);
  return (
    <li
      id={`finding-${finding.displayId}`}
      style={{
        listStyle: 'none',
        borderTop: '1px solid var(--border)',
        background: open ? 'var(--surface-2)' : 'transparent',
      }}
    >
      <button
        type="button"
        onClick={onToggle}
        aria-expanded={open}
        aria-controls={open ? detailId : undefined}
        style={{
          display: 'block', width: '100%', textAlign: 'left', background: 'transparent',
          border: 'none', padding: '0.6rem 0.7rem', cursor: 'pointer', color: 'var(--ink)',
          font: 'inherit',
        }}
      >
        <span className="sr-only">{open ? 'Hide evidence for' : 'Show evidence for'}</span>
        <span style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: '0.4rem' }}>
          <span aria-hidden="true" style={{ color: 'var(--ink-3)', fontSize: '0.75rem', width: '0.8rem' }}>
            {open ? '▾' : '▸'}
          </span>
          <Mono>{finding.displayId}</Mono>
          {finding.priority ? <PriorityPill priority={finding.priority} /> : null}
          <SeverityPill severity={finding.severity} />
          <ConfidencePill confidence={finding.confidence} />
          <StatusPill status={finding.status} />
        </span>
        <span
          style={{
            display: 'block', marginTop: '0.2rem', paddingLeft: '1.2rem',
            fontWeight: 600, fontSize: '0.92rem', lineHeight: 1.45,
          }}
        >
          {finding.title}
        </span>
        <span
          style={{
            display: 'block', paddingLeft: '1.2rem', marginTop: '0.1rem',
            color: 'var(--ink-3)', fontFamily: 'var(--font-mono)', fontSize: '0.76rem',
            wordBreak: 'break-all',
          }}
        >
          {location || 'no location recorded'}
        </span>
      </button>
      {open ? (
        <div id={detailId} style={{ padding: '0 0.7rem 0.9rem' }}>
          <FindingDetail finding={finding} currentScanId={currentScanId} />
        </div>
      ) : null}
    </li>
  );
}

export function FindingsExplorer({
  findings,
  featureNames,
  scanId,
  scanParam,
  initialFilters,
  initialGroup,
  initialFinding,
}: {
  findings: Finding[];
  /** Feature inventory names, used as the option set for the feature filter. */
  featureNames: string[];
  scanId: string;
  /** The `?scan=` value to preserve in the URL, when one was supplied. */
  scanParam?: string;
  initialFilters: Filters;
  initialGroup: GroupKey;
  initialFinding?: string;
}) {
  const [filters, setFilters] = useState<Filters>(initialFilters);
  const [group, setGroup] = useState<GroupKey>(initialGroup);
  const [open, setOpen] = useState<string | undefined>(initialFinding);
  const scrolled = useRef(false);

  // Mirror the view into the URL without navigating, so it can be copied and reloaded.
  useEffect(() => {
    const params = new URLSearchParams();
    if (scanParam) params.set('scan', scanParam);
    if (filters.q) params.set('q', filters.q);
    for (const facet of FACETS) {
      const value = filters[facet.key];
      if (value) params.set(facet.key, value);
    }
    if (group !== 'priority') params.set('group', group);
    if (open) params.set('finding', open);
    const qs = params.toString();
    try {
      window.history.replaceState(null, '', `${window.location.pathname}${qs ? `?${qs}` : ''}`);
    } catch { /* history unavailable: the view still works, it just is not shareable */ }
  }, [filters, group, open, scanParam]);

  // Bring a deep-linked finding into view once.
  useEffect(() => {
    if (scrolled.current || !initialFinding) return;
    scrolled.current = true;
    document.getElementById(`finding-${initialFinding}`)?.scrollIntoView({ block: 'center' });
  }, [initialFinding]);

  const total = findings.length;

  /** Option sets, with the number of findings behind each value. */
  const options = useMemo(() => {
    const out: Record<FacetKey, Array<{ value: string; label: string; count: number }>> = {
      category: [], severity: [], confidence: [], status: [],
      priority: [], source: [], feature: [], effort: [],
    };
    for (const facet of FACETS) {
      const counts = new Map<string, number>();
      if (facet.key === 'feature') for (const name of featureNames) counts.set(name, 0);
      for (const f of findings) {
        for (const v of facet.valuesOf(f)) counts.set(v, (counts.get(v) ?? 0) + 1);
      }
      const keys = [...counts.keys()];
      keys.sort((a, b) => {
        if (facet.order) {
          const ia = facet.order.indexOf(a);
          const ib = facet.order.indexOf(b);
          if (ia !== -1 || ib !== -1) return (ia === -1 ? 99 : ia) - (ib === -1 ? 99 : ib);
        }
        return facet.labelOf(a).localeCompare(facet.labelOf(b));
      });
      out[facet.key] = keys.map((value) => ({
        value, label: facet.labelOf(value), count: counts.get(value) ?? 0,
      }));
    }
    return out;
  }, [findings, featureNames]);

  const activeCount = useMemo(
    () => (filters.q ? 1 : 0) + FACETS.filter((f) => filters[f.key]).length,
    [filters],
  );

  const filtered = useMemo(() => {
    const q = filters.q.trim().toLowerCase();
    return findings.filter((f) => {
      for (const facet of FACETS) {
        const want = filters[facet.key];
        if (want && !facet.valuesOf(f).includes(want)) return false;
      }
      if (q) {
        const hay = [
          f.title, f.ruleId, f.displayId, ...f.files, ...f.evidence.map((e) => e.file),
        ].join(' ').toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
  }, [findings, filters]);

  const groups = useMemo(() => groupFindings(filtered, group), [filtered, group]);

  const openFinding = open ? findings.find((f) => f.displayId === open) : undefined;
  const openIsFilteredOut = openFinding !== undefined && !filtered.includes(openFinding);
  const openMissing = open !== undefined && openFinding === undefined;

  const toggle = (displayId: string) => setOpen((cur) => (cur === displayId ? undefined : displayId));

  return (
    <>
      <Card>
        <SectionHeading
          id="filters"
          hint="Every filter is recorded in the address bar, so a narrowed view can be copied and reopened."
        >
          Filter and group
        </SectionHeading>

        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))',
            gap: '0.7rem',
          }}
        >
          <div style={{ gridColumn: '1 / -1' }}>
            <FieldLabel htmlFor="findings-q">Search title, rule, identifier or file</FieldLabel>
            <input
              id="findings-q"
              type="search"
              value={filters.q}
              placeholder="e.g. authorisation, security.injection, src/lib/db.ts"
              onChange={(e) => setFilters((cur) => ({ ...cur, q: e.target.value }))}
              style={controlStyle}
            />
          </div>

          {FACETS.map((facet) => (
            <div key={facet.key}>
              <FieldLabel htmlFor={`findings-${facet.key}`}>{facet.label}</FieldLabel>
              <select
                id={`findings-${facet.key}`}
                value={filters[facet.key]}
                onChange={(e) => setFilters((cur) => ({ ...cur, [facet.key]: e.target.value }))}
                style={controlStyle}
              >
                <option value="">Any {facet.label.toLowerCase()}</option>
                {options[facet.key].map((o) => (
                  <option key={o.value} value={o.value}>
                    {o.label} ({o.count})
                  </option>
                ))}
              </select>
            </div>
          ))}

          <div>
            <FieldLabel htmlFor="findings-group">Group by</FieldLabel>
            <select
              id="findings-group"
              value={group}
              onChange={(e) => setGroup(e.target.value as GroupKey)}
              style={controlStyle}
            >
              {(Object.keys(GROUP_LABEL) as GroupKey[]).map((k) => (
                <option key={k} value={k}>{GROUP_LABEL[k]}</option>
              ))}
            </select>
          </div>
        </div>

        <div
          style={{
            marginTop: '0.9rem', display: 'flex', flexWrap: 'wrap',
            alignItems: 'center', gap: '0.6rem',
          }}
        >
          <p role="status" style={{ margin: 0, fontSize: '0.86rem', color: 'var(--ink-2)' }}>
            {activeCount === 0
              ? `Showing all ${total} ${total === 1 ? 'finding' : 'findings'}.`
              : `Showing ${filtered.length} of ${total} findings. ${activeCount} ${activeCount === 1 ? 'filter' : 'filters'} active.`}
          </p>
          {activeCount > 0 ? (
            <button type="button" onClick={() => setFilters(EMPTY_FILTERS)} style={buttonStyle}>
              Clear all filters
            </button>
          ) : null}
        </div>
      </Card>

      {openMissing ? (
        <Caveat>
          No finding with the identifier <Mono>{open}</Mono> exists in this scan. It may belong to a
          different scan of this project.
        </Caveat>
      ) : null}

      {openIsFilteredOut && openFinding ? (
        <Card>
          <SectionHeading hint="This finding was opened from a link and does not match the current filters.">
            Opened finding
          </SectionHeading>
          <ul style={{ margin: 0, padding: 0 }}>
            <Row
              finding={openFinding}
              open
              onToggle={() => toggle(openFinding.displayId)}
              currentScanId={scanId}
            />
          </ul>
        </Card>
      ) : null}

      {filtered.length === 0 ? (
        <EmptyState title="No findings match these filters">
          <p style={{ margin: 0 }}>
            This scan reported {total} {total === 1 ? 'finding' : 'findings'}; none of them match this
            combination. Widen or clear a filter to see them.
          </p>
        </EmptyState>
      ) : (
        groups.map((g) => (
          <Card key={g.key} as="section">
            <SectionHeading hint={g.hint}>
              <span style={{ display: 'inline-flex', flexWrap: 'wrap', alignItems: 'baseline', gap: '0.45rem' }}>
                <span>{g.label}</span>
                <span style={{ color: 'var(--ink-3)', fontWeight: 500, fontSize: '0.86rem' }}>
                  {g.items.length} {g.items.length === 1 ? 'finding' : 'findings'}
                </span>
              </span>
            </SectionHeading>
            <ul style={{ margin: 0, padding: 0, borderBottom: '1px solid var(--border)' }}>
              {g.items.map((f) => (
                <Row
                  key={`${g.key}:${f.displayId}`}
                  finding={f}
                  open={open === f.displayId}
                  onToggle={() => toggle(f.displayId)}
                  currentScanId={scanId}
                />
              ))}
            </ul>
          </Card>
        ))
      )}
    </>
  );
}

interface Group {
  key: string;
  label: string;
  hint?: string;
  items: Finding[];
}

/**
 * Bucket the findings for display. Order within a bucket is the order the store
 * returned, which is already priority order.
 *
 * Grouping by feature can place one finding in several buckets, because a
 * finding can affect several features; the "N of M" count above stays a count
 * of distinct findings.
 */
function groupFindings(findings: Finding[], by: GroupKey): Group[] {
  const buckets = new Map<string, Finding[]>();
  const push = (key: string, f: Finding) => {
    const list = buckets.get(key);
    if (list) list.push(f);
    else buckets.set(key, [f]);
  };

  for (const f of findings) {
    if (by === 'priority') push(f.priority ?? NO_PRIORITY, f);
    else if (by === 'category') push(f.category, f);
    else if (by === 'severity') push(f.severity, f);
    else if (by === 'file') push(primaryFile(f), f);
    else if (f.affectedFeatures.length === 0) push(NO_FEATURE, f);
    else for (const name of f.affectedFeatures) push(name, f);
  }

  const canonical: readonly string[] | undefined =
    by === 'priority' ? PRIORITY_ORDER : by === 'severity' ? SEVERITY_ORDER : undefined;

  const order = (keys: string[]): string[] =>
    keys.sort((a, b) => {
      // Buckets that stand for "nothing recorded" sort last, never first.
      const sentinelA = a.startsWith('\u0000') ? 1 : 0;
      const sentinelB = b.startsWith('\u0000') ? 1 : 0;
      if (sentinelA !== sentinelB) return sentinelA - sentinelB;
      if (canonical) {
        const ia = canonical.indexOf(a);
        const ib = canonical.indexOf(b);
        if (ia !== -1 || ib !== -1) return (ia === -1 ? 99 : ia) - (ib === -1 ? 99 : ib);
      }
      return label(a).localeCompare(label(b));
    });

  const label = (key: string): string => {
    if (key === NO_PRIORITY) return 'Not prioritised';
    if (key === NO_FILE) return 'No file recorded';
    if (key === NO_FEATURE) return 'No feature attributed';
    if (by === 'priority') return `Priority ${key}`;
    if (by === 'category') return CATEGORY_LABEL[key] ?? key;
    if (by === 'severity') return `${key.charAt(0).toUpperCase()}${key.slice(1)} severity`;
    if (by === 'feature') return `Feature: ${key}`;
    return key;
  };

  const hint = (key: string): string | undefined => {
    if (by === 'priority') {
      return key === NO_PRIORITY
        ? 'The prioritiser assigned no band to these.'
        : PRIORITY_MEANING[key];
    }
    if (by === 'feature' && key === NO_FEATURE) {
      return 'No feature in the inventory was attributed to these findings.';
    }
    if (by === 'file' && key === NO_FILE) {
      return 'Neither the finding nor its evidence recorded a file.';
    }
    return undefined;
  };

  return order([...buckets.keys()]).map((key) => ({
    key,
    label: label(key),
    hint: hint(key),
    items: buckets.get(key) ?? [],
  }));
}
