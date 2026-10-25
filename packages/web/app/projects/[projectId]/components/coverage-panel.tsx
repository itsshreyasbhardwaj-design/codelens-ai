import { CATEGORY_LABEL } from '../../../lib/format.ts';
import { Card, Caveat, SectionHeading, Stat, Tag } from '../../../components/ui.tsx';
import type { ScanRow } from '../../../lib/store.ts';

/**
 * Coverage panel.
 *
 * This is what stops a clean report being read as a clean codebase. Everything
 * here is recorded by the scan: how much was read, which analyzers ran, which
 * did not and why, and which of the four analysis layers completed.
 */

type Coverage = NonNullable<ScanRow['coverage']>;

const LANGUAGE_LABEL: Record<string, string> = {
  javascript: 'JavaScript', typescript: 'TypeScript', tsx: 'TSX', jsx: 'JSX',
  json: 'JSON', yaml: 'YAML', toml: 'TOML', markdown: 'Markdown', html: 'HTML',
  css: 'CSS', scss: 'SCSS', sql: 'SQL', graphql: 'GraphQL', dockerfile: 'Dockerfile',
  dotenv: 'dotenv', prisma: 'Prisma', python: 'Python', go: 'Go', rust: 'Rust',
  java: 'Java', kotlin: 'Kotlin', swift: 'Swift', ruby: 'Ruby', php: 'PHP',
  csharp: 'C#', cpp: 'C++', c: 'C', shell: 'Shell', bash: 'Shell',
};

function languageLabel(lang: string): string {
  return LANGUAGE_LABEL[lang] ?? `${lang.charAt(0).toUpperCase()}${lang.slice(1)}`;
}

function analyzerLabel(analyzer: string): string {
  return CATEGORY_LABEL[analyzer] ?? `${analyzer.charAt(0).toUpperCase()}${analyzer.slice(1)}`;
}

const LAYERS: Array<{ key: keyof Coverage['layers']; label: string; what: string }> = [
  { key: 'static', label: 'Deterministic static analysis', what: 'Rule and AST checks over the files that were parsed.' },
  { key: 'graph', label: 'Architecture reconstruction', what: 'Cross-file imports, calls and route-to-model relationships.' },
  { key: 'ai', label: 'AI semantic investigation', what: 'Model-assisted reading of code the deterministic rules cannot judge.' },
  { key: 'dynamic', label: 'Dynamic verification', what: 'Running the project to confirm behaviour rather than infer it.' },
];

function TagRow({ items, empty }: { items: string[]; empty: string }) {
  if (items.length === 0) {
    return <p style={{ margin: 0, fontSize: '0.82rem', color: 'var(--ink-3)' }}>{empty}</p>;
  }
  return (
    <ul style={{ margin: 0, padding: 0, listStyle: 'none', display: 'flex', flexWrap: 'wrap', gap: '0.3rem' }}>
      {items.map((item) => (
        <li key={item}><Tag>{item}</Tag></li>
      ))}
    </ul>
  );
}

function Block({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div style={{ display: 'grid', gap: '0.4rem', alignContent: 'start' }}>
      <h3
        style={{
          margin: 0, fontSize: '0.78rem', fontWeight: 600, color: 'var(--ink-3)',
          textTransform: 'uppercase', letterSpacing: '0.05em',
        }}
      >
        {title}
      </h3>
      {children}
    </div>
  );
}

export function CoveragePanel({ coverage, aiProvider }: { coverage: Coverage | undefined; aiProvider: string }) {
  if (!coverage) {
    return (
      <Card>
        <SectionHeading id="coverage" hint="How much of this project was actually read.">
          Coverage of this scan
        </SectionHeading>
        <Caveat>
          This scan recorded no coverage data, so there is no way to tell how much of the project was read.
          Treat every other number on this page as unqualified: a category with no findings may simply never
          have been looked at.
        </Caveat>
      </Card>
    );
  }

  const notParsed = Math.max(0, coverage.filesIndexed - coverage.filesParsed);
  const skipReasons = Object.entries(coverage.skippedReasons);
  const layersDone = LAYERS.filter((l) => coverage.layers[l.key]).length;

  return (
    <Card>
      <SectionHeading
        id="coverage"
        hint="A clean result only means something where something was read. These are the limits of this scan, recorded as it ran."
      >
        Coverage of this scan
      </SectionHeading>

      {coverage.truncated ? (
        <div style={{ marginBottom: '1rem' }}>
          <Caveat>
            <strong>This scan was truncated.</strong>{' '}
            {coverage.truncationNote
              ? coverage.truncationNote
              : 'The scan exceeded a bound and stopped short of the whole project; no note recording what was dropped was stored.'}{' '}
            Findings and scores below describe only the part that was reached.
          </Caveat>
        </div>
      ) : null}

      <div
        style={{
          display: 'grid', gap: '0.9rem', gridTemplateColumns: 'repeat(auto-fit, minmax(8rem, 1fr))',
          paddingBottom: '1rem', borderBottom: '1px solid var(--border)',
        }}
      >
        <Stat label="Files indexed" value={coverage.filesIndexed} hint={`of ${coverage.filesTotal} discovered`} />
        <Stat label="Parsed into an AST" value={coverage.filesParsed} hint="read structurally, not just as text" />
        <Stat
          label="Indexed, not parsed"
          value={notParsed}
          hint={notParsed > 0 ? 'text-level rules only' : 'every indexed file was parsed'}
          tone={notParsed > 0 ? 'critical' : 'neutral'}
        />
        <Stat label="Excluded" value={coverage.filesSkipped} hint="never indexed" />
        <Stat
          label="Parse coverage"
          value={`${Math.round(coverage.parseRatio * 100)}%`}
          hint="of files in deep-support languages"
        />
      </div>

      <div style={{ padding: '1rem 0', borderBottom: '1px solid var(--border)' }}>
        <h3 style={{ margin: '0 0 0.15rem', fontSize: '0.92rem', fontWeight: 650 }}>
          Analysis layers
        </h3>
        <p style={{ margin: '0 0 0.6rem', fontSize: '0.82rem', color: 'var(--ink-3)' }}>
          {layersDone} of {LAYERS.length} completed. A layer that did not run produced no findings at all —
          that absence is not a result.
        </p>
        <ul
          style={{
            margin: 0, padding: 0, listStyle: 'none',
            display: 'grid', gap: '0.5rem', gridTemplateColumns: 'repeat(auto-fit, minmax(14rem, 1fr))',
          }}
        >
          {LAYERS.map((layer) => {
            const done = coverage.layers[layer.key];
            return (
              <li
                key={layer.key}
                style={{
                  border: '1px solid var(--border)', borderRadius: 8, padding: '0.55rem 0.7rem',
                  background: done ? 'var(--good-soft)' : 'var(--surface-2)',
                  display: 'grid', gap: '0.2rem', alignContent: 'start',
                }}
              >
                <div style={{ display: 'flex', gap: '0.4rem', alignItems: 'baseline', flexWrap: 'wrap' }}>
                  <span
                    aria-hidden="true"
                    style={{ color: done ? 'var(--good)' : 'var(--ink-3)', fontSize: '0.8rem' }}
                  >
                    {done ? '●' : '○'}
                  </span>
                  <span style={{ fontWeight: 600, fontSize: '0.88rem' }}>{layer.label}</span>
                </div>
                <span style={{ fontSize: '0.8rem', fontWeight: 600, color: done ? 'var(--good)' : 'var(--ink-2)' }}>
                  {done ? 'Completed' : 'Did not run'}
                </span>
                <span style={{ fontSize: '0.8rem', color: 'var(--ink-3)', lineHeight: 1.45 }}>
                  {layer.what}
                  {layer.key === 'ai' ? ` AI provider for this scan: ${aiProvider}.` : ''}
                </span>
              </li>
            );
          })}
        </ul>
      </div>

      <div
        style={{
          display: 'grid', gap: '1rem', gridTemplateColumns: 'repeat(auto-fit, minmax(15rem, 1fr))',
          padding: '1rem 0', borderBottom: '1px solid var(--border)',
        }}
      >
        <Block title={`Analyzers that ran (${coverage.analyzersRun.length})`}>
          <TagRow
            items={coverage.analyzersRun.map(analyzerLabel)}
            empty="No analyzer ran. Nothing on this page was assessed."
          />
        </Block>
        <Block title={`Analyzers that did not run (${coverage.analyzersSkipped.length})`}>
          {coverage.analyzersSkipped.length === 0 ? (
            <p style={{ margin: 0, fontSize: '0.82rem', color: 'var(--ink-3)' }}>
              Every analyzer in this build ran.
            </p>
          ) : (
            <ul style={{ margin: 0, padding: 0, listStyle: 'none', display: 'grid', gap: '0.35rem' }}>
              {coverage.analyzersSkipped.map((a) => (
                <li key={a.analyzer} style={{ fontSize: '0.82rem', lineHeight: 1.45 }}>
                  <strong style={{ color: 'var(--medium)' }}>{analyzerLabel(a.analyzer)}</strong>
                  <span style={{ color: 'var(--ink-2)' }}> — {a.reason}</span>
                </li>
              ))}
            </ul>
          )}
        </Block>
      </div>

      <div
        style={{
          display: 'grid', gap: '1rem', gridTemplateColumns: 'repeat(auto-fit, minmax(13rem, 1fr))',
          padding: '1rem 0',
        }}
      >
        <Block title={`Deep support (${coverage.languagesDeep.length})`}>
          <TagRow
            items={coverage.languagesDeep.map(languageLabel)}
            empty="No file was in a deep-support language."
          />
          <p style={{ margin: 0, fontSize: '0.78rem', color: 'var(--ink-3)', lineHeight: 1.45 }}>
            AST parsing, symbol resolution and cross-file tracing.
          </p>
        </Block>
        <Block title={`Shallow support (${coverage.languagesShallow.length})`}>
          <TagRow items={coverage.languagesShallow.map(languageLabel)} empty="None." />
          <p style={{ margin: 0, fontSize: '0.78rem', color: 'var(--ink-3)', lineHeight: 1.45 }}>
            Structural indexing, manifest and config analysis, text-level rules only.
          </p>
        </Block>
        <Block title={`Unsupported (${coverage.languagesUnsupported.length})`}>
          <TagRow items={coverage.languagesUnsupported.map(languageLabel)} empty="None." />
          <p style={{ margin: 0, fontSize: '0.78rem', color: 'var(--ink-3)', lineHeight: 1.45 }}>
            Indexed by path only. No rule was applied to their contents.
          </p>
        </Block>
      </div>

      {skipReasons.length > 0 ? (
        <div style={{ borderTop: '1px solid var(--border)', paddingTop: '1rem' }}>
          <Block title="Recorded reasons files were excluded or left unparsed">
            <ul style={{ margin: 0, paddingLeft: '1.1rem', display: 'grid', gap: '0.25rem' }}>
              {skipReasons.map(([reason, count]) => (
                <li key={reason} style={{ fontSize: '0.82rem', color: 'var(--ink-2)', lineHeight: 1.45 }}>
                  <span style={{ fontVariantNumeric: 'tabular-nums', fontWeight: 650 }}>{count}</span>
                  {' '}file{count === 1 ? '' : 's'}: {reason}
                </li>
              ))}
            </ul>
          </Block>
        </div>
      ) : null}
    </Card>
  );
}
