import Link from 'next/link';
import type { ReactNode } from 'react';
import { Card, Caveat, ConfidencePill, EmptyState, SectionHeading, SeverityPill, Table, Tag, Td } from '../../../components/ui.tsx';
import type { RouteRow } from '../../../lib/store.ts';
import type { FindingLink } from './explorer.tsx';

/**
 * The HTTP surface, one row per route.
 *
 * The load-bearing column is authentication, and it has three states that must
 * not be allowed to collapse into two:
 *
 *  - `required` — an authentication check was found inside the handler.
 *  - `public`   — the handler was read and no check was found in it.
 *  - `unknown`  — enforcement may exist in middleware or a framework
 *                 convention that CodeLens does not model.
 *
 * `unknown` must not be rendered as though it were safe, and must not be
 * rendered as though it were a confirmed hole either. It is an unresolved
 * question, so it gets its own neutral treatment and its own gloss, and the
 * word itself does the work rather than a colour.
 */

const AUTH_NOTE: Record<string, string> = {
  required: 'An authentication check was found inside this handler.',
  public:
    'The handler was read and no authentication check was found inside it. If enforcement exists elsewhere, it was not visible here.',
  unknown:
    'Not resolved. Enforcement may live in middleware or a framework convention that was not modelled. Neither safe nor confirmed open — trace it.',
};

const VALIDATION_NOTE: Record<string, string> = {
  present: 'Input validation was found in the handler.',
  partial: 'Some input is validated and some is not.',
  absent: 'No input validation was found in the handler.',
  unknown: 'Could not be resolved from the handler body.',
};

const ERROR_NOTE: Record<string, string> = {
  present: 'The handler has error handling.',
  absent: 'No error handling was found in the handler.',
  unknown: 'Could not be resolved from the handler body.',
};

function AuthCell({ value }: { value: string }) {
  const glyph = value === 'required' ? '✓' : value === 'public' ? '○' : '?';
  const tone: 'good' | 'warn' | 'neutral' =
    value === 'required' ? 'good' : value === 'public' ? 'warn' : 'neutral';
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: '0.3rem' }} title={AUTH_NOTE[value] ?? value}>
      <span aria-hidden="true" style={{ fontFamily: 'var(--font-mono)', color: 'var(--ink-3)' }}>
        {glyph}
      </span>
      <Tag tone={tone}>{value}</Tag>
    </span>
  );
}

function Plain({ value, notes }: { value: string; notes: Record<string, string> }) {
  return <span title={notes[value] ?? value}>{value}</span>;
}

function Shape({ value, label }: { value: string | undefined; label: string }): ReactNode {
  if (!value) {
    return (
      <span style={{ color: 'var(--ink-3)', fontStyle: 'italic' }}>
        no {label} shape recorded
      </span>
    );
  }
  return <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.78rem' }}>{value}</span>;
}

export function ApiSurface({
  projectId,
  routes,
  findings,
}: {
  projectId: string;
  routes: RouteRow[];
  findings: FindingLink[];
}) {
  const byFile = new Map<string, FindingLink[]>();
  for (const f of findings) {
    for (const file of f.files) {
      const arr = byFile.get(file);
      if (arr) arr.push(f);
      else byFile.set(file, [f]);
    }
  }

  const counts = routes.reduce<Record<string, number>>((acc, r) => {
    acc[r.authRequired] = (acc[r.authRequired] ?? 0) + 1;
    return acc;
  }, {});

  return (
    <Card>
      <SectionHeading
        id="api-surface"
        hint="Every route read from a handler definition, with what was found inside that handler. Nothing here was exercised against a running server."
      >
        API surface
      </SectionHeading>

      {routes.length === 0 ? (
        <EmptyState title="No API routes were extracted from this scan">
          Either this codebase exposes no HTTP surface the extractor recognises, or its routes are
          defined in a way that cannot be read statically — string-built paths and dynamic
          registration are both invisible here.
        </EmptyState>
      ) : (
        <>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.4rem', marginBottom: '0.8rem', fontSize: '0.85rem', alignItems: 'center' }}>
            <span style={{ color: 'var(--ink-3)' }}>Authentication across {routes.length} routes:</span>
            <Tag tone="good">required {counts.required ?? 0}</Tag>
            <Tag tone="warn">public {counts.public ?? 0}</Tag>
            <Tag>unknown {counts.unknown ?? 0}</Tag>
          </div>

          <Table
            head={[
              'Method',
              'Path',
              'Auth',
              'Authorisation checks',
              'Validation',
              'Error handling',
              'Request',
              'Response',
              'Source',
              'Findings',
            ]}
            caption="API routes with authentication, authorisation, validation and error handling as read from each handler"
          >
            {routes.map((r) => {
              const hits = byFile.get(r.file) ?? [];
              return (
                <tr key={`${r.method} ${r.path} ${r.file}:${r.line ?? ''}`}>
                  <Td mono nowrap>
                    {r.method}
                  </Td>
                  <Td mono>{r.path}</Td>
                  <Td nowrap>
                    <AuthCell value={r.authRequired} />
                  </Td>
                  <Td>
                    {r.authorizationChecks.length === 0 ? (
                      <span style={{ color: 'var(--ink-3)' }}>none detected</span>
                    ) : (
                      <ul style={{ margin: 0, paddingLeft: '1rem' }}>
                        {r.authorizationChecks.map((c) => (
                          <li key={c} style={{ fontFamily: 'var(--font-mono)', fontSize: '0.78rem' }}>
                            {c}
                          </li>
                        ))}
                      </ul>
                    )}
                  </Td>
                  <Td nowrap>
                    <Plain value={r.validation} notes={VALIDATION_NOTE} />
                  </Td>
                  <Td nowrap>
                    <Plain value={r.errorHandling} notes={ERROR_NOTE} />
                  </Td>
                  <Td>
                    <Shape value={r.requestShape} label="request" />
                  </Td>
                  <Td>
                    <Shape value={r.responseShape} label="response" />
                  </Td>
                  <Td mono>
                    {r.file}
                    {r.line ? `:${r.line}` : ''}
                    {r.handlerSymbol ? (
                      <div style={{ color: 'var(--ink-3)' }}>{r.handlerSymbol}</div>
                    ) : (
                      <div style={{ color: 'var(--ink-3)' }}>anonymous handler</div>
                    )}
                  </Td>
                  <Td>
                    {hits.length === 0 ? (
                      <span style={{ color: 'var(--ink-3)' }}>none</span>
                    ) : (
                      <ul style={{ margin: 0, padding: 0, listStyle: 'none', display: 'grid', gap: '0.3rem' }}>
                        {hits.map((f) => (
                          <li key={f.displayId} style={{ display: 'grid', gap: '0.15rem' }}>
                            <Link
                              href={`/projects/${encodeURIComponent(projectId)}/findings/${encodeURIComponent(f.displayId)}`}
                              style={{ fontFamily: 'var(--font-mono)', fontSize: '0.78rem' }}
                            >
                              {f.displayId}
                            </Link>
                            <span style={{ display: 'flex', flexWrap: 'wrap', gap: '0.2rem' }}>
                              <SeverityPill severity={f.severity} />
                              <ConfidencePill confidence={f.confidence} />
                            </span>
                          </li>
                        ))}
                      </ul>
                    )}
                  </Td>
                </tr>
              );
            })}
          </Table>

          <div style={{ marginTop: '0.9rem', display: 'grid', gap: '0.7rem' }}>
            <Caveat>
              <strong>What the authentication column means.</strong> <em>required</em> — a check was
              found inside the handler. <em>public</em> — the handler was read and no check was found
              in it. <em>unknown</em> — enforcement may live in middleware or a framework convention
              that CodeLens does not model, so the route is neither shown as protected nor reported as
              an open hole. Trace the evidence before acting on any of the three.
            </Caveat>
            <Caveat tone="neutral">
              Authorisation checks are those bound to the authenticated identity inside the handler;
              a check that happens in a layer above is not visible here. Request and response shapes
              are the keys the extractor could read, not a validated schema. No route was called, so
              nothing in this table reflects observed runtime behaviour.
            </Caveat>
          </div>
        </>
      )}
    </Card>
  );
}
