import type { ReactNode } from 'react';
import { Card, Caveat, EmptyState, SectionHeading, Table, Tag, Td } from '../../../components/ui.tsx';
import type { ModelRow } from '../../../lib/store.ts';

/**
 * `Shell` lays its children out in a grid, where a grid item's default
 * `min-width: auto` lets its widest content set the track width. `width: 0`
 * drops this subtree's intrinsic contribution and `min-width: 100%` fills the
 * resolved width, so a wide field table scrolls inside itself rather than
 * stretching the page sideways.
 */
function FitWidth({ children }: { children: ReactNode }) {
  return <div style={{ width: 0, minWidth: '100%' }}>{children}</div>;
}

/**
 * Data models as declared in source.
 *
 * Two things are called out deliberately. An ownership column is the field an
 * authorisation check keys on — "this row belongs to the caller" — so a model
 * that has one is marked, because its absence changes what a route can safely
 * be allowed to do. And a model whose only index is its primary key is stated
 * plainly rather than left as an empty cell, since "no secondary index" is a
 * fact worth reading and an empty cell is ambiguous.
 *
 * What is NOT here: any claim about query speed. These are schema definitions
 * read from a file. No database was running and nothing was timed.
 */

const MODEL_KIND_LABEL: Record<string, string> = {
  orm_model: 'ORM model',
  sql_table: 'SQL table',
  schema: 'Schema',
  type: 'Type declaration',
};

function primaryKeyOf(model: ModelRow): string | undefined {
  const unique = model.fields.find((f) => f.unique);
  if (unique) return unique.name;
  return model.fields.find((f) => f.name === 'id')?.name;
}

export function DataModels({ models }: { models: ModelRow[] }) {
  if (models.length === 0) {
    return (
      <Card>
        <SectionHeading id="data-models">Data models</SectionHeading>
        <EmptyState title="No data models were extracted from this scan">
          No ORM schema, SQL table definition or typed record declaration was found in a form the
          extractor could read.
        </EmptyState>
      </Card>
    );
  }

  const withOwnership = models.filter((m) => m.ownershipField).length;

  return (
    <Card>
      <SectionHeading
        id="data-models"
        hint="Fields, relations and indexes as declared in the schema files of this codebase."
      >
        Data models
      </SectionHeading>

      <p style={{ margin: '0 0 0.9rem', fontSize: '0.88rem', color: 'var(--ink-2)' }}>
        {models.length} model{models.length === 1 ? '' : 's'}, of which {withOwnership} declare
        {withOwnership === 1 ? 's' : ''} an ownership column.
      </p>

      <div style={{ display: 'grid', gap: '1.1rem' }}>
        {models.map((model) => {
          const pk = primaryKeyOf(model);
          const secondary = model.indexes.filter((i) => i !== pk);
          const owned = model.ownershipField;

          return (
            <section
              key={`${model.file}:${model.name}`}
              style={{
                border: `1px solid ${owned ? 'var(--accent)' : 'var(--border)'}`,
                borderLeftWidth: owned ? 3 : 1,
                borderRadius: 8,
                padding: '0.85rem 0.95rem',
                background: owned ? 'var(--accent-soft)' : 'var(--surface-2)',
              }}
            >
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.4rem', alignItems: 'baseline' }}>
                <h3 style={{ margin: 0, fontSize: '0.98rem', fontWeight: 650 }}>{model.name}</h3>
                <Tag>{MODEL_KIND_LABEL[model.kind] ?? model.kind}</Tag>
                {owned ? <Tag tone="accent">ownership column: {owned}</Tag> : null}
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.76rem', color: 'var(--ink-3)', wordBreak: 'break-all' }}>
                  {model.file}
                </span>
              </div>

              {owned ? (
                <p style={{ margin: '0.45rem 0 0', fontSize: '0.85rem', color: 'var(--ink-2)' }}>
                  <strong>{model.name}.{owned}</strong> is the column an authorisation check keys on:
                  a route that reads or writes this model should constrain the query by the
                  authenticated caller's identity through it.
                </p>
              ) : (
                <p style={{ margin: '0.45rem 0 0', fontSize: '0.85rem', color: 'var(--ink-3)' }}>
                  No ownership column was identified, so rows of this model cannot be attributed to a
                  particular user from the schema alone.
                </p>
              )}

              <div style={{ marginTop: '0.7rem' }}>
                <h4 style={{ margin: '0 0 0.35rem', fontSize: '0.82rem', fontWeight: 650 }}>
                  Fields ({model.fields.length})
                </h4>
                {model.fields.length === 0 ? (
                  <p style={{ margin: 0, fontSize: '0.85rem', color: 'var(--ink-3)' }}>
                    No fields were recorded for this model.
                  </p>
                ) : (
                  <FitWidth>
                    <Table
                      head={['Field', 'Type', 'Nullable', 'Unique', 'Role']}
                      caption={`Fields of ${model.name}`}
                    >
                      {model.fields.map((f) => (
                        <tr key={f.name}>
                          <Td mono>{f.name}</Td>
                          <Td mono>{f.type ?? <span style={{ color: 'var(--ink-3)' }}>not recorded</span>}</Td>
                          <Td nowrap>
                            {f.nullable === undefined ? (
                              <span style={{ color: 'var(--ink-3)' }}>not recorded</span>
                            ) : f.nullable ? (
                              'nullable'
                            ) : (
                              'not null'
                            )}
                          </Td>
                          <Td nowrap>
                            {f.unique === undefined ? (
                              <span style={{ color: 'var(--ink-3)' }}>not recorded</span>
                            ) : f.unique ? (
                              'unique'
                            ) : (
                              'not unique'
                            )}
                          </Td>
                          <Td nowrap>
                            {f.name === owned ? (
                              <Tag tone="accent">ownership</Tag>
                            ) : f.name === pk ? (
                              <Tag>primary key</Tag>
                            ) : model.indexes.includes(f.name) ? (
                              <Tag>indexed</Tag>
                            ) : (
                              <span style={{ color: 'var(--ink-3)' }}>—</span>
                            )}
                          </Td>
                        </tr>
                      ))}
                    </Table>
                  </FitWidth>
                )}
              </div>

              <div
                style={{
                  marginTop: '0.75rem',
                  display: 'grid',
                  gap: '0.7rem',
                  gridTemplateColumns: 'repeat(auto-fit, minmax(13rem, 1fr))',
                }}
              >
                <div>
                  <h4 style={{ margin: '0 0 0.25rem', fontSize: '0.82rem', fontWeight: 650 }}>
                    Relations ({model.relations.length})
                  </h4>
                  {model.relations.length === 0 ? (
                    <p style={{ margin: 0, fontSize: '0.84rem', color: 'var(--ink-3)' }}>
                      No relation to another model was declared.
                    </p>
                  ) : (
                    <ul style={{ margin: 0, paddingLeft: '1.1rem', fontSize: '0.85rem', display: 'grid', gap: '0.1rem' }}>
                      {model.relations.map((r) => (
                        <li key={`${r.kind}:${r.to}`}>
                          <span style={{ color: 'var(--ink-3)' }}>{r.kind.replace(/_/g, ' ')}</span>{' '}
                          <strong>{r.to}</strong>
                        </li>
                      ))}
                    </ul>
                  )}
                </div>

                <div>
                  <h4 style={{ margin: '0 0 0.25rem', fontSize: '0.82rem', fontWeight: 650 }}>
                    Indexes ({model.indexes.length})
                  </h4>
                  {model.indexes.length === 0 ? (
                    <p style={{ margin: 0, fontSize: '0.84rem', color: 'var(--ink-3)' }}>
                      No index was declared for this model, not even a primary key.
                    </p>
                  ) : (
                    <>
                      <ul style={{ margin: 0, paddingLeft: '1.1rem', fontSize: '0.85rem', display: 'grid', gap: '0.1rem' }}>
                        {model.indexes.map((i) => (
                          <li key={i}>
                            <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem' }}>{i}</span>
                            {i === pk ? <span style={{ color: 'var(--ink-3)' }}> (primary key)</span> : null}
                          </li>
                        ))}
                      </ul>
                      {secondary.length === 0 ? (
                        <p style={{ margin: '0.35rem 0 0', fontSize: '0.84rem', color: 'var(--ink-2)' }}>
                          No index beyond the primary key. Any query that filters or sorts on another
                          column has no declared index to use.
                        </p>
                      ) : null}
                    </>
                  )}
                </div>
              </div>
            </section>
          );
        })}
      </div>

      <div style={{ marginTop: '1rem' }}>
        <Caveat tone="neutral">
          These are schema definitions read from source files. No database was connected and no query
          was executed, so nothing here is a performance measurement — the absence of a secondary
          index is a fact about the schema, not an observed slow query. Indexes created outside the
          schema, by a migration or by hand, are not visible.
        </Caveat>
      </div>
    </Card>
  );
}
