import type { ApiEndpoint, ArchComponent, ArchRelationship, DataModel, Evidence, TechDetection } from '@codelens/core';
import type { SourceFile } from '../ingest/normalize.ts';
import type { ParsedModule } from '../parse/types.ts';

/**
 * Architecture reconstruction.
 *
 * Every component and relationship carries a provenance:
 *   - `detected`: read from code (an import, a query call, a route export).
 *   - `inferred`: concluded from convention (a path layout, a naming pattern).
 * The UI renders the two differently, because an inferred edge is a hypothesis.
 */

/** External SDKs worth showing as their own architecture node. */
const EXTERNAL_SERVICE_PACKAGES: Array<{ match: RegExp; name: string }> = [
  { match: /^stripe$/, name: 'Stripe' },
  { match: /^openai$/, name: 'OpenAI' },
  { match: /^@anthropic-ai\/sdk$/, name: 'Anthropic' },
  { match: /^@aws-sdk\//, name: 'AWS' },
  { match: /^(nodemailer|resend|@sendgrid\/mail|postmark)/, name: 'Email provider' },
  { match: /^twilio$/, name: 'Twilio' },
  { match: /^@supabase\//, name: 'Supabase' },
  { match: /^firebase(-admin)?$/, name: 'Firebase' },
  { match: /^(ioredis|redis|@upstash\/redis)$/, name: 'Redis' },
  { match: /^(pg|mysql2|mongodb)$/, name: 'Database driver' },
  { match: /^@clerk\//, name: 'Clerk' },
  { match: /^(algoliasearch|meilisearch)$/, name: 'Search provider' },
  { match: /^(@sentry\/|datadog)/, name: 'Observability provider' },
];

function keyFor(kind: string, name: string): string {
  return `${kind}:${name}`;
}

function fileEvidence(path: string, line: number | undefined, excerpt: string | undefined, note: string): Evidence {
  return { file: path, startLine: line, excerpt: excerpt?.slice(0, 200), note, verified: true };
}

export interface GraphResult {
  components: ArchComponent[];
  relationships: ArchRelationship[];
}

export function buildArchitecture(input: {
  files: SourceFile[];
  modules: Map<string, ParsedModule>;
  routes: ApiEndpoint[];
  models: DataModel[];
  tech: TechDetection[];
}): GraphResult {
  const { files, modules, routes, models } = input;
  const components = new Map<string, ArchComponent>();
  const relationships: ArchRelationship[] = [];

  const add = (c: ArchComponent): ArchComponent => {
    const existing = components.get(c.id);
    if (existing) {
      existing.files = [...new Set([...existing.files, ...c.files])];
      if (existing.provenance === 'inferred' && c.provenance === 'detected') existing.provenance = 'detected';
      return existing;
    }
    components.set(c.id, c);
    return c;
  };

  const relate = (rel: ArchRelationship): void => {
    const dup = relationships.find(
      (r) => r.from === rel.from && r.to === rel.to && r.kind === rel.kind,
    );
    if (dup) { dup.evidence.push(...rel.evidence); return; }
    relationships.push(rel);
  };

  // ---- API routes (detected: an exported handler exists) ----
  for (const r of routes) {
    add({
      id: keyFor('api_route', `${r.method} ${r.path}`),
      name: `${r.method} ${r.path}`,
      kind: 'api_route',
      files: [r.file],
      provenance: 'detected',
      summary: `handler ${r.handlerSymbol ?? 'anonymous'}; auth ${r.authRequired}; validation ${r.validation}`,
    });
  }

  // ---- Data stores (detected: a model/table definition exists) ----
  for (const m of models) {
    add({
      id: keyFor('datastore', m.name),
      name: m.name,
      kind: 'datastore',
      files: [m.file],
      provenance: 'detected',
      summary: `${m.fields.length} field(s), ${m.relations.length} relation(s)${m.ownershipField ? `, owned via ${m.ownershipField}` : ''}`,
    });
  }

  // ---- Pages and components ----
  for (const f of files) {
    if (f.generated || f.vendored) continue;
    if (/(?:^|\/)app\/.*\/page\.[cm]?[jt]sx?$/.test(f.path) || /(?:^|\/)pages\/(?!api\/).*\.[cm]?[jt]sx?$/.test(f.path)) {
      add({
        id: keyFor('page', f.path), name: f.path, kind: 'page',
        files: [f.path], provenance: 'detected', summary: 'route-rendering page module',
      });
    } else if (f.role === 'component') {
      add({
        id: keyFor('component', f.path), name: f.path, kind: 'component',
        files: [f.path], provenance: 'inferred', summary: 'UI component (classified by path and extension)',
      });
    } else if (f.role === 'source' && !f.binary) {
      add({
        id: keyFor('module', f.path), name: f.path, kind: 'module',
        files: [f.path], provenance: 'detected', summary: 'application module',
      });
    } else if (f.role === 'middleware' as string) {
      add({
        id: keyFor('middleware', f.path), name: f.path, kind: 'middleware',
        files: [f.path], provenance: 'detected',
      });
    }
  }

  // Next.js middleware is a real architectural element.
  const middleware = files.find((f) => /^(src\/)?middleware\.[cm]?[jt]s$/.test(f.path));
  if (middleware) {
    add({
      id: keyFor('middleware', middleware.path), name: 'middleware', kind: 'middleware',
      files: [middleware.path], provenance: 'detected', summary: 'runs before matching requests',
    });
  }

  // ---- External services (detected: a real import of the SDK) ----
  for (const mod of modules.values()) {
    for (const imp of mod.imports) {
      if (!imp.external) continue;
      const hit = EXTERNAL_SERVICE_PACKAGES.find((p) => p.match.test(imp.specifier));
      if (!hit) continue;
      const svc = add({
        id: keyFor('external_service', hit.name), name: hit.name, kind: 'external_service',
        files: [], provenance: 'detected', summary: `used via '${imp.specifier}'`,
      });
      svc.files = [...new Set([...svc.files, mod.path])];

      const owner = ownerComponentFor(mod.path, routes, components);
      if (owner) {
        relate({
          from: owner, to: svc.id, kind: 'calls', provenance: 'detected',
          evidence: [fileEvidence(mod.path, imp.line, `import '${imp.specifier}'`, 'SDK imported in this module')],
        });
      }
    }
  }

  // ---- Import relationships (detected) ----
  for (const mod of modules.values()) {
    for (const imp of mod.imports) {
      if (!imp.resolvedPath) continue;
      const from = ownerComponentFor(mod.path, routes, components);
      const to = ownerComponentFor(imp.resolvedPath, routes, components);
      if (!from || !to || from === to) continue;
      relate({
        from, to, kind: 'imports', provenance: 'detected',
        evidence: [fileEvidence(mod.path, imp.line, `import … from '${imp.specifier}'`, 'resolved to a file in this repository')],
      });
    }
  }

  // ---- Query relationships: route/module -> datastore (detected) ----
  const modelByLower = new Map(models.map((m) => [m.name.toLowerCase(), m]));
  for (const mod of modules.values()) {
    for (const call of mod.calls) {
      // prisma.order.findMany / db.order.create / Order.objects.filter
      const m = /^(?:\w+\.)?(\w+)\.(findMany|findUnique|findFirst|create|createMany|update|updateMany|delete|deleteMany|upsert|count|aggregate|save|objects|query|insert|select)$/.exec(call.callee);
      if (!m) continue;
      const model = modelByLower.get(m[1]!.toLowerCase());
      if (!model) continue;
      const from = ownerComponentFor(mod.path, routes, components, call.line);
      if (!from) continue;
      relate({
        from, to: keyFor('datastore', model.name), kind: 'queries', provenance: 'detected',
        evidence: [fileEvidence(mod.path, call.line, `${call.callee}(…)`, `queries the ${model.name} model`)],
      });
    }
  }

  // ---- Frontend -> route relationships (detected via a literal fetch path) ----
  const routeByPath = new Map(routes.map((r) => [r.path, r]));
  for (const mod of modules.values()) {
    for (const call of mod.calls) {
      const leaf = call.callee.split('.').pop() ?? '';
      if (!['fetch', 'get', 'post', 'put', 'patch', 'delete', 'request'].includes(leaf)) continue;
      const arg = call.args[0];
      if (!arg) continue;
      const literal = /^['"`]([^'"`]+)['"`]$/.exec(arg.trim())?.[1]
        ?? /^`([^`]*)`$/.exec(arg.trim())?.[1];
      if (!literal || !literal.startsWith('/')) continue;
      const target = matchRoutePath(literal, routeByPath);
      if (!target) continue;
      const from = ownerComponentFor(mod.path, routes, components, call.line);
      if (!from) continue;
      relate({
        from, to: keyFor('api_route', `${target.method} ${target.path}`), kind: 'calls', provenance: 'detected',
        evidence: [fileEvidence(mod.path, call.line, `${leaf}('${literal}')`, 'client call to this route')],
      });
    }
  }

  return { components: [...components.values()], relationships };
}

/** Which component owns a file (a route handler if the line falls in one, else the module). */
function ownerComponentFor(
  path: string, routes: ApiEndpoint[], components: Map<string, ArchComponent>, line?: number,
): string | undefined {
  const routesInFile = routes.filter((r) => r.file === path);
  if (routesInFile.length === 1) return keyFor('api_route', `${routesInFile[0]!.method} ${routesInFile[0]!.path}`);
  if (routesInFile.length > 1) {
    // Attribute to the handler whose declaration is closest above this line.
    if (line !== undefined) {
      const sorted = routesInFile
        .filter((r) => (r.line ?? 0) <= line)
        .sort((a, b) => (b.line ?? 0) - (a.line ?? 0));
      if (sorted[0]) return keyFor('api_route', `${sorted[0].method} ${sorted[0].path}`);
    }
    return keyFor('api_route', `${routesInFile[0]!.method} ${routesInFile[0]!.path}`);
  }
  for (const kind of ['page', 'component', 'module', 'middleware']) {
    const k = keyFor(kind, path);
    if (components.has(k)) return k;
  }
  return undefined;
}

/** Match a concrete URL against route patterns, including [param] and :param. */
function matchRoutePath(url: string, routes: Map<string, ApiEndpoint>): ApiEndpoint | undefined {
  const clean = url.split('?')[0]!.replace(/\/$/, '') || '/';
  const direct = routes.get(clean);
  if (direct) return direct;
  const urlParts = clean.split('/');
  for (const [pattern, route] of routes) {
    const parts = pattern.split('/');
    if (parts.length !== urlParts.length) continue;
    const ok = parts.every((p, i) => {
      if (/^\[.*\]$/.test(p) || p.startsWith(':') || p.startsWith('{')) return true;
      // A template hole in the URL matches any single segment.
      return p === urlParts[i] || urlParts[i]!.includes('${');
    });
    if (ok) return route;
  }
  return undefined;
}
