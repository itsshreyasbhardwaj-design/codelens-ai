import type { ApiEndpoint, ArchRelationship, DataModel, Evidence, Feature, FeatureStatus } from '@codelens/core';
import type { SourceFile } from '../ingest/normalize.ts';
import type { ParsedModule } from '../parse/types.ts';

/**
 * Feature inventory.
 *
 * Features are clustered around the resource they operate on, from three
 * independent signals: route paths, data models, and page/component paths.
 *
 * Status is assigned from evidence only. In particular, a feature is never
 * called working because its files exist: with code present but no test
 * covering it, the status is `implemented_unverified`, which is the honest
 * answer.
 */

function singular(word: string): string {
  if (word.endsWith('ies')) return `${word.slice(0, -3)}y`;
  if (word.endsWith('sses') || word.endsWith('shes') || word.endsWith('ches')) return word.slice(0, -2);
  if (word.endsWith('s') && !word.endsWith('ss')) return word.slice(0, -1);
  return word;
}

function titleize(slug: string): string {
  return slug
    // Split camelCase and PascalCase so a model named OrderItem reads
    // "Order Item" rather than "Orderitem".
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .split(/[-_\s]+/)
    .filter(Boolean)
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(' ');
}

/** Resource slug for a route path: /api/orders/[id] -> orders */
function resourceOfRoute(path: string): string | undefined {
  const parts = path.split('/').filter(Boolean);
  const start = parts[0] === 'api' || parts[0] === 'v1' || parts[0] === 'v2' ? 1 : 0;
  for (let i = start; i < parts.length; i++) {
    const p = parts[i]!;
    if (/^[[:{]/.test(p) || p.startsWith(':')) continue;
    if (['api', 'v1', 'v2', 'index'].includes(p)) continue;
    return p.toLowerCase();
  }
  return undefined;
}

/** Resource slug for a page/component path. */
function resourceOfFile(path: string): string | undefined {
  const m = /(?:^|\/)(?:app|pages|src\/app|src\/pages)\/(.+?)\/(?:page|index|layout)\.[cm]?[jt]sx?$/.exec(path);
  if (m) {
    const seg = m[1]!.split('/').filter((s) => !s.startsWith('(') && !s.startsWith('_') && !/^[[:]/.test(s)).pop();
    if (seg) return seg.toLowerCase();
  }
  const base = path.slice(path.lastIndexOf('/') + 1).replace(/\.[cm]?[jt]sx?$/, '');
  if (!base || base === 'index') return undefined;
  // CheckoutButton -> checkout, OrderSummary -> order
  const words = base.replace(/([a-z0-9])([A-Z])/g, '$1 $2').toLowerCase().split(/[\s\-_]+/);
  const head = words[0];
  return head && head.length > 2 ? head : undefined;
}

const PLACEHOLDER_RE = /\b(TODO|FIXME|not implemented|notImplemented|unimplemented|coming soon|stub|mock(?:ed)?\s+(?:response|data))\b/i;

export function buildFeatures(input: {
  files: SourceFile[];
  modules: Map<string, ParsedModule>;
  routes: ApiEndpoint[];
  models: DataModel[];
  relationships: ArchRelationship[];
}): Feature[] {
  const { files, modules, routes, models } = input;

  interface Bucket {
    slug: string;
    routes: ApiEndpoint[];
    models: DataModel[];
    frontend: Set<string>;
    backend: Set<string>;
  }
  const buckets = new Map<string, Bucket>();
  const bucket = (slug: string): Bucket => {
    // Keys are compared case-insensitively so a route '/api/orders' and a model
    // 'Order' land in the same feature, but the first-seen casing is kept for
    // the display name.
    const key = singular(slug).toLowerCase();
    let b = buckets.get(key);
    if (!b) {
      b = { slug: singular(slug), routes: [], models: [], frontend: new Set(), backend: new Set() };
      buckets.set(key, b);
    }
    return b;
  };

  for (const r of routes) {
    const res = resourceOfRoute(r.path);
    if (!res) continue;
    const b = bucket(res);
    b.routes.push(r);
    b.backend.add(r.file);
  }
  for (const m of models) {
    bucket(m.name).models.push(m);
  }
  for (const f of files) {
    if (f.generated || f.vendored || f.binary) continue;
    const isFrontend = f.role === 'component' || /\/(?:app|pages)\/.*\.[cm]?[jt]sx$/.test(f.path) || /\.(tsx|jsx|vue|svelte|astro)$/.test(f.path);
    if (!isFrontend) continue;
    const res = resourceOfFile(f.path);
    if (!res) continue;
    bucket(res).frontend.add(f.path);
  }

  // Tests referencing a feature's files, via resolved imports.
  const testImports = new Map<string, Set<string>>();
  for (const f of files) {
    if (f.role !== 'test') continue;
    const mod = modules.get(f.path);
    if (!mod) continue;
    for (const imp of mod.imports) {
      if (!imp.resolvedPath) continue;
      const set = testImports.get(imp.resolvedPath) ?? new Set();
      set.add(f.path);
      testImports.set(imp.resolvedPath, set);
    }
  }

  const features: Feature[] = [];
  for (const b of buckets.values()) {
    // A bucket with no route and no model is not a feature, just a file.
    if (b.routes.length === 0 && b.models.length === 0 && b.frontend.size === 0) continue;
    if (b.routes.length === 0 && b.models.length === 0) continue;

    const allFiles = [...b.backend, ...b.frontend, ...b.models.map((m) => m.file)];
    const tests = [...new Set(allFiles.flatMap((p) => [...(testImports.get(p) ?? [])]))];

    const evidence: Evidence[] = [];
    for (const r of b.routes.slice(0, 4)) {
      evidence.push({
        file: r.file, startLine: r.line,
        excerpt: `${r.method} ${r.path}`,
        note: `route handler ${r.handlerSymbol ?? ''} (auth: ${r.authRequired})`.trim(),
        verified: true,
      });
    }
    for (const m of b.models.slice(0, 2)) {
      evidence.push({
        file: m.file, excerpt: `model ${m.name}`,
        note: `${m.fields.length} fields`, verified: true,
      });
    }
    for (const p of [...b.frontend].slice(0, 3)) {
      evidence.push({ file: p, note: 'user interface for this feature', verified: true });
    }

    const defects: string[] = [];

    // Placeholder detection: a handler or component body that admits it is unfinished.
    let placeholder = false;
    for (const p of allFiles) {
      const mod = modules.get(p);
      if (!mod) continue;
      for (const sym of mod.symbols) {
        if (PLACEHOLDER_RE.test(sym.text)) {
          placeholder = true;
          defects.push(`${p}:${sym.startLine} — ${sym.name} contains an unfinished marker (TODO/stub)`);
        }
      }
    }

    const hasBackend = b.routes.length > 0;
    const hasFrontend = b.frontend.size > 0;
    const hasModel = b.models.length > 0;

    let status: FeatureStatus;
    if (placeholder) {
      status = 'placeholder_or_mock';
    } else if (hasFrontend && !hasBackend && !hasModel) {
      status = 'partially_implemented';
      defects.push('user interface exists but no matching API route or data model was found');
    } else if (hasBackend || hasModel) {
      // Importing a feature's file is not the same as testing the feature. We
      // require the test to actually name the route path, a handler, or the
      // model before calling the feature verified.
      const meaningfullyTested = tests.some((t) => {
        const mod = modules.get(t);
        if (!mod) return false;
        const haystack = [
          ...mod.stringLiterals.map((s) => s.value),
          ...mod.symbols.map((s) => s.text),
        ].join(' ').toLowerCase();
        return b.routes.some((r) => haystack.includes(r.path.toLowerCase()))
          || b.models.some((m) => haystack.includes(m.name.toLowerCase()))
          || b.routes.some((r) => !!r.handlerSymbol && haystack.includes(r.handlerSymbol.toLowerCase()));
      });
      status = meaningfullyTested ? 'implemented_verified' : 'implemented_unverified';
      if (tests.length > 0 && !meaningfullyTested) {
        defects.push(`a test imports this feature's code but does not exercise its routes or models, so it is not covered`);
      }
    } else {
      status = 'unknown';
    }

    const authValues = new Set(b.routes.map((r) => r.authRequired));
    const authRequirement: Feature['authRequirement'] =
      authValues.size === 0 ? 'unknown'
      : authValues.has('public') && authValues.size === 1 ? 'public'
      : authValues.has('required') && !authValues.has('public') && !authValues.has('unknown') ? 'required'
      : 'unknown';

    const externalServices = new Set<string>();
    for (const p of allFiles) {
      const mod = modules.get(p);
      if (!mod) continue;
      for (const imp of mod.imports) {
        if (imp.external && !/^(react|next|node:|@types)/.test(imp.specifier) && !imp.specifier.startsWith('.')) {
          externalServices.add(imp.specifier);
        }
      }
    }

    features.push({
      id: `feature:${b.slug}`,
      name: titleize(b.slug),
      intendedFunction: describeFeature(b.slug, b.routes, b.models),
      status,
      frontendFiles: [...b.frontend].sort(),
      backendFiles: [...b.backend].sort(),
      databaseDeps: b.models.map((m) => m.name),
      externalServices: [...externalServices].sort(),
      authRequirement,
      implementationEvidence: evidence,
      tests,
      possibleDefects: defects,
    });
  }

  return features.sort((a, b) => a.name.localeCompare(b.name));
}

function describeFeature(slug: string, routes: ApiEndpoint[], models: DataModel[]): string {
  const verbs = new Set(routes.map((r) => r.method));
  const actions: string[] = [];
  if (verbs.has('GET')) actions.push('read');
  if (verbs.has('POST')) actions.push('create');
  if (verbs.has('PUT') || verbs.has('PATCH')) actions.push('update');
  if (verbs.has('DELETE')) actions.push('delete');

  const noun = titleize(slug).toLowerCase();
  if (actions.length === 0 && models.length > 0) {
    return `Stores ${noun} records (${models.map((m) => m.name).join(', ')}). No HTTP route for it was found, so it may be used internally or not yet exposed.`;
  }
  if (actions.length === 0) return `Handles ${noun}. Behaviour could not be determined from the available evidence.`;
  return `Lets a caller ${actions.join(', ')} ${noun}${models.length ? `, backed by the ${models.map((m) => m.name).join('/')} model(s)` : ''}.`;
}
