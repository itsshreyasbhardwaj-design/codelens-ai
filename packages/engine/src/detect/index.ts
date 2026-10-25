import type { Evidence, TechDetection, TechKind } from '@codelens/core';
import type { Snapshot, SourceFile } from '../ingest/normalize.ts';
import { depthFor } from '../index/classify.ts';
import { NODE_CATALOG, PYTHON_CATALOG, type TechSpec } from './catalog.ts';
import { basename, evidenceFor, fileEvidence, safeJson } from './evidence.ts';

/**
 * Stage 3 — technology detection.
 *
 * Detection is evidence-first: nothing is reported without a file (and usually
 * a line) that supports it, and the reported confidence reflects how direct
 * that evidence is rather than a guess.
 *
 * Adapters are plain functions, so supporting a new ecosystem means adding one
 * to ADAPTERS without touching the runner.
 */

export interface DetectionContext {
  snapshot: Snapshot;
}

export type DetectionAdapter = (ctx: DetectionContext) => TechDetection[];

/** Confidence by how direct the evidence is. Documented, not improvised. */
const CONF = {
  manifestAndConfig: 0.98,
  directDependency: 0.95,
  devDependency: 0.88,
  configFileOnly: 0.70,
  importOnly: 0.60,
  fileCountOnly: 0.85,
} as const;

function dedupe(items: TechDetection[]): TechDetection[] {
  const byKey = new Map<string, TechDetection>();
  for (const d of items) {
    const key = `${d.kind}:${d.name}`;
    const prev = byKey.get(key);
    if (!prev) { byKey.set(key, d); continue; }
    byKey.set(key, {
      ...prev,
      confidence: Math.max(prev.confidence, d.confidence),
      version: prev.version ?? d.version,
      evidence: [...prev.evidence, ...d.evidence].slice(0, 6),
    });
  }
  return [...byKey.values()].sort((a, b) => b.confidence - a.confidence || a.name.localeCompare(b.name));
}

function round2(n: number): number {
  return Math.round(n * 100) / 100;
}

function detect(
  name: string, kind: TechKind, confidence: number, evidence: Evidence[], version?: string,
): TechDetection {
  const languageName = kind === 'language' ? name.toLowerCase() : undefined;
  return {
    kind, name, confidence: round2(confidence), evidence,
    version,
    analysisDepth: languageName ? depthFor(languageName) : 'shallow',
  };
}

// --------------------------------------------------------------- Node.js ----

const nodeAdapter: DetectionAdapter = ({ snapshot }) => {
  const out: TechDetection[] = [];
  const manifests = snapshot.files.filter((f) => basename(f.path) === 'package.json' && !f.vendored);
  if (manifests.length === 0) return out;

  const paths = new Set(snapshot.files.map((f) => f.path));
  const hasFile = (candidate: string) =>
    paths.has(candidate) || [...paths].some((p) => p.endsWith(`/${candidate}`));
  const fileFor = (candidate: string) =>
    snapshot.files.find((f) => f.path === candidate || f.path.endsWith(`/${candidate}`));

  // Node itself.
  out.push(detect('Node.js', 'language', CONF.directDependency, [fileEvidence(manifests[0]!, 'package.json present')]));

  const allDeps = new Map<string, { version: string; dev: boolean; file: SourceFile }>();
  let packageManager: string | undefined;

  for (const m of manifests) {
    const pkg = safeJson<{
      dependencies?: Record<string, string>;
      devDependencies?: Record<string, string>;
      packageManager?: string;
      engines?: Record<string, string>;
    }>(m.text);
    if (!pkg) continue;
    if (pkg.packageManager) packageManager = pkg.packageManager;
    for (const [n, v] of Object.entries(pkg.dependencies ?? {})) {
      if (!allDeps.has(n)) allDeps.set(n, { version: v, dev: false, file: m });
    }
    for (const [n, v] of Object.entries(pkg.devDependencies ?? {})) {
      if (!allDeps.has(n)) allDeps.set(n, { version: v, dev: true, file: m });
    }
  }

  for (const spec of NODE_CATALOG) {
    const hit = spec.packages.find((p) => allDeps.has(p));
    const configFile = spec.files?.find((f) => hasFile(f));
    if (!hit && !configFile) continue;

    const evidence: Evidence[] = [];
    let confidence: number;
    let version: string | undefined;

    if (hit) {
      const dep = allDeps.get(hit)!;
      version = dep.version;
      evidence.push(evidenceFor(dep.file, `"${hit}"`, `declared as a ${dep.dev ? 'dev ' : ''}dependency`));
      confidence = dep.dev ? CONF.devDependency : CONF.directDependency;
    } else {
      confidence = CONF.configFileOnly;
    }
    if (configFile) {
      const cf = fileFor(configFile);
      if (cf) evidence.push(fileEvidence(cf, 'framework configuration file present'));
      if (hit) confidence = CONF.manifestAndConfig;
    }
    out.push(detect(spec.name, spec.kind, confidence, evidence, version));
  }

  if (packageManager) {
    const m = manifests.find((f) => (f.text ?? '').includes('packageManager'));
    out.push(detect(packageManager.split('@')[0]!, 'package_manager', CONF.directDependency,
      m ? [evidenceFor(m, 'packageManager')] : [], packageManager.split('@')[1]));
  }
  for (const [lock, pm] of [
    ['pnpm-lock.yaml', 'pnpm'], ['package-lock.json', 'npm'],
    ['yarn.lock', 'yarn'], ['bun.lockb', 'bun'],
  ] as const) {
    const f = fileFor(lock);
    if (f) out.push(detect(pm, 'package_manager', CONF.directDependency, [fileEvidence(f, `${lock} present`)]));
  }
  return out;
};

// ---------------------------------------------------------------- Python ----

const pythonAdapter: DetectionAdapter = ({ snapshot }) => {
  const out: TechDetection[] = [];
  const manifestNames = new Set(['pyproject.toml', 'requirements.txt', 'setup.py', 'Pipfile', 'setup.cfg']);
  const manifests = snapshot.files.filter((f) => manifestNames.has(basename(f.path)) && !f.vendored);
  const managePy = snapshot.files.find((f) => basename(f.path) === 'manage.py');
  if (manifests.length === 0 && !managePy) return out;

  out.push(detect('Python', 'language', CONF.directDependency,
    manifests.length ? [fileEvidence(manifests[0]!, 'Python manifest present')] : [fileEvidence(managePy!)]));

  for (const spec of PYTHON_CATALOG) {
    const evidence: Evidence[] = [];
    let confidence = 0;
    let version: string | undefined;

    for (const m of manifests) {
      const text = (m.text ?? '').toLowerCase();
      const hit = spec.packages.find((p) => {
        // Match a requirement line, not an arbitrary substring:
        // "fastapi", "fastapi==0.1", "fastapi>=1", 'fastapi = "^0.1"'.
        const re = new RegExp(`(^|[\\s"'\\[])${p.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\s*([=<>~!\\]"',]|$)`, 'm');
        return re.test(text);
      });
      if (!hit) continue;
      evidence.push(evidenceFor(m, hit, 'declared as a Python dependency'));
      confidence = Math.max(confidence, CONF.directDependency);
      const vm = (m.text ?? '').match(new RegExp(`${hit}[=><~\\s"']*([0-9][^\\s"',\\]]*)`, 'i'));
      if (vm) version ??= vm[1];
    }
    const configFile = spec.files?.find((f) => snapshot.files.some((sf) => sf.path === f || sf.path.endsWith(`/${f}`)));
    if (configFile) {
      const cf = snapshot.files.find((sf) => sf.path === configFile || sf.path.endsWith(`/${configFile}`));
      if (cf) evidence.push(fileEvidence(cf, 'framework file present'));
      confidence = Math.max(confidence, confidence > 0 ? CONF.manifestAndConfig : CONF.configFileOnly);
    }
    if (confidence > 0) out.push(detect(spec.name, spec.kind, confidence, evidence, version));
  }
  return out;
};

// ------------------------------------------------- other language runtimes --

interface SimpleEcosystem {
  manifest: string;
  language: string;
  kind: TechKind;
  frameworks: Array<{ name: string; kind: TechKind; needle: RegExp }>;
}

const SIMPLE_ECOSYSTEMS: SimpleEcosystem[] = [
  {
    manifest: 'go.mod', language: 'Go', kind: 'language',
    frameworks: [
      { name: 'Gin', kind: 'backend', needle: /gin-gonic\/gin/ },
      { name: 'Echo', kind: 'backend', needle: /labstack\/echo/ },
      { name: 'Fiber', kind: 'backend', needle: /gofiber\/fiber/ },
      { name: 'Chi', kind: 'backend', needle: /go-chi\/chi/ },
      { name: 'GORM', kind: 'orm', needle: /gorm\.io\/gorm/ },
      { name: 'PostgreSQL', kind: 'database', needle: /lib\/pq|jackc\/pgx/ },
    ],
  },
  {
    manifest: 'Cargo.toml', language: 'Rust', kind: 'language',
    frameworks: [
      { name: 'Axum', kind: 'backend', needle: /^\s*axum\s*=/m },
      { name: 'Actix Web', kind: 'backend', needle: /actix-web\s*=/ },
      { name: 'Rocket', kind: 'backend', needle: /^\s*rocket\s*=/m },
      { name: 'SQLx', kind: 'orm', needle: /^\s*sqlx\s*=/m },
      { name: 'Diesel', kind: 'orm', needle: /^\s*diesel\s*=/m },
    ],
  },
  {
    manifest: 'composer.json', language: 'PHP', kind: 'language',
    frameworks: [
      { name: 'Laravel', kind: 'backend', needle: /laravel\/framework/ },
      { name: 'Symfony', kind: 'backend', needle: /symfony\//},
      { name: 'Eloquent', kind: 'orm', needle: /illuminate\/database|laravel\/framework/ },
    ],
  },
  {
    manifest: 'Gemfile', language: 'Ruby', kind: 'language',
    frameworks: [
      { name: 'Ruby on Rails', kind: 'backend', needle: /['"]rails['"]/ },
      { name: 'Sinatra', kind: 'backend', needle: /['"]sinatra['"]/ },
      { name: 'ActiveRecord', kind: 'orm', needle: /activerecord|['"]rails['"]/ },
      { name: 'RSpec', kind: 'testing', needle: /rspec/ },
    ],
  },
  {
    manifest: 'pom.xml', language: 'Java', kind: 'language',
    frameworks: [
      { name: 'Spring Boot', kind: 'backend', needle: /spring-boot/ },
      { name: 'Hibernate', kind: 'orm', needle: /hibernate/ },
      { name: 'JUnit', kind: 'testing', needle: /junit/ },
    ],
  },
  {
    manifest: 'build.gradle', language: 'Java', kind: 'language',
    frameworks: [
      { name: 'Spring Boot', kind: 'backend', needle: /spring-boot/ },
      { name: 'JUnit', kind: 'testing', needle: /junit/ },
    ],
  },
];

const simpleEcosystemAdapter: DetectionAdapter = ({ snapshot }) => {
  const out: TechDetection[] = [];
  for (const eco of SIMPLE_ECOSYSTEMS) {
    const manifest = snapshot.files.find((f) => basename(f.path) === eco.manifest && !f.vendored);
    if (!manifest) continue;
    out.push(detect(eco.language, eco.kind, CONF.directDependency, [fileEvidence(manifest, `${eco.manifest} present`)]));
    for (const fw of eco.frameworks) {
      const m = (manifest.text ?? '').match(fw.needle);
      if (!m) continue;
      out.push(detect(fw.name, fw.kind, CONF.directDependency, [evidenceFor(manifest, m[0], 'declared in manifest')]));
    }
  }
  // .NET projects are identified by any .csproj/.fsproj file.
  const csproj = snapshot.files.find((f) => /\.(cs|fs|vb)proj$/.test(f.path));
  if (csproj) {
    out.push(detect('C#', 'language', CONF.directDependency, [fileEvidence(csproj, 'project file present')]));
    if (/Microsoft\.AspNetCore|Sdk="Microsoft\.NET\.Sdk\.Web"/.test(csproj.text ?? '')) {
      out.push(detect('ASP.NET Core', 'backend', CONF.directDependency, [fileEvidence(csproj, 'ASP.NET Core SDK reference')]));
    }
    if (/EntityFrameworkCore/.test(csproj.text ?? '')) {
      out.push(detect('Entity Framework Core', 'orm', CONF.directDependency, [fileEvidence(csproj, 'EF Core package reference')]));
    }
  }
  return out;
};

// ----------------------------------------------------------- infra & CI ----

const INFRA_SIGNALS: Array<{ name: string; kind: TechKind; match: (p: string) => boolean; note: string }> = [
  { name: 'Docker', kind: 'infrastructure', match: (p) => basename(p).startsWith('Dockerfile'), note: 'Dockerfile present' },
  { name: 'Docker Compose', kind: 'infrastructure', match: (p) => /docker-compose.*\.ya?ml$/.test(basename(p)), note: 'compose file present' },
  { name: 'Kubernetes', kind: 'infrastructure', match: (p) => /^(k8s|kubernetes)\//.test(p) || /^(helm|charts)\//.test(p), note: 'Kubernetes manifests present' },
  { name: 'Terraform', kind: 'infrastructure', match: (p) => p.endsWith('.tf'), note: 'Terraform configuration present' },
  { name: 'Vercel', kind: 'infrastructure', match: (p) => basename(p) === 'vercel.json', note: 'vercel.json present' },
  { name: 'Netlify', kind: 'infrastructure', match: (p) => basename(p) === 'netlify.toml', note: 'netlify.toml present' },
  { name: 'Fly.io', kind: 'infrastructure', match: (p) => basename(p) === 'fly.toml', note: 'fly.toml present' },
  { name: 'Render', kind: 'infrastructure', match: (p) => basename(p) === 'render.yaml', note: 'render.yaml present' },
  { name: 'Cloudflare Workers', kind: 'infrastructure', match: (p) => basename(p) === 'wrangler.toml' || basename(p) === 'wrangler.json', note: 'wrangler config present' },
  { name: 'AWS SAM', kind: 'infrastructure', match: (p) => basename(p) === 'template.yaml' || basename(p) === 'samconfig.toml', note: 'SAM template present' },
  { name: 'Serverless Framework', kind: 'infrastructure', match: (p) => /^serverless\.ya?ml$/.test(basename(p)), note: 'serverless.yml present' },
  { name: 'GitHub Actions', kind: 'ci', match: (p) => p.startsWith('.github/workflows/'), note: 'workflow file present' },
  { name: 'GitLab CI', kind: 'ci', match: (p) => basename(p) === '.gitlab-ci.yml', note: '.gitlab-ci.yml present' },
  { name: 'CircleCI', kind: 'ci', match: (p) => p.startsWith('.circleci/'), note: 'CircleCI config present' },
  { name: 'Jenkins', kind: 'ci', match: (p) => basename(p) === 'Jenkinsfile', note: 'Jenkinsfile present' },
];

const infraAdapter: DetectionAdapter = ({ snapshot }) => {
  const out: TechDetection[] = [];
  for (const sig of INFRA_SIGNALS) {
    const f = snapshot.files.find((sf) => sig.match(sf.path) && !sf.vendored);
    if (f) out.push(detect(sig.name, sig.kind, CONF.configFileOnly + 0.2, [fileEvidence(f, sig.note)]));
  }
  return out;
};

// -------------------------------------------------------- language counts ---

/**
 * Display names for languages, so a manifest-derived detection ("TypeScript")
 * and a file-count-derived one ("typescript") dedupe into a single row.
 */
const LANGUAGE_DISPLAY: Record<string, string> = {
  typescript: 'TypeScript', tsx: 'TypeScript', javascript: 'JavaScript', jsx: 'JavaScript',
  python: 'Python', ruby: 'Ruby', php: 'PHP', java: 'Java', kotlin: 'Kotlin',
  csharp: 'C#', fsharp: 'F#', go: 'Go', rust: 'Rust', swift: 'Swift',
  c: 'C', cpp: 'C++', scala: 'Scala', shell: 'Shell', sql: 'SQL',
  dart: 'Dart', elixir: 'Elixir', erlang: 'Erlang', clojure: 'Clojure',
  lua: 'Lua', r: 'R', perl: 'Perl', zig: 'Zig', objc: 'Objective-C',
  vue: 'Vue', svelte: 'Svelte', astro: 'Astro', html: 'HTML', css: 'CSS',
  scss: 'SCSS', sass: 'Sass', less: 'Less', powershell: 'PowerShell',
};

/**
 * Data and configuration formats. They are counted in coverage but are not
 * reported as "languages the project is written in".
 */
const NON_LANGUAGE_FORMATS = new Set([
  'json', 'yaml', 'toml', 'xml', 'markdown', 'mdx', 'text', 'dotenv',
  'restructuredtext', 'gomod', 'makefile', 'dockerfile', 'terraform', 'hcl',
  'prisma', 'graphql',
]);

/**
 * Languages present by file count. This is the honest floor of detection: it
 * reports what is in the repository even when no manifest explains it.
 */
const languageCountAdapter: DetectionAdapter = ({ snapshot }) => {
  const counts = new Map<string, { files: number; lines: number; sample: SourceFile }>();
  for (const f of snapshot.files) {
    if (!f.language || f.generated || f.vendored || f.binary) continue;
    if (f.role === 'documentation') continue;
    const prev = counts.get(f.language);
    if (prev) { prev.files++; prev.lines += f.lines; }
    else counts.set(f.language, { files: 1, lines: f.lines, sample: f });
  }
  const out: TechDetection[] = [];
  for (const [language, c] of counts) {
    if (NON_LANGUAGE_FORMATS.has(language)) continue;
    // Ignore incidental single config files as "languages".
    if (c.files < 2 && c.lines < 40) continue;
    out.push({
      kind: 'language',
      name: LANGUAGE_DISPLAY[language] ?? language,
      confidence: round2(CONF.fileCountOnly),
      evidence: [fileEvidence(c.sample, `${c.files} file(s), ~${c.lines} lines of ${language}`)],
      analysisDepth: depthFor(language),
    });
  }
  return out;
};

export const ADAPTERS: Array<{ id: string; run: DetectionAdapter }> = [
  { id: 'node', run: nodeAdapter },
  { id: 'python', run: pythonAdapter },
  { id: 'ecosystems', run: simpleEcosystemAdapter },
  { id: 'infra', run: infraAdapter },
  { id: 'languages', run: languageCountAdapter },
];

export interface DetectionReport {
  detections: TechDetection[];
  adaptersRun: string[];
  adapterErrors: Array<{ adapter: string; error: string }>;
}

/** Run every adapter. One adapter failing must not fail detection. */
export function detectTechnologies(snapshot: Snapshot): DetectionReport {
  const all: TechDetection[] = [];
  const adaptersRun: string[] = [];
  const adapterErrors: DetectionReport['adapterErrors'] = [];

  for (const a of ADAPTERS) {
    try {
      all.push(...a.run({ snapshot }));
      adaptersRun.push(a.id);
    } catch (e) {
      adapterErrors.push({ adapter: a.id, error: (e as Error).message });
    }
  }
  return { detections: dedupe(all), adaptersRun, adapterErrors };
}
