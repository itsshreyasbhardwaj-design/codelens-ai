import type { FileRole } from '@codelens/core';
import { basenameOf, extensionOf } from '../ingest/ignore.ts';

/**
 * Language and role classification.
 *
 * Role is used to steer analysis, never to assert behaviour: calling a file a
 * "route" means "look for routes here", not "this file serves traffic". Claims
 * about behaviour must come from parsing, per the brief's rule that runtime
 * behaviour is not inferred from file names.
 */

const EXT_LANGUAGE: Record<string, string> = {
  ts: 'typescript', mts: 'typescript', cts: 'typescript', tsx: 'tsx',
  js: 'javascript', mjs: 'javascript', cjs: 'javascript', jsx: 'jsx',
  py: 'python', pyi: 'python', rb: 'ruby', php: 'php',
  java: 'java', kt: 'kotlin', kts: 'kotlin', scala: 'scala', groovy: 'groovy',
  cs: 'csharp', fs: 'fsharp', vb: 'vbnet',
  go: 'go', rs: 'rust', swift: 'swift', m: 'objc', mm: 'objcpp',
  c: 'c', h: 'c', cc: 'cpp', cpp: 'cpp', cxx: 'cpp', hpp: 'cpp', hh: 'cpp',
  sh: 'shell', bash: 'shell', zsh: 'shell', fish: 'shell', ps1: 'powershell',
  sql: 'sql', prisma: 'prisma', graphql: 'graphql', gql: 'graphql',
  html: 'html', htm: 'html', css: 'css', scss: 'scss', sass: 'sass', less: 'less',
  vue: 'vue', svelte: 'svelte', astro: 'astro',
  json: 'json', jsonc: 'json', yaml: 'yaml', yml: 'yaml', toml: 'toml', xml: 'xml',
  md: 'markdown', mdx: 'mdx', rst: 'restructuredtext', txt: 'text',
  tf: 'terraform', tfvars: 'terraform', hcl: 'hcl',
  dart: 'dart', ex: 'elixir', exs: 'elixir', erl: 'erlang', clj: 'clojure',
  lua: 'lua', r: 'r', pl: 'perl', zig: 'zig',
};

const FILENAME_LANGUAGE: Record<string, string> = {
  Dockerfile: 'dockerfile', 'Containerfile': 'dockerfile',
  Makefile: 'makefile', Gemfile: 'ruby', Rakefile: 'ruby', Procfile: 'text',
  'go.mod': 'gomod', 'go.sum': 'text', '.env': 'dotenv',
};

export function languageOf(path: string): string | undefined {
  const base = basenameOf(path);
  if (FILENAME_LANGUAGE[base]) return FILENAME_LANGUAGE[base];
  if (base.startsWith('.env')) return 'dotenv';
  if (base.startsWith('Dockerfile')) return 'dockerfile';
  return EXT_LANGUAGE[extensionOf(path)];
}

const MANIFEST_NAMES = new Set([
  'package.json', 'pyproject.toml', 'setup.py', 'setup.cfg', 'requirements.txt',
  'Pipfile', 'go.mod', 'Cargo.toml', 'composer.json', 'Gemfile', 'pom.xml',
  'build.gradle', 'build.gradle.kts', 'pubspec.yaml', 'mix.exs', 'deno.json',
  'bun.lockb', 'uv.lock',
]);

const CI_PATTERNS = [
  /^\.github\/workflows\//, /^\.gitlab-ci\.yml$/, /^Jenkinsfile$/,
  /^\.circleci\//, /^\.travis\.yml$/, /^azure-pipelines\.yml$/,
  /^\.buildkite\//, /^\.drone\.yml$/, /^bitbucket-pipelines\.yml$/,
];

const INFRA_PATTERNS = [
  /^Dockerfile/, /docker-compose.*\.ya?ml$/, /\.tf$/, /\.tfvars$/,
  /^k8s\//, /^kubernetes\//, /^helm\//, /^charts\//,
  /^vercel\.json$/, /^netlify\.toml$/, /^fly\.toml$/, /^render\.yaml$/,
  /^serverless\.ya?ml$/, /^Procfile$/, /^skaffold\.ya?ml$/, /^\.ebextensions\//,
];

const TEST_PATTERNS = [
  /(^|\/)__tests__\//, /(^|\/)tests?\//, /(^|\/)spec\//, /(^|\/)e2e\//,
  /\.test\.[cm]?[jt]sx?$/, /\.spec\.[cm]?[jt]sx?$/,
  /(^|\/)test_[^/]+\.py$/, /_test\.py$/, /_test\.go$/,
  /Test\.java$/, /Tests?\.cs$/, /_spec\.rb$/, /\.cy\.[jt]sx?$/,
];

const ROUTE_PATTERNS = [
  /(^|\/)app\/.*\/route\.[cm]?[jt]s$/, /(^|\/)pages\/api\//,
  /(^|\/)routes?\//, /(^|\/)controllers?\//, /(^|\/)endpoints?\//,
  /(^|\/)handlers?\//, /(^|\/)api\//,
  /\.controller\.[cm]?[jt]s$/, /(^|\/)urls\.py$/, /(^|\/)views\.py$/,
  /(^|\/)resolvers?\//,
];

const MIGRATION_PATTERNS = [
  /(^|\/)migrations?\//, /(^|\/)migrate\//, /(^|\/)alembic\//,
  /(^|\/)db\/migrate\//, /(^|\/)prisma\/migrations\//,
];

const SCHEMA_PATTERNS = [
  /schema\.prisma$/, /\.graphql$/, /\.gql$/, /(^|\/)schema\.sql$/,
  /(^|\/)schema\//, /(^|\/)models?\.py$/, /(^|\/)models?\//, /\.entity\.[cm]?[jt]s$/,
];

const COMPONENT_PATTERNS = [
  /(^|\/)components?\//, /(^|\/)ui\//, /(^|\/)views?\//, /(^|\/)widgets?\//,
  /\.(tsx|jsx|vue|svelte|astro)$/,
];

const CONFIG_PATTERNS = [
  /\.config\.[cm]?[jt]s$/, /^tsconfig.*\.json$/, /^jsconfig\.json$/,
  /^\.eslintrc/, /^eslint\.config\./, /^\.prettierrc/, /^babel\.config\./,
  /^\.babelrc/, /^jest\.config\./, /^vitest\.config\./, /^playwright\.config\./,
  /^next\.config\./, /^vite\.config\./, /^webpack\.config\./, /^rollup\.config\./,
  /^tailwind\.config\./, /^postcss\.config\./, /^nuxt\.config\./,
  /^svelte\.config\./, /^astro\.config\./, /^nest-cli\.json$/,
  /^\.env/, /^manage\.py$/, /settings\.py$/, /^application\.(properties|ya?ml)$/,
  /^appsettings.*\.json$/, /^\.npmrc$/, /^\.nvmrc$/, /^pnpm-workspace\.yaml$/,
];

const DOC_PATTERNS = [/\.mdx?$/, /^docs?\//, /^README/i, /^CHANGELOG/i, /^LICENSE/i, /\.rst$/];

function matchAny(path: string, patterns: RegExp[]): boolean {
  const base = basenameOf(path);
  return patterns.some((re) => re.test(path) || re.test(base));
}

/**
 * Assign a single role. Order matters: a test file that also looks like a
 * component is a test, because that is how analysis should treat it.
 */
export function roleOf(path: string, opts: { generated?: boolean; vendored?: boolean; binary?: boolean } = {}): FileRole {
  if (opts.vendored) return 'vendored';
  if (opts.generated) return 'generated';
  if (opts.binary) return 'asset';

  const base = basenameOf(path);
  if (MANIFEST_NAMES.has(base)) return 'manifest';
  if (matchAny(path, TEST_PATTERNS)) return 'test';
  if (matchAny(path, CI_PATTERNS)) return 'ci';
  if (matchAny(path, INFRA_PATTERNS)) return 'infrastructure';
  if (matchAny(path, MIGRATION_PATTERNS)) return 'migration';
  if (matchAny(path, SCHEMA_PATTERNS)) return 'schema';
  if (matchAny(path, ROUTE_PATTERNS)) return 'route';
  if (matchAny(path, CONFIG_PATTERNS)) return 'config';
  if (matchAny(path, DOC_PATTERNS)) return 'documentation';
  if (matchAny(path, COMPONENT_PATTERNS)) return 'component';
  if (languageOf(path)) return 'source';
  return 'unknown';
}

/** Languages CodeLens can parse into an AST and trace across files. */
export const DEEP_LANGUAGES = new Set(['typescript', 'tsx', 'javascript', 'jsx', 'python']);
/** Languages with structural + text-level analysis but no AST. */
export const SHALLOW_LANGUAGES = new Set([
  'go', 'java', 'csharp', 'ruby', 'php', 'rust', 'c', 'cpp', 'kotlin', 'swift',
  'sql', 'prisma', 'graphql', 'vue', 'svelte', 'astro', 'yaml', 'json', 'toml',
  'dockerfile', 'terraform', 'shell', 'html', 'css', 'scss', 'dotenv', 'gomod',
]);

export function depthFor(language: string | undefined): 'deep' | 'shallow' | 'detected_only' {
  if (!language) return 'detected_only';
  if (DEEP_LANGUAGES.has(language)) return 'deep';
  if (SHALLOW_LANGUAGES.has(language)) return 'shallow';
  return 'detected_only';
}
