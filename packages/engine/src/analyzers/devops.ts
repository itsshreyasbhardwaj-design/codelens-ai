import type { Confidence, Evidence, Finding, Severity } from '@codelens/core';
import type { RepoMap } from '../graph/repomap.ts';
import type { SourceFile } from '../ingest/normalize.ts';
import type { Analyzer, AnalyzerContext } from './types.ts';
import { codeText } from './text.ts';

/**
 * DevOps and deployment audit.
 *
 * Nothing in this module is a confirmed production failure. A deployment cannot
 * be observed from a source snapshot: there is no running container, no
 * orchestrator, no pipeline run, and no view of the hosting platform's own
 * settings. What can be read is the configuration the repository commits to,
 * and that is what these rules are about — configuration risk, stated as
 * recommended improvement rather than diagnosed outage.
 *
 * Confidence discipline:
 *   - a directive that is absent from a file we fully read is `strong`
 *     (the absence is observed, but the behaviour it implies may be supplied by
 *     a base image, a platform default, or a repository setting we cannot see);
 *   - a value written in the file, such as an unpinned tag, is `confirmed`
 *     only where it cannot be anything else;
 *   - anything that depends on configuration living outside the repository
 *     (environment protection rules, managed backups, platform monitoring) is
 *     capped at `moderate` and says so in the finding.
 *
 * Dockerfiles, YAML, and TOML are not parsed into ASTs, so these rules read
 * file text. Every text match runs over codeText() output first: a Dockerfile
 * comment reading "no healthcheck here" otherwise satisfies a naive presence
 * check for HEALTHCHECK, and a commented-out step reads as a live one.
 */

const REF = {
  dockerBest: 'Docker — Best practices for writing Dockerfiles',
  dockerMultiStage: 'Docker — Multi-stage builds',
  dockerignore: 'Docker — Build context and .dockerignore',
  cisDocker: 'CIS Docker Benchmark — 4.1 Create a user for the container',
  cweRootPriv: 'CWE-250 Execution with Unnecessary Privileges',
  cweExposedFile: 'CWE-538 Insertion of Sensitive Information into Externally-Accessible File or Directory',
  cweMonitoring: 'CWE-778 Insufficient Logging and Monitoring',
  cweUnpinned: 'CWE-1104 Use of Unmaintained Third Party Components',
  owaspMisconfig: 'OWASP A05:2021 Security Misconfiguration',
  owaspIntegrity: 'OWASP A08:2021 Software and Data Integrity Failures',
  twelveFactorConfig: 'Twelve-Factor App — III. Config',
  twelveFactorBuild: 'Twelve-Factor App — V. Build, release, run',
  twelveFactorParity: 'Twelve-Factor App — X. Dev/prod parity',
  twelveFactorLogs: 'Twelve-Factor App — XI. Logs',
  twelveFactorAdmin: 'Twelve-Factor App — XII. Admin processes',
  ghHardening: 'GitHub — Security hardening for GitHub Actions',
  ghEnvironments: 'GitHub — Using environments for deployment',
  ossfPinned: 'OpenSSF Scorecard — Pinned-Dependencies check',
  ossfDependencyUpdate: 'OpenSSF Scorecard — Dependency-Update-Tool check',
  slsa: 'SLSA v1.0 — Build track, hermetic and reproducible builds',
  k8sProbes: 'Kubernetes — Configure liveness, readiness and startup probes',
  sreSlo: 'Google SRE Workbook — Alerting on SLOs',
  dora: 'DORA — Deployment automation and recovery capabilities',
} as const;

// ---------------------------------------------------------------------------
// Shared helpers (deliberately inlined: analyzers own their own helpers so
// sibling modules can be written independently).
// ---------------------------------------------------------------------------

/** Evidence that resolved against the snapshot, or undefined. */
function verified(e: Evidence): Evidence | undefined {
  return e.verified ? e : undefined;
}

/** First line (1-based) of `stripped` matching `re`, or undefined. */
function lineMatching(stripped: string, re: RegExp): number | undefined {
  const lines = stripped.split('\n');
  for (let i = 0; i < lines.length; i++) {
    if (re.test(lines[i]!)) return i + 1;
  }
  return undefined;
}

/** First non-empty line of a file, for anchoring a whole-file observation. */
function firstContentLine(file: SourceFile): number {
  const lines = (file.text ?? '').split('\n');
  for (let i = 0; i < lines.length; i++) {
    if (lines[i]!.trim().length > 0) return i + 1;
  }
  return 1;
}

function basename(path: string): string {
  return path.slice(path.lastIndexOf('/') + 1);
}

function readable(map: RepoMap, predicate: (f: SourceFile) => boolean): SourceFile[] {
  return map.files.filter((f) => f.text !== null && !f.binary && predicate(f));
}

/** Container image definitions: Dockerfile, Containerfile, and variants. */
function dockerfiles(map: RepoMap): SourceFile[] {
  return readable(map, (f) => /^(?:Dockerfile|Containerfile)(?:\..+)?$/.test(basename(f.path))
    || /\.[Dd]ockerfile$/.test(basename(f.path)));
}

function composeFiles(map: RepoMap): SourceFile[] {
  return readable(map, (f) => /^(?:docker-)?compose(?:\.[\w-]+)?\.ya?ml$/.test(basename(f.path)));
}

function kubernetesFiles(map: RepoMap): SourceFile[] {
  return readable(map, (f) => /^(?:k8s|kubernetes|helm|charts|manifests|deploy)\//.test(f.path)
    && /\.ya?ml$/.test(f.path));
}

const PLATFORM_CONFIG_NAMES = new Set([
  'fly.toml', 'render.yaml', 'render.yml', 'railway.json', 'railway.toml',
  'app.yaml', 'app.json', 'vercel.json', 'netlify.toml', 'Procfile',
  'serverless.yml', 'serverless.yaml', 'template.yaml', 'samconfig.toml',
  'ecs-task-definition.json', 'task-definition.json', 'cloudbuild.yaml',
  'skaffold.yaml', 'wrangler.toml', 'wrangler.json', 'captain-definition',
]);

function platformConfigFiles(map: RepoMap): SourceFile[] {
  return readable(map, (f) => PLATFORM_CONFIG_NAMES.has(basename(f.path))
    || /\.tf$/.test(f.path));
}

/** Every file that describes how this project is deployed or run. */
function deploymentConfigFiles(map: RepoMap): SourceFile[] {
  const seen = new Set<string>();
  const out: SourceFile[] = [];
  for (const f of [...dockerfiles(map), ...composeFiles(map), ...kubernetesFiles(map), ...platformConfigFiles(map)]) {
    if (seen.has(f.path)) continue;
    seen.add(f.path);
    out.push(f);
  }
  return out;
}

function ciFiles(map: RepoMap): SourceFile[] {
  return readable(map, (f) => f.role === 'ci');
}

const LOCKFILE_NAMES = new Set([
  'package-lock.json', 'pnpm-lock.yaml', 'yarn.lock', 'bun.lockb', 'bun.lock',
  'npm-shrinkwrap.json', 'poetry.lock', 'Pipfile.lock', 'uv.lock', 'pdm.lock',
  'requirements.txt', 'Gemfile.lock', 'composer.lock', 'go.sum', 'Cargo.lock',
  'packages.lock.json', 'gradle.lockfile', 'mix.lock', 'pubspec.lock',
]);

function lockfiles(map: RepoMap): SourceFile[] {
  return map.files.filter((f) => LOCKFILE_NAMES.has(basename(f.path)));
}

interface ManifestView {
  file: SourceFile;
  scripts: Map<string, string>;
}

/** package.json scripts, which say what the project builds and starts. */
function manifests(map: RepoMap): ManifestView[] {
  const out: ManifestView[] = [];
  for (const f of readable(map, (x) => x.role === 'manifest')) {
    const scripts = new Map<string, string>();
    if (basename(f.path) === 'package.json') {
      try {
        const parsed = JSON.parse(f.text!) as { scripts?: Record<string, unknown> };
        for (const [k, v] of Object.entries(parsed.scripts ?? {})) {
          if (typeof v === 'string') scripts.set(k, v);
        }
      } catch {
        // A manifest we cannot parse still counts as a manifest; it just
        // contributes no script facts.
      }
    }
    out.push({ file: f, scripts });
  }
  return out;
}

/** Roles whose text is configuration rather than prose or application code. */
const CONFIG_ROLES = new Set(['manifest', 'ci', 'infrastructure', 'config', 'documentation', 'schema']);

/** Comment-free text of every configuration-ish file, for presence checks. */
function configCorpus(map: RepoMap): Array<{ file: SourceFile; stripped: string }> {
  return readable(map, (f) => CONFIG_ROLES.has(f.role))
    .map((f) => ({ file: f, stripped: codeText(f.text, f.language) }));
}

/** True when any configuration file or module import mentions a marker. */
function presentAnywhere(map: RepoMap, re: RegExp): { file: string; line: number } | undefined {
  for (const { file, stripped } of configCorpus(map)) {
    const line = lineMatching(stripped, re);
    if (line !== undefined) return { file: file.path, line };
  }
  for (const mod of map.modules.values()) {
    if (!mod.parsed) continue;
    const imp = mod.imports.find((i) => re.test(i.specifier));
    if (imp) return { file: mod.path, line: imp.line };
  }
  return undefined;
}

// ---------------------------------------------------------------------------
// Dockerfile model
// ---------------------------------------------------------------------------

const DOCKER_KEYWORDS = new Set([
  'FROM', 'RUN', 'CMD', 'LABEL', 'EXPOSE', 'ENV', 'ADD', 'COPY', 'ENTRYPOINT',
  'VOLUME', 'USER', 'WORKDIR', 'ARG', 'ONBUILD', 'STOPSIGNAL', 'HEALTHCHECK', 'SHELL',
]);

interface DockerInstruction {
  keyword: string;
  args: string;
  /** 1-based line of the instruction's first line in the original file. */
  line: number;
}

interface DockerStage {
  index: number;
  name?: string;
  /** The FROM argument as written, e.g. 'node:20' or '${BASE}'. */
  reference: string;
  line: number;
  instructions: DockerInstruction[];
}

interface DockerView {
  file: SourceFile;
  stripped: string;
  stages: DockerStage[];
  /** The stage that produces the runtime image. */
  final?: DockerStage;
}

/** Instructions of a Dockerfile, with line continuations joined. */
function parseDockerfile(file: SourceFile): DockerView {
  const stripped = codeText(file.text, file.language);
  const lines = stripped.split('\n');
  const instructions: DockerInstruction[] = [];

  let i = 0;
  while (i < lines.length) {
    const startLine = i + 1;
    let text = lines[i]!;
    while (/\\\s*$/.test(text) && i + 1 < lines.length) {
      i++;
      text = `${text.replace(/\\\s*$/, ' ')}${lines[i]!}`;
    }
    i++;
    const m = /^\s*([A-Za-z][A-Za-z_]*)\s+(.*)$/.exec(text);
    if (!m) continue;
    const keyword = m[1]!.toUpperCase();
    if (!DOCKER_KEYWORDS.has(keyword)) continue;
    instructions.push({ keyword, args: m[2]!.trim(), line: startLine });
  }

  const stages: DockerStage[] = [];
  for (const inst of instructions) {
    if (inst.keyword === 'FROM') {
      const asMatch = /^(\S+)(?:\s+(?:AS|as|As|aS)\s+(\S+))?/.exec(inst.args);
      stages.push({
        index: stages.length,
        name: asMatch?.[2],
        reference: asMatch?.[1] ?? inst.args,
        line: inst.line,
        instructions: [],
      });
      continue;
    }
    stages[stages.length - 1]?.instructions.push(inst);
  }

  return { file, stripped, stages, final: stages[stages.length - 1] };
}

interface ImageRef {
  /** Repository part, e.g. 'node' or 'ghcr.io/org/app'. */
  image: string;
  tag?: string;
  digest?: string;
  /** True when the reference is an ARG/variable we cannot resolve. */
  unresolvable: boolean;
}

function parseImageRef(reference: string): ImageRef {
  const unresolvable = /\$\{|\$[A-Za-z_]/.test(reference);
  const digestSplit = reference.split('@');
  const beforeDigest = digestSplit[0]!;
  const digest = digestSplit[1];
  // A colon in the final path segment is a tag; earlier ones are registry ports.
  const lastSlash = beforeDigest.lastIndexOf('/');
  const lastSegment = beforeDigest.slice(lastSlash + 1);
  const colon = lastSegment.lastIndexOf(':');
  const image = colon === -1 ? beforeDigest : beforeDigest.slice(0, lastSlash + 1 + colon);
  const tag = colon === -1 ? undefined : lastSegment.slice(colon + 1);
  return { image, tag, digest, unresolvable };
}

/** Base images that already run as a non-root user by convention. */
const NON_ROOT_IMAGE_RE = /nonroot|non-root|unprivileged|chainguard|distroless|cgr\.dev/i;

/** A stage that only produces build output and is copied from, not run. */
function isCopiedFrom(view: DockerView, stage: DockerStage): boolean {
  const names = [stage.name, String(stage.index)].filter((x): x is string => x !== undefined);
  return view.stages.some((s) => s.instructions.some((inst) =>
    (inst.keyword === 'COPY' || inst.keyword === 'ADD')
    && names.some((n) => new RegExp(`--from=${n}(?:\\s|$)`).test(inst.args))));
}

/** The user this stage runs as, following FROM references between stages. */
function effectiveUser(view: DockerView, stage: DockerStage, seen: Set<number> = new Set()): DockerInstruction | undefined {
  if (seen.has(stage.index)) return undefined;
  seen.add(stage.index);
  const own = [...stage.instructions].reverse().find((i) => i.keyword === 'USER');
  if (own) return own;
  const parent = view.stages.find((s) => s.name !== undefined && s.name === stage.reference);
  if (parent) return effectiveUser(view, parent, seen);
  return undefined;
}

function isRootUser(args: string): boolean {
  const name = args.trim().split(/[:\s]/)[0] ?? '';
  return name === 'root' || name === '0';
}

// ---------------------------------------------------------------------------
// Pipeline model
// ---------------------------------------------------------------------------

const DEPLOY_RE = new RegExp([
  '\\bdeploy\\b', '\\bdeploys\\b', '\\bdeployment\\b', '\\brelease\\b', '\\bpromote\\b',
  '\\brollout\\b', '\\bvercel\\b', '\\bnetlify\\b', '\\bflyctl\\b', '\\bfly\\s+deploy\\b',
  '\\bheroku\\b', '\\bkubectl\\b', '\\bhelm\\s+(?:upgrade|install)\\b', 'terraform\\s+apply',
  '\\bserverless\\s+deploy\\b', '\\bcdk\\s+deploy\\b', 'aws\\s+s3\\s+sync', 'aws\\s+ecs',
  'gcloud\\s+(?:run|app)\\s+deploy', 'az\\s+webapp', 'docker\\s+push', 'ansible-playbook',
  'cap\\s+production', 'wrangler\\s+(?:deploy|publish)', 'eas\\s+(?:submit|update)',
].join('|'), 'i');

const TEST_STEP_RE = new RegExp([
  '(?:npm|pnpm|yarn|bun|npx)\\s+(?:run\\s+)?(?:test|tests|spec|e2e|unit|integration|verify|ci:test)\\b',
  '\\bjest\\b', '\\bvitest\\b', '\\bmocha\\b', '\\bpytest\\b', '\\btox\\b', '\\bnox\\b',
  '\\brspec\\b', '\\bphpunit\\b', '\\bpest\\b', 'go\\s+test', 'cargo\\s+test',
  'dotnet\\s+test', 'mvn[\\w\\s-]*\\btest\\b', 'gradle\\w*\\s+(?:test|check)\\b', 'mix\\s+test',
  'make\\s+(?:test|check)\\b', 'node\\s+--test', 'rails\\s+test', 'bundle\\s+exec\\s+rspec',
  'playwright\\s+test', 'cypress\\s+run', '\\bctest\\b', 'uses:\\s*\\S*(?:test|codecov)',
].join('|'), 'i');

const CHECK_STEP_RE = new RegExp([
  '(?:npm|pnpm|yarn|bun|npx)\\s+(?:run\\s+)?(?:lint|typecheck|type-check|tsc|check|audit)\\b',
  '\\btsc\\b', '\\bmypy\\b', '\\bpyright\\b', '\\bruff\\b', '\\beslint\\b', '\\bflake8\\b',
  'golangci-lint', 'cargo\\s+clippy', 'uses:\\s*\\S*(?:lint|codeql|semgrep|trivy|snyk)',
].join('|'), 'i');

const ENVIRONMENT_KEY_RE = /^\s*environment\s*:/;
const APPROVAL_RE = /manual[-_ ]approval|\bwhen\s*:\s*manual\b|\brequires?[-_ ]approval\b|\bapproval\b/i;
const NEEDS_KEY_RE = /^\s*needs\s*:/;
const ROLLBACK_RE = new RegExp([
  '\\brollback\\b', '\\brollbacks\\b', '\\brevert\\b', '\\bundeploy\\b',
  'helm\\s+rollback', 'kubectl\\s+rollout\\s+undo', 'vercel\\s+rollback',
  '\\bblue[-_ ]?green\\b', '\\bcanary\\b', 'rolling[-_ ]?(?:update|release)',
  'previous[-_ ](?:version|deployment|release)', 'aws\\s+deploy\\s+stop-deployment',
].join('|'), 'i');
const MIGRATE_RE = new RegExp([
  'prisma\\s+migrate\\s+(?:deploy|dev)', 'migrate\\s+deploy', 'alembic\\s+upgrade',
  'db:migrate', 'knex\\s+migrate', 'drizzle-kit\\s+(?:push|migrate)',
  'sequelize\\s+db:migrate', 'dotnet\\s+ef\\s+database\\s+update', 'manage\\.py\\s+migrate',
  'flyway\\s+(?:migrate|info)', 'liquibase\\s+update', 'atlas\\s+migrate\\s+apply',
  'sqitch\\s+deploy', 'goose\\s+(?:up|up-to)', 'migrate\\s+-path', 'typeorm\\s+migration:run',
  '(?:npm|pnpm|yarn|bun|npx)\\s+(?:run\\s+)?migrate', 'mix\\s+ecto\\.migrate',
  'rake\\s+db:migrate', 'diesel\\s+migration\\s+run', 'migration[s]?:run',
].join('|'), 'i');
const PRODUCTION_RE = /--prod\b|--production\b|\bproduction\b|\bprod\b|NODE_ENV\s*[:=]\s*["']?production/i;
const INLINE_SECRET_RE = /\$\{\{\s*secrets\./;
/** `KEY: ${{ secrets.X }}` — an env or input mapping, which is the right way. */
const ENV_MAPPING_RE = /^\s*[A-Za-z_][\w.-]*\s*:\s*["']?\$\{\{\s*secrets\./;
const SECRET_FLAG_RE = /--(?:token|password|passwd|api[-_]?key|apikey|secret|auth[-_]?token|access[-_]?key)(?:=|\s+)["']?\$\{?([A-Za-z_][A-Za-z0-9_]*)/;
const LOOSE_INSTALL_RE = /\b(?:npm|yarn)\s+install\b/;
const FROZEN_INSTALL_RE = /--frozen-lockfile|--immutable|--no-save/;

interface ActionRef {
  line: number;
  ref: string;
  owner: string;
  thirdParty: boolean;
}

interface CiView {
  file: SourceFile;
  stripped: string;
  deployLine?: number;
  testLine?: number;
  checkLine?: number;
  environmentLine?: number;
  approvalLine?: number;
  needsLine?: number;
  rollbackLine?: number;
  migrateLine?: number;
  productionLine?: number;
  pushDefaultLine?: number;
  manualTriggerLine?: number;
  unpinnedActions: ActionRef[];
  inlineSecretLines: number[];
  secretFlags: Array<{ line: number; name: string }>;
  looseInstallLine?: number;
}

/** The block of a top-level YAML key, as [startLine, endLine] 1-based. */
function topLevelBlock(lines: string[], key: string): { start: number; end: number } | undefined {
  const keyRe = new RegExp(`^${key}\\s*:`);
  for (let i = 0; i < lines.length; i++) {
    if (!keyRe.test(lines[i]!)) continue;
    let end = i + 1;
    while (end < lines.length && (lines[end]!.trim() === '' || /^\s/.test(lines[end]!))) end++;
    return { start: i + 1, end };
  }
  return undefined;
}

/** The line of the step that performs the deployment, preferred over a job name. */
function deployLineOf(stripped: string): number | undefined {
  const lines = stripped.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const l = lines[i]!;
    if (/^\s+.*\b(?:run|uses|script|command|entrypoint|cmd)\s*:/.test(l) && DEPLOY_RE.test(l)) return i + 1;
  }
  for (let i = 0; i < lines.length; i++) {
    if (/^\s/.test(lines[i]!) && DEPLOY_RE.test(lines[i]!)) return i + 1;
  }
  return undefined;
}

/** A dependency install that does not honour the lockfile exactly. */
function looseInstallLineOf(stripped: string): number | undefined {
  const lines = stripped.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const l = lines[i]!;
    if (!LOOSE_INSTALL_RE.test(l)) continue;
    if (FROZEN_INSTALL_RE.test(l)) continue;
    return i + 1;
  }
  return undefined;
}

const TRUSTED_ACTION_OWNERS = new Set(['actions', 'github', 'docker', 'hashicorp', 'aws-actions', 'azure', 'google-github-actions']);

function buildCiView(file: SourceFile): CiView {
  const stripped = codeText(file.text, file.language);
  const lines = stripped.split('\n');

  const unpinnedActions: ActionRef[] = [];
  const inlineSecretLines: number[] = [];
  const secretFlags: Array<{ line: number; name: string }> = [];
  let inCommand = false;
  let commandIndent = 0;

  for (let i = 0; i < lines.length; i++) {
    const l = lines[i]!;
    const uses = /^\s*-?\s*uses\s*:\s*["']?([^\s"'#]+)/.exec(l);
    if (uses) {
      const ref = uses[1]!;
      const at = ref.lastIndexOf('@');
      const version = at === -1 ? '' : ref.slice(at + 1);
      const repo = at === -1 ? ref : ref.slice(0, at);
      const local = repo.startsWith('./') || repo.startsWith('.github/') || repo.startsWith('docker://');
      const pinned = /^[0-9a-f]{40}$/.test(version) || /^[0-9a-f]{64}$/.test(version);
      if (!local && !pinned) {
        const owner = repo.split('/')[0] ?? repo;
        unpinnedActions.push({ line: i + 1, ref, owner, thirdParty: !TRUSTED_ACTION_OWNERS.has(owner.toLowerCase()) });
      }
    }
    // A secret expanded inside a shell command is the risk; a mapping of a
    // key to a secret (an `env:` or `with:` entry) is the correct practice, so
    // the command block has to be tracked rather than guessed from indentation.
    const commandKey = /^(\s*)(?:-\s*)?(?:run|script|command|entrypoint|args)\s*:\s*(.*)$/.exec(l);
    if (commandKey) {
      commandIndent = commandKey[1]!.length;
      const rest = commandKey[2]!.trim();
      inCommand = rest === '' || rest === '|' || rest === '>' || /^[|>][-+]?\d*$/.test(rest);
      if (!inCommand && INLINE_SECRET_RE.test(rest)) inlineSecretLines.push(i + 1);
    } else if (inCommand) {
      const indent = /^(\s*)/.exec(l)![1]!.length;
      if (l.trim() !== '' && indent <= commandIndent) {
        inCommand = false;
      } else if (INLINE_SECRET_RE.test(l) && !ENV_MAPPING_RE.test(l)) {
        inlineSecretLines.push(i + 1);
      }
    }
    const flag = SECRET_FLAG_RE.exec(l);
    if (flag) secretFlags.push({ line: i + 1, name: flag[1]! });
  }

  // Triggers: a push to the repository's default branch is the risky one.
  let pushDefaultLine: number | undefined;
  let manualTriggerLine: number | undefined;
  const onBlock = topLevelBlock(lines, 'on');
  const triggerText = onBlock
    ? lines.slice(onBlock.start - 1, onBlock.end).join('\n')
    : lines.slice(0, Math.min(lines.length, 40)).join('\n');
  if (/\bpush\b/.test(triggerText)) {
    const branchRe = /\b(?:branches|branches-ignore|only|refs)\b[^\n]*|^\s*-\s*["']?(?:main|master|trunk)["']?\s*$/m;
    const hasDefault = /\b(?:main|master|trunk)\b/.test(triggerText);
    const bare = /^on\s*:\s*(?:\[[^\]]*push[^\]]*\]|push)\s*$/m.test(triggerText)
      || /^\s*push\s*:\s*$/m.test(triggerText) && !/\bbranches\b/.test(triggerText);
    if (hasDefault || bare) {
      pushDefaultLine = (onBlock?.start ?? 1) + (lineMatching(triggerText, branchRe) ?? 1) - 1;
      if (!onBlock) pushDefaultLine = lineMatching(stripped, /\bpush\b/) ?? 1;
    }
  }
  if (/workflow_dispatch|\bschedule\b|\bwhen\s*:\s*manual\b/.test(triggerText)) {
    manualTriggerLine = (onBlock?.start ?? 1) + (lineMatching(triggerText, /workflow_dispatch|\bschedule\b|\bwhen\s*:\s*manual\b/) ?? 1) - 1;
  }

  return {
    file,
    stripped,
    deployLine: deployLineOf(stripped),
    testLine: lineMatching(stripped, TEST_STEP_RE),
    checkLine: lineMatching(stripped, CHECK_STEP_RE),
    environmentLine: lineMatching(stripped, ENVIRONMENT_KEY_RE),
    approvalLine: lineMatching(stripped, APPROVAL_RE),
    needsLine: lineMatching(stripped, NEEDS_KEY_RE),
    rollbackLine: lineMatching(stripped, ROLLBACK_RE),
    migrateLine: lineMatching(stripped, MIGRATE_RE),
    productionLine: lineMatching(stripped, PRODUCTION_RE),
    pushDefaultLine,
    manualTriggerLine,
    unpinnedActions,
    inlineSecretLines,
    secretFlags,
    looseInstallLine: looseInstallLineOf(stripped),
  };
}

// ---------------------------------------------------------------------------
// Analyzer
// ---------------------------------------------------------------------------

export const devopsAnalyzer: Analyzer = {
  id: 'devops',
  category: 'devops',
  description: 'Container image, pipeline, environment separation, release safety, and operability checks over committed configuration.',

  precondition(map: RepoMap): string | undefined {
    const deployment = deploymentConfigFiles(map).length;
    const pipelines = ciFiles(map).length;
    const manifest = map.files.some((f) => f.role === 'manifest');
    if (deployment === 0 && pipelines === 0 && !manifest) {
      return 'no container, platform, pipeline, or package manifest configuration found in this snapshot';
    }
    return undefined;
  },

  run(ctx: AnalyzerContext): Finding[] {
    const { map } = ctx;
    const views = dockerfiles(map).map(parseDockerfile);
    const pipelines = ciFiles(map).map(buildCiView);
    const findings: Finding[] = [];

    findings.push(...containerRunsAsRoot(ctx, views));
    findings.push(...containerNoHealthcheck(ctx, views));
    findings.push(...unpinnedBaseImage(ctx, views));
    findings.push(...envFileInImageLayer(ctx, views));
    findings.push(...singleStageBuild(ctx, views));
    findings.push(...packageCacheRetained(ctx, views));

    findings.push(...unguardedProductionDeploy(ctx, pipelines));
    findings.push(...noRollbackStep(ctx, pipelines));
    findings.push(...noEnvironmentSeparation(ctx, pipelines));
    findings.push(...secretOnCommandLine(ctx, pipelines));
    findings.push(...unpinnedPipelineActions(ctx, pipelines));
    findings.push(...noPipeline(ctx, pipelines));
    findings.push(...dependencyPinning(ctx, pipelines, views));

    findings.push(...migrationsNotInPipeline(ctx, pipelines, views));
    findings.push(...noHealthEndpoint(ctx, views));
    findings.push(...noMonitoring(ctx, pipelines));
    findings.push(...noBackupConfiguration(ctx));
    findings.push(...unstructuredLogging(ctx));
    findings.push(...noDependencyUpdateTool(ctx, pipelines));

    return findings;
  },
};

// -------------------------------------------------------- container image ---

function containerRunsAsRoot(ctx: AnalyzerContext, views: DockerView[]): Finding[] {
  const { map } = ctx;
  const out: Finding[] = [];

  for (const view of views) {
    const final = view.final;
    if (!final) continue;
    // A stage that exists only to be copied out of never runs anything.
    if (isCopiedFrom(view, final)) continue;
    const ref = parseImageRef(final.reference);
    // An unresolvable base (built from an ARG) could already be a non-root
    // image, so the absence of USER here proves nothing.
    if (ref.unresolvable) continue;
    if (NON_ROOT_IMAGE_RE.test(final.reference)) continue;

    const user = effectiveUser(view, final);
    if (user && !isRootUser(user.args)) continue;

    const entry = [...final.instructions].reverse().find((i) => i.keyword === 'CMD' || i.keyword === 'ENTRYPOINT');
    const explicitRoot = user !== undefined;

    const primary = verified(map.evidenceLine(view.file.path, explicitRoot ? user.line : final.line,
      explicitRoot
        ? 'the image explicitly selects the root account for the running process'
        : 'no USER directive applies to this stage, so the process keeps the base image default of uid 0 (comments are stripped before matching, so a comment about USER does not count)'));
    if (!primary) continue;
    const evidence: Evidence[] = [primary];
    if (entry) {
      const e = verified(map.evidenceLine(view.file.path, entry.line, `this is the process that runs as root`));
      if (e) evidence.push(e);
    }

    out.push(ctx.finding({
      ruleId: explicitRoot ? 'devops.container.explicit_root_user' : 'devops.container.runs_as_root',
      title: explicitRoot
        ? `${view.file.path} sets USER root for the runtime image`
        : `${view.file.path} defines no USER, so the container runs as root`,
      severity: 'medium',
      confidence: explicitRoot ? 'confirmed' : 'strong',
      files: [view.file.path],
      evidence,
      explanation:
        (explicitRoot
          ? `The runtime stage of ${view.file.path} selects root explicitly, so the application process runs as uid 0 inside the container.`
          : `The runtime stage of ${view.file.path} contains no USER directive. Official base images do not drop privileges for you, so the `
            + 'application process runs as uid 0 inside the container.')
        + ' A root process inside a container can write anywhere in the image filesystem, install packages at runtime, and bind privileged '
        + 'ports; where the container runtime is not additionally hardened (user namespaces, a seccomp or AppArmor profile, a read-only root '
        + 'filesystem, dropped capabilities) root in the container is a much shorter distance from root on the host than most teams assume. '
        + 'It also makes any code-execution defect elsewhere in the application considerably more useful to an attacker.',
      userImpact:
        'Users are not affected while the application behaves normally. If an attacker achieves code execution through another defect, running '
        + 'as root is what turns a limited foothold into full control of the container: application files and secrets can be rewritten, a '
        + 'persistent backdoor can be installed, and outbound traffic can be redirected, which users experience as tampered pages, leaked '
        + 'data, or a service that has to be rebuilt from scratch.',
      likelyRootCause: 'The Dockerfile was written from a base-image quickstart, which never includes a USER line.',
      downstreamConsequences: [
        'Kubernetes `runAsNonRoot` or a restricted Pod Security Standard will refuse to schedule this image once such a policy is adopted.',
        'Files the container writes to a mounted volume will be owned by root on the host, which is awkward to undo later.',
      ],
      remediation:
        'Create an unprivileged account in the image and switch to it before the process starts: add a group and user (for example '
        + '`RUN addgroup --system --gid 1001 app && adduser --system --uid 1001 app`, or use the `node` user that Node images already ship), '
        + 'chown only the paths the process must write, then add `USER app` as the last instruction before CMD/ENTRYPOINT. Keep writable '
        + 'state on a mounted volume or a tmpfs rather than widening permissions in the image, and pair this with a read-only root '
        + 'filesystem and dropped capabilities in the orchestrator manifest.',
      effort: 'small',
      verificationSteps: [
        'Run `docker run --rm <image> id` and confirm the uid is not 0.',
        'Start the container and confirm it still writes everything it needs (logs, caches, uploads) without permission errors.',
        'Confirm the image still starts under `--read-only` with only the directories it genuinely needs mounted writable.',
      ],
      references: [REF.cisDocker, REF.cweRootPriv, REF.dockerBest],
    }));
  }
  return out;
}

/** Any orchestrator-level health probe configured outside the Dockerfile. */
function externalProbe(map: RepoMap): { file: string; line: number } | undefined {
  const PROBE_RE = /\b(?:healthcheck|health_check|livenessProbe|readinessProbe|startupProbe|healthCheckPath|health_check_path|http_checks|tcp_checks|\[checks\]|HEALTHCHECK)\b/i;
  for (const f of [...composeFiles(map), ...kubernetesFiles(map), ...platformConfigFiles(map)]) {
    const line = lineMatching(codeText(f.text, f.language), PROBE_RE);
    if (line !== undefined) return { file: f.path, line };
  }
  return undefined;
}

function containerNoHealthcheck(ctx: AnalyzerContext, views: DockerView[]): Finding[] {
  const { map } = ctx;
  const out: Finding[] = [];
  const probe = externalProbe(map);
  if (probe) return out;

  for (const view of views) {
    const final = view.final;
    if (!final) continue;
    if (isCopiedFrom(view, final)) continue;
    if (view.stages.some((s) => s.instructions.some((i) => i.keyword === 'HEALTHCHECK'))) continue;

    const entry = [...final.instructions].reverse().find((i) => i.keyword === 'CMD' || i.keyword === 'ENTRYPOINT');
    const anchor = entry?.line ?? final.line;
    const primary = verified(map.evidenceLine(view.file.path, anchor,
      'no HEALTHCHECK directive exists in this file and no orchestrator probe was found in any committed deployment configuration'));
    if (!primary) continue;

    out.push(ctx.finding({
      ruleId: 'devops.container.no_healthcheck',
      title: `${view.file.path} declares no health check for the container`,
      severity: 'low',
      confidence: 'strong',
      files: [view.file.path],
      evidence: [primary],
      explanation:
        `${view.file.path} has no HEALTHCHECK, and no liveness or readiness probe appears in any committed compose, Kubernetes, or platform `
        + 'configuration. Without one, the only liveness signal available to whatever runs this image is whether process 1 is still alive. '
        + 'The failure modes that matter in production are precisely the ones that keep the process alive: an exhausted connection pool, an '
        + 'event loop blocked on a synchronous call, a deadlock, or a dependency that stopped answering. In each case the container looks '
        + 'healthy, stays in the load-balancer rotation, and keeps receiving traffic.',
      userImpact:
        'When the application wedges rather than crashes, users keep being routed to the broken instance: requests hang or time out, and '
        + 'nothing restarts or drains it until a human notices. Rolling deployments are affected too — a new version that starts but cannot '
        + 'serve traffic is treated as a success and the old, working version is removed.',
      likelyRootCause: 'A health check needs an endpoint to call, so it is commonly deferred until the first production incident.',
      downstreamConsequences: [
        'Zero-downtime deployment cannot be relied on: nothing distinguishes "process started" from "ready to serve".',
        'Autoscaling and restart policies have no signal to act on other than process exit.',
      ],
      remediation:
        'Add an endpoint that checks the dependencies a request actually needs (database connectivity, cache, required configuration) and '
        + 'returns a non-2xx status when any of them is unusable, then wire it up: `HEALTHCHECK --interval=30s --timeout=3s --start-period=30s '
        + '--retries=3 CMD <http client> -f http://localhost:<port>/healthz || exit 1` in the image, and the equivalent liveness and readiness '
        + 'probes in the orchestrator manifest, where readiness gates traffic and liveness triggers a restart. Keep the check cheap and '
        + 'unauthenticated, and do not make it depend on a service whose outage should not take this one down.',
      effort: 'small',
      verificationSteps: [
        'Start the container and confirm `docker inspect --format "{{.State.Health.Status}}" <container>` reports healthy.',
        'Stop the database and confirm the endpoint reports unhealthy and the orchestrator removes the instance from rotation.',
        'Confirm the check passes during normal startup, so the start period is long enough not to cause a restart loop.',
      ],
      references: [REF.k8sProbes, REF.dockerBest],
    }));
  }
  return out;
}

function unpinnedBaseImage(ctx: AnalyzerContext, views: DockerView[]): Finding[] {
  const { map } = ctx;
  const out: Finding[] = [];

  for (const view of views) {
    const stageNames = new Set(view.stages.map((s) => s.name).filter((n): n is string => n !== undefined));
    interface Offender { stage: DockerStage; ref: ImageRef; floating: boolean }
    const offenders: Offender[] = [];

    for (const stage of view.stages) {
      const ref = parseImageRef(stage.reference);
      if (ref.unresolvable) continue;
      if (ref.digest) continue;
      if (stageNames.has(ref.image)) continue;          // a reference to an earlier stage
      if (ref.image === 'scratch') continue;
      const mutable = ref.tag === undefined || ref.tag === 'latest' || ref.tag === 'edge' || ref.tag === 'stable';
      // A full version (1.2.3) still moves if the publisher re-tags, but a bare
      // major or minor moves on every upstream release.
      const floating = !mutable && !/^\d+\.\d+\.\d+/.test(ref.tag!);
      if (!mutable && !floating) continue;
      offenders.push({ stage, ref, floating });
    }
    if (offenders.length === 0) continue;

    const worst = offenders.find((o) => !o.floating) ?? offenders[0]!;
    const primary = verified(map.evidenceLine(view.file.path, worst.stage.line,
      worst.floating
        ? `base image tag '${worst.ref.tag}' moves whenever the publisher re-tags it, and no digest pins it`
        : 'base image has no immutable tag and no digest'));
    if (!primary) continue;
    const evidence: Evidence[] = [primary];
    for (const o of offenders) {
      if (o.stage.line === worst.stage.line) continue;
      const e = verified(map.evidenceLine(view.file.path, o.stage.line, 'also unpinned'));
      if (e) evidence.push(e);
    }

    const mutableTag = !worst.floating;
    out.push(ctx.finding({
      ruleId: 'devops.container.unpinned_base_image',
      title: mutableTag
        ? `${view.file.path} builds on a mutable base image tag`
        : `${view.file.path} builds on a floating base image tag (${worst.ref.image}:${worst.ref.tag})`,
      severity: mutableTag ? 'medium' : 'low',
      confidence: mutableTag ? 'confirmed' : 'strong',
      files: [view.file.path],
      evidence,
      explanation:
        `The base image is referenced as \`${worst.stage.reference}\`, which resolves to whatever the publisher currently points that tag at. `
        + 'Two builds of the same commit can therefore produce different images: a different runtime patch level, different system libraries, '
        + 'and a different set of CVEs. That is the opposite of what a build should be — the image is part of the artefact, so it needs to be '
        + 'as fixed as the application code. It also means a compromised or mistakenly republished upstream tag enters the build with no '
        + 'review and no record of the change.',
      userImpact:
        'Users see failures that do not correspond to any change in the application: a deploy that worked yesterday breaks today because the '
        + 'base image moved underneath it, and the failure cannot be reproduced from the repository at that commit.',
      likelyRootCause: 'The tag was copied from the image\'s quickstart documentation, which always shows the convenient moving tag.',
      downstreamConsequences: [
        'A rebuild is not a safe recovery action: it may pull a different base than the image currently in production.',
        'Vulnerability scan results cannot be tied to a specific commit, because the scanned image is not reproducible from it.',
      ],
      remediation:
        'Pin the base image by digest (`FROM '
        + `${worst.ref.image}:${worst.ref.tag ?? '<version>'}@sha256:<digest>`
        + '`), keeping the human-readable tag for context, and let an automated update tool raise the digest in a reviewable pull request. '
        + 'Record the resolved digest in the build log or image labels so the running image can always be traced back to a commit.',
      effort: 'trivial',
      verificationSteps: [
        'Build twice from the same commit and confirm `docker image inspect` reports the same base layer digests.',
        'Confirm CI fails, rather than silently resolving a new image, if the pinned digest no longer exists.',
        'Confirm the update tool opens a pull request when a newer digest is published.',
      ],
      references: [REF.ossfPinned, REF.slsa, REF.cweUnpinned],
    }));
  }
  return out;
}

/** A COPY/ADD that pulls the whole build context into the image. */
function broadContextCopies(stage: DockerStage): DockerInstruction[] {
  return stage.instructions.filter((inst) => {
    if (inst.keyword !== 'COPY' && inst.keyword !== 'ADD') return false;
    if (/--from=/.test(inst.args)) return false;
    const parts = inst.args.split(/\s+/).filter((p) => !p.startsWith('--'));
    if (parts.length < 2) return false;
    return parts.slice(0, -1).some((src) => src === '.' || src === './' || src === '*' || src === './*');
  });
}

/** True when .dockerignore excludes the given path from the build context. */
function dockerignoreCovers(map: RepoMap, path: string): { covered: boolean; file?: SourceFile } {
  const file = map.files.find((f) => basename(f.path) === '.dockerignore' && f.text !== null);
  if (!file) return { covered: false };
  const name = basename(path);
  for (const raw of codeText(file.text, 'dockerignore').split('\n')) {
    const line = raw.trim();
    if (!line || line.startsWith('!')) continue;
    const pattern = line.replace(/^\.\//, '').replace(/\/$/, '');
    if (pattern === name || pattern === path) return { covered: true, file };
    if (pattern.includes('*')) {
      const re = new RegExp(`^${pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '[^/]*')}$`);
      if (re.test(name) || re.test(path)) return { covered: true, file };
    }
  }
  return { covered: false, file };
}

function envFileInImageLayer(ctx: AnalyzerContext, views: DockerView[]): Finding[] {
  const { map } = ctx;
  const out: Finding[] = [];
  if (map.env.committedEnvFiles.length === 0) return out;

  for (const view of views) {
    const final = view.final;
    if (!final) continue;
    const inFinal = broadContextCopies(final);
    const earlier = view.stages
      .filter((s) => s.index !== final.index)
      .flatMap((s) => broadContextCopies(s));
    const copy = inFinal[0] ?? earlier[0];
    if (!copy) continue;
    const runtimeLayer = inFinal.length > 0;

    for (const envPath of map.env.committedEnvFiles) {
      const ignored = dockerignoreCovers(map, envPath);
      if (ignored.covered) continue;

      const envFile = map.filesByPath.get(envPath);
      if (!envFile?.text) continue;
      // Cite the env file without reproducing any value from it.
      const envLines = envFile.text.split('\n');
      let keyLine = firstContentLine(envFile);
      let keyName = '';
      for (let i = 0; i < envLines.length; i++) {
        const m = /^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*\S/.exec(envLines[i]!.trim());
        if (m) { keyLine = i + 1; keyName = m[1]!; break; }
      }

      const primary = verified(map.evidenceLine(view.file.path, copy.line,
        `copies the entire build context, including ${envPath}, into ${runtimeLayer ? 'the runtime image' : 'a build stage'}`));
      if (!primary) continue;
      const evidence: Evidence[] = [primary];
      evidence.push({
        file: envPath,
        startLine: keyLine,
        excerpt: keyName ? `${keyName}=<value deliberately not reproduced>` : '<values deliberately not reproduced>',
        note: 'this file is tracked in the repository and is not excluded by a .dockerignore entry',
        verified: true,
      });
      const dockerignoreNote = ignored.file
        ? `A .dockerignore exists at ${ignored.file.path} but no pattern in it matches ${envPath}.`
        : 'No .dockerignore exists, so nothing is excluded from the build context.';

      out.push(ctx.finding({
        ruleId: 'devops.container.env_file_in_image_layer',
        title: `${envPath} is baked into the container image by \`${copy.keyword} ${copy.args}\``,
        severity: runtimeLayer ? 'high' : 'medium',
        confidence: runtimeLayer ? 'strong' : 'moderate',
        detectionSource: 'graph',
        files: [view.file.path, envPath],
        evidence,
        trace: {
          kind: 'env_var',
          steps: [
            { file: envPath, line: keyLine, detail: 'environment file tracked in the repository' },
            { file: view.file.path, line: copy.line, detail: `${copy.keyword} ${copy.args} copies the whole build context` },
            { file: view.file.path, line: final.line, detail: runtimeLayer ? 'the copy happens in the stage that produces the runtime image' : 'the copy happens in an earlier build stage, so it lands in an intermediate layer and the build cache' },
          ],
          complete: true,
        },
        explanation:
          `${view.file.path} copies the entire build context with \`${copy.keyword} ${copy.args}\`, and ${envPath} is tracked in the `
          + `repository, so the file becomes part of ${runtimeLayer ? 'the image' : 'an intermediate image layer'}. ${dockerignoreNote} `
          + 'An image layer is not private storage: anyone who can pull the image can extract the file with `docker save`, and the layer '
          + 'persists in the registry and in the build cache even if a later instruction deletes the file. This is distinct from the file '
          + 'being committed at all — that is a source-control problem; this is the image distributing it to every host, CI job, and registry '
          + 'mirror that ever receives a pull.'
          + (runtimeLayer ? '' : ' Because the copy is in an earlier stage, the values may not reach the final image, but they are still '
            + 'written to the build cache and to any layer pushed from that stage.'),
        userImpact:
          'Users are exposed indirectly: every credential in that file — database, payment provider, token-signing key — is readable by anyone '
          + 'who obtains the image, and those credentials are usually enough to read customer records or spend money on the account. Because '
          + 'the leak path is the image rather than the source tree, it keeps working after the file is removed from the repository.',
        likelyRootCause: '`COPY . .` is the shortest way to get an application into an image, and the build context quietly includes dotfiles.',
        downstreamConsequences: [
          'Deleting the file in a later RUN does not remove it: the earlier layer still contains it.',
          'Every credential in the file must be rotated, not just excluded from future builds.',
          'Registry mirrors, CI caches, and local pulls hold copies that are outside the repository\'s control.',
        ],
        remediation:
          'Add a .dockerignore that excludes `.env*`, `.git`, `node_modules`, and local tooling output, then copy only what the image needs '
          + '(the manifest and lockfile, then the build output) rather than the whole context. Supply configuration at run time through the '
          + 'orchestrator\'s environment or secret mechanism, and use build secrets (`RUN --mount=type=secret`) when a value is genuinely '
          + 'needed during the build, since those are not written to a layer. Treat every value in the file as compromised and rotate it.',
        effort: 'small',
        verificationSteps: [
          'Build the image and run `docker run --rm --entrypoint sh <image> -c \'ls -a /app\'` to confirm no environment file is present.',
          'Run `docker history --no-trunc <image>` and confirm no layer copies the whole context.',
          'Confirm the application still starts with configuration supplied only through the runtime environment.',
          'Confirm each credential that was in the file has been rotated at its provider.',
        ],
        references: [REF.dockerignore, REF.cweExposedFile, REF.twelveFactorConfig, REF.owaspMisconfig],
      }));
    }
  }
  return out;
}

const BUILD_TOOL_RE = /\b(?:npm|pnpm|yarn|bun)\s+(?:run\s+)?build\b|\btsc\b|\bwebpack\b|\bvite\s+build\b|next\s+build|nest\s+build|go\s+build|cargo\s+build|mvn\s+(?:package|install)|gradle\w*\s+(?:build|assemble)|dotnet\s+(?:publish|build)|make\b/i;
const DEV_INSTALL_RE = /\b(?:npm|pnpm|yarn|bun)\s+(?:install|ci|add)\b|pip\s+install|poetry\s+install|bundle\s+install|composer\s+install/i;
const PROD_ONLY_RE = /--omit=dev|--production|--prod\b|--only=production|--no-dev|--without\s+dev/i;

function singleStageBuild(ctx: AnalyzerContext, views: DockerView[]): Finding[] {
  const { map } = ctx;
  const out: Finding[] = [];
  const buildsSomething = manifests(map).some((m) => [...m.scripts.keys()].some((k) => /^(?:build|compile|bundle)/.test(k)))
    || map.hasTech('TypeScript') || map.hasTech('Next.js') || map.hasTech('Vite') || map.hasTech('Go') || map.hasTech('Rust') || map.hasTech('Java');

  for (const view of views) {
    if (view.stages.length !== 1) continue;
    const stage = view.stages[0]!;
    if (isCopiedFrom(view, stage)) continue;
    const install = stage.instructions.find((i) => i.keyword === 'RUN' && DEV_INSTALL_RE.test(i.args) && !PROD_ONLY_RE.test(i.args));
    const compiles = stage.instructions.some((i) => i.keyword === 'RUN' && BUILD_TOOL_RE.test(i.args));
    if (!install && !compiles) continue;
    if (!buildsSomething && !compiles) continue;

    const anchor = install ?? stage.instructions.find((i) => i.keyword === 'RUN' && BUILD_TOOL_RE.test(i.args));
    if (!anchor) continue;
    const primary = verified(map.evidenceLine(view.file.path, anchor.line,
      'build-time dependencies are installed into the same stage that produces the runtime image; this file declares only one FROM'));
    if (!primary) continue;

    out.push(ctx.finding({
      ruleId: 'devops.container.single_stage_build',
      title: `${view.file.path} ships its build toolchain in the runtime image`,
      severity: 'low',
      confidence: 'moderate',
      files: [view.file.path],
      evidence: [primary],
      explanation:
        `${view.file.path} declares a single stage, and that stage installs dependencies without restricting them to production (and in `
        + 'some cases compiles the project) in the same image that is run. Everything needed to build therefore ships to production: '
        + 'compilers, development dependencies, source maps, and the package manager itself. Each of those is extra attack surface that the '
        + 'application never uses at run time, and each contributes to a larger image, which means slower pulls, slower rollbacks, and more '
        + 'to scan and patch.',
      userImpact:
        'No direct user-visible effect in normal operation. Users feel it during an incident: a larger image takes longer to pull, which '
        + 'lengthens both a deploy and the rollback that ends an outage.',
      likelyRootCause: 'A single-stage Dockerfile is the simplest thing that works, and splitting it is rarely urgent.',
      downstreamConsequences: [
        'Vulnerability scanners report findings in build-only packages, which dilutes the signal from ones that matter.',
        'Development dependencies in the runtime image give a code-execution foothold more tools to work with.',
      ],
      remediation:
        'Split the Dockerfile into a build stage and a runtime stage: install all dependencies and build in the first stage, then start the '
        + 'runtime stage from a slim or distroless base and `COPY --from=build` only the build output plus the production dependency tree '
        + '(installed with `npm ci --omit=dev` or the equivalent). Keep the lockfile copy before the source copy so dependency layers stay '
        + 'cached, and set a non-root USER in the runtime stage.',
      effort: 'small',
      verificationSteps: [
        'Compare `docker image ls` before and after; the runtime image should be substantially smaller.',
        'Run `docker run --rm --entrypoint sh <image> -c \'command -v gcc; ls node_modules/.bin | head\'` and confirm build tooling is absent.',
        'Confirm the application still starts and serves a request from the runtime image.',
      ],
      references: [REF.dockerMultiStage, REF.dockerBest],
    }));
  }
  return out;
}

function packageCacheRetained(ctx: AnalyzerContext, views: DockerView[]): Finding[] {
  const { map } = ctx;
  const out: Finding[] = [];

  for (const view of views) {
    for (const stage of view.stages) {
      const offender = stage.instructions.find((inst) => {
        if (inst.keyword !== 'RUN') return false;
        if (/--mount=type=cache/.test(inst.args)) return false;
        const apt = /\bapt(?:-get)?\s+install\b/.test(inst.args) && !/rm\s+-rf?\s+\/var\/lib\/apt\/lists/.test(inst.args);
        const apk = /\bapk\s+add\b/.test(inst.args) && !/--no-cache/.test(inst.args) && !/rm\s+-rf?\s+\/var\/cache\/apk/.test(inst.args);
        const dnf = /\b(?:yum|dnf|microdnf)\s+install\b/.test(inst.args) && !/clean\s+all/.test(inst.args);
        return apt || apk || dnf;
      });
      if (!offender) continue;
      const primary = verified(map.evidenceLine(view.file.path, offender.line,
        'the package index or cache this command downloads is never removed in the same layer'));
      if (!primary) continue;

      out.push(ctx.finding({
        ruleId: 'devops.container.package_cache_retained',
        title: `${view.file.path} leaves the system package cache in an image layer`,
        severity: 'low',
        confidence: 'strong',
        files: [view.file.path],
        evidence: [primary],
        explanation:
          'A system package manager downloads its index and package archives into the image, and this RUN instruction does not remove them '
          + 'in the same layer. Because each instruction is its own layer, deleting the cache in a later instruction does not reclaim the '
          + 'space — the data stays in the earlier layer and is still pushed and pulled.',
        userImpact:
          'No direct effect on the application. The cost is operational: a larger image to pull on every deploy and rollback, and more data '
          + 'to store in the registry.',
        remediation:
          'Clean up inside the same RUN: for Debian or Ubuntu bases, `apt-get update && apt-get install --no-install-recommends -y <pkgs> '
          + '&& rm -rf /var/lib/apt/lists/*`; for Alpine, `apk add --no-cache <pkgs>`; for RPM bases, add `&& <yum|dnf> clean all`. Where '
          + 'BuildKit is available, a `--mount=type=cache` mount keeps the cache out of the image entirely while still speeding up builds.',
        effort: 'trivial',
        verificationSteps: [
          'Rebuild and confirm the image is smaller via `docker image ls`.',
          'Run `docker run --rm --entrypoint sh <image> -c \'du -sh /var/lib/apt/lists /var/cache/apk 2>/dev/null\'` and confirm the caches are empty or absent.',
        ],
        references: [REF.dockerBest],
      }));
      break;
    }
  }
  return out;
}

// --------------------------------------------------------------- pipelines ---

/** Anything in the pipeline that can stop a bad change reaching production. */
function gateOf(ci: CiView): { line: number; kind: string } | undefined {
  if (ci.testLine !== undefined) return { line: ci.testLine, kind: 'a test step' };
  if (ci.approvalLine !== undefined) return { line: ci.approvalLine, kind: 'a manual approval step' };
  if (ci.environmentLine !== undefined) return { line: ci.environmentLine, kind: 'a declared deployment environment' };
  return undefined;
}

/** The project's own test command, which a pipeline is expected to run. */
function testScript(map: RepoMap): { file: string; line: number; name: string; command: string } | undefined {
  for (const m of manifests(map)) {
    for (const [name, command] of m.scripts) {
      if (!/^(?:test|tests|verify|ci)(?::|$)/.test(name)) continue;
      const e = map.evidenceAt(m.file.path, `"${name}"`);
      if (e.verified && e.startLine !== undefined) return { file: m.file.path, line: e.startLine, name, command };
    }
  }
  return undefined;
}

function unguardedProductionDeploy(ctx: AnalyzerContext, pipelines: CiView[]): Finding[] {
  const { map } = ctx;
  const out: Finding[] = [];
  const script = testScript(map);
  const testedElsewhere = pipelines.filter((p) => p.testLine !== undefined);

  for (const ci of pipelines) {
    if (ci.deployLine === undefined) continue;
    if (ci.pushDefaultLine === undefined) continue;   // not triggered by a push to the default branch
    if (gateOf(ci)) continue;

    const primary = verified(map.evidenceLine(ci.file.path, ci.deployLine,
      'this step performs the deployment; comments are stripped before matching, so a comment about tests is not a test step'));
    if (!primary) continue;
    const evidence: Evidence[] = [primary];
    const trigger = verified(map.evidenceLine(ci.file.path, ci.pushDefaultLine,
      'the workflow runs on every push to the default branch, so any merge reaches this deploy step'));
    if (trigger) evidence.push(trigger);
    if (script) {
      const e = verified(map.evidenceLine(script.file, script.line,
        `the project declares '${script.name}' (\`${script.command}\`), which this pipeline never invokes`));
      if (e) evidence.push(e);
    }

    const elsewhere = testedElsewhere.filter((p) => p.file.path !== ci.file.path);
    const severity: Severity = elsewhere.length > 0 ? 'medium' : 'high';
    const missing: string[] = [];
    if (ci.testLine === undefined) missing.push('no test step');
    if (ci.checkLine === undefined) missing.push('no lint or type check');
    if (ci.environmentLine === undefined) missing.push('no declared deployment environment');
    if (ci.approvalLine === undefined) missing.push('no manual approval');
    if (ci.rollbackLine === undefined) missing.push('no rollback step');

    out.push(ctx.finding({
      ruleId: 'devops.cicd.unguarded_production_deploy',
      title: `${ci.file.path} deploys on every push to the default branch with no gate`,
      severity,
      confidence: 'strong',
      detectionSource: script ? 'graph' : 'static',
      files: script ? [ci.file.path, script.file] : [ci.file.path],
      evidence,
      trace: script
        ? {
          kind: 'import',
          steps: [
            { file: ci.file.path, line: ci.pushDefaultLine, detail: 'triggered by push to the default branch' },
            { file: script.file, line: script.line, detail: `the project's own '${script.name}' command exists but is not invoked by this workflow` },
            { file: ci.file.path, line: ci.deployLine, detail: 'the deployment step runs unconditionally' },
          ],
          complete: true,
        }
        : undefined,
      explanation:
        `${ci.file.path} is triggered by a push to the default branch and runs a deployment step with nothing between the two: `
        + `${missing.join(', ')}. `
        + (script
          ? `The repository does contain a '${script.name}' command, so the verification exists — the pipeline simply does not run it. `
          : 'No automated verification runs in this pipeline at all. ')
        + 'Every merge therefore becomes a release, and the first place a defect can be caught is production. The absence of a declared '
        + 'environment also means the hosting platform has no opportunity to apply protection rules (required reviewers, wait timers, '
        + 'branch restrictions) to this deployment, and the absence of a rollback step means recovery depends on someone remembering the '
        + 'right command under pressure.'
        + (elsewhere.length > 0
          ? ` Tests do run in ${elsewhere.map((p) => p.file.path).join(', ')}, but that workflow does not gate this one: the deploy job has no dependency on it, so a red test run does not stop the release.`
          : ''),
      userImpact:
        'Users are the test suite. A change that breaks checkout, login, or any other path goes live within minutes of a merge, stays live '
        + 'until someone notices, and is removed only when a human works out how to undo it — which, without a rollback step, is itself an '
        + 'improvised operation during an incident.',
      likelyRootCause: 'Continuous deployment was set up before continuous integration, which is the easier half to configure.',
      downstreamConsequences: [
        'Mean time to recovery is bounded by how long it takes a human to notice and improvise, not by automation.',
        'The pipeline provides no record that anything was verified before a given release.',
        'A broken dependency update or a bad migration reaches production with the same ease as a reviewed change.',
      ],
      remediation:
        'Split verification from release and make the release depend on it: run install, lint or type check, and the test suite in one job, '
        + 'then give the deploy job `needs: [<verification job>]` so a failure stops it. Declare the target environment on the deploy job '
        + '(`environment: production`) and configure its protection rules — required reviewers and, where useful, a wait timer — in the '
        + 'repository settings, since those rules are not visible in this file. Deploy to a staging environment from the default branch and '
        + 'promote to production from a tag or a manual dispatch. Add an explicit rollback path (redeploy the previous release, or the '
        + 'platform\'s own rollback command) and record in the repository how to run it.',
      effort: 'medium',
      verificationSteps: [
        'Open a pull request that deliberately fails a test and confirm no deployment runs for it.',
        'Push a commit whose test suite fails on the default branch and confirm the deploy job is skipped, not merely reported red.',
        'Confirm the deploy job appears under the environment in the platform UI, and that its protection rules are the intended ones.',
        'Rehearse the documented rollback against the staging environment and time it.',
      ],
      references: [REF.ghEnvironments, REF.dora, REF.twelveFactorBuild],
    }));
  }
  return out;
}

function noRollbackStep(ctx: AnalyzerContext, pipelines: CiView[]): Finding[] {
  const { map } = ctx;
  const out: Finding[] = [];
  // Projects whose platform provides rollback outside the repository are common,
  // so this is reported as a recommended improvement, never as a defect.
  const documented = presentAnywhere(map, ROLLBACK_RE);

  for (const ci of pipelines) {
    if (ci.deployLine === undefined) continue;
    if (!gateOf(ci)) continue;                 // the unguarded-deploy rule covers these
    if (ci.rollbackLine !== undefined) continue;
    if (documented) continue;

    const primary = verified(map.evidenceLine(ci.file.path, ci.deployLine,
      'this pipeline deploys; no step, script, or document in the repository describes undoing a release'));
    if (!primary) continue;

    out.push(ctx.finding({
      ruleId: 'devops.cicd.no_rollback_path',
      title: `${ci.file.path} deploys with no rollback path in the repository`,
      severity: 'low',
      confidence: 'moderate',
      files: [ci.file.path],
      evidence: [primary],
      explanation:
        `${ci.file.path} performs a deployment, and nothing in the repository — not this pipeline, not a script, not a document — describes `
        + 'how to return to the previous release. Many hosting platforms keep previous deployments and can promote one back with a single '
        + 'command or click, so the capability may well exist; what is missing is a rehearsed, written path to it. That distinction matters '
        + 'during an incident, when the people on call may not be the people who set the pipeline up.',
      userImpact:
        'When a release is bad, the time users spend on a broken service is the time it takes someone to work out how to undo it. An '
        + 'unrehearsed rollback also risks making things worse — rolling back application code while a schema change stays applied is a '
        + 'common way to turn a short outage into a longer one.',
      remediation:
        'Add an explicit rollback route and rehearse it: either a pipeline job that redeploys a chosen previous reference, or a documented '
        + 'invocation of the platform\'s own rollback command, kept next to the deployment configuration. Make schema changes backward '
        + 'compatible (expand, then migrate, then contract) so application code can be rolled back independently of the database, and record '
        + 'which releases are safe to roll back to.',
      effort: 'small',
      verificationSteps: [
        'Roll back a staging deployment using only the written procedure, timed, without consulting the person who wrote the pipeline.',
        'Confirm the procedure states what to do about database changes applied by the release being undone.',
      ],
      references: [REF.dora, REF.twelveFactorBuild],
    }));
  }
  return out;
}

const STAGING_RE = /\b(?:staging|stage|preview|pre-?prod|uat|qa|sandbox|development|dev)\b/i;

function noEnvironmentSeparation(ctx: AnalyzerContext, pipelines: CiView[]): Finding[] {
  const { map } = ctx;
  const out: Finding[] = [];
  const anyStaging = pipelines.some((p) => STAGING_RE.test(p.stripped))
    || presentAnywhere(map, /\b(?:staging|preview|pre-?prod|uat)\b/i) !== undefined;
  if (anyStaging) return out;

  for (const ci of pipelines) {
    if (ci.deployLine === undefined) continue;
    if (ci.productionLine === undefined) continue;
    if (!gateOf(ci)) continue;                 // the unguarded-deploy rule covers these
    if (ci.environmentLine !== undefined) continue;

    const primary = verified(map.evidenceLine(ci.file.path, ci.productionLine,
      'this pipeline targets production directly, and no staging or preview target appears anywhere in the repository'));
    if (!primary) continue;

    out.push(ctx.finding({
      ruleId: 'devops.cicd.no_environment_separation',
      title: `${ci.file.path} deploys to production with no separate pre-production environment`,
      severity: 'medium',
      confidence: 'moderate',
      files: [ci.file.path],
      evidence: [primary],
      explanation:
        `${ci.file.path} deploys straight to production, and no staging, preview, or pre-production target appears in any committed `
        + 'configuration. Production is therefore the first environment in which the application runs against real configuration, real '
        + 'data shapes, and real third-party endpoints. Environments configured outside the repository would not be visible here, so this '
        + 'is a question to confirm rather than a settled fact — but if there genuinely is only one environment, every change is tested in '
        + 'front of users.',
      userImpact:
        'Users encounter problems that an identical pre-production run would have caught first: a migration that behaves differently at real '
        + 'data volumes, a missing configuration value, or a third-party integration that only fails against the live endpoint.',
      remediation:
        'Add a pre-production environment that mirrors production in topology and configuration (not in data): deploy the default branch to '
        + 'it automatically, run smoke tests against it, and promote the same artefact to production from a tag or manual dispatch rather '
        + 'than rebuilding. Declare both targets as environments in the pipeline so credentials and protection rules can differ per '
        + 'environment, and keep their configuration in the same file so drift between them is visible in review.',
      effort: 'medium',
      verificationSteps: [
        'Confirm a push to the default branch deploys to the pre-production environment and not to production.',
        'Confirm the production deployment reuses the artefact that was verified in pre-production.',
        'Confirm the two environments hold separate credentials.',
      ],
      references: [REF.ghEnvironments, REF.twelveFactorParity, REF.dora],
    }));
  }
  return out;
}

function secretOnCommandLine(ctx: AnalyzerContext, pipelines: CiView[]): Finding[] {
  const { map } = ctx;
  const out: Finding[] = [];

  for (const ci of pipelines) {
    const inline = ci.inlineSecretLines[0];
    const flag = ci.secretFlags[0];
    if (inline === undefined && !flag) continue;

    const useInline = inline !== undefined;
    const line = useInline ? inline : flag!.line;
    const primary = verified(map.evidenceLine(ci.file.path, line,
      useInline
        ? 'a secret is expanded directly into the command text rather than passed through the step environment'
        : 'a secret-shaped value is passed as a command-line argument, where it is visible to other processes on the runner'));
    if (!primary) continue;

    out.push(ctx.finding({
      ruleId: useInline ? 'devops.cicd.secret_interpolated_into_command' : 'devops.cicd.secret_on_command_line',
      title: useInline
        ? `${ci.file.path} expands a secret into a shell command`
        : `${ci.file.path} passes a credential as a command-line argument`,
      severity: useInline ? 'high' : 'medium',
      confidence: useInline ? 'strong' : 'moderate',
      files: [ci.file.path],
      evidence: [primary],
      explanation: useInline
        ? 'The secret is substituted into the command text before the shell runs it. The expanded command is what gets traced, echoed on '
          + 'error, and written to the log when a step enables shell tracing or when a tool prints the command it was given. Pipeline log '
          + 'redaction only masks values the runner knows are secrets in the exact form they were registered, so a value that has been '
          + 'concatenated, re-encoded, or embedded in a longer string can pass through unmasked.'
        : `The value for \`${flag!.name}\` is passed as a command-line argument. Arguments are visible in the process table to every other `
          + 'process on the runner, they are captured by shell tracing and by many tools\' own error output, and they end up in shell '
          + 'history where a shell is reused. The environment is the narrower channel: it is per-process and is not printed by default.',
      userImpact:
        'Users are not affected directly. The risk is to them indirectly: a deployment or provider token that leaks into a log reachable by '
        + 'anyone with read access to the pipeline — on a public repository, by anyone at all — can be used to push code or configuration to '
        + 'the service they use.',
      likelyRootCause: 'The documented example for the tool shows the credential as a flag, which is the shortest thing that works.',
      downstreamConsequences: [
        'A leaked value has to be rotated at the provider; removing the log line does not undo the exposure.',
        'Forks and pull-request workflows widen who can observe a step\'s output.',
      ],
      remediation: useInline
        ? 'Pass the secret through the step\'s `env:` mapping and let the command read the environment variable (`$TOKEN`), so the value is '
          + 'never part of the command text. Where the tool only accepts a flag, prefer a file or stdin (`--password-stdin`), keep `set -x` '
          + 'off, and scope the credential to the narrowest permission and shortest lifetime the deployment needs — a short-lived OIDC token '
          + 'exchanged at run time is better than a long-lived stored secret.'
        : 'Give the step an `env:` entry and let the tool read the variable itself rather than receiving it as an argument; most deployment '
          + 'CLIs support an environment variable for their token. Where only a flag is available, pass the value through stdin or a file '
          + 'with restrictive permissions, avoid shell tracing in that step, and replace the long-lived token with a short-lived credential '
          + '(OIDC federation) where the provider supports it.',
      effort: 'small',
      verificationSteps: [
        'Re-run the pipeline and confirm the step log shows the command without the value.',
        'Confirm the deployment still authenticates with the value supplied only through the environment.',
        'Confirm the credential\'s scope is limited to deployment and that it has an expiry.',
      ],
      references: [REF.ghHardening, REF.owaspMisconfig],
    }));
  }
  return out;
}

function unpinnedPipelineActions(ctx: AnalyzerContext, pipelines: CiView[]): Finding[] {
  const { map } = ctx;
  const out: Finding[] = [];

  for (const ci of pipelines) {
    if (ci.unpinnedActions.length === 0) continue;
    const thirdParty = ci.unpinnedActions.filter((a) => a.thirdParty);
    const worst = thirdParty[0] ?? ci.unpinnedActions[0]!;

    const primary = verified(map.evidenceLine(ci.file.path, worst.line,
      `\`${worst.ref}\` is referenced by a tag or branch, which the publisher can move to different code at any time`));
    if (!primary) continue;
    const evidence: Evidence[] = [primary];
    for (const a of ci.unpinnedActions.slice(0, 4)) {
      if (a.line === worst.line) continue;
      const e = verified(map.evidenceLine(ci.file.path, a.line, 'also referenced by a mutable tag'));
      if (e) evidence.push(e);
    }

    out.push(ctx.finding({
      ruleId: 'devops.cicd.action_pinned_by_mutable_tag',
      title: thirdParty.length > 0
        ? `${ci.file.path} runs third-party pipeline steps pinned only by a mutable tag`
        : `${ci.file.path} pins its pipeline steps by mutable tag rather than commit`,
      severity: thirdParty.length > 0 ? 'medium' : 'low',
      confidence: 'strong',
      files: [ci.file.path],
      evidence,
      explanation:
        `${ci.unpinnedActions.length} step reference(s) in this workflow name a tag or branch rather than a commit: `
        + `${ci.unpinnedActions.slice(0, 5).map((a) => a.ref).join(', ')}. A tag is a movable pointer, so the code that runs in the pipeline `
        + 'can change without any change in this repository. These steps execute inside the pipeline with access to its secrets and its '
        + 'checkout, which makes them part of the trust boundary of every release.'
        + (thirdParty.length > 0
          ? ` ${thirdParty.length} of them are published outside the well-known first-party namespaces (${[...new Set(thirdParty.map((a) => a.owner))].join(', ')}), where a maintainer-account compromise or an ownership transfer is a realistic supply-chain path.`
          : ' All of them come from well-known first-party namespaces, which lowers but does not remove the risk.'),
      userImpact:
        'No direct effect in normal operation. If a pipeline step is replaced upstream with hostile code, the consequence for users is a '
        + 'tampered release or stolen deployment credentials, reaching them through the ordinary deployment path and with no local change to '
        + 'point at during the investigation.',
      likelyRootCause: 'Tag references are what every example in the marketplace documentation shows.',
      downstreamConsequences: [
        'The pipeline is not reproducible: the same commit can run different step code on different days.',
        'An incident review cannot establish which version of a step ran for a given release.',
      ],
      remediation:
        'Pin each step to a full commit SHA, keeping the tag in a trailing comment for readability, and let an automated update tool raise '
        + 'those SHAs in reviewable pull requests. Give each job the least `permissions:` it needs (start from `contents: read`), avoid '
        + 'exposing secrets to steps that do not need them, and prefer first-party or vendored steps for anything that touches credentials.',
      effort: 'small',
      verificationSteps: [
        'Confirm every `uses:` reference in the workflow is a 40-character commit SHA.',
        'Confirm the pipeline still succeeds after pinning.',
        'Confirm the update tool opens pull requests for new step versions.',
      ],
      references: [REF.ghHardening, REF.ossfPinned, REF.owaspIntegrity],
    }));
  }
  return out;
}

/** True when this snapshot looks like something that gets deployed. */
function isDeployable(map: RepoMap): boolean {
  if (deploymentConfigFiles(map).length > 0) return true;
  if (map.routes.length > 0) return true;
  return manifests(map).some((m) => [...m.scripts.keys()].some((k) => /^(?:start|serve|deploy|release)/.test(k)));
}

function noPipeline(ctx: AnalyzerContext, pipelines: CiView[]): Finding[] {
  const { map } = ctx;
  if (pipelines.length > 0) return [];
  if (!isDeployable(map)) return [];
  const script = testScript(map);
  const anchorFile = deploymentConfigFiles(map)[0] ?? manifests(map)[0]?.file;
  if (!anchorFile) return [];

  const primary = verified(map.evidenceLine(anchorFile.path, firstContentLine(anchorFile),
    'this project is built and deployed, but the snapshot contains no pipeline configuration for any known CI system'));
  if (!primary) return [];
  const evidence: Evidence[] = [primary];
  if (script) {
    const e = verified(map.evidenceLine(script.file, script.line,
      `the project declares '${script.name}', which nothing in the repository runs automatically`));
    if (e) evidence.push(e);
  }

  return [ctx.finding({
    ruleId: 'devops.cicd.no_pipeline',
    title: 'No continuous integration or deployment pipeline is configured',
    severity: 'medium',
    confidence: 'strong',
    files: [anchorFile.path],
    evidence,
    explanation:
      'The project has deployment configuration and a build or start command, but the snapshot contains no workflow, pipeline, or job '
      + 'definition for any CI system this scanner recognises (GitHub Actions, GitLab CI, CircleCI, Jenkins, Travis, Azure Pipelines, '
      + 'Buildkite, Drone, Bitbucket). Verification and release therefore depend on whoever is at a workstation: the commands that must run '
      + 'before a release exist only as habit, and the state of the deployed artefact cannot be tied to a recorded, repeatable process.'
      + (script ? ` The repository does declare '${script.name}', so the checks exist — nothing runs them.` : ''),
    userImpact:
      'Users receive whatever the last person to deploy happened to have on their machine. Defects that a routine automated check would '
      + 'have caught reach them, and an urgent fix depends on one person\'s local environment being in working order.',
    likelyRootCause: 'The project was deployed manually from the start and the pipeline was never added.',
    downstreamConsequences: [
      'Builds are not reproducible: no record exists of which commit produced the running artefact.',
      'Onboarding another maintainer means transferring undocumented local steps.',
    ],
    remediation:
      'Add a pipeline that runs on pull requests and on the default branch: install dependencies from the lockfile, lint or type check, run '
      + 'the test suite, and build. Then add a deployment job that depends on it and runs only for the default branch or a tag, deploying '
      + 'the artefact the verification job produced. Keep it minimal to start with — a single workflow that installs, tests, and builds is '
      + 'already most of the benefit.',
    effort: 'medium',
    verificationSteps: [
      'Open a pull request and confirm the checks run and are reported on it.',
      'Confirm a failing test blocks the merge and the deployment.',
      'Confirm the deployed artefact can be traced to the commit that produced it.',
    ],
    references: [REF.dora, REF.twelveFactorBuild],
  })];
}

function dependencyPinning(ctx: AnalyzerContext, pipelines: CiView[], views: DockerView[]): Finding[] {
  const { map } = ctx;
  const out: Finding[] = [];
  const manifestViews = manifests(map);
  if (manifestViews.length === 0) return out;
  if (!isDeployable(map)) return out;          // a library may legitimately omit a lockfile
  const locks = lockfiles(map);

  if (locks.length === 0) {
    const manifest = manifestViews[0]!;
    const anchor = map.evidenceAt(manifest.file.path, '"dependencies"', 'dependency ranges declared here, with no lockfile in the snapshot to resolve them')
      ?? undefined;
    const primary = verified(anchor) ?? verified(map.evidenceLine(manifest.file.path, firstContentLine(manifest.file),
      'this manifest declares dependencies and no lockfile is committed alongside it'));
    if (!primary) return out;
    const evidence: Evidence[] = [primary];
    const installSite = pipelines.find((p) => p.looseInstallLine !== undefined);
    if (installSite) {
      const e = verified(map.evidenceLine(installSite.file.path, installSite.looseInstallLine!,
        'the pipeline resolves dependency ranges afresh on every run'));
      if (e) evidence.push(e);
    }

    out.push(ctx.finding({
      ruleId: 'devops.build.no_lockfile_committed',
      title: 'No dependency lockfile is committed, so builds are not reproducible',
      severity: 'medium',
      confidence: 'strong',
      files: [manifest.file.path],
      evidence,
      explanation:
        `${manifest.file.path} declares dependencies as version ranges and no lockfile is committed beside it. Each install therefore `
        + 'resolves the whole transitive tree against whatever the registry currently offers, so two builds of the same commit can ship '
        + 'different code — including transitive packages nobody in the project has ever read. A newly published patch version of any '
        + 'dependency, or of any dependency of a dependency, enters the build with no review and no record of the change.',
      userImpact:
        'Users see breakage that nothing in the repository explains: a deploy of an unchanged commit behaves differently because a '
        + 'dependency moved. In the worst case a compromised package version reaches them through a routine deployment.',
      likelyRootCause: 'The lockfile was never committed, or it was added to .gitignore to avoid merge conflicts.',
      downstreamConsequences: [
        'A failing build cannot be reproduced locally with certainty.',
        'Vulnerability scanning cannot state what is actually installed, only what is permitted by the ranges.',
        'Rebuilding an old commit does not recreate the artefact that was released from it.',
      ],
      remediation:
        'Generate and commit the lockfile for the package manager in use (`package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `poetry.lock`, '
        + '`uv.lock`, and so on), then make every automated install honour it exactly (`npm ci`, `pnpm install --frozen-lockfile`, '
        + '`yarn install --immutable`, `poetry install --sync`). Resolve lockfile merge conflicts by regenerating rather than editing, and '
        + 'let an update tool raise dependency changes in reviewable pull requests.',
      effort: 'small',
      verificationSteps: [
        'Confirm the lockfile is tracked and is not matched by .gitignore.',
        'Confirm the pipeline install step fails when the lockfile and manifest disagree, rather than quietly updating the lockfile.',
        'Install twice from a clean cache and confirm the resolved tree is identical.',
      ],
      references: [REF.slsa, REF.ossfPinned, REF.twelveFactorBuild],
    }));
    return out;
  }

  // A lockfile exists; the risk is an install command that ignores it.
  const dockerLoose: Array<{ path: string; line: number }> = [];
  for (const view of views) {
    for (const stage of view.stages) {
      const inst = stage.instructions.find((i) => i.keyword === 'RUN'
        && LOOSE_INSTALL_RE.test(i.args) && !FROZEN_INSTALL_RE.test(i.args));
      if (inst) dockerLoose.push({ path: view.file.path, line: inst.line });
    }
  }
  const ciLoose = pipelines
    .filter((p) => p.looseInstallLine !== undefined)
    .map((p) => ({ path: p.file.path, line: p.looseInstallLine! }));
  const sites = [...ciLoose, ...dockerLoose];
  if (sites.length === 0) return out;

  const evidence: Evidence[] = [];
  for (const s of sites.slice(0, 3)) {
    const e = verified(map.evidenceLine(s.path, s.line,
      'this install resolves dependency ranges instead of installing exactly what the lockfile records'));
    if (e) evidence.push(e);
  }
  if (evidence.length === 0) return out;

  out.push(ctx.finding({
    ruleId: 'devops.build.non_reproducible_install',
    title: 'Automated builds install dependencies without honouring the lockfile',
    severity: 'low',
    confidence: 'strong',
    files: [...new Set(sites.map((s) => s.path))],
    evidence,
    explanation:
      `A lockfile is committed (${locks.map((l) => l.path).slice(0, 3).join(', ')}), but the install command used in the build resolves `
      + 'version ranges rather than installing the locked tree. `npm install` and a bare `yarn install` may update the lockfile in place and '
      + 'will happily pick up a newer transitive version, so the artefact that is built and deployed need not match what the lockfile '
      + 'describes — which defeats the purpose of committing it.',
    userImpact:
      'Users can be served a build containing dependency code that was never reviewed in this repository, with no change in the commit to '
      + 'explain a behavioural difference.',
    remediation:
      'Use the lockfile-exact command in every automated build: `npm ci`, `pnpm install --frozen-lockfile`, `yarn install --immutable`, '
      + '`bun install --frozen-lockfile`, or the equivalent for the package manager in use. These fail when the lockfile and manifest '
      + 'disagree, which is the behaviour a pipeline wants.',
    effort: 'trivial',
    verificationSteps: [
      'Confirm the build fails rather than updating the lockfile when the manifest and lockfile disagree.',
      'Confirm `git status` is clean after the install step runs in CI.',
    ],
    references: [REF.slsa, REF.twelveFactorBuild],
  }));
  return out;
}

// ------------------------------------------------ release-time correlation ---

/** Migration definitions committed to the repository. */
function migrationFiles(map: RepoMap): SourceFile[] {
  return readable(map, (f) => f.role === 'migration'
    || /(^|\/)(?:migrations?|alembic\/versions|db\/migrate)\//.test(f.path));
}

/** Anywhere in the repository that applies migrations as part of a release. */
function migrationStepSite(map: RepoMap, pipelines: CiView[], views: DockerView[]): { file: string; line: number } | undefined {
  for (const ci of pipelines) {
    if (ci.migrateLine !== undefined) return { file: ci.file.path, line: ci.migrateLine };
  }
  for (const view of views) {
    for (const stage of view.stages) {
      const inst = stage.instructions.find((i) => MIGRATE_RE.test(i.args));
      if (inst) return { file: view.file.path, line: inst.line };
    }
  }
  for (const m of manifests(map)) {
    for (const [name, command] of m.scripts) {
      if (!/^(?:start|serve|release|deploy|predeploy|postdeploy|prestart|poststart|entrypoint)/.test(name)) continue;
      if (!MIGRATE_RE.test(command)) continue;
      const e = map.evidenceAt(m.file.path, `"${name}"`);
      if (e.verified && e.startLine !== undefined) return { file: m.file.path, line: e.startLine };
    }
  }
  const shellAndConfig = readable(map, (f) => f.language === 'shell'
    || f.role === 'infrastructure' || basename(f.path) === 'Procfile' || PLATFORM_CONFIG_NAMES.has(basename(f.path)));
  for (const f of shellAndConfig) {
    const line = lineMatching(codeText(f.text, f.language), MIGRATE_RE);
    if (line !== undefined) return { file: f.path, line };
  }
  return undefined;
}

function migrationsNotInPipeline(ctx: AnalyzerContext, pipelines: CiView[], views: DockerView[]): Finding[] {
  const { map } = ctx;
  const migrations = migrationFiles(map);
  if (migrations.length === 0) return [];
  const deploying = pipelines.filter((p) => p.deployLine !== undefined);
  if (deploying.length === 0) return [];
  if (migrationStepSite(map, pipelines, views)) return [];

  const ci = deploying[0]!;
  const latest = migrations[migrations.length - 1]!;
  const primary = verified(map.evidenceLine(latest.path, firstContentLine(latest),
    'a committed migration that no release step in the repository applies'));
  if (!primary) return [];
  const deployEvidence = verified(map.evidenceLine(ci.file.path, ci.deployLine!,
    'the deployment step; no migration command appears in this pipeline, in the image, in a release script, or in any platform configuration'));
  if (!deployEvidence) return [];

  return [ctx.finding({
    ruleId: 'devops.deployment.migrations_not_in_pipeline',
    title: `Migrations are committed but no release step applies them (${migrations.length} migration file(s))`,
    severity: 'high',
    confidence: 'strong',
    detectionSource: 'graph',
    files: [latest.path, ci.file.path],
    evidence: [primary, deployEvidence],
    trace: {
      kind: 'import',
      steps: [
        { file: latest.path, line: firstContentLine(latest), detail: 'migration committed to the repository' },
        { file: ci.file.path, line: ci.deployLine, detail: 'pipeline deploys the application code' },
        { file: ci.file.path, detail: 'no migration command found in this pipeline, the container image, any release script, or any platform configuration' },
      ],
      complete: true,
    },
    explanation:
      `The repository contains ${migrations.length} migration file(s), the newest being ${latest.path}, and a pipeline that deploys the `
      + 'application. Nothing in the repository applies those migrations: no migration command appears in the pipeline, in the container '
      + 'image, in a release or entrypoint script, in the package manifest\'s start or release scripts, or in any committed platform '
      + 'configuration. Application code and schema therefore move independently, and the code is the half that moves automatically. If '
      + 'migrations are in fact applied by hand or by a platform release command configured outside the repository, the gap is in the '
      + 'record rather than the mechanism — but then the ordering and the rollback story are also undocumented.',
    userImpact:
      'A release that expects a new column, table, or index runs against a schema that does not have it. Users see errors from every path '
      + 'that touches the changed model — often the newest feature, sometimes a core flow — from the moment the deploy completes until '
      + 'someone runs the migration manually. Worse, a partially migrated schema can accept writes that later migrations cannot reconcile.',
    likelyRootCause: 'Migrations were run by hand during early development and the habit was never encoded in the pipeline.',
    downstreamConsequences: [
      'Rolling back application code does not roll back a schema change, so the two can end up incompatible in either direction.',
      'Concurrent deployments can run migrations twice or race, depending on how they are applied.',
      'Nothing records which schema version a given release expects.',
    ],
    remediation:
      'Make schema change part of the release, ordered and recorded: run the migration command (for example `prisma migrate deploy`, '
      + '`alembic upgrade head`, `rails db:migrate`, `knex migrate:latest`) as a dedicated step that the deploy step depends on, using a '
      + 'single-runner lock or the migration tool\'s own advisory lock so concurrent deploys cannot race. Write migrations to be backward '
      + 'compatible with the previous release (expand, migrate, then contract in a later release) so application code can be rolled back on '
      + 'its own, and keep destructive steps in a separate, reviewed release.',
    effort: 'medium',
    verificationSteps: [
      'Deploy to a pre-production environment from a clean schema and confirm the migration step runs before traffic reaches the new code.',
      'Run two deployments concurrently against the same database and confirm the migration is applied exactly once.',
      'Roll back the application to the previous release with the new migration still applied and confirm it still works.',
    ],
    references: [REF.twelveFactorAdmin, REF.twelveFactorBuild, REF.dora],
  })];
}

const HEALTH_PATH_RE = /\b(?:health|healthz|healthcheck|health-check|livez|liveness|readyz|readiness|heartbeat|ping|up)\b|\/_?status\b/i;

function noHealthEndpoint(ctx: AnalyzerContext, views: DockerView[]): Finding[] {
  const { map } = ctx;
  const container = views[0]?.file ?? composeFiles(map)[0] ?? kubernetesFiles(map)[0] ?? platformConfigFiles(map)[0];
  if (!container) return [];
  // Route extraction must have worked for an absence claim to mean anything.
  if (map.routes.length < 2) return [];
  if (map.routes.some((r) => HEALTH_PATH_RE.test(r.path) || HEALTH_PATH_RE.test(r.file))) return [];
  // A probe configured anywhere may point at a path this scanner does not model
  // (a static page, or a framework route it cannot see), so stay quiet.
  if (externalProbe(map)) return [];
  if (views.some((v) => v.stages.some((s) => s.instructions.some((i) => i.keyword === 'HEALTHCHECK')))) return [];

  const anchorLine = views[0]?.final?.line ?? firstContentLine(container);
  const primary = verified(map.evidenceLine(container.path, anchorLine,
    'this configuration defines how the service is run, and no readiness or liveness target exists for it'));
  if (!primary) return [];
  const sample = map.routes[0]!;
  const routeEvidence = verified(map.evidenceLine(sample.file, sample.line ?? 1,
    `one of ${map.routes.length} detected routes; none of them is a health or readiness endpoint`));
  if (!routeEvidence) return [];

  return [ctx.finding({
    ruleId: 'devops.deployment.no_health_endpoint',
    title: 'The service is containerised but exposes no health or readiness endpoint',
    severity: 'medium',
    confidence: 'strong',
    detectionSource: 'graph',
    files: [container.path, sample.file],
    evidence: [primary, routeEvidence],
    trace: {
      kind: 'import',
      steps: [
        { file: container.path, line: anchorLine, detail: 'the service is packaged to run under a container runtime or platform' },
        { file: sample.file, line: sample.line, detail: `${map.routes.length} routes detected across the project` },
        { file: container.path, detail: 'none of the detected routes answers a health, readiness, or liveness check, and no probe is configured' },
      ],
      complete: true,
    },
    explanation:
      `${container.path} describes how this service is run, and the project exposes ${map.routes.length} detected route(s), none of which `
      + 'is a health, readiness, or liveness endpoint. Nothing therefore distinguishes "the process is running" from "the process can serve '
      + 'a request": not the container runtime, not a load balancer, not a deployment that needs to know whether the new version came up. '
      + 'The routes considered here are the ones this scanner resolved statically, so an endpoint served by a framework mechanism it does '
      + 'not model would not appear — but no probe configuration pointing at such an endpoint exists either, which is the corroborating '
      + 'half of this observation.',
    userImpact:
      'During a partial failure — a lost database connection, an exhausted pool, a blocked event loop — the instance stays in rotation and '
      + 'users keep being sent to it, receiving timeouts rather than being routed to a working instance. During a deployment, a new version '
      + 'that starts but cannot serve traffic is treated as a success, so users can be moved onto a broken release.',
    likelyRootCause: 'Health endpoints are infrastructure rather than product work, so they are added after the first incident that needed one.',
    downstreamConsequences: [
      'Zero-downtime and rolling deployments cannot be relied on without a readiness signal.',
      'Autoscaling and restart decisions have nothing to act on but process exit.',
      'Uptime monitoring can only probe a real user-facing route, which mixes application errors with availability.',
    ],
    remediation:
      'Add two cheap, unauthenticated endpoints and wire them up: a liveness route that returns 200 if the process is responsive, and a '
      + 'readiness route that checks the dependencies a request needs (database connectivity, cache, required configuration) and returns a '
      + 'non-2xx status when any is unusable. Reference them from the container HEALTHCHECK and from the orchestrator\'s liveness and '
      + 'readiness probes, keep them out of request logging and rate limiting, and make sure readiness failure drains traffic rather than '
      + 'restarting the process.',
    effort: 'small',
    verificationSteps: [
      'Request the readiness endpoint and confirm it returns 200 with the service healthy.',
      'Stop the database and confirm readiness returns a non-2xx status while liveness still succeeds.',
      'Confirm the orchestrator removes an unready instance from rotation and restarts a non-live one.',
      'Confirm the endpoints are excluded from request logs and authentication.',
    ],
    references: [REF.k8sProbes, REF.sreSlo],
  })];
}

const MONITORING_RE = new RegExp([
  '\\bsentry\\b', '\\bdatadog\\b', 'dd-trace', '\\bnewrelic\\b', 'new[-_]relic',
  'opentelemetry', '\\botel\\b', 'prom-client', '\\bprometheus\\b', '\\bgrafana\\b',
  '\\brollbar\\b', '\\bbugsnag\\b', '\\bhoneycomb\\b', 'elastic-apm', '\\bappsignal\\b',
  'scout_apm', '\\bskywalking\\b', '\\bstatsd\\b', '\\bcloudwatch\\b', '\\bstackdriver\\b',
  'application[-_]?insights', '\\blogtail\\b', '\\baxiom\\b', 'better[-_]?stack',
  '\\bpagerduty\\b', '\\bopsgenie\\b', 'healthchecks\\.io', 'uptimerobot', '\\bstatuscake\\b',
  '\\bpingdom\\b', '\\bsignoz\\b', '\\bsentry-cli\\b', 'alertmanager', '\\bgraylog\\b',
].join('|'), 'i');

function noMonitoring(ctx: AnalyzerContext, pipelines: CiView[]): Finding[] {
  const { map } = ctx;
  if (map.routes.length === 0 && deploymentConfigFiles(map).length === 0) return [];
  if (presentAnywhere(map, MONITORING_RE)) return [];
  // Convention-named instrumentation files count as monitoring configuration.
  if (map.files.some((f) => /^(?:instrumentation|sentry\.|otel|telemetry|monitoring|tracing)/.test(basename(f.path)))) return [];

  const anchor = manifests(map)[0]?.file ?? deploymentConfigFiles(map)[0] ?? pipelines[0]?.file;
  if (!anchor) return [];
  const note = 'no error-tracking, metrics, tracing, or alerting dependency or configuration appears anywhere in this snapshot';
  const primary = verified(map.evidenceAt(anchor.path, '"dependencies"', note))
    ?? verified(map.evidenceLine(anchor.path, firstContentLine(anchor), note));
  if (!primary) return [];

  return [ctx.finding({
    ruleId: 'devops.observability.no_monitoring_configured',
    title: 'No error tracking, metrics, or alerting is configured in the repository',
    severity: 'medium',
    confidence: 'moderate',
    files: [anchor.path],
    evidence: [primary],
    explanation:
      'No dependency, import, or configuration for error tracking, metrics, tracing, or alerting appears anywhere in this snapshot — not in '
      + 'the manifests, not in the application code, not in the deployment or pipeline configuration. The project therefore has no committed '
      + 'way to learn that something is wrong other than someone looking. Hosting platforms do provide some of this (request logs, basic '
      + 'metrics, crash reporting) and that would not be visible in the repository, which is why this is reported as moderate confidence: '
      + 'the claim is that the repository configures none, not that none exists.',
    userImpact:
      'Users become the alerting system. A failure affecting a subset of requests — one route, one browser, one payment path — can continue '
      + 'for as long as it takes someone to report it, and because nothing recorded the failure, the report arrives without the detail needed '
      + 'to reproduce it.',
    likelyRootCause: 'Monitoring is usually added after the first incident that could not be explained from logs alone.',
    downstreamConsequences: [
      'There is no error rate or latency baseline, so a regression cannot be distinguished from normal variation.',
      'Incident investigation depends on logs that may have already rotated away.',
      'Error budgets and availability targets cannot be stated, let alone enforced.',
    ],
    remediation:
      'Start with error tracking: add an error-reporting SDK to both the server and the browser, capture release and request context, and '
      + 'route alerts to somewhere a human will see them. Then add the few metrics that describe user experience (request rate, error rate, '
      + 'latency percentiles, saturation of any pool or queue) and alert on symptoms rather than causes. Self-hosted and free tiers exist for '
      + 'all of this; the important part is that something other than a user notices first.',
    effort: 'medium',
    verificationSteps: [
      'Trigger a deliberate server error in pre-production and confirm it appears in the error tracker with a stack trace and request context.',
      'Confirm an alert reaches the intended destination, and that someone is responsible for receiving it.',
      'Confirm the error rate and latency of the main user journey are visible on a dashboard.',
    ],
    references: [REF.cweMonitoring, REF.sreSlo, REF.twelveFactorLogs],
  })];
}

const SELF_HOSTED_DB_RE = /\b(?:postgres|postgresql|mysql|mariadb|mongo|mongodb|redis|clickhouse|elasticsearch|opensearch|cassandra|couchdb|neo4j|influxdb|timescale)\b\s*(?::|image)/i;
const VOLUME_RE = /\bvolumes?\s*:|persistentVolumeClaim|volumeClaimTemplates|\bVOLUME\b/;
const BACKUP_RE = /\bbackup(?:s|ed)?\b|\brestore\b|pg_dump|pg_dumpall|pgbackrest|mysqldump|mongodump|\bwal-?g\b|\bbarman\b|\bvelero\b|\brestic\b|\blitestream\b|\bsnapshot\b|point-in-time/i;

function noBackupConfiguration(ctx: AnalyzerContext): Finding[] {
  const { map } = ctx;
  const candidates = [...composeFiles(map), ...kubernetesFiles(map)];
  const selfHosted = candidates.find((f) => {
    const stripped = codeText(f.text, f.language);
    return SELF_HOSTED_DB_RE.test(stripped) && VOLUME_RE.test(stripped);
  });
  if (!selfHosted) return [];
  if (presentAnywhere(map, BACKUP_RE)) return [];

  const stripped = codeText(selfHosted.text, selfHosted.language);
  const line = lineMatching(stripped, SELF_HOSTED_DB_RE) ?? firstContentLine(selfHosted);
  const primary = verified(map.evidenceLine(selfHosted.path, line,
    'a datastore this project runs itself, with persistent storage and no backup or restore configuration anywhere in the repository'));
  if (!primary) return [];

  return [ctx.finding({
    ruleId: 'devops.data.no_backup_configuration',
    title: `${selfHosted.path} runs a self-hosted datastore with no committed backup configuration`,
    severity: 'medium',
    confidence: 'moderate',
    status: 'needs_runtime_verification',
    files: [selfHosted.path],
    evidence: [primary],
    explanation:
      `${selfHosted.path} declares a datastore that this project runs itself, with persistent storage attached, and no backup, dump, `
      + 'snapshot, or restore configuration appears anywhere in the repository. Whether backups actually exist cannot be determined from a '
      + 'source snapshot — they may be configured in a cloud console, on the host, or by a provider — so this finding is a question for an '
      + 'operator rather than a defect in the code. What can be said is that the repository does not describe them, which means nobody can '
      + 'tell from the project what the recovery point objective is or how a restore is performed.',
    userImpact:
      'If the volume is lost, corrupted, or deleted in error, user data is lost with it. Users experience that as permanently missing '
      + 'records — orders, messages, uploads — and there is no documented path to getting them back.',
    remediation:
      'Decide and record the recovery point and recovery time objectives, then automate a backup that meets them: a scheduled logical dump '
      + 'or physical snapshot stored off the host, with retention, plus continuous archiving (write-ahead log shipping) where the objective '
      + 'is tighter than the schedule. Keep the restore procedure in the repository next to the deployment configuration and rehearse it on '
      + 'a schedule — an untested backup is a hypothesis. Encrypt backups at rest and restrict who can delete them.',
    effort: 'medium',
    verificationSteps: [
      'Restore the most recent backup into a scratch environment and confirm the application starts and the data is intact.',
      'Confirm backups are stored somewhere that survives the loss of the host or the volume.',
      'Confirm the measured restore time meets the stated objective, and record the date of the last rehearsal.',
    ],
    references: [REF.dora, REF.twelveFactorAdmin],
  })];
}

const STRUCTURED_LOG_RE = /\bpino\b|\bwinston\b|\bbunyan\b|\bstructlog\b|\bzerolog\b|\blogrus\b|\bserilog\b|\bmonolog\b|log4j|\btslog\b|\bconsola\b|\bsignale\b|\bloguru\b|\bslog\b|\broarr\b|\bbole\b/i;
const CONSOLE_CALL_RE = /^(?:console\.(?:log|info|debug|warn|error|trace)|print|println|System\.out\.print)/;
const SERVER_PATH_RE = /(^|\/)(?:api|server|services?|lib|jobs?|workers?|handlers?|controllers?|routes?|functions?)\//;

function unstructuredLogging(ctx: AnalyzerContext): Finding[] {
  const { map } = ctx;
  if (presentAnywhere(map, STRUCTURED_LOG_RE)) return [];
  const routeFiles = new Set(map.routes.map((r) => r.file));

  const sites: Array<{ file: string; line: number }> = [];
  for (const mod of map.modules.values()) {
    if (!mod.parsed) continue;
    if (mod.jsx.length > 0) continue;                        // browser code is a different subject
    if (!routeFiles.has(mod.path) && !SERVER_PATH_RE.test(mod.path)) continue;
    for (const call of mod.calls) {
      if (!CONSOLE_CALL_RE.test(call.callee)) continue;
      sites.push({ file: mod.path, line: call.line });
    }
  }
  if (sites.length < 3) return [];

  const evidence: Evidence[] = [];
  for (const s of sites.slice(0, 3)) {
    const e = verified(map.evidenceLine(s.file, s.line, 'server-side logging through the console, with no structured logger in the project'));
    if (e) evidence.push(e);
  }
  if (evidence.length === 0) return [];

  return [ctx.finding({
    ruleId: 'devops.observability.unstructured_logging',
    title: `Server-side logging goes through the console with no structured logger (${sites.length} call sites)`,
    severity: 'low',
    confidence: 'moderate',
    files: [...new Set(sites.map((s) => s.file))].slice(0, 5),
    evidence,
    explanation:
      `${sites.length} server-side log call(s) write free-form text to the console, and no structured logging library appears anywhere in `
      + 'the project. Free-form lines are hard to use operationally: there is no level to filter on consistently, no request or user '
      + 'identifier to correlate the lines belonging to one request, and no stable field names to search or aggregate. Multi-line output '
      + '(an interpolated object, a stack trace) is also split into separate records by most log collectors, so the context is lost exactly '
      + 'when it is needed.',
    userImpact:
      'No direct effect on the application. The cost lands on users during an incident: diagnosing a problem that affects some requests and '
      + 'not others is much slower when the lines from one request cannot be grouped, which lengthens every outage.',
    remediation:
      'Adopt a structured logger (pino, winston, structlog, zerolog, or the platform\'s own) emitting one JSON object per event with a level, '
      + 'a timestamp, a message, and context fields. Attach a request identifier at the edge and carry it through, so all lines for a request '
      + 'can be retrieved together. Log at the boundaries (request start and end, external calls, errors with stack traces) rather than '
      + 'inside hot loops, and keep credentials, tokens, and personal data out of the fields.',
    effort: 'small',
    verificationSteps: [
      'Confirm log output parses as one JSON object per line.',
      'Make a request and confirm every line it produced can be retrieved by its request identifier.',
      'Confirm no log field contains a credential, token, or personal data.',
    ],
    references: [REF.twelveFactorLogs, REF.cweMonitoring],
  })];
}

const UPDATE_TOOL_FILE_RE = /^\.github\/(?:dependabot\.ya?ml|renovate\.json5?)$|^renovate\.json5?$|^\.renovaterc(?:\.json5?)?$|^\.whitesource$|^\.snyk$/;
const UPDATE_TOOL_TEXT_RE = /\bdependabot\b|\brenovate\b|(?:npm|pnpm|yarn)\s+audit|pip-audit|cargo\s+audit|bundler-audit|dependency-review|\bsnyk\b|\btrivy\b|osv-scanner|\bsafety\s+check\b|\bgrype\b/i;

function noDependencyUpdateTool(ctx: AnalyzerContext, pipelines: CiView[]): Finding[] {
  const { map } = ctx;
  const manifestViews = manifests(map);
  if (manifestViews.length === 0) return [];
  // Only meaningful where the project already runs automation it could hook into.
  if (pipelines.length === 0) return [];
  if (map.files.some((f) => UPDATE_TOOL_FILE_RE.test(f.path))) return [];
  if (presentAnywhere(map, UPDATE_TOOL_TEXT_RE)) return [];

  const manifest = manifestViews[0]!;
  const anchor = map.evidenceAt(manifest.file.path, '"dependencies"',
    'third-party dependencies declared here, with nothing in the repository watching them for updates or advisories');
  const primary = verified(anchor) ?? verified(map.evidenceLine(manifest.file.path, firstContentLine(manifest.file),
    'third-party dependencies declared here, with no automated update or advisory tooling configured'));
  if (!primary) return [];
  const evidence: Evidence[] = [primary];
  const ci = pipelines[0]!;
  const e = verified(map.evidenceLine(ci.file.path, firstContentLine(ci.file),
    'an existing pipeline that could run dependency and advisory checks'));
  if (e) evidence.push(e);

  return [ctx.finding({
    ruleId: 'devops.dependencies.no_automated_updates',
    title: 'No automated dependency update or advisory checking is configured',
    severity: 'low',
    confidence: 'strong',
    files: [manifest.file.path],
    evidence,
    explanation:
      'The project depends on third-party packages and already runs a pipeline, but no dependency update tool (Dependabot, Renovate, or '
      + 'equivalent) is configured and no advisory or vulnerability check runs in CI. Dependency updates therefore happen only when someone '
      + 'remembers, which in practice means a long gap followed by a large, risky upgrade — and a published advisory affecting a direct or '
      + 'transitive dependency produces no signal in this repository at all.',
    userImpact:
      'Users are exposed for longer to defects and vulnerabilities fixed upstream, because nothing notices the fix exists. When the backlog '
      + 'is eventually cleared, it arrives as one large change, which is itself more likely to break something they rely on.',
    remediation:
      'Enable an update tool with a schedule and grouping: a `.github/dependabot.yml` or `renovate.json` that batches minor and patch '
      + 'updates into one pull request per ecosystem per week, keeps major versions separate, and is gated by the existing test pipeline so '
      + 'routine updates can be merged on green. Add an advisory check to CI (`npm audit --omit=dev`, `pip-audit`, `osv-scanner`, or the '
      + 'platform\'s dependency review) and decide which severities fail the build rather than merely reporting.',
    effort: 'trivial',
    verificationSteps: [
      'Confirm the update tool opens a pull request on its next scheduled run.',
      'Confirm those pull requests run the full test pipeline.',
      'Confirm the advisory check fails the build for a known-vulnerable dependency version.',
    ],
    references: [REF.ossfDependencyUpdate, REF.owaspIntegrity],
  })];
}
