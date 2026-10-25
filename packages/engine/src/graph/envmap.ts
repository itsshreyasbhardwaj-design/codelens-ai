import type { SourceFile } from '../ingest/normalize.ts';
import type { ParsedModule } from '../parse/types.ts';

/**
 * Environment variable map: what the code reads versus what is documented.
 *
 * An undocumented variable is a real deployment hazard — the application starts
 * and then fails at the moment the value is first needed.
 */

export interface EnvUsage {
  name: string;
  readIn: Array<{ file: string; line: number }>;
  documented: boolean;
  /** True when the code supplies a fallback, so absence is non-fatal. */
  hasFallback: boolean;
}

export interface EnvMap {
  usages: EnvUsage[];
  documentedNames: Set<string>;
  /** Example/template files that were read. */
  templateFiles: string[];
  /** Committed .env files that contain real-looking values. */
  committedEnvFiles: string[];
}

const TEMPLATE_NAMES = [
  '.env.example', '.env.sample', '.env.template', '.env.defaults',
  'env.example', '.env.dist', '.env.local.example',
];

function parseEnvFileKeys(text: string): string[] {
  const keys: string[] = [];
  for (const raw of text.split('\n')) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const m = /^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=/.exec(line);
    if (m) keys.push(m[1]!);
  }
  return keys;
}

export function buildEnvMap(files: SourceFile[], modules: Map<string, ParsedModule>): EnvMap {
  const documentedNames = new Set<string>();
  const templateFiles: string[] = [];
  const committedEnvFiles: string[] = [];

  for (const f of files) {
    const base = f.path.slice(f.path.lastIndexOf('/') + 1);
    if (!f.text) continue;

    if (TEMPLATE_NAMES.includes(base)) {
      templateFiles.push(f.path);
      for (const k of parseEnvFileKeys(f.text)) documentedNames.add(k);
      continue;
    }
    // A committed .env that is not a template is itself a finding input.
    if (base === '.env' || /^\.env\.(local|development|production|staging|prod|dev)$/.test(base)) {
      committedEnvFiles.push(f.path);
      for (const k of parseEnvFileKeys(f.text)) documentedNames.add(k);
    }
  }

  // Also treat documentation and compose/CI files as documentation of a name.
  for (const f of files) {
    if (!f.text) continue;
    if (f.role === 'documentation' || f.role === 'ci' || f.role === 'infrastructure') {
      for (const m of f.text.matchAll(/\b([A-Z][A-Z0-9_]{3,})\b\s*[:=]/g)) {
        documentedNames.add(m[1]!);
      }
    }
  }

  const byName = new Map<string, EnvUsage>();
  for (const mod of modules.values()) {
    if (!mod.parsed) continue;
    for (const name of mod.envVars) {
      const existing = byName.get(name);
      // Locate the reading line for evidence.
      const line = findEnvLine(mod, name);
      const hasFallback = hasEnvFallback(mod, name);
      if (existing) {
        existing.readIn.push({ file: mod.path, line });
        existing.hasFallback = existing.hasFallback || hasFallback;
      } else {
        byName.set(name, {
          name,
          readIn: [{ file: mod.path, line }],
          documented: documentedNames.has(name),
          hasFallback,
        });
      }
    }
  }

  return { usages: [...byName.values()], documentedNames, templateFiles, committedEnvFiles };
}

function findEnvLine(mod: ParsedModule, name: string): number {
  const access = mod.memberAccesses.find((a) => a.property === name);
  if (access) return access.line;
  const call = mod.calls.find((c) => c.args.some((a) => a.includes(name)));
  return call?.line ?? 1;
}

/** True when the read is guarded by `?? x`, `|| x`, or a default argument. */
function hasEnvFallback(mod: ParsedModule, name: string): boolean {
  const sym = mod.symbols.find((s) => s.text.includes(name));
  const haystack = sym?.text ?? '';
  const re = new RegExp(
    `${name}\\s*(?:\\]|\\))?\\s*(?:\\?\\?|\\|\\|)|getenv\\s*\\(\\s*['"]${name}['"]\\s*,`,
  );
  return re.test(haystack);
}
