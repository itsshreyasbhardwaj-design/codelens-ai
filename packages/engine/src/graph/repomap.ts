import type {
  ApiEndpoint, ArchComponent, ArchRelationship, DataModel, Evidence, Feature, TechDetection,
} from '@codelens/core';
import type { Snapshot, SourceFile } from '../ingest/normalize.ts';
import type { ParsedModule } from '../parse/types.ts';
import { buildImporterIndex } from '../parse/resolve.ts';
import { extractRoutes } from './routes.ts';
import { extractDataModels } from './models.ts';
import { buildEnvMap, type EnvMap } from './envmap.ts';
import { buildArchitecture } from './components.ts';
import { buildFeatures } from './features.ts';

/**
 * The repository map: the single object every analyzer reads.
 *
 * Analyzers must not re-read files or re-parse anything. They take this map,
 * return findings with evidence drawn from it, and stay independent of each
 * other so they can run in any order.
 */
export interface RepoMap {
  snapshot: Snapshot;
  files: SourceFile[];
  filesByPath: Map<string, SourceFile>;
  modules: Map<string, ParsedModule>;
  /** path -> paths that import it. */
  importers: Map<string, string[]>;
  tech: TechDetection[];
  routes: ApiEndpoint[];
  models: DataModel[];
  env: EnvMap;
  components: ArchComponent[];
  relationships: ArchRelationship[];
  features: Feature[];

  // ---- helpers analyzers use to produce verified evidence ----
  /** True when a technology was detected by name (case-insensitive). */
  hasTech(name: string): boolean;
  /** Evidence for a literal in a file, verified against the snapshot. */
  evidenceAt(path: string, needle: string, note?: string): Evidence;
  /** Evidence for a specific line of a file. */
  evidenceLine(path: string, line: number, note?: string): Evidence;
  /** Files whose role matches. */
  byRole(role: SourceFile['role']): SourceFile[];
}

export function buildRepoMap(input: {
  snapshot: Snapshot;
  modules: Map<string, ParsedModule>;
  tech: TechDetection[];
}): RepoMap {
  const { snapshot, modules, tech } = input;
  const files = snapshot.files;
  const filesByPath = new Map(files.map((f) => [f.path, f]));

  const routes = extractRoutes(modules);
  const models = extractDataModels(files, modules);
  const env = buildEnvMap(files, modules);
  const { components, relationships } = buildArchitecture({ files, modules, routes, models, tech });
  const features = buildFeatures({ files, modules, routes, models, relationships });
  const importers = buildImporterIndex(modules);

  const techNames = new Set(tech.map((t) => t.name.toLowerCase()));

  return {
    snapshot, files, filesByPath, modules, importers, tech,
    routes, models, env, components, relationships, features,

    hasTech(name) { return techNames.has(name.toLowerCase()); },

    evidenceAt(path, needle, note) {
      const f = filesByPath.get(path);
      if (!f?.text) return { file: path, note, verified: false };
      const idx = f.text.indexOf(needle);
      if (idx === -1) return { file: path, note, verified: false };
      const before = f.text.slice(0, idx);
      const line = before.split('\n').length;
      const lineStart = before.lastIndexOf('\n') + 1;
      const nl = f.text.indexOf('\n', idx);
      return {
        file: path, startLine: line,
        excerpt: f.text.slice(lineStart, nl === -1 ? undefined : nl).trim().slice(0, 300),
        note, verified: true,
      };
    },

    evidenceLine(path, line, note) {
      const f = filesByPath.get(path);
      if (!f?.text) return { file: path, startLine: line, note, verified: false };
      const lines = f.text.split('\n');
      const excerpt = lines[line - 1];
      if (excerpt === undefined) return { file: path, startLine: line, note, verified: false };
      return { file: path, startLine: line, excerpt: excerpt.trim().slice(0, 300), note, verified: true };
    },

    byRole(role) { return files.filter((f) => f.role === role); },
  };
}
