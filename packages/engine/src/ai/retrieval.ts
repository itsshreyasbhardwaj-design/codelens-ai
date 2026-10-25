import type { RepoMap } from '../graph/repomap.ts';
import { estimateTokens } from './provider.ts';

/**
 * Repository-aware context selection.
 *
 * The brief forbids sending a whole repository to a model, and that is also the
 * only way to get useful answers: a model given everything reasons about nothing
 * in particular. So context is selected per investigation target, following the
 * dependency graph outward from the target, and packed to a token budget.
 *
 * Targets are chosen deterministically from the repository map — the places
 * where static analysis knows it cannot finish the job.
 */

export interface InvestigationTarget {
  id: string;
  /** What to investigate, in one sentence. */
  question: string;
  /** Files to include, most important first. */
  files: string[];
  /** Why static analysis could not settle this. */
  rationale: string;
}

export interface ContextBundle {
  target: InvestigationTarget;
  /** Packed excerpts, each labelled with its path and line offsets. */
  excerpts: Array<{ path: string; startLine: number; endLine: number; text: string }>;
  tokensEstimated: number;
  /** Files that were relevant but did not fit the budget. */
  omitted: string[];
}

/**
 * Choose what to investigate.
 *
 * Deliberately conservative: each target names a specific uncertainty that the
 * deterministic layers surfaced but could not resolve.
 */
export function selectTargets(map: RepoMap, limit = 8): InvestigationTarget[] {
  const targets: InvestigationTarget[] = [];

  // 1. Routes where we could not determine whether auth is enforced.
  for (const r of map.routes.filter((x) => x.authRequired === 'unknown')) {
    targets.push({
      id: `auth-unknown:${r.method}:${r.path}`,
      question:
        `Does ${r.method} ${r.path} enforce authentication and authorisation? Static analysis found an auth-related ` +
        `call but no clear rejection path for an unauthenticated or unauthorised caller. Determine whether the ` +
        `handler actually refuses such a caller, and whether it restricts access to resources the caller owns.`,
      files: [r.file, ...relatedFiles(map, r.file, 2)],
      rationale: 'an authentication helper is called but no rejection path was detected',
    });
  }

  // 2. Handlers that read input but have no detected validation.
  for (const r of map.routes.filter((x) => x.validation === 'absent' && ['POST', 'PUT', 'PATCH'].includes(x.method))) {
    targets.push({
      id: `validation:${r.method}:${r.path}`,
      question:
        `Does ${r.method} ${r.path} validate its request body before using it? Identify specifically which fields are ` +
        `used without being checked, and what a malformed or hostile value would do.`,
      files: [r.file, ...relatedFiles(map, r.file, 2)],
      rationale: 'request input is read with no validation library or manual check detected',
    });
  }

  // 3. Features whose status could not be determined.
  for (const f of map.features.filter((x) => x.status === 'unknown' || x.status === 'partially_implemented')) {
    const files = [...f.backendFiles, ...f.frontendFiles].slice(0, 4);
    if (files.length === 0) continue;
    targets.push({
      id: `feature:${f.id}`,
      question:
        `Is the "${f.name}" feature actually complete? Static analysis classified it as ${f.status}. ` +
        `Determine what works, what is missing, and whether any part is a placeholder that would fail at runtime.`,
      files,
      rationale: `feature status could not be established from structure alone (${f.status})`,
    });
  }

  // 4. Error handling absent on routes that write data.
  for (const r of map.routes.filter((x) => x.errorHandling === 'absent' && ['POST', 'PUT', 'PATCH', 'DELETE'].includes(x.method))) {
    targets.push({
      id: `errors:${r.method}:${r.path}`,
      question:
        `What happens when ${r.method} ${r.path} fails partway through? Identify the operations that could fail and ` +
        `whether a failure leaves data in an inconsistent state.`,
      files: [r.file, ...relatedFiles(map, r.file, 2)],
      rationale: 'no error handling detected in a handler that writes data',
    });
  }

  // Prefer targets on the most-depended-upon files, which is where an error costs most.
  return targets.slice(0, limit);
}

/** Files one or two import hops from a starting file. */
function relatedFiles(map: RepoMap, path: string, depth: number): string[] {
  const out = new Set<string>();
  let frontier = [path];
  for (let d = 0; d < depth; d++) {
    const next: string[] = [];
    for (const p of frontier) {
      const mod = map.modules.get(p);
      if (!mod) continue;
      for (const imp of mod.imports) {
        if (!imp.resolvedPath || out.has(imp.resolvedPath) || imp.resolvedPath === path) continue;
        out.add(imp.resolvedPath);
        next.push(imp.resolvedPath);
      }
    }
    frontier = next;
  }
  return [...out];
}

/**
 * Pack a target's files into excerpts under a token budget.
 *
 * Whole small files are preferred over fragments, because a fragment invites the
 * model to guess at what surrounds it. Large files are reduced to the symbols
 * that matter rather than truncated arbitrarily.
 */
export function buildContext(
  map: RepoMap,
  target: InvestigationTarget,
  tokenBudget: number,
): ContextBundle {
  const excerpts: ContextBundle['excerpts'] = [];
  const omitted: string[] = [];
  let used = 0;

  for (const path of target.files) {
    const file = map.filesByPath.get(path);
    if (!file?.text) { omitted.push(path); continue; }

    const whole = estimateTokens(file.text);
    if (used + whole <= tokenBudget) {
      excerpts.push({ path, startLine: 1, endLine: file.lines, text: file.text });
      used += whole;
      continue;
    }

    // Too large: include its most relevant symbols instead.
    const mod = map.modules.get(path);
    if (!mod?.parsed) { omitted.push(path); continue; }

    const ranked = [...mod.symbols]
      .filter((s) => s.kind === 'function' || s.kind === 'method' || s.kind === 'arrow' || s.kind === 'class')
      .sort((a, b) => (b.endLine - b.startLine) - (a.endLine - a.startLine));

    let addedAny = false;
    for (const sym of ranked) {
      const cost = estimateTokens(sym.text);
      if (used + cost > tokenBudget) continue;
      excerpts.push({ path, startLine: sym.startLine, endLine: sym.endLine, text: sym.text });
      used += cost;
      addedAny = true;
    }
    if (!addedAny) omitted.push(path);
  }

  return { target, excerpts, tokensEstimated: used, omitted };
}

/** Render a bundle for the user message, with line numbers so citations are checkable. */
export function renderContext(bundle: ContextBundle): string {
  const parts: string[] = [];
  for (const e of bundle.excerpts) {
    const numbered = e.text
      .split('\n')
      .map((line, i) => `${String(e.startLine + i).padStart(5)} | ${line}`)
      .join('\n');
    parts.push(`--- ${e.path} (lines ${e.startLine}-${e.endLine}) ---\n${numbered}`);
  }
  if (bundle.omitted.length > 0) {
    parts.push(
      `--- NOT INCLUDED (did not fit the context budget) ---\n${bundle.omitted.join('\n')}\n` +
      `Do not make claims about these files.`,
    );
  }
  return parts.join('\n\n');
}
