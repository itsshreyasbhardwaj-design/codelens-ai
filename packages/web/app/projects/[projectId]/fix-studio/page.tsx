import type { Metadata } from 'next';
import Link from 'next/link';
import { revalidatePath } from 'next/cache';
import { projectTabs, Shell, TopBar } from '../../../components/nav.tsx';
import { Caveat, EmptyState, Mono } from '../../../components/ui.tsx';
import { formatRelative, PRIORITY_ORDER, SEVERITY_ORDER } from '../../../lib/format.ts';
import {
  db,
  getProject,
  latestScan,
  listScans,
  markPackApplied,
  scanFindings,
  scanFixPacks,
  type FindingRow,
  type FixPackRow,
} from '../../../lib/store.ts';
import { Studio, type StudioPack, type StudioPrerequisite } from './studio.tsx';

/**
 * Fix Studio, server half.
 *
 * Reads the Fix Packs and findings for one scan, derives the few aggregates the
 * roadmap needs, and hands plain data to the client component. Store access
 * stays here: it is server-only, and a prompt must arrive at the browser as the
 * text the engine generated rather than as something assembled on the way.
 */

export const dynamic = 'force-dynamic';

const AGENT_FORMATS = ['claude_code', 'codex', 'generic'] as const;

interface PageParams {
  params: Promise<{ projectId: string }>;
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}

function first(value: string | string[] | undefined): string | undefined {
  return Array.isArray(value) ? value[0] : value;
}

export async function generateMetadata({ params }: PageParams): Promise<Metadata> {
  const { projectId } = await params;
  const project = getProject(projectId);
  return {
    title: project ? `Fix Studio — ${project.name} — CodeLens AI` : 'Fix Studio — CodeLens AI',
  };
}

// ------------------------------------------------------------------ action --

/**
 * Persist the "marked applied" note.
 *
 * The pack is re-checked against the project before anything is written, so a
 * pack id from another project cannot be flipped through this action. The note
 * is bookkeeping only — nothing in CodeLens edits the repository.
 */
async function setPackApplied(
  projectId: string,
  packId: string,
  applied: boolean,
): Promise<{ ok: boolean; message?: string }> {
  'use server';

  if (!getProject(projectId)) {
    return { ok: false, message: 'That project no longer exists.' };
  }
  // store.ts exposes no "which project owns this pack" query, so the ownership
  // check is derived here from the exported handle rather than trusting the id.
  const owner = db().get<{ project_id: string }>(
    'SELECT s.project_id FROM fix_packs fp JOIN scan_jobs s ON s.id = fp.scan_id WHERE fp.id = ?',
    packId,
  );
  if (!owner || owner.project_id !== projectId) {
    return { ok: false, message: 'That Fix Pack is not part of this project.' };
  }

  try {
    markPackApplied(packId, applied);
  } catch {
    return { ok: false, message: 'The database rejected the change. Nothing was saved.' };
  }
  revalidatePath(`/projects/${projectId}/fix-studio`);
  return { ok: true };
}

// ------------------------------------------------------------- derivations --

function uniqueSorted(values: string[]): string[] {
  return [...new Set(values.filter((v) => v.length > 0))].sort((a, b) => a.localeCompare(b));
}

function severityMix(findings: FindingRow[]): Array<{ severity: string; count: number }> {
  const counts = new Map<string, number>();
  for (const f of findings) counts.set(f.severity, (counts.get(f.severity) ?? 0) + 1);
  const known = SEVERITY_ORDER.filter((s) => counts.has(s)).map((s) => ({ severity: s, count: counts.get(s) as number }));
  const other = [...counts.keys()]
    .filter((s) => !(SEVERITY_ORDER as readonly string[]).includes(s))
    .map((s) => ({ severity: s, count: counts.get(s) as number }));
  return [...known, ...other];
}

function topPriority(findings: FindingRow[]): string | undefined {
  for (const p of PRIORITY_ORDER) {
    if (findings.some((f) => f.priority === p)) return p;
  }
  return findings.find((f) => f.priority)?.priority;
}

/** Verification steps from every finding in the pack, in order, deduplicated. */
function verificationUnion(findings: FindingRow[]): string[] {
  const seen = new Set<string>();
  const steps: string[] = [];
  for (const f of findings) {
    for (const step of f.verificationSteps) {
      const key = step.trim();
      if (key.length === 0 || seen.has(key)) continue;
      seen.add(key);
      steps.push(key);
    }
  }
  return steps;
}

function toStudioPack(pack: FixPackRow, byDisplayId: Map<string, FindingRow>, packs: FixPackRow[]): StudioPack {
  const findings = pack.findingIds
    .map((id) => byDisplayId.get(id))
    .filter((f): f is FindingRow => f !== undefined);

  const prerequisites: StudioPrerequisite[] = pack.dependsOn.map((key) => {
    const dep = packs.find((p) => p.key === key);
    return {
      key,
      title: dep?.title,
      ordinal: dep?.ordinal,
      appliedAt: dep?.appliedAt,
      outOfOrder: dep !== undefined && dep.ordinal > pack.ordinal,
    };
  });

  return {
    id: pack.id,
    key: pack.key,
    ordinal: pack.ordinal,
    title: pack.title,
    family: pack.family,
    objective: pack.objective,
    effort: pack.effort,
    appliedAt: pack.appliedAt,
    baselineCommit: pack.baselineCommit,
    prerequisites,
    formats: AGENT_FORMATS.filter((f) => typeof pack.prompts[f] === 'string' && pack.prompts[f].length > 0),
    findings: findings.map((f) => ({
      displayId: f.displayId,
      title: f.title,
      severity: f.severity,
      confidence: f.confidence,
      status: f.status,
      priority: f.priority,
      effort: f.effort,
      category: f.category,
      files: f.files,
      affectedFeatures: f.affectedFeatures,
      verificationSteps: f.verificationSteps,
    })),
    affectedFiles: uniqueSorted(findings.flatMap((f) => f.files)),
    affectedFeatures: uniqueSorted(findings.flatMap((f) => f.affectedFeatures)),
    severityMix: severityMix(findings),
    topPriority: topPriority(findings),
    verificationSteps: verificationUnion(findings),
    validation: {
      presentable: pack.validation.presentable,
      checksRun: pack.validation.checksRun,
      issues: pack.validation.issues,
    },
  };
}

// --------------------------------------------------------------------- page --

export default async function FixStudioPage({ params, searchParams }: PageParams) {
  const { projectId } = await params;
  const query = await searchParams;
  const project = getProject(projectId);
  const tabs = projectTabs(projectId);
  const current = `/projects/${encodeURIComponent(projectId)}/fix-studio`;

  if (!project) {
    return (
      <>
        <TopBar />
        <Shell>
          <h1 style={{ fontSize: '1.4rem', fontWeight: 680, margin: 0 }}>Fix Studio</h1>
          <EmptyState title={`No project '${projectId}'`}>
            <p style={{ margin: 0 }}>
              Nothing has been scanned under that id. Open the dashboard to see the projects that exist.
            </p>
            <p style={{ margin: '0.5rem 0 0' }}>
              <Link href="/dashboard">Go to the dashboard</Link>
            </p>
          </EmptyState>
        </Shell>
      </>
    );
  }

  const scans = listScans(projectId);
  const requestedScanId = first(query.scan);
  const scan = requestedScanId ? scans.find((s) => s.id === requestedScanId) : latestScan(projectId);

  const header = (
    <header style={{ display: 'grid', gap: '0.4rem' }}>
      <h1 style={{ fontSize: '1.4rem', fontWeight: 680, margin: 0, letterSpacing: '-0.015em' }}>Fix Studio</h1>
      <p style={{ margin: 0, color: 'var(--ink-2)', fontSize: '0.92rem', lineHeight: 1.6, maxWidth: '54rem' }}>
        The findings from this scan, grouped into packs that can each be handed to a coding agent as one piece
        of work. The roadmap is in dependency order.
      </p>
    </header>
  );

  if (!scan) {
    return (
      <>
        <TopBar tabs={tabs} current={current} context={project.name} />
        <Shell>
          {header}
          <EmptyState
            title={
              requestedScanId
                ? `Scan '${requestedScanId}' is not part of this project`
                : `No scan has completed for ${project.name}`
            }
          >
            <p style={{ margin: 0 }}>
              Fix Packs are produced by a scan. {scans.length > 0
                ? 'Choose a scan from the project overview.'
                : 'Run a scan for this project and the roadmap will appear here.'}
            </p>
            <p style={{ margin: '0.5rem 0 0' }}>
              <Link href={`/projects/${encodeURIComponent(projectId)}`}>Project overview</Link>
            </p>
          </EmptyState>
        </Shell>
      </>
    );
  }

  const rawPacks = scanFixPacks(scan.id);
  const byDisplayId = new Map(scanFindings(scan.id).map((f) => [f.displayId, f]));
  const packs = rawPacks.map((p) => toStudioPack(p, byDisplayId, rawPacks));

  const provenance = (
    <p style={{ margin: 0, color: 'var(--ink-3)', fontSize: '0.82rem', lineHeight: 1.6 }}>
      Scan <Mono>{scan.id}</Mono> · {formatRelative(scan.finishedAt ?? scan.queuedAt)} ·{' '}
      {scan.findings} findings · {scan.status}
      {scan.commitSha ? <> · commit <Mono>{scan.commitSha.slice(0, 12)}</Mono></> : null}
      {requestedScanId && scans[0] && scans[0].id !== scan.id ? ' · not the latest scan' : null}
    </p>
  );

  if (packs.length === 0) {
    return (
      <>
        <TopBar tabs={tabs} current={current} context={project.name} />
        <Shell>
          {header}
          {provenance}
          <EmptyState title="No Fix Packs in this scan">
            <p style={{ margin: 0 }}>
              {scan.findings === 0
                ? 'The scan recorded no findings, so there is nothing to group into a pack. That means these checks found nothing, not that the code is free of defects.'
                : 'The scan recorded findings but produced no presentable pack. A pack that fails a pre-flight check is withheld rather than shown.'}
            </p>
            <p style={{ margin: '0.5rem 0 0' }}>
              <Link href={`/projects/${encodeURIComponent(projectId)}/findings`}>Open the findings explorer</Link>
            </p>
          </EmptyState>
        </Shell>
      </>
    );
  }

  // Initial selection comes from the URL so a pack can be linked to directly;
  // the client takes over from there without a round trip.
  const requestedPack = first(query.pack);
  const initialPack = packs.find((p) => p.key === requestedPack) ?? packs[0];
  const requestedFormat = first(query.format);
  const initialFormat =
    requestedFormat && initialPack.formats.includes(requestedFormat)
      ? requestedFormat
      : (initialPack.formats[0] ?? 'claude_code');

  // Only the first pack's prompts travel with the page. The rest are fetched
  // from the download route when they are opened, which keeps a scan with many
  // long prompts from shipping all of them to the browser at once.
  const initialPrompts: Record<string, string> = {};
  const initialRaw = rawPacks.find((p) => p.key === initialPack.key);
  if (initialRaw) {
    for (const format of initialPack.formats) {
      const text = initialRaw.prompts[format];
      if (text) initialPrompts[`${initialPack.key}::${format}`] = text;
    }
  }

  return (
    <>
      <TopBar tabs={tabs} current={current} context={project.name} />
      <Shell>
        {header}
        {provenance}

        <Caveat>
          <strong>Applying a pack happens outside CodeLens.</strong> Give the prompt to your own coding agent, or
          to an engineer. CodeLens does not edit your repository, open a branch, or observe whether a change was
          made. Apply one pack, then re-scan before starting the next: when several packs are applied between
          scans, the next scan cannot attribute what changed to any one of them. The findings behind these packs
          come from static analysis of a snapshot — where the code contradicts a finding, the code is right.
        </Caveat>

        <Studio
          projectId={projectId}
          scanId={scan.id}
          packs={packs}
          initialPackKey={initialPack.key}
          initialFormat={initialFormat}
          initialPrompts={initialPrompts}
          setApplied={setPackApplied}
        />
      </Shell>
    </>
  );
}
