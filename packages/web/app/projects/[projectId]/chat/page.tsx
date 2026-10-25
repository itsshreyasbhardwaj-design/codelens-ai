import type { Metadata } from 'next';
import { loadAiConfig, ModelClient } from '@codelens/engine/ai/provider.ts';
import { projectTabs, Shell, TopBar } from '../../../components/nav.tsx';
import { Card, Caveat, EmptyState, Mono, SectionHeading, Stat } from '../../../components/ui.tsx';
import { formatRelative, pluralize } from '../../../lib/format.ts';
import {
  getProject, latestScan, listScans, scanComponents, scanFeatures, scanFindings,
  scanRoutes,
} from '../../../lib/store.ts';
import { ChatPanel, type SuggestedQuestion } from './chat-panel.tsx';

/**
 * The question surface.
 *
 * Data access happens here, on the server. The interactive panel receives plain
 * props and talks to the POST handler at /api/projects/<id>/chat, which is where
 * the deterministic query engine lives.
 */

export const dynamic = 'force-dynamic';

export const metadata: Metadata = {
  title: 'Ask — CodeLens AI',
  description: 'Question a scanned codebase and get answers composed from the scan\'s own stored evidence.',
};

/**
 * The questions the POST handler can answer. Kept in step with the INTENTS
 * array in app/api/projects/[projectId]/chat/route.ts — that file cannot export
 * the list, because Next rejects unrecognised exports from a route module.
 */
const SUGGESTED: SuggestedQuestion[] = [
  { id: 'auth', question: 'How does authentication work in this project?' },
  { id: 'architecture', question: 'Explain the backend architecture.' },
  { id: 'untested-endpoints', question: 'Which API endpoints lack tests?' },
  { id: 'reliability-risks', question: 'What are the most significant reliability risks?' },
  { id: 'coupling', question: 'Which modules are unnecessarily coupled?' },
  { id: 'fix-first', question: 'What should I fix first?' },
  { id: 'scan-diff', question: 'What changed between the last two scans?' },
  { id: 'incomplete-features', question: 'Which features are incomplete?' },
];

export default async function ChatPage({ params }: { params: Promise<{ projectId: string }> }) {
  const { projectId } = await params;
  const project = getProject(projectId);
  const base = `/projects/${encodeURIComponent(projectId)}`;

  if (!project) {
    return (
      <>
        <TopBar context={projectId} />
        <Shell>
          <h1 style={{ fontSize: '1.4rem', margin: 0 }}>Project not found</h1>
          <EmptyState title={`No project '${projectId}' exists in this organisation.`}>
            <p style={{ margin: 0 }}>
              Either it was never scanned, or it belongs to another organisation. Nothing is
              disclosed about which, by design.
            </p>
          </EmptyState>
        </Shell>
      </>
    );
  }

  const scan = latestScan(projectId);
  const tabs = projectTabs(projectId);

  if (!scan) {
    return (
      <>
        <TopBar tabs={tabs} current={`${base}/chat`} context={project.name} />
        <Shell>
          <h1 style={{ fontSize: '1.4rem', margin: 0 }}>Ask about {project.name}</h1>
          <EmptyState title="This project has no scan yet.">
            <p style={{ margin: 0 }}>
              Answers here are composed from a scan&rsquo;s stored evidence, so there is nothing to
              answer from until one has run.
            </p>
          </EmptyState>
        </Shell>
      </>
    );
  }

  // Read once, on the server: the client panel is told only whether a model is
  // available and why not, never the configuration itself.
  const modelUnavailableReason = new ModelClient(loadAiConfig()).unavailableReason();

  const findings = scanFindings(scan.id);
  const routes = scanRoutes(scan.id);
  const features = scanFeatures(scan.id);
  const components = scanComponents(scan.id);
  const evidenceCount = findings.reduce((n, f) => n + f.evidence.length, 0);
  const scanCount = listScans(projectId).length;
  const scanLabel = `scan ${scan.id.slice(0, 12)}… (${formatRelative(scan.queuedAt)})`;

  return (
    <>
      <TopBar tabs={tabs} current={`${base}/chat`} context={project.name} />
      <Shell>
        <header>
          <h1 style={{ fontSize: '1.4rem', margin: 0, letterSpacing: '-0.02em' }}>
            Ask about {project.name}
          </h1>
          <p style={{ margin: '0.35rem 0 0', color: 'var(--ink-3)', fontSize: '0.9rem', lineHeight: 1.55 }}>
            A query engine over the stored scan, not a chatbot. Every answer is assembled from the
            rows this scan wrote and cites the file and line it came from.
          </p>
        </header>

        <Card>
          <SectionHeading hint={`Answers are drawn from ${scanLabel}.`}>
            What there is to answer from
          </SectionHeading>
          <div
            style={{
              display: 'grid', gap: '1rem',
              gridTemplateColumns: 'repeat(auto-fit, minmax(8.5rem, 1fr))',
            }}
          >
            <Stat label="Findings" value={findings.length} hint={`${evidenceCount} evidence record(s)`} />
            <Stat label="Routes" value={routes.length} hint="with resolved auth requirement" />
            <Stat label="Features" value={features.length} hint="with status and tests" />
            <Stat label="Components" value={components.length} hint="with relationships" />
            <Stat
              label="Scans"
              value={scanCount}
              hint={scanCount < 2 ? 'two are needed to compare' : 'comparison available'}
            />
          </div>
          <p style={{ margin: '0.9rem 0 0', fontSize: '0.86rem', color: 'var(--ink-3)' }}>
            Scan status <Mono>{scan.status}</Mono>, AI provider recorded as <Mono>{scan.aiProvider}</Mono>,{' '}
            {pluralize(scan.coverage?.analyzersRun.length ?? 0, 'analyzer')} ran.
          </p>
        </Card>

        <ChatPanel
          projectId={projectId}
          scanLabel={scanLabel}
          suggested={SUGGESTED}
          modelUnavailableReason={modelUnavailableReason}
        />

        <Caveat>
          <span style={{ fontWeight: 650 }}>What this surface cannot do. </span>
          It answers from what the scan stored. It cannot read the repository again, cannot run
          anything, and cannot answer a question the scan holds no evidence for — in that case it
          says so and lists what it can answer instead. A question it answers from a partial scan
          is still a partial answer: each reply carries the coverage notes for the scan it used.
        </Caveat>
      </Shell>
    </>
  );
}
