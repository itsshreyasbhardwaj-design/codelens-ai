import Link from 'next/link';
import { CATEGORIES } from '@codelens/core';
import { ALL_ANALYZERS } from '@codelens/engine/analyzers/all.ts';
import { Shell, TopBar } from './components/nav.tsx';
import {
  Card, Caveat, ScoreBar, SectionHeading, SeverityPill, Stat, Tag,
} from './components/ui.tsx';
import { CATEGORY_LABEL, formatRelative, pluralize, SEVERITY_ORDER } from './lib/format.ts';
import {
  getProject, latestScan, scanFindings, scanFixPacks, scanStages, LOCAL_ORG } from './lib/store.ts';

/**
 * The landing page.
 *
 * Everything claimed here is checked against the code that implements it. The
 * diagnostic module list is derived from the analyzer registry rather than
 * written out, so it cannot drift from what actually ships, and a capability
 * that is not implemented in this release is named as missing rather than
 * quietly omitted.
 *
 * The sample report reads the bundled demo scan from the database instead of
 * showing invented numbers, and is labelled as the synthetic demonstration it
 * is on every element of the panel.
 */

export const dynamic = 'force-dynamic';

/** The bundled deliberately-defective demo project, if it has been scanned. */
const DEMO_PROJECT_ID = 'vulnerable-shop';
const DEMO_FIXTURE_PATH = './fixtures/vulnerable-shop';

function h1Style() {
  return {
    fontSize: 'clamp(1.6rem, 1.1rem + 2.2vw, 2.5rem)',
    lineHeight: 1.15,
    letterSpacing: '-0.03em',
    fontWeight: 700,
    margin: 0,
    maxWidth: '36rem',
  } as const;
}

function ctaStyle(primary: boolean) {
  return {
    display: 'inline-block',
    padding: '0.6rem 1.1rem',
    borderRadius: 8,
    fontSize: '0.94rem',
    fontWeight: 650,
    textDecoration: 'none',
    border: primary ? '1px solid var(--accent)' : '1px solid var(--border-strong)',
    background: primary ? 'var(--accent)' : 'var(--surface)',
    color: primary ? 'var(--accent-ink)' : 'var(--ink)',
  } as const;
}

const gridStyle = (min: string) =>
  ({
    display: 'grid',
    gap: '0.85rem',
    gridTemplateColumns: `repeat(auto-fit, minmax(min(100%, ${min}), 1fr))`,
  }) as const;

// ----------------------------------------------------------------- pipeline --

/** The eight things a scan does, and the recorded stages each one covers. */
const PIPELINE: Array<{ step: string; stages: string; body: string }> = [
  {
    step: 'Connect',
    stages: 'ingestion_validation, source_normalization',
    body:
      'A local directory, a GitHub repository, or a ZIP of the source tree. Size, entry count, path depth and compression ratio are checked before anything is read, and files that are unsuitable for analysis are excluded with the reason recorded.',
  },
  {
    step: 'Index',
    stages: 'technology_detection, code_indexing',
    body:
      'Languages, frameworks and dependencies are identified from manifests and file evidence, then supported languages are parsed into structural indexes. Which files were parsed, and which had no grammar available, is recorded as coverage.',
  },
  {
    step: 'Reconstruct architecture',
    stages: 'architecture_reconstruction',
    body:
      'Components, the relationships between them, API routes, data models and a feature inventory are built from the index — the blueprint of a codebase nobody documented.',
  },
  {
    step: 'Diagnose',
    stages: 'deterministic_diagnostics, dynamic_verification, ai_semantic_investigation',
    body:
      'Non-executing analyzers run over the repository map. Dynamic verification and the AI semantic layer are separate, optional stages: both are disabled by default, and when they do not run the scan says so rather than leaving a gap unexplained.',
  },
  {
    step: 'Validate evidence',
    stages: 'finding_consolidation',
    body:
      'Duplicates are merged and every finding is held to its evidence. An excerpt is re-read against the snapshot it was taken from; an AI-sourced finding whose cited evidence cannot be verified is discarded outright, and a finding with no verified evidence from any source is capped at moderate confidence.',
  },
  {
    step: 'Prioritise',
    stages: 'risk_prioritization',
    body:
      'Findings are ranked P0 to P3 from severity, confidence, blast radius and effort, each with the rationale for its rank. Severity and confidence stay separate throughout: a critical finding that is only suspected is presented as exactly that.',
  },
  {
    step: 'Generate Fix Packs',
    stages: 'fix_pack_generation',
    body:
      'Related findings are grouped into dependency-ordered work packages, each rendered as a prompt for a coding agent and then validated against a fixed checklist before it is offered.',
  },
  {
    step: 'Re-scan and compare',
    stages: 'report_generation',
    body:
      'Scans are stored, and each finding records the scan in which it was first seen, so a later scan can be compared with an earlier one. A finding that merely stopped appearing is reported as an unverified absence, never counted as fixed.',
  },
];

// ------------------------------------------------------------------ modules --

/**
 * The diagnostic modules: every finding category the report model defines,
 * except `architecture`, which is reconstructed by the pipeline rather than
 * produced by a rule set. The description comes from the analyzer itself, so
 * this list reflects what is installed.
 */
function modules() {
  return CATEGORIES.filter((c) => c !== 'architecture').map((category) => {
    const analyzer = ALL_ANALYZERS.find((a) => a.category === category);
    return {
      category,
      label: CATEGORY_LABEL[category] ?? category,
      description: analyzer?.description,
    };
  });
}

// ------------------------------------------------------------ demo preview --

function DemoPreview() {
  // The landing page is public, so there is no session here. The demonstration
  // project is the one the CLI seeds, which lives in the local organisation.
  const project = getProject(LOCAL_ORG, DEMO_PROJECT_ID);
  const scan = project ? latestScan(LOCAL_ORG, project.id) : undefined;

  const synthetic = (
    <Tag tone="warn">Synthetic demonstration data</Tag>
  );

  if (!project || !scan) {
    return (
      <Card>
        <SectionHeading hint="The demonstration scan is not present in this installation, so there is nothing to preview. No sample figures are shown in its place.">
          Sample report {synthetic}
        </SectionHeading>
        <p style={{ margin: 0, fontSize: '0.88rem', color: 'var(--ink-2)' }}>
          Scan the bundled defective demo project to populate it: run{' '}
          <code style={{ fontFamily: 'var(--font-mono)' }}>pnpm scan {DEMO_FIXTURE_PATH}</code> from the repository
          root. This panel is public, so it reads the CLI&rsquo;s own organisation — a scan started from the{' '}
          <Link href="/dashboard#new-scan">dashboard</Link> belongs to your account instead and will not appear
          here.
        </p>
      </Card>
    );
  }

  const counts: Record<string, number> = {};
  for (const f of scanFindings(scan.id)) counts[f.severity] = (counts[f.severity] ?? 0) + 1;
  const packs = scanFixPacks(scan.id);
  const presentable = packs.filter((p) => p.validation.presentable).length;
  const notRun = scanStages(scan.id).filter((s) => s.status === 'skipped' || s.status === 'failed');

  return (
    <Card>
      <SectionHeading
        hint={`Real output from a real scan of ${project.name}, a codebase written on purpose to be defective. It is bundled with the project as a demonstration fixture — it is not a customer, and these figures describe nothing but that fixture.`}
      >
        Sample report {synthetic}
      </SectionHeading>

      <div style={gridStyle('8.5rem')}>
        <div>
          <div
            style={{
              fontSize: '0.76rem', color: 'var(--ink-3)', textTransform: 'uppercase',
              letterSpacing: '0.05em', fontWeight: 600,
            }}
          >
            Overall score
          </div>
          <div style={{ marginTop: '0.3rem', maxWidth: '12rem' }}>
            <ScoreBar value={scan.score} />
          </div>
        </div>
        <Stat label="Findings" value={scan.findings} />
        <Stat label="Critical" value={scan.critical} tone={scan.critical > 0 ? 'critical' : 'good'} />
        <Stat
          label="Fix Packs"
          value={presentable}
          hint={packs.length === presentable ? undefined : `${packs.length} generated, ${presentable} passed validation`}
        />
      </div>

      {scan.findings > 0 ? (
        <ul
          style={{
            listStyle: 'none', margin: '0.95rem 0 0', padding: 0,
            display: 'flex', flexWrap: 'wrap', gap: '0.45rem',
          }}
        >
          {SEVERITY_ORDER.filter((s) => (counts[s] ?? 0) > 0).map((s) => (
            <li key={s} style={{ display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
              <SeverityPill severity={s} />
              <span style={{ fontVariantNumeric: 'tabular-nums', fontWeight: 650, fontSize: '0.88rem' }}>
                {counts[s]}
              </span>
            </li>
          ))}
        </ul>
      ) : null}

      {notRun.length > 0 ? (
        <div style={{ marginTop: '1rem' }}>
          <h3 style={{ margin: '0 0 0.4rem', fontSize: '0.84rem', fontWeight: 650 }}>
            What this scan did not do
          </h3>
          <ul style={{ margin: 0, paddingLeft: '1.1rem', fontSize: '0.84rem', color: 'var(--ink-2)', lineHeight: 1.55 }}>
            {notRun.map((s) => (
              <li key={s.name} style={{ marginBottom: '0.3rem' }}>
                <strong style={{ fontWeight: 600 }}>{s.name.replace(/_/g, ' ')}</strong> — {s.status}
                {s.message ? `: ${s.message}` : '.'}
              </li>
            ))}
          </ul>
        </div>
      ) : null}

      <p style={{ margin: '1rem 0 0', fontSize: '0.88rem' }}>
        <Link href={`/projects/${encodeURIComponent(project.id)}`}>
          Open the demonstration report
        </Link>{' '}
        <span style={{ color: 'var(--ink-3)' }}>· scanned {formatRelative(scan.queuedAt)}</span>
      </p>
    </Card>
  );
}

// --------------------------------------------------------------------- page --

export default function LandingPage() {
  const mods = modules();
  const implemented = mods.filter((m) => m.description !== undefined);

  return (
    <>
      <TopBar />
      <Shell>
        <section aria-labelledby="proposition" style={{ paddingTop: '1.5rem' }}>
          <h1 id="proposition" style={h1Style()}>
            Understand any codebase.
            <br />
            Diagnose what matters.
            <br />
            <span style={{ color: 'var(--accent)' }}>Fix it with precision.</span>
          </h1>
          <p style={{ margin: '1rem 0 0', maxWidth: '44rem', color: 'var(--ink-2)', fontSize: '1.02rem' }}>
            CodeLens reads a repository, reconstructs the architecture nobody documented, and reports the defects it can
            evidence — each one with the code it was found in, how strongly it is supported, and what it would take to
            fix. The output is a blueprint, a ranked diagnostic report, and a short list of work packages a coding agent
            can execute.
          </p>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.6rem', marginTop: '1.4rem' }}>
            <Link href="/dashboard#new-scan" style={ctaStyle(true)}>
              Connect a repository
            </Link>
            <Link href="/dashboard#new-scan" style={ctaStyle(false)}>
              Scan a local path
            </Link>
          </div>
          <p style={{ margin: '0.9rem 0 0', fontSize: '0.84rem', color: 'var(--ink-3)' }}>
            Runs locally with no account and no configuration. The AI layer is off unless you turn it on.
          </p>
        </section>

        <section aria-labelledby="pipeline-heading">
          <SectionHeading
            id="pipeline-heading"
            hint="Eight steps, recorded as twelve pipeline stages. Every scan stores the status, duration and any warning or skip reason for each stage, so a partial scan can never be read as a complete one."
          >
            How it works
          </SectionHeading>
          <ol style={{ listStyle: 'none', margin: 0, padding: 0, display: 'grid', gap: '0.6rem' }}>
            {PIPELINE.map((p, i) => (
              <li key={p.step}>
                <Card as="div">
                  <div style={{ display: 'flex', gap: '0.8rem', alignItems: 'baseline', flexWrap: 'wrap' }}>
                    <span
                      aria-hidden="true"
                      style={{
                        fontFamily: 'var(--font-mono)', fontSize: '0.8rem', fontWeight: 700,
                        color: 'var(--accent)',
                      }}
                    >
                      {String(i + 1).padStart(2, '0')}
                    </span>
                    <h3 style={{ margin: 0, fontSize: '0.98rem', fontWeight: 650 }}>{p.step}</h3>
                    <code
                      style={{
                        fontFamily: 'var(--font-mono)', fontSize: '0.74rem', color: 'var(--ink-3)',
                        background: 'var(--surface-2)', border: '1px solid var(--border)',
                        borderRadius: 4, padding: '0.05rem 0.35rem', wordBreak: 'break-all',
                      }}
                    >
                      {p.stages}
                    </code>
                  </div>
                  <p style={{ margin: '0.5rem 0 0', fontSize: '0.89rem', color: 'var(--ink-2)', lineHeight: 1.6 }}>
                    {p.body}
                  </p>
                </Card>
              </li>
            ))}
          </ol>
        </section>

        <DemoPreview />

        <section aria-labelledby="modules-heading">
          <SectionHeading
            id="modules-heading"
            hint={
              implemented.length === mods.length
                ? `${mods.length} diagnostic modules define what the audit can report, and all ${mods.length} have a rule set installed. What any one of them finds still depends on the coverage a given scan achieved.`
                : `${mods.length} diagnostic modules define what the audit can report. ${implemented.length} have a rule set installed; the remaining ${mods.length - implemented.length} are categories the report model carries but for which no rule exists yet, and they produce no findings.`
            }
          >
            What the audit covers
          </SectionHeading>
          <ul style={{ listStyle: 'none', margin: 0, padding: 0, ...gridStyle('17rem') }}>
            {mods.map((m) => (
              <li key={m.category}>
                <Card as="div">
                  <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'baseline', flexWrap: 'wrap' }}>
                    <h3 style={{ margin: 0, fontSize: '0.94rem', fontWeight: 650 }}>{m.label}</h3>
                    {m.description ? null : <Tag tone="warn">No rules in this release</Tag>}
                  </div>
                  <p style={{ margin: '0.4rem 0 0', fontSize: '0.86rem', color: 'var(--ink-2)', lineHeight: 1.55 }}>
                    {m.description ??
                      'The report model carries this category, but no rule set is installed for it, so a scan produces no findings here. It is listed to be explicit about the gap rather than to imply coverage.'}
                  </p>
                </Card>
              </li>
            ))}
          </ul>
          <p style={{ margin: '0.8rem 0 0', fontSize: '0.86rem', color: 'var(--ink-3)', maxWidth: '48rem' }}>
            Architecture is not in this list because it is not a rule set: components, relationships, routes, data
            models and the feature inventory are reconstructed by the pipeline, and quality findings are scored against
            them.
          </p>
        </section>

        <section aria-labelledby="fixpacks-heading">
          <SectionHeading
            id="fixpacks-heading"
            hint="A list of problems is not the hard part. Turning it into work that can actually be carried out is."
          >
            Fix Packs are the output that matters
          </SectionHeading>
          <Card>
            <p style={{ margin: 0, fontSize: '0.92rem', color: 'var(--ink-2)', lineHeight: 1.65 }}>
              A Fix Pack is one coherent unit of remediation: a group of related findings, an explicit objective, the
              files involved, the order it must be done in relative to other packs, an effort band, and acceptance
              criteria. It is rendered as a prompt in three formats — Claude Code, Codex, and a generic one — so the
              work can be handed straight to a coding agent, or read by a person who would rather do it themselves.
            </p>
            <p style={{ margin: '0.8rem 0 0', fontSize: '0.92rem', color: 'var(--ink-2)', lineHeight: 1.65 }}>
              Each pack is validated before it is offered, and the checks are the reason this is the differentiator
              rather than a feature: that every referenced file exists, that every finding belongs to the scan, that the
              declared dependencies are real, that the cited evidence was verified against the snapshot, that nothing in
              it contradicts anything else, that it contains no destructive operation, that its scope is reasonable,
              that remaining uncertainty is marked, and that it does not overclaim. A pack that fails a check is
              reported as not presentable, with the specific issue, instead of being shown as ready.
            </p>
            <p style={{ margin: '0.8rem 0 0', fontSize: '0.86rem', color: 'var(--ink-3)' }}>
              Applying a Fix Pack is still your decision and your review. Nothing is changed in your repository by a
              scan.
            </p>
          </Card>
        </section>

        <section aria-labelledby="privacy-heading">
          <SectionHeading
            id="privacy-heading"
            hint="What the implementation guarantees, stated as narrowly as it is actually true."
          >
            Security and privacy
          </SectionHeading>
          <ul style={{ listStyle: 'none', margin: 0, padding: 0, ...gridStyle('18rem') }}>
            {[
              {
                title: 'Local-first',
                body:
                  'The analysis runs on this machine and the results are stored in a local SQLite database. There is no service to sign up to and no telemetry.',
              },
              {
                title: 'The AI layer is disabled by default',
                body:
                  'With no provider configured the scan is fully deterministic and entirely offline. The AI semantic stage is recorded as skipped, with that reason, so you can see that it did not run.',
              },
              {
                title: 'Nothing leaves the machine unless you enable it',
                body:
                  'No repository content is sent anywhere by a default scan. Enabling a local model keeps it on the machine; enabling a hosted provider sends retrieved evidence to that provider, is opt-in, and bills you directly under a hard per-scan token ceiling.',
              },
              {
                title: 'Credentials are encrypted or refused',
                body:
                  'A stored provider token is AES-256-GCM ciphertext; with no encryption key configured, storage is refused outright rather than falling back to plaintext. A token typed into the scan form is used for that one scan and is never written to the database.',
              },
              {
                title: 'Untrusted code is never executed',
                body:
                  'Dynamic verification is off by default, and dependency installation and project build scripts are refused outright — on this host they are arbitrary code execution. Repository import accepts github.com only, so an arbitrary URL is never fetched.',
              },
              {
                title: 'Project deletion is incomplete',
                body:
                  'Projects are soft-deleted and every query excludes a deleted project, but no interface in this release sets that flag. Until one exists, removing a project means deleting the local database file. Said plainly because the alternative is implying a control you do not have.',
              },
            ].map((item) => (
              <li key={item.title}>
                <Card as="div">
                  <h3 style={{ margin: 0, fontSize: '0.92rem', fontWeight: 650 }}>{item.title}</h3>
                  <p style={{ margin: '0.4rem 0 0', fontSize: '0.86rem', color: 'var(--ink-2)', lineHeight: 1.55 }}>
                    {item.body}
                  </p>
                </Card>
              </li>
            ))}
          </ul>
        </section>

        <section aria-labelledby="integrations-heading">
          <SectionHeading id="integrations-heading" hint="Four ways in were specified. Three of them work.">
            Supported integrations
          </SectionHeading>
          <ul style={{ listStyle: 'none', margin: 0, padding: 0, display: 'grid', gap: '0.5rem' }}>
            {[
              {
                name: 'Local directory',
                state: 'Available',
                tone: 'good' as const,
                body: 'Any directory on this machine. The fastest first scan, and nothing is copied or uploaded.',
              },
              {
                name: 'GitHub repository — public',
                state: 'Available',
                tone: 'good' as const,
                body: 'owner/repo, or owner/repo@branch-or-tag-or-sha to pin a ref. Only github.com is accepted.',
              },
              {
                name: 'GitHub repository — private, with permission',
                state: 'Available',
                tone: 'good' as const,
                body: 'Supply a token with read-only scopes. It is used for that scan and not persisted.',
              },
              {
                name: 'ZIP upload',
                state: 'Available',
                tone: 'good' as const,
                body: 'Up to 64 MiB. Traversal entries, excessive compression ratios and ZIP64 are refused with the specific reason.',
              },
              {
                name: 'Deployed-URL website mode',
                state: 'Not implemented in this release',
                tone: 'warn' as const,
                body:
                  'Observing a running deployment — headers, TLS, page metadata, client-side signals — is designed for and reserved in the report model, but no ingestion path for it ships here. Pointing CodeLens at a URL will not work today.',
              },
            ].map((item) => (
              <li key={item.name}>
                <Card as="div">
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem', alignItems: 'baseline' }}>
                    <h3 style={{ margin: 0, fontSize: '0.92rem', fontWeight: 650 }}>{item.name}</h3>
                    <Tag tone={item.tone}>{item.state}</Tag>
                  </div>
                  <p style={{ margin: '0.35rem 0 0', fontSize: '0.86rem', color: 'var(--ink-2)', lineHeight: 1.55 }}>
                    {item.body}
                  </p>
                </Card>
              </li>
            ))}
          </ul>
        </section>

        <Caveat>
          <strong style={{ fontWeight: 650 }}>What this cannot tell you.</strong> CodeLens performs static analysis of a
          snapshot. It can show you a defect it has evidence for; it cannot prove that a defect is absent. A clean
          report means these checks found nothing — not that the code is sound. With dynamic verification disabled
          nothing is runtime-verified, so no throughput, latency or capacity figure is produced; where a measurement is
          missing, the report says so rather than estimating. Depth also varies by language, and every scan publishes
          the coverage it achieved. The limits are written down in{' '}
          <code style={{ fontFamily: 'var(--font-mono)' }}>docs/LIMITATIONS.md</code>; read them before treating a
          report as a verdict.
        </Caveat>

        <section
          aria-labelledby="start-heading"
          style={{
            display: 'flex', flexWrap: 'wrap', gap: '0.75rem', alignItems: 'center',
            justifyContent: 'space-between', padding: '1.2rem 1.25rem',
            borderRadius: 10, background: 'var(--surface-2)', border: '1px solid var(--border)',
          }}
        >
          <div>
            <h2 id="start-heading" style={{ margin: 0, fontSize: '1.02rem', fontWeight: 650 }}>
              Scan something
            </h2>
            <p style={{ margin: '0.25rem 0 0', fontSize: '0.88rem', color: 'var(--ink-2)' }}>
              A directory, a repository, or an archive. Create an account and scan — no AI provider key, and
              nothing leaves the machine.
            </p>
          </div>
          <Link href="/dashboard" style={ctaStyle(true)}>
            Open the dashboard
          </Link>
        </section>

        <footer style={{ fontSize: '0.82rem', color: 'var(--ink-3)', paddingTop: '0.5rem' }}>
          <p style={{ margin: 0 }}>
            This release is self-hosted and runs as a single process. Each account gets its own organisation and
            sees only its own projects; {pluralize(ALL_ANALYZERS.length, 'analyzer')} are installed.
          </p>
        </footer>
      </Shell>
    </>
  );
}
