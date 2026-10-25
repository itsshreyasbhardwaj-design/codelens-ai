import type { ScanOutcome } from '../pipeline/orchestrator.ts';

/**
 * Printable HTML report.
 *
 * PDF generation is deliberately done by the browser's own print-to-PDF rather
 * than by bundling a rendering engine: it needs no extra dependency, produces
 * correct text selection and accessibility structure, and works offline. The
 * stylesheet below is written for paged output — page breaks before sections,
 * no fixed positioning, link targets printed.
 */

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

const PRINT_CSS = `
:root {
  --ink: #16181d;
  --muted: #5c6370;
  --rule: #d8dce3;
  --critical: #a4133c;
  --high: #c05621;
  --medium: #8a6d1f;
  --low: #3b6ea5;
  --surface: #f6f7f9;
}
* { box-sizing: border-box; }
body {
  font: 11pt/1.55 ui-serif, Georgia, 'Times New Roman', serif;
  color: var(--ink);
  margin: 0 auto;
  padding: 2rem 1.5rem 4rem;
  max-width: 50rem;
  background: #fff;
}
h1, h2, h3, h4 { font-family: ui-sans-serif, system-ui, -apple-system, 'Segoe UI', sans-serif; line-height: 1.25; }
h1 { font-size: 1.9rem; margin: 0 0 .25rem; letter-spacing: -0.015em; }
h2 { font-size: 1.3rem; margin: 2.25rem 0 .75rem; padding-bottom: .3rem; border-bottom: 2px solid var(--rule); }
h3 { font-size: 1.05rem; margin: 1.6rem 0 .4rem; }
h4 { font-size: .95rem; margin: 1.2rem 0 .3rem; color: var(--muted); }
p, li { orphans: 3; widows: 3; }
.meta { color: var(--muted); font-size: .85rem; margin-bottom: 1.5rem; }
table { width: 100%; border-collapse: collapse; margin: .75rem 0 1.25rem; font-size: .82rem; }
th, td { text-align: left; padding: .4rem .5rem; border-bottom: 1px solid var(--rule); vertical-align: top; }
th { background: var(--surface); font-family: ui-sans-serif, system-ui, sans-serif; font-weight: 600; }
code, pre { font-family: ui-monospace, 'SF Mono', Menlo, Consolas, monospace; font-size: .8rem; }
pre {
  background: var(--surface); padding: .6rem .7rem; border-left: 3px solid var(--rule);
  overflow-x: auto; white-space: pre-wrap; word-break: break-word; margin: .5rem 0;
}
.sev { font-weight: 600; font-family: ui-sans-serif, system-ui, sans-serif; font-size: .78rem; text-transform: uppercase; letter-spacing: .04em; }
.sev-critical { color: var(--critical); }
.sev-high { color: var(--high); }
.sev-medium { color: var(--medium); }
.sev-low, .sev-info { color: var(--low); }
.callout {
  border: 1px solid var(--rule); border-left: 4px solid var(--medium);
  background: var(--surface); padding: .75rem 1rem; margin: 1.25rem 0; font-size: .9rem;
}
.finding { border-top: 1px solid var(--rule); padding-top: 1rem; margin-top: 1.5rem; break-inside: avoid-page; }
.badges { color: var(--muted); font-size: .8rem; font-family: ui-sans-serif, system-ui, sans-serif; margin: .2rem 0 .6rem; }
dl { margin: .5rem 0; }
dt { font-weight: 600; font-size: .85rem; font-family: ui-sans-serif, system-ui, sans-serif; margin-top: .6rem; }
dd { margin: .15rem 0 0; }
footer { margin-top: 3rem; padding-top: 1rem; border-top: 1px solid var(--rule); color: var(--muted); font-size: .78rem; }
.no-print { margin: 1rem 0 2rem; }
button {
  font: inherit; font-family: ui-sans-serif, system-ui, sans-serif; font-size: .9rem;
  padding: .5rem 1rem; border: 1px solid var(--ink); background: var(--ink); color: #fff;
  border-radius: 6px; cursor: pointer;
}
@media print {
  body { padding: 0; max-width: none; font-size: 10pt; }
  .no-print { display: none; }
  h2 { break-before: page; }
  h2:first-of-type { break-before: avoid; }
  a[href^="http"]::after { content: " (" attr(href) ")"; font-size: .75em; color: #555; }
  pre, table, .finding { break-inside: avoid; }
}
@page { margin: 18mm 16mm; }
`;

export interface HtmlReportOptions {
  projectName: string;
  /** 'executive' is the short document; 'technical' is the full one. */
  kind: 'executive' | 'technical';
}

/**
 * Render a print-ready report. `bodyHtml` is produced from the markdown
 * renderers by the caller (the web app converts markdown to HTML); when it is
 * omitted, a structured report is generated directly from the outcome.
 */
export function renderHtmlReport(outcome: ScanOutcome, opts: HtmlReportOptions): string {
  const title = `${opts.projectName} — ${opts.kind === 'executive' ? 'Executive summary' : 'Technical diagnostic report'}`;
  const body: string[] = [];

  body.push(`<h1>${escapeHtml(title)}</h1>`);
  body.push(
    `<p class="meta">CodeLens AI scan <code>${escapeHtml(outcome.scanId)}</code> · status <strong>${escapeHtml(outcome.status)}</strong>` +
    (outcome.commitSha ? ` · commit <code>${escapeHtml(outcome.commitSha.slice(0, 10))}</code>` : '') +
    (outcome.snapshot ? ` · file-set hash <code>${escapeHtml(outcome.snapshot.contentHash.slice(0, 16))}</code>` : '') +
    `</p>`,
  );

  body.push(
    '<div class="callout"><strong>How to read this report.</strong> It reports static analysis of a code ' +
    'snapshot and cannot prove the absence of defects. Severity is what an issue would cost if real; confidence ' +
    'is how strong the evidence is. Read both. Nothing here is a runtime measurement unless a dynamic verification ' +
    'stage is recorded as completed.</div>',
  );

  // --- score ---
  const card = outcome.scorecard;
  body.push('<h2>Assessment</h2>');
  if (!card) {
    body.push('<p>No score was produced because the scan did not complete.</p>');
  } else if (card.overall === null) {
    body.push(
      `<p><strong>Overall: insufficient evidence.</strong> Only ${(card.assessedWeight * 100).toFixed(0)}% of the ` +
      `assessment weight could be graded. Unassessed: ${escapeHtml(card.unassessedDimensions.join(', ') || 'none')}.</p>`,
    );
  } else {
    body.push(`<p><strong>Overall: ${card.overall}/100 (${card.overallGrade}).</strong> Graded from ${(card.assessedWeight * 100).toFixed(0)}% of the assessment weight.</p>`);
  }
  if (card) {
    body.push('<table><thead><tr><th>Area</th><th>Score</th><th>Grade</th><th>Weight</th><th>Reason if ungraded</th></tr></thead><tbody>');
    for (const d of card.dimensions) {
      body.push(
        `<tr><td>${escapeHtml(d.dimension)}</td><td>${d.score ?? '—'}</td>` +
        `<td>${escapeHtml(d.grade === 'insufficient_evidence' ? 'insufficient evidence' : d.grade)}</td>` +
        `<td>${(d.weight * 100).toFixed(0)}%</td><td>${escapeHtml(d.reason ?? '')}</td></tr>`,
      );
    }
    body.push('</tbody></table>');
  }

  // --- coverage ---
  const c = outcome.coverage;
  body.push('<h2>Coverage</h2>');
  body.push('<table><tbody>');
  body.push(`<tr><th>Files indexed</th><td>${c.filesIndexed} of ${c.filesTotal}</td></tr>`);
  body.push(`<tr><th>Files parsed</th><td>${c.filesParsed}</td></tr>`);
  body.push(`<tr><th>Parse coverage</th><td>${(c.parseRatio * 100).toFixed(0)}%</td></tr>`);
  body.push(`<tr><th>Analyzers run</th><td>${escapeHtml(c.analyzersRun.join(', ') || 'none')}</td></tr>`);
  body.push(`<tr><th>Deep languages</th><td>${escapeHtml(c.languagesDeep.join(', ') || 'none')}</td></tr>`);
  body.push(`<tr><th>Shallow languages</th><td>${escapeHtml(c.languagesShallow.join(', ') || 'none')}</td></tr>`);
  body.push(
    `<tr><th>Layers completed</th><td>static: ${c.layers.static ? 'yes' : 'no'}, cross-file: ${c.layers.graph ? 'yes' : 'no'}, ` +
    `AI: ${c.layers.ai ? 'yes' : 'no'}, dynamic: ${c.layers.dynamic ? 'yes' : 'no'}</td></tr>`,
  );
  body.push('</tbody></table>');
  if (c.analyzersSkipped.length > 0) {
    body.push('<h4>Analyzers that did not run</h4><ul>');
    for (const s of c.analyzersSkipped) body.push(`<li><code>${escapeHtml(s.analyzer)}</code> — ${escapeHtml(s.reason)}</li>`);
    body.push('</ul>');
  }

  // --- findings ---
  body.push('<h2>Findings</h2>');
  if (outcome.prioritized.length === 0) {
    body.push('<p>No findings were reported by the analyzers that ran. Read the coverage section above before treating that as reassurance.</p>');
  } else {
    body.push('<table><thead><tr><th>ID</th><th>Priority</th><th>Severity</th><th>Confidence</th><th>Title</th><th>Location</th></tr></thead><tbody>');
    for (const p of outcome.prioritized) {
      const f = p.finding;
      const ev = f.evidence[0];
      body.push(
        `<tr><td><code>${escapeHtml(f.id)}</code></td><td>${escapeHtml(p.priority)}</td>` +
        `<td class="sev sev-${f.severity}">${escapeHtml(f.severity)}</td><td>${escapeHtml(f.confidence)}</td>` +
        `<td>${escapeHtml(f.title)}</td><td><code>${escapeHtml((ev?.file ?? f.files[0] ?? '') + (ev?.startLine ? `:${ev.startLine}` : ''))}</code></td></tr>`,
      );
    }
    body.push('</tbody></table>');

    if (opts.kind === 'technical') {
      for (const p of outcome.prioritized) {
        const f = p.finding;
        body.push('<div class="finding">');
        body.push(`<h3>${escapeHtml(f.id)} — ${escapeHtml(f.title)}</h3>`);
        body.push(
          `<p class="badges"><span class="sev sev-${f.severity}">${escapeHtml(f.severity)}</span> · ` +
          `${escapeHtml(f.confidence)} confidence · ${escapeHtml(f.status.replace(/_/g, ' '))} · ` +
          `priority ${escapeHtml(p.priority)} · detected by ${escapeHtml(f.detectionSource)} · effort ${escapeHtml(f.effort)}</p>`,
        );
        body.push('<dl>');
        body.push(`<dt>What is wrong</dt><dd>${escapeHtml(f.explanation)}</dd>`);
        body.push(`<dt>User impact</dt><dd>${escapeHtml(f.userImpact)}</dd>`);
        if (f.likelyRootCause) body.push(`<dt>Likely root cause</dt><dd>${escapeHtml(f.likelyRootCause)}</dd>`);
        body.push('<dt>Evidence</dt><dd>');
        for (const e of f.evidence) {
          body.push(`<div><code>${escapeHtml(e.file + (e.startLine ? `:${e.startLine}` : ''))}</code>${e.verified ? '' : ' <em>(unverified)</em>'}</div>`);
          if (e.excerpt) body.push(`<pre>${escapeHtml(e.excerpt)}</pre>`);
          if (e.note) body.push(`<div>${escapeHtml(e.note)}</div>`);
        }
        body.push('</dd>');
        if (f.trace) {
          body.push(`<dt>Traced relationship${f.trace.complete ? '' : ' (incomplete)'}</dt><dd><ol>`);
          for (const s of f.trace.steps) {
            body.push(`<li><code>${escapeHtml(s.file + (s.line ? `:${s.line}` : ''))}</code> — ${escapeHtml(s.detail)}</li>`);
          }
          body.push('</ol></dd>');
        }
        body.push(`<dt>Remediation</dt><dd>${escapeHtml(f.remediation)}</dd>`);
        if (f.verificationSteps.length) {
          body.push('<dt>Verification</dt><dd><ul>');
          for (const v of f.verificationSteps) body.push(`<li>${escapeHtml(v)}</li>`);
          body.push('</ul></dd>');
        }
        if (f.references.length) body.push(`<dt>References</dt><dd>${escapeHtml(f.references.join('; '))}</dd>`);
        body.push('</dl></div>');
      }
    }
  }

  // --- fix packs ---
  if (outcome.fixPacks.length > 0) {
    body.push('<h2>Remediation roadmap</h2>');
    body.push('<table><thead><tr><th>#</th><th>Fix Pack</th><th>Findings</th><th>Priority</th><th>Effort</th><th>Prerequisites</th></tr></thead><tbody>');
    for (const p of outcome.fixPacks) {
      body.push(
        `<tr><td>${p.ordinal}</td><td>${escapeHtml(p.title)}</td><td>${p.findings.length}</td>` +
        `<td>${escapeHtml(p.topPriority)}</td><td>${escapeHtml(p.effort)}</td>` +
        `<td>${escapeHtml(p.dependsOn.join(', ') || 'none')}</td></tr>`,
      );
    }
    body.push('</tbody></table>');
  }

  body.push(
    '<footer>Generated by CodeLens AI. This report describes a code snapshot and is not a certification. ' +
    'It cannot prove the absence of vulnerabilities or defects.</footer>',
  );

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(title)}</title>
<style>${PRINT_CSS}</style>
</head>
<body>
<div class="no-print"><button onclick="window.print()">Save as PDF</button></div>
${body.join('\n')}
</body>
</html>`;
}
