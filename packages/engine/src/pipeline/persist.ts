import type { Coverage, Finding, Scorecard } from '@codelens/core';
import { Db, newId, now } from '../db/index.ts';
import type { ScanOutcome } from './orchestrator.ts';
import type { ScanSide } from '../reports/compare.ts';

/**
 * Scan persistence.
 *
 * Everything a report or a comparison needs is written here, including the
 * things it would be convenient to omit: refused findings, stage warnings, and
 * coverage. A later comparison depends on coverage being stored, because
 * deciding whether a finding was fixed requires knowing what the earlier scan
 * actually looked at.
 */

export interface SaveOptions {
  organizationId: string;
  projectId: string;
  projectName: string;
  requestedBy?: string;
}

export function ensureProject(db: Db, opts: SaveOptions & { slug?: string }): void {
  const existingOrg = db.get('SELECT id FROM organizations WHERE id = ?', opts.organizationId);
  if (!existingOrg) {
    db.run(
      'INSERT INTO organizations (id, name, slug, created_at, updated_at) VALUES (?,?,?,?,?)',
      opts.organizationId, opts.projectName, `org-${opts.organizationId.slice(0, 8)}`, now(), now(),
    );
  }
  const existing = db.get('SELECT id FROM projects WHERE id = ?', opts.projectId);
  if (!existing) {
    db.run(
      'INSERT INTO projects (id, organization_id, name, slug, kind, created_at, updated_at) VALUES (?,?,?,?,?,?,?)',
      opts.projectId, opts.organizationId, opts.projectName,
      opts.slug ?? opts.projectId.slice(0, 24), 'source', now(), now(),
    );
  }
}

export function saveScan(db: Db, outcome: ScanOutcome, opts: SaveOptions): void {
  ensureProject(db, opts);

  db.tx(() => {
    // --- snapshot ---
    let snapshotId: string | undefined;
    if (outcome.snapshot) {
      const existing = db.get<{ id: string }>(
        'SELECT id FROM repository_snapshots WHERE project_id = ? AND content_hash = ?',
        opts.projectId, outcome.snapshot.contentHash,
      );
      snapshotId = existing?.id ?? newId();
      if (!existing) {
        db.run(
          `INSERT INTO repository_snapshots
             (id, project_id, source_kind, commit_sha, branch, content_hash, file_count, total_bytes, ingested_at)
           VALUES (?,?,?,?,?,?,?,?,?)`,
          snapshotId, opts.projectId, 'local', outcome.commitSha ?? null, outcome.branch ?? null,
          outcome.snapshot.contentHash, outcome.snapshot.files.length, outcome.snapshot.totalBytes, now(),
        );
        for (const f of outcome.snapshot.files) {
          db.run(
            `INSERT INTO project_files
               (id, snapshot_id, path, language, role, bytes, lines, sha256, parsed, unparsed_reason, generated, vendored)
             VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
            newId(), snapshotId, f.path, f.language ?? null, f.role, f.bytes, f.lines, f.sha256,
            f.parsed ? 1 : 0, f.unparsedReason ?? null, f.generated ? 1 : 0, f.vendored ? 1 : 0,
          );
        }
      }
    }

    // --- scan job ---
    db.run(
      `INSERT INTO scan_jobs
         (id, project_id, snapshot_id, idempotency_key, status, requested_by, ai_provider, dynamic_verify,
          coverage_json, error_message, queued_at, started_at, finished_at)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`,
      outcome.scanId, opts.projectId, snapshotId ?? null, outcome.scanId, outcome.status,
      opts.requestedBy ?? null, outcome.aiReport?.usage.provider ?? 'none',
      outcome.coverage.layers.dynamic ? 1 : 0,
      JSON.stringify(outcome.coverage), outcome.errorMessage ?? null,
      now(), now(), now(),
    );

    // --- stages ---
    outcome.stages.forEach((s, i) => {
      db.run(
        `INSERT INTO scan_stages
           (id, scan_id, name, ordinal, status, attempts, message, warnings_json, started_at, finished_at, duration_ms)
         VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
        newId(), outcome.scanId, s.name, i + 1, s.status, s.attempts, s.message ?? null,
        JSON.stringify(s.warnings), s.startedAt ?? null, s.finishedAt ?? null, s.durationMs ?? null,
      );
    });

    // --- technology ---
    for (const t of outcome.tech) {
      db.run(
        `INSERT OR REPLACE INTO tech_detections
           (id, scan_id, kind, name, version, confidence, analysis_depth, evidence_json)
         VALUES (?,?,?,?,?,?,?,?)`,
        newId(), outcome.scanId, t.kind, t.name, t.version ?? null, t.confidence, t.analysisDepth,
        JSON.stringify(t.evidence),
      );
    }

    // --- architecture, routes, models, features ---
    if (outcome.map) {
      for (const c of outcome.map.components) {
        db.run(
          `INSERT OR REPLACE INTO architecture_components (id, scan_id, key, name, kind, provenance, files_json, summary)
           VALUES (?,?,?,?,?,?,?,?)`,
          newId(), outcome.scanId, c.id, c.name, c.kind, c.provenance, JSON.stringify(c.files), c.summary ?? null,
        );
      }
      for (const r of outcome.map.relationships) {
        db.run(
          `INSERT OR REPLACE INTO architecture_relationships (id, scan_id, from_key, to_key, kind, provenance, evidence_json)
           VALUES (?,?,?,?,?,?,?)`,
          newId(), outcome.scanId, r.from, r.to, r.kind, r.provenance, JSON.stringify(r.evidence),
        );
      }
      for (const e of outcome.map.routes) {
        db.run(
          `INSERT OR REPLACE INTO api_endpoints
             (id, scan_id, method, path, file, line, handler_symbol, auth_required,
              authorization_checks_json, request_shape, response_shape, validation, error_handling)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`,
          newId(), outcome.scanId, e.method, e.path, e.file, e.line ?? null, e.handlerSymbol ?? null,
          e.authRequired, JSON.stringify(e.authorizationChecks), e.requestShape ?? null,
          e.responseShape ?? null, e.validation, e.errorHandling,
        );
      }
      for (const m of outcome.map.models) {
        db.run(
          `INSERT OR REPLACE INTO data_models
             (id, scan_id, name, file, kind, fields_json, relations_json, indexes_json, ownership_field)
           VALUES (?,?,?,?,?,?,?,?,?)`,
          newId(), outcome.scanId, m.name, m.file, m.kind, JSON.stringify(m.fields),
          JSON.stringify(m.relations), JSON.stringify(m.indexes), m.ownershipField ?? null,
        );
      }
      for (const f of outcome.map.features) {
        db.run(
          `INSERT OR REPLACE INTO feature_inventory
             (id, scan_id, key, name, intended_function, status, frontend_files_json, backend_files_json,
              database_deps_json, external_services_json, auth_requirement, evidence_json, tests_json, possible_defects_json)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
          newId(), outcome.scanId, f.id, f.name, f.intendedFunction, f.status,
          JSON.stringify(f.frontendFiles), JSON.stringify(f.backendFiles), JSON.stringify(f.databaseDeps),
          JSON.stringify(f.externalServices), f.authRequirement, JSON.stringify(f.implementationEvidence),
          JSON.stringify(f.tests), JSON.stringify(f.possibleDefects),
        );
      }
    }

    // --- findings, evidence, occurrences ---
    const findingRowIds = new Map<string, string>();
    for (const p of outcome.prioritized) {
      const f = p.finding;
      const rowId = newId();
      findingRowIds.set(f.fingerprint, rowId);

      // First-detected provenance: carry forward from an earlier scan if present.
      const prior = db.get<{ scan_id: string; observed_at: string }>(
        `SELECT scan_id, observed_at FROM finding_occurrences
          WHERE project_id = ? AND fingerprint = ? ORDER BY observed_at ASC LIMIT 1`,
        opts.projectId, f.fingerprint,
      );

      db.run(
        `INSERT INTO diagnostic_findings
           (id, scan_id, project_id, display_id, fingerprint, rule_id, title, category, severity, confidence,
            status, detection_source, priority, priority_score, priority_rationale, files_json, explanation,
            user_impact, likely_root_cause, downstream_json, remediation, effort, related_tests_json,
            verification_steps_json, related_findings_json, references_json, affected_features_json,
            trace_json, first_detected_commit, first_detected_scan_id, created_at)
         VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
        rowId, outcome.scanId, opts.projectId, f.id, f.fingerprint, f.ruleId, f.title, f.category,
        f.severity, f.confidence, f.status, f.detectionSource, p.priority, p.score, p.rationale,
        JSON.stringify(f.files), f.explanation, f.userImpact, f.likelyRootCause ?? null,
        JSON.stringify(f.downstreamConsequences), f.remediation, f.effort,
        JSON.stringify(f.relatedTests), JSON.stringify(f.verificationSteps),
        JSON.stringify(f.relatedFindings), JSON.stringify(f.references),
        JSON.stringify(f.affectedFeatures), f.trace ? JSON.stringify(f.trace) : null,
        f.firstDetectedCommit ?? outcome.commitSha ?? null,
        prior?.scan_id ?? outcome.scanId, now(),
      );

      for (const e of f.evidence) {
        db.run(
          `INSERT INTO finding_evidence (id, finding_id, file, start_line, end_line, symbol, excerpt, note, verified)
           VALUES (?,?,?,?,?,?,?,?,?)`,
          newId(), rowId, e.file, e.startLine ?? null, e.endLine ?? null, e.symbol ?? null,
          e.excerpt ?? null, e.note ?? null, e.verified ? 1 : 0,
        );
      }

      db.run(
        `INSERT OR REPLACE INTO finding_occurrences
           (id, project_id, fingerprint, scan_id, severity, confidence, status, observed_at)
         VALUES (?,?,?,?,?,?,?,?)`,
        newId(), opts.projectId, f.fingerprint, outcome.scanId, f.severity, f.confidence, f.status, now(),
      );
    }

    // --- scores ---
    if (outcome.scorecard) {
      for (const d of outcome.scorecard.dimensions) {
        db.run(
          `INSERT OR REPLACE INTO scan_scores (id, scan_id, dimension, score, grade, weight, penalty, reason, counts_json)
           VALUES (?,?,?,?,?,?,?,?,?)`,
          newId(), outcome.scanId, d.dimension, d.score, d.grade, d.weight, d.penalty,
          d.reason ?? null, JSON.stringify(d.findingCounts),
        );
      }
    }

    // --- fix packs and prompts ---
    for (const pack of outcome.fixPacks) {
      const packId = newId();
      db.run(
        `INSERT INTO fix_packs
           (id, scan_id, key, title, category, ordinal, objective, effort, depends_on_json, baseline_commit, created_at)
         VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
        packId, outcome.scanId, pack.key, pack.title, pack.family, pack.ordinal, pack.objective,
        pack.effort, JSON.stringify(pack.dependsOn), outcome.commitSha ?? null, now(),
      );
      for (const p of pack.findings) {
        const fid = findingRowIds.get(p.finding.fingerprint);
        if (!fid) continue;
        db.run('INSERT OR REPLACE INTO fix_pack_findings (id, fix_pack_id, finding_id) VALUES (?,?,?)', newId(), packId, fid);
      }
      const prompts = outcome.packPrompts.get(pack.key);
      const validation = outcome.packValidations.get(pack.key);
      if (prompts) {
        for (const [format, markdown] of Object.entries(prompts)) {
          db.run(
            `INSERT OR REPLACE INTO fix_pack_versions
               (id, fix_pack_id, version, agent_format, prompt_markdown, validation_json, created_at)
             VALUES (?,?,?,?,?,?,?)`,
            newId(), packId, 1, format, markdown, JSON.stringify(validation ?? {}), now(),
          );
        }
      }
    }

    // --- AI usage metering ---
    if (outcome.aiReport && !outcome.aiReport.skippedReason) {
      const u = outcome.aiReport.usage;
      db.run(
        `INSERT INTO usage_records
           (id, organization_id, project_id, scan_id, kind, provider, model, tokens_in, tokens_out, requests, created_at)
         VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
        newId(), opts.organizationId, opts.projectId, outcome.scanId, 'ai_analysis',
        u.provider, u.model, u.tokensIn, u.tokensOut, u.requests, now(),
      );
    }

    db.audit({
      organizationId: opts.organizationId,
      actorUserId: opts.requestedBy,
      action: 'scan.completed',
      targetKind: 'scan',
      targetId: outcome.scanId,
      detail: {
        status: outcome.status,
        findings: outcome.findings.length,
        fixPacks: outcome.fixPacks.length,
        refused: outcome.rejectedFindings.length,
      },
    });
  });
}

/** Load one scan into the shape the comparison engine needs. */
export function loadScanSide(db: Db, scanId: string): ScanSide | undefined {
  const scan = db.get<{ id: string; project_id: string; coverage_json: string; snapshot_id: string | null }>(
    'SELECT id, project_id, coverage_json, snapshot_id FROM scan_jobs WHERE id = ?', scanId,
  );
  if (!scan) return undefined;

  const coverage = JSON.parse(scan.coverage_json || '{}') as Coverage;
  const snapshot = scan.snapshot_id
    ? db.get<{ content_hash: string }>('SELECT content_hash FROM repository_snapshots WHERE id = ?', scan.snapshot_id)
    : undefined;

  const rows = db.all<Record<string, string | number | null>>(
    'SELECT * FROM diagnostic_findings WHERE scan_id = ?', scanId,
  );
  const findings: Finding[] = rows.map((r) => {
    const evidence = db.all<Record<string, string | number | null>>(
      'SELECT * FROM finding_evidence WHERE finding_id = ?', String(r.id),
    );
    return {
      id: String(r.display_id),
      fingerprint: String(r.fingerprint),
      ruleId: String(r.rule_id),
      title: String(r.title),
      category: r.category as Finding['category'],
      severity: r.severity as Finding['severity'],
      confidence: r.confidence as Finding['confidence'],
      status: r.status as Finding['status'],
      detectionSource: r.detection_source as Finding['detectionSource'],
      files: JSON.parse(String(r.files_json)) as string[],
      evidence: evidence.map((e) => ({
        file: String(e.file),
        startLine: e.start_line === null ? undefined : Number(e.start_line),
        endLine: e.end_line === null ? undefined : Number(e.end_line),
        symbol: e.symbol === null ? undefined : String(e.symbol),
        excerpt: e.excerpt === null ? undefined : String(e.excerpt),
        note: e.note === null ? undefined : String(e.note),
        verified: Number(e.verified) === 1,
      })),
      trace: r.trace_json ? JSON.parse(String(r.trace_json)) : undefined,
      explanation: String(r.explanation),
      userImpact: String(r.user_impact),
      likelyRootCause: r.likely_root_cause === null ? undefined : String(r.likely_root_cause),
      downstreamConsequences: JSON.parse(String(r.downstream_json ?? '[]')) as string[],
      remediation: String(r.remediation),
      effort: r.effort as Finding['effort'],
      relatedTests: JSON.parse(String(r.related_tests_json ?? '[]')) as string[],
      verificationSteps: JSON.parse(String(r.verification_steps_json ?? '[]')) as string[],
      relatedFindings: JSON.parse(String(r.related_findings_json ?? '[]')) as string[],
      references: JSON.parse(String(r.references_json ?? '[]')) as string[],
      affectedFeatures: JSON.parse(String(r.affected_features_json ?? '[]')) as string[],
      firstDetectedCommit: r.first_detected_commit === null ? undefined : String(r.first_detected_commit),
      firstDetectedScanId: r.first_detected_scan_id === null ? undefined : String(r.first_detected_scan_id),
    };
  });

  const scoreRows = db.all<{ dimension: string; score: number | null; grade: string; weight: number }>(
    'SELECT dimension, score, grade, weight FROM scan_scores WHERE scan_id = ?', scanId,
  );
  const graded = scoreRows.filter((s) => s.score !== null);
  const assessedWeight = graded.reduce((sum, s) => sum + s.weight, 0);
  const overall = assessedWeight >= 0.5
    ? Math.round(graded.reduce((sum, s) => sum + (s.score as number) * s.weight, 0) / assessedWeight)
    : null;

  // Every path this scan indexed, so a comparison can tell "fixed" from
  // "no longer looked at" per finding rather than per file count.
  const indexedFiles = new Set(
    scan.snapshot_id
      ? db.all<{ path: string }>('SELECT path FROM project_files WHERE snapshot_id = ?', scan.snapshot_id)
          .map((r) => r.path)
      : [],
  );

  // Fingerprints observed in scans strictly older than this one. Ordering is by
  // queued_at, which is what makes "came back" distinguishable from "is new".
  const fingerprintsBeforeThisScan = new Set(
    db.all<{ fingerprint: string }>(
      `SELECT DISTINCT o.fingerprint
         FROM finding_occurrences o
         JOIN scan_jobs s ON s.id = o.scan_id
        WHERE o.project_id = ?
          AND s.queued_at < (SELECT queued_at FROM scan_jobs WHERE id = ?)`,
      scan.project_id, scanId,
    ).map((r) => r.fingerprint),
  );

  return {
    scanId,
    findings,
    coverage,
    contentHash: snapshot?.content_hash ?? '',
    indexedFiles: indexedFiles.size > 0 ? indexedFiles : undefined,
    fingerprintsBeforeThisScan,
    scorecard: scoreRows.length
      ? ({ overall, overallGrade: overall === null ? 'insufficient_evidence' : 'B', dimensions: [], assessedWeight, criticalCount: 0, unassessedDimensions: [], rules: {} } as unknown as Scorecard)
      : undefined,
  };
}

export function listScans(db: Db, projectId: string): Array<{ id: string; status: string; queuedAt: string; findings: number }> {
  return db.all<{ id: string; status: string; queued_at: string; findings: number }>(
    `SELECT s.id, s.status, s.queued_at,
            (SELECT COUNT(*) FROM diagnostic_findings d WHERE d.scan_id = s.id) AS findings
       FROM scan_jobs s WHERE s.project_id = ? ORDER BY s.queued_at DESC`,
    projectId,
  ).map((r) => ({ id: r.id, status: r.status, queuedAt: r.queued_at, findings: Number(r.findings) }));
}
