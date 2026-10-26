import type { ApiEndpoint, Confidence, Evidence, Finding } from '@codelens/core';
import type { RepoMap } from '../graph/repomap.ts';
import type { ParsedModule } from '../parse/types.ts';
import type { Analyzer, AnalyzerContext } from './types.ts';
import { assessAssignment, isTestOrExamplePath, matchKnownSecret } from './secrets.ts';
import { codeText } from './text.ts';

/**
 * Security audit (OWASP-aligned, defensive guidance only).
 *
 * Confidence discipline in this analyzer:
 *   - a pattern match alone is `moderate`;
 *   - a pattern plus a traced relationship (ownership field, request-derived
 *     value, absent middleware) is `strong`;
 *   - only something that cannot be anything else — a committed live-shaped
 *     credential, interpolation into raw SQL — is `confirmed`.
 *
 * Where enforcement could live somewhere we do not model (a middleware file we
 * could not parse), confidence is lowered and the note says so, because
 * reporting a false critical is worse than reporting an honest maybe.
 */

const OWASP = {
  bac: 'OWASP A01:2021 Broken Access Control',
  crypto: 'OWASP A02:2021 Cryptographic Failures',
  injection: 'OWASP A03:2021 Injection',
  insecureDesign: 'OWASP A04:2021 Insecure Design',
  misconfig: 'OWASP A05:2021 Security Misconfiguration',
  authFailure: 'OWASP A07:2021 Identification and Authentication Failures',
  integrity: 'OWASP A08:2021 Software and Data Integrity Failures',
  ssrf: 'OWASP A10:2021 Server-Side Request Forgery',
} as const;

/** True when the project has middleware we could not fully model. */
function hasUnmodelledMiddleware(map: RepoMap): string | undefined {
  const mw = map.files.find((f) => /^(?:src\/)?middleware\.[cm]?[jt]s$/.test(f.path));
  if (!mw) return undefined;
  const mod = map.modules.get(mw.path);
  // If middleware exists and mentions auth, enforcement may happen there.
  if (mod?.parsed && /auth|session|token|clerk|jwt|protect/i.test(mod.symbols.map((s) => s.text).join(' '))) {
    return mw.path;
  }
  return undefined;
}

/** Rate limiting evidence anywhere in the handler or project middleware. */
const RATE_LIMIT_RE =
  /\b(rateLimit|rate_limit|rateLimiter|RateLimiter|limiter|throttle|Throttle|slowDown|express-rate-limit|@upstash\/ratelimit|Ratelimit)\b/;

const SENSITIVE_ROUTE_RE = /\b(admin|internal|billing|payment|invoice|user|account|order|export|report|settings|key|token|secret)\b/i;

function routeIsStateChanging(r: ApiEndpoint): boolean {
  return ['POST', 'PUT', 'PATCH', 'DELETE'].includes(r.method);
}

/**
 * A route handler's body, with comments removed.
 *
 * Comments are stripped because every rule below matches on this text, and a
 * comment that *describes* a problem reads exactly like the problem. That has
 * produced three separate false positives during development, the last one on
 * this project's own login handler: a comment explaining why the response is
 * deliberately uniform was read as evidence that it is not.
 */
function handlerSymbolText(map: RepoMap, r: ApiEndpoint): string {
  const mod = map.modules.get(r.file);
  if (!mod) return '';
  const sym = mod.symbols.find((s) => s.name === r.handlerSymbol)
    ?? mod.symbols.find((s) => r.line !== undefined && s.startLine <= r.line && s.endLine >= r.line);
  return codeText(sym?.text ?? '', mod.language);
}

export const securityAnalyzer: Analyzer = {
  id: 'security',
  category: 'security',
  description: 'Authentication, authorisation, injection, secrets, upload, SSRF, and configuration checks.',

  run(ctx: AnalyzerContext): Finding[] {
    const { map } = ctx;
    const findings: Finding[] = [];
    const unmodelledMiddleware = hasUnmodelledMiddleware(map);

    findings.push(...hardcodedSecrets(ctx));
    findings.push(...committedEnvFiles(ctx));
    findings.push(...sqlInjection(ctx));
    findings.push(...missingAuthorization(ctx, unmodelledMiddleware));
    findings.push(...brokenObjectLevelAuthorization(ctx, unmodelledMiddleware));
    findings.push(...authenticationWeaknesses(ctx));
    findings.push(...webhookVerification(ctx));
    findings.push(...unsafeUploads(ctx));
    findings.push(...serverSideRequestForgery(ctx));
    findings.push(...crossSiteScripting(ctx));
    findings.push(...securityHeaders(ctx));
    findings.push(...credentialStorage(ctx));

    return findings;
  },
};

// ---------------------------------------------------------------- secrets ---

function hardcodedSecrets(ctx: AnalyzerContext): Finding[] {
  const { map } = ctx;
  const out: Finding[] = [];

  for (const mod of map.modules.values()) {
    if (!mod.parsed) continue;
    const isFixture = isTestOrExamplePath(mod.path);

    for (const lit of mod.stringLiterals) {
      // Interpolated skeletons contain no real value.
      if (lit.value.includes('${')) continue;

      const known = matchKnownSecret(lit.value);
      // Find the identifier this literal is assigned to, for name-based rules.
      const assignedName = nameAssignedAt(mod, lit.line);
      const match = known ?? (assignedName ? assessAssignment(assignedName, lit.value) : undefined);
      if (!match) continue;

      const evidence: Evidence = {
        ...map.evidenceLine(mod.path, lit.line, `${match.kind} (value masked: ${match.masked})`),
      };
      // Never let the raw secret reach storage through the excerpt.
      evidence.excerpt = evidence.excerpt?.replace(lit.value, match.masked);

      const confidence: Confidence =
        isFixture ? 'moderate' : match.shapeConfidence >= 0.95 ? 'confirmed' : 'strong';

      out.push(ctx.finding({
        ruleId: 'security.secret.hardcoded',
        title: `Hardcoded credential in source: ${match.kind}`,
        severity: isFixture ? 'medium' : match.shapeConfidence >= 0.95 ? 'critical' : 'high',
        confidence,
        files: [mod.path],
        symbol: assignedName,
        evidence: [evidence],
        explanation:
          `A credential is written directly into source at ${mod.path}:${lit.line}. ` +
          `Anyone with read access to the repository — including its full history after the value is removed — has the credential.` +
          (isFixture ? ' This file sits under a test or fixture path, which lowers the severity but does not make it safe.' : ''),
        userImpact:
          'If this credential is live, an attacker can act with the privileges it grants: reading or modifying customer data, or spending money through the provider.',
        likelyRootCause: 'A value was pasted in during development and never moved to configuration.',
        downstreamConsequences: [
          'Rotating the credential requires a code change and redeploy.',
          'The value remains in git history after it is deleted from the working tree.',
        ],
        remediation:
          'Move the value to an environment variable read at startup, fail fast when it is absent instead of falling back to a literal, ' +
          'add the file pattern to .gitignore if applicable, and rotate the credential — it must be treated as compromised.',
        effort: 'small',
        verificationSteps: [
          'Confirm the application still starts with the value supplied only through the environment.',
          'Confirm no fallback literal remains in the code path.',
          'Confirm the old credential has been revoked at the provider.',
        ],
        references: [OWASP.crypto, 'CWE-798 Use of Hard-coded Credentials'],
      }));
    }
  }
  return out;
}

/** The identifier a literal on this line is assigned to, if any. */
function nameAssignedAt(mod: ParsedModule, line: number): string | undefined {
  const sym = mod.symbols.find((s) => s.startLine === line && (s.kind === 'const' || s.kind === 'arrow'));
  if (sym) return sym.name;
  const enclosing = mod.symbols.find((s) => s.startLine <= line && s.endLine >= line);
  if (!enclosing) return undefined;
  const offset = line - enclosing.startLine;
  const lineText = enclosing.text.split('\n')[offset];
  if (!lineText) return undefined;
  const m = /(?:const|let|var)?\s*([A-Za-z_$][\w$]*)\s*[:=]/.exec(lineText);
  return m?.[1];
}

function committedEnvFiles(ctx: AnalyzerContext): Finding[] {
  const { map } = ctx;
  const out: Finding[] = [];

  for (const path of map.env.committedEnvFiles) {
    const file = map.filesByPath.get(path);
    if (!file?.text) continue;

    const secrets: string[] = [];
    let firstLine = 1;
    let lineNo = 0;
    for (const raw of file.text.split('\n')) {
      lineNo++;
      const m = /^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/.exec(raw.trim());
      if (!m) continue;
      const value = m[2]!.replace(/^["']|["']$/g, '');
      const match = matchKnownSecret(value) ?? assessAssignment(m[1]!, value);
      if (match) {
        if (secrets.length === 0) firstLine = lineNo;
        secrets.push(`${m[1]} (${match.kind})`);
      }
    }
    if (secrets.length === 0) continue;

    out.push(ctx.finding({
      ruleId: 'security.secret.committed_env',
      title: `Environment file with live-looking credentials is committed: ${path}`,
      severity: 'critical',
      confidence: 'confirmed',
      files: [path],
      evidence: [{
        file: path,
        startLine: firstLine,
        excerpt: `${secrets.length} credential-shaped value(s): ${secrets.slice(0, 4).join(', ')}`,
        note: 'values deliberately not reproduced here',
        verified: true,
      }],
      explanation:
        `${path} is tracked in the repository and contains ${secrets.length} value(s) matching live credential shapes. ` +
        'An environment file is meant to hold deployment configuration and stay out of version control.',
      userImpact:
        'Every credential in this file is available to anyone who can read the repository or any of its clones, forks, or backups.',
      likelyRootCause: 'The file was committed before .gitignore covered it, or it was added with `git add -f`.',
      downstreamConsequences: [
        'All listed credentials must be rotated, not merely deleted from the file.',
        'The values persist in git history and in every existing clone.',
      ],
      remediation:
        'Rotate every credential in the file. Add the file to .gitignore, remove it from tracking with `git rm --cached`, and keep only a ' +
        '.env.example listing names with empty values. Purging history requires a rewrite and coordination with everyone who has a clone.',
      effort: 'medium',
      verificationSteps: [
        'Confirm `git ls-files` no longer lists the file.',
        'Confirm the application reads each value from the deployment environment.',
        'Confirm each old credential is revoked at its provider.',
      ],
      references: [OWASP.misconfig, 'CWE-540 Inclusion of Sensitive Information in Source Code'],
    }));
  }
  return out;
}

// -------------------------------------------------------------- injection ---

const RAW_QUERY_CALLEES =
  /(?:^|\.)(?:query|execute|executemany|raw|rawQuery|\$queryRaw|\$executeRaw|queryRaw|executeRaw|exec|run|all|get)$/;

function sqlInjection(ctx: AnalyzerContext): Finding[] {
  const { map } = ctx;
  const out: Finding[] = [];

  for (const mod of map.modules.values()) {
    if (!mod.parsed) continue;

    for (const call of mod.calls) {
      if (!RAW_QUERY_CALLEES.test(call.callee)) continue;
      const arg = call.args[0];
      if (!arg) continue;

      // The dangerous shapes: template interpolation or string concatenation
      // of a non-literal into something that reads as SQL.
      const interpolated = /\$\{/.test(arg);
      const concatenated = /['"`]\s*\+|\+\s*['"`]/.test(arg);
      const looksLikeSql = /\b(SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM|DROP|ALTER|CREATE\s+TABLE|WHERE|JOIN|FROM)\b/i.test(arg);

      // The statement is very often built into a variable on the line above and
      // the call then receives a bare identifier, so following that binding is
      // required rather than optional.
      const sqlVar = sqlVariableNear(mod, call.line, arg);
      const inlineDangerous = (interpolated || concatenated) && looksLikeSql;
      if (!inlineDangerous && !sqlVar) continue;

      // Interpolating a compile-time constant is not injection. An ORDER BY
      // fragment held in a module-scope `const` is a common and safe pattern,
      // and this project's own self-audit reported two of them as critical,
      // confirmed SQL injection — the most damaging kind of false positive a
      // scanner can produce. The finding stands only when at least one
      // interpolated expression is something other than such a constant.
      const interpolatedSource = sqlVar ? symbolTextAt(mod, sqlVar.line) : arg;
      if (interpolatedSource && allInterpolationsAreConstants(mod, interpolatedSource)) continue;

      const evidenceLine = sqlVar?.line ?? call.line;
      const evidence: Evidence[] = [map.evidenceLine(mod.path, evidenceLine, 'untrusted value interpolated into query text')];
      if (sqlVar) evidence.push(map.evidenceLine(mod.path, call.line, `the built string is passed to ${call.callee}()`));

      out.push(ctx.finding({
        ruleId: 'security.injection.sql',
        title: `SQL built by string interpolation and passed to ${call.callee}()`,
        severity: 'critical',
        confidence: 'confirmed',
        files: [mod.path],
        symbol: call.inSymbol,
        evidence,
        trace: {
          kind: 'import',
          steps: [
            { file: mod.path, line: evidenceLine, symbol: call.inSymbol, detail: 'query text assembled with interpolation' },
            { file: mod.path, line: call.line, symbol: call.inSymbol, detail: `passed to ${call.callee}() as statement text` },
          ],
          complete: true,
        },
        explanation:
          `The statement passed to ${call.callee}() is assembled by interpolation rather than parameterised. ` +
          'Any value reaching that interpolation is executed as SQL, not treated as data.',
        userImpact:
          'An attacker who controls the interpolated value can read, modify, or delete any data the database user can reach, ' +
          'including other customers\' records, and in many configurations can escalate further.',
        likelyRootCause: 'A query was written as a string because the value was assumed to be internal or already validated.',
        downstreamConsequences: [
          'Input validation elsewhere does not fix this: the vulnerability is in how the statement is built.',
          'Database audit logs will show the injected statement as a legitimate application query.',
        ],
        remediation:
          'Replace the interpolation with a parameterised query: pass values as bind parameters ($1/? placeholders or the ORM\'s ' +
          'tagged-template form such as Prisma\'s `$queryRaw` with template parameters) so the driver sends them separately from the ' +
          'statement text. Where an identifier (table or column name) genuinely must be dynamic, validate it against a fixed allowlist.',
        effort: 'small',
        verificationSteps: [
          'Confirm the query now passes values as bind parameters.',
          'Add a regression test that supplies a value containing a quote and a semicolon and asserts it is stored or matched literally.',
          'Confirm no remaining call site builds this statement by concatenation.',
        ],
        references: [OWASP.injection, 'CWE-89 SQL Injection'],
      }));
    }
  }
  return out;
}


/** Source text of the symbol declared at a line, for inspecting a built query. */
function symbolTextAt(mod: ParsedModule, line: number): string | undefined {
  return mod.symbols.find((sym) => sym.startLine === line)?.text
    ?? mod.symbols.find((sym) => sym.startLine <= line && sym.endLine >= line)?.text;
}

/** The expressions inside `${...}` in a template literal, brace-matched. */
function interpolatedExpressions(text: string): string[] {
  const out: string[] = [];
  for (let i = 0; i < text.length - 1; i++) {
    if (text[i] !== '$' || text[i + 1] !== '{') continue;
    let depth = 0;
    for (let j = i + 1; j < text.length; j++) {
      if (text[j] === '{') depth++;
      else if (text[j] === '}') {
        depth--;
        if (depth === 0) { out.push(text.slice(i + 2, j).trim()); i = j; break; }
      }
    }
  }
  return out;
}

/**
 * True when every interpolation is a reference to a module-scope constant bound
 * to a plain string literal — a value fixed at author time that no request can
 * influence.
 *
 * Deliberately strict: a bare identifier only, resolving to a `const` whose own
 * initialiser is a literal with no interpolation of its own. Anything it cannot
 * prove constant — a call, a property access, a parameter — leaves the finding
 * in place, so the failure mode is reporting rather than silence.
 */
function allInterpolationsAreConstants(mod: ParsedModule, text: string): boolean {
  const expressions = interpolatedExpressions(text);
  if (expressions.length === 0) return false;

  return expressions.every((expr) => {
    if (!/^[A-Za-z_$][\w$]*$/.test(expr)) return false;
    const decl = mod.symbols.find((sym) => sym.name === expr && sym.kind === 'const');
    if (!decl) return false;
    // Its initialiser must itself be a literal string, not another template.
    const initialiser = decl.text.slice(decl.text.indexOf('=') + 1).trim();
    if (!/^['"]/.test(initialiser)) return false;
    return !initialiser.includes('${');
  });
}

/** A nearby variable holding interpolated SQL that is then passed to the call. */
function sqlVariableNear(mod: ParsedModule, callLine: number, arg: string): { line: number } | undefined {
  const varName = /^([A-Za-z_$][\w$]*)$/.exec(arg.trim())?.[1];
  if (!varName) return undefined;
  const sym = mod.symbols.find((s) => s.name === varName && s.kind === 'const');
  if (sym && /\b(SELECT|INSERT|UPDATE|DELETE|WHERE|FROM)\b/i.test(sym.text) && /\$\{|\+/.test(sym.text)) {
    return { line: sym.startLine };
  }
  // Fall back to scanning the enclosing symbol for the assignment.
  const enclosing = mod.symbols.find((s) => s.startLine <= callLine && s.endLine >= callLine);
  if (!enclosing) return undefined;
  const lines = enclosing.text.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const l = lines[i]!;
    if (!l.includes(varName)) continue;
    if (!/=/.test(l)) continue;
    if (/\b(SELECT|INSERT|UPDATE|DELETE|WHERE|FROM)\b/i.test(l) && /\$\{|\+/.test(l)) {
      return { line: enclosing.startLine + i };
    }
  }
  return undefined;
}

// ---------------------------------------------------------- authorisation ---

function missingAuthorization(ctx: AnalyzerContext, unmodelledMiddleware: string | undefined): Finding[] {
  const { map } = ctx;
  const out: Finding[] = [];

  for (const r of map.routes) {
    if (r.authRequired !== 'public') continue;

    // A route is only interesting if it touches data or changes state.
    const touchesData = map.relationships.some(
      (rel) => rel.kind === 'queries' && rel.from === `api_route:${r.method} ${r.path}`,
    );
    const stateChanging = routeIsStateChanging(r);
    const sensitivePath = SENSITIVE_ROUTE_RE.test(r.path);

    // Deliberately public endpoints: health checks, auth entry points, webhooks
    // (which are covered by their own signature rule).
    if (/\b(health|healthz|readyz|livez|ping|status|metrics|robots|sitemap)\b/.test(r.path)) continue;
    if (/\b(login|signin|sign-in|register|signup|sign-up|auth|callback|reset|forgot|verify|magic)\b/.test(r.path)) continue;
    if (/webhook/i.test(r.path)) continue;

    if (!touchesData && !stateChanging) continue;

    const isAdmin = /\b(admin|internal|superuser|staff|moderator)\b/i.test(r.path);
    const exposesPii = exposesPersonalData(map, r);

    let severity: Finding['severity'];
    if (isAdmin || (r.method === 'DELETE' && touchesData)) severity = 'critical';
    else if (stateChanging && touchesData) severity = 'high';
    else if (exposesPii) severity = 'high';
    else severity = sensitivePath ? 'high' : 'medium';

    // If middleware we could not model mentions auth, enforcement may live
    // there. Say so and lower confidence rather than overclaiming.
    const confidence: Confidence = unmodelledMiddleware ? 'moderate' : 'strong';

    const evidence: Evidence[] = [
      map.evidenceLine(r.file, r.line ?? 1,
        `handler ${r.handlerSymbol ?? ''} contains no authentication check`.trim()),
    ];
    if (unmodelledMiddleware) {
      evidence.push({
        file: unmodelledMiddleware,
        note: 'this middleware mentions authentication; verify whether it covers this route before acting',
        verified: true,
      });
    }

    const queriedModels = map.relationships
      .filter((rel) => rel.kind === 'queries' && rel.from === `api_route:${r.method} ${r.path}`)
      .map((rel) => rel.to.replace('datastore:', ''));

    out.push(ctx.finding({
      ruleId: isAdmin ? 'security.authz.admin_route_unauthenticated' : 'security.authz.missing_authentication',
      title: `${r.method} ${r.path} performs no authentication check`,
      severity,
      confidence,
      detectionSource: 'graph',
      files: [r.file],
      symbol: r.handlerSymbol,
      evidence,
      trace: {
        kind: 'route_authorization',
        steps: [
          { file: r.file, line: r.line, symbol: r.handlerSymbol, detail: `${r.method} ${r.path} handler declared` },
          { file: r.file, line: r.line, symbol: r.handlerSymbol, detail: 'no call to a session or authentication helper in the handler body' },
          ...queriedModels.map((m) => ({ file: r.file, detail: `handler queries the ${m} model` })),
        ],
        complete: !unmodelledMiddleware,
      },
      explanation:
        `The handler for ${r.method} ${r.path} does not call any session or authentication helper, and no rejection path for an ` +
        `unauthenticated caller exists in its body.` +
        (queriedModels.length ? ` It queries: ${queriedModels.join(', ')}.` : '') +
        (isAdmin ? ' The path indicates an administrative endpoint, which should be the most tightly controlled surface in the application.' : '') +
        (unmodelledMiddleware ? ` Note: ${unmodelledMiddleware} mentions authentication, so enforcement may happen there — confirm before treating this as exploitable.` : ''),
      userImpact: isAdmin
        ? 'Anyone who can reach this URL can read or change administrative data without logging in.'
        : exposesPii
          ? 'An unauthenticated caller can retrieve personal data belonging to other people.'
          : stateChanging
            ? 'An unauthenticated caller can change or destroy stored data.'
            : 'An unauthenticated caller can read data that should require a session.',
      likelyRootCause: 'The route was added without the project\'s authentication helper, or enforcement was assumed to be global.',
      downstreamConsequences: [
        'Client-side route guards do not mitigate this: the endpoint is reachable directly.',
        'Rate limiting and logging will record the access as anonymous traffic.',
      ],
      remediation:
        'Resolve the session at the top of the handler using the project\'s existing helper, return 401 when it is absent, and then ' +
        'apply the authorisation rule for the resource. Enforce this server-side in the handler (or in middleware that provably matches ' +
        'this path), not in the client.',
      effort: 'small',
      verificationSteps: [
        `Call ${r.method} ${r.path} with no credentials and confirm a 401.`,
        'Call it with a valid session and confirm the previous behaviour is unchanged.',
        isAdmin ? 'Call it with a valid non-admin session and confirm a 403.' : 'Confirm a caller cannot read another account\'s data.',
      ],
      references: [OWASP.bac, 'CWE-306 Missing Authentication for Critical Function'],
    }));
  }
  return out;
}

function exposesPersonalData(map: RepoMap, r: ApiEndpoint): boolean {
  const PII = /\b(email|phone|address|ssn|dob|birth|name|password|card|iban|passport)\b/i;
  if (r.responseShape && PII.test(r.responseShape)) return true;
  const queried = map.relationships
    .filter((rel) => rel.kind === 'queries' && rel.from === `api_route:${r.method} ${r.path}`)
    .map((rel) => rel.to.replace('datastore:', ''));
  return queried.some((name) => {
    const model = map.models.find((m) => m.name === name);
    return !!model?.fields.some((f) => PII.test(f.name));
  });
}

/**
 * Broken object-level authorisation.
 *
 * The signal is specific: the caller is authenticated, the handler reads a
 * record keyed by an identifier that came from the request, the record's model
 * has an ownership column, and the handler never compares that column to the
 * session. That conjunction is what makes this reportable rather than a guess.
 */
function brokenObjectLevelAuthorization(ctx: AnalyzerContext, unmodelledMiddleware: string | undefined): Finding[] {
  const { map } = ctx;
  const out: Finding[] = [];

  for (const r of map.routes) {
    if (r.authRequired !== 'required') continue;
    if (r.authorizationChecks.length > 0) continue;

    const mod = map.modules.get(r.file);
    if (!mod?.parsed) continue;

    const sym = mod.symbols.find((s) => s.name === r.handlerSymbol);
    if (!sym) continue;

    // Queries inside this handler keyed by a request-derived identifier.
    const callsInHandler = mod.calls.filter((c) => c.line >= sym.startLine && c.line <= sym.endLine);
    for (const call of callsInHandler) {
      const m = /^(?:\w+\.)?(\w+)\.(findUnique|findFirst|findOne|update|delete|destroy|findByPk)$/.exec(call.callee);
      if (!m) continue;

      const model = map.models.find((md) => md.name.toLowerCase() === m[1]!.toLowerCase());
      if (!model?.ownershipField) continue;

      const argText = call.args.join(' ');
      // Keyed by something that came from the request.
      const requestDerived = /\bparams?\b|\bquery\b|\bbody\b|\breq\b|\brequest\b|\bsearchParams\b|\bpathname\b/.test(argText);
      if (!requestDerived) continue;
      // And not scoped to the owner.
      if (new RegExp(`\\b${model.ownershipField}\\b`).test(argText)) continue;

      const paramName = /\bparams\.(\w+)/.exec(argText)?.[1] ?? 'id';

      out.push(ctx.finding({
        ruleId: 'security.authz.broken_object_level',
        title: `${r.method} ${r.path} reads a ${model.name} by request id without checking ownership`,
        severity: r.method === 'GET' ? 'critical' : 'critical',
        confidence: unmodelledMiddleware ? 'moderate' : 'strong',
        detectionSource: 'graph',
        files: [r.file, model.file],
        symbol: r.handlerSymbol,
        evidence: [
          map.evidenceLine(r.file, r.line ?? sym.startLine, 'session is resolved, so the caller is authenticated'),
          map.evidenceLine(r.file, call.line, `${model.name} looked up by an identifier taken from the request (${paramName})`),
          {
            file: model.file,
            excerpt: `model ${model.name} { … ${model.ownershipField} … }`,
            note: `the model has an ownership column '${model.ownershipField}' that this query does not filter on`,
            verified: true,
          },
        ],
        trace: {
          kind: 'route_authorization',
          steps: [
            { file: r.file, line: r.line, symbol: r.handlerSymbol, detail: 'authentication enforced: an unauthenticated caller is rejected' },
            { file: r.file, line: call.line, symbol: r.handlerSymbol, detail: `${call.callee}() keyed by request value '${paramName}'` },
            { file: model.file, detail: `${model.name}.${model.ownershipField} identifies the owning user` },
            { file: r.file, line: call.line, detail: `no comparison between ${model.ownershipField} and the session identity anywhere in the handler` },
          ],
          complete: !unmodelledMiddleware,
        },
        explanation:
          `The handler authenticates the caller but then loads a ${model.name} using the '${paramName}' value from the request, ` +
          `without restricting the query to records the caller owns. ${model.name} has an ownership column ` +
          `('${model.ownershipField}'), and it is never compared with the session identity in this handler. ` +
          'Authentication answers "who is this"; this handler never answers "may they see this record".',
        userImpact:
          `Any logged-in user can read or modify another user's ${model.name} records simply by changing the identifier in the URL. ` +
          'This is the most commonly exploited class of API flaw and requires no special tooling.',
        likelyRootCause:
          'The authentication check was added and mistaken for an authorisation check, which is a very common conflation.',
        downStreamNote: undefined as never,
        downstreamConsequences: [
          `Every other handler that loads a ${model.name} by request id likely has the same gap.`,
          'Sequential or guessable identifiers make enumeration trivial; opaque ids reduce but do not remove the exposure.',
        ],
        remediation:
          `Scope the query to the caller: include '${model.ownershipField}' from the resolved session in the where clause ` +
          `(for example \`where: { id, ${model.ownershipField}: session.userId }\`) so a record belonging to someone else simply is not found. ` +
          'Where administrators must bypass this, branch on an explicit role check rather than widening the default query. ' +
          'Returning 404 rather than 403 for a record the caller does not own avoids confirming that it exists.',
        effort: 'small',
        verificationSteps: [
          `Create records for two different users, then request user A's ${model.name} while authenticated as user B and confirm it is not returned.`,
          'Confirm the owner can still read and modify their own records.',
          'Add a regression test covering all three cases: unauthenticated, owner, and non-owner.',
          'Audit the other handlers that load this model by request id.',
        ],
        references: [OWASP.bac, 'CWE-639 Authorization Bypass Through User-Controlled Key', 'OWASP API Security Top 10: API1 Broken Object Level Authorization'],
      } as never));
    }
  }
  return out;
}

// -------------------------------------------------------- authentication ----

function authenticationWeaknesses(ctx: AnalyzerContext): Finding[] {
  const { map } = ctx;
  const out: Finding[] = [];

  const authRoutes = map.routes.filter((r) =>
    /\b(login|signin|sign-in|register|signup|sign-up|auth|token|password|reset|forgot|verify|otp|mfa)\b/i.test(r.path));

  // --- missing rate limiting on authentication endpoints ---
  const projectWideRateLimit = [...map.modules.values()].some(
    (m) => m.parsed && (
      m.imports.some((i) => RATE_LIMIT_RE.test(i.specifier)) ||
      m.symbols.some((s) => RATE_LIMIT_RE.test(s.text))
    ),
  );

  for (const r of authRoutes) {
    if (!routeIsStateChanging(r)) continue;
    const body = handlerSymbolText(map, r);
    if (RATE_LIMIT_RE.test(body) || projectWideRateLimit) continue;

    out.push(ctx.finding({
      ruleId: 'security.auth.missing_rate_limit',
      title: `${r.method} ${r.path} accepts unlimited authentication attempts`,
      severity: 'high',
      confidence: 'strong',
      files: [r.file],
      symbol: r.handlerSymbol,
      evidence: [map.evidenceLine(r.file, r.line ?? 1, 'authentication handler with no rate limiting in its body, and no rate-limiting dependency anywhere in the project')],
      explanation:
        `The ${r.method} ${r.path} handler performs no rate limiting, and no rate-limiting library or middleware was found in the ` +
        'project. Credential guessing is therefore bounded only by network throughput.',
      userImpact:
        'Attackers can brute-force passwords and run credential-stuffing attacks against the login endpoint, compromising accounts whose ' +
        'passwords are weak or reused. Users may also be locked out or the service degraded by the attempt volume.',
      likelyRootCause: 'Rate limiting is often deferred to infrastructure and then never configured.',
      downstreamConsequences: [
        'Password strength rules alone do not stop credential stuffing with breached passwords.',
        'Without limits there is no natural signal that an attack is in progress.',
      ],
      remediation:
        'Apply a rate limit keyed on both client IP and the submitted account identifier, with exponential backoff or a temporary lockout ' +
        'after repeated failures. Enforce it server-side ahead of the credential check, log the rejections, and return a uniform error so the ' +
        'limiter does not itself leak which accounts exist.',
      effort: 'medium',
      verificationSteps: [
        'Send repeated failed attempts for one account and confirm later attempts are rejected.',
        'Confirm a legitimate user is not blocked by normal use.',
        'Confirm rejected attempts appear in the logs.',
      ],
      references: [OWASP.authFailure, 'CWE-307 Improper Restriction of Excessive Authentication Attempts'],
    }));
  }

  // --- plaintext password comparison ---
  for (const r of authRoutes) {
    const body = handlerSymbolText(map, r);
    if (!body) continue;
    // A direct comparison of a stored password against a supplied value.
    const direct = /\b(\w*\.?password\w*)\s*(?:!==|===|==|!=)\s*([\w.]*(?:password|pwd|pass)\w*)/i.exec(body);
    if (!direct) continue;
    // A hash comparison is fine.
    if (/\b(bcrypt|argon2|scrypt|pbkdf2|compare|verify|checkpw|timingSafeEqual)\b/i.test(body)) continue;

    out.push(ctx.finding({
      ruleId: 'security.auth.plaintext_password_comparison',
      title: `${r.method} ${r.path} compares passwords without hashing`,
      severity: 'critical',
      confidence: 'strong',
      files: [r.file],
      symbol: r.handlerSymbol,
      evidence: [map.evidenceAt(r.file, direct[0], 'stored value compared directly against the submitted password; no hashing function is used in this handler')],
      explanation:
        'The handler compares a stored password value directly with the submitted one. No password hashing function ' +
        '(bcrypt, argon2, scrypt, or PBKDF2) appears in this handler, which means the stored value is the password itself. ' +
        'The comparison is also not constant-time, so it leaks information through timing.',
      userImpact:
        'If the database is ever read by an attacker — through a backup, a log, an injection flaw, or an insider — every user\'s password ' +
        'is immediately usable, including on the other services where people reuse passwords.',
      likelyRootCause: 'Authentication was built against a plaintext column during early development and never migrated.',
      downstreamConsequences: [
        'Migration requires a rehash-on-next-login path; existing stored values cannot be recovered into hashes.',
        'Password reuse means the breach extends beyond this application.',
      ],
      remediation:
        'Store a hash produced by argon2id, scrypt, or bcrypt with a per-user salt, and verify with that library\'s constant-time compare. ' +
        'Migrate by adding a hash column, hashing on next successful login, and removing the plaintext column once no rows depend on it. ' +
        'Treat all existing passwords as compromised and require a reset.',
      effort: 'medium',
      verificationSteps: [
        'Confirm the stored column holds a hash with a recognisable algorithm prefix.',
        'Confirm login succeeds for a newly set password and fails for a wrong one.',
        'Confirm no code path reads or logs the plaintext password.',
      ],
      references: [OWASP.crypto, 'CWE-256 Plaintext Storage of a Password'],
    }));
  }

  // --- account enumeration via distinguishable errors ---
  for (const r of authRoutes) {
    const body = handlerSymbolText(map, r);
    if (!body) continue;
    const distinct = /(?:no\s+(?:account|user)|user\s+not\s+found|unknown\s+(?:account|email|user)|email\s+not\s+(?:found|registered))/i.test(body)
      && /(?:incorrect|wrong|invalid)\s+password/i.test(body);
    if (!distinct) continue;

    out.push(ctx.finding({
      ruleId: 'security.auth.account_enumeration',
      title: `${r.method} ${r.path} reveals whether an account exists`,
      severity: 'medium',
      confidence: 'strong',
      files: [r.file],
      symbol: r.handlerSymbol,
      evidence: [map.evidenceLine(r.file, r.line ?? 1, 'the handler returns different messages for an unknown account and a wrong password')],
      explanation:
        'The handler distinguishes "no such account" from "wrong password" in its response. That difference lets anyone test ' +
        'an email address and learn whether it is registered.',
      userImpact:
        'An attacker can compile a list of valid customer email addresses, which enables targeted phishing and narrows a ' +
        'credential-stuffing attack to accounts that actually exist.',
      remediation:
        'Return one identical message and status for both cases ("those credentials are not valid"). Keep the timing of both paths ' +
        'similar so the difference does not leak through response time, and record the specific reason in server logs only.',
      effort: 'trivial',
      verificationSteps: [
        'Submit an unregistered address and a registered address with a wrong password; confirm the responses are identical.',
        'Confirm the distinction is still available in server-side logs.',
      ],
      references: [OWASP.authFailure, 'CWE-204 Observable Response Discrepancy'],
    }));
  }

  // --- tokens signed without expiry ---
  for (const mod of map.modules.values()) {
    if (!mod.parsed) continue;
    for (const call of mod.calls) {
      if (!/(?:^|\.)(?:sign|encode)$/.test(call.callee)) continue;
      if (!/\bjwt\b|\bjose\b|\bjsonwebtoken\b/i.test(call.callee + mod.imports.map((i) => i.specifier).join(' '))) continue;
      const argText = call.args.join(' ');
      if (/expiresIn|exp\b|setExpirationTime|maxAge/.test(argText)) continue;

      out.push(ctx.finding({
        ruleId: 'security.auth.token_without_expiry',
        title: 'Session token is signed without an expiry',
        severity: 'medium',
        confidence: 'strong',
        files: [mod.path],
        symbol: call.inSymbol,
        evidence: [map.evidenceLine(mod.path, call.line, 'token signed with no expiresIn or exp claim')],
        explanation:
          'The token is signed without an expiry claim, so it stays valid indefinitely. There is also no way to narrow the window ' +
          'of a leaked token short of rotating the signing key, which invalidates every session at once.',
        userImpact:
          'A token captured from a shared machine, a log, or a proxy keeps working forever, so a user cannot really be logged out and ' +
          'a stolen session cannot be aged out.',
        remediation:
          'Set a short expiry on access tokens (minutes to hours) and issue a separate, revocable refresh token. Keep a server-side ' +
          'record that lets an individual session be revoked without rotating the signing key for everyone.',
        effort: 'medium',
        verificationSteps: [
          'Decode a freshly issued token and confirm an `exp` claim is present.',
          'Confirm a token past its expiry is rejected.',
          'Confirm refresh still produces a working session.',
        ],
        references: [OWASP.authFailure, 'CWE-613 Insufficient Session Expiration'],
      }));
    }
  }

  return out;
}

// ---------------------------------------------------------------- webhooks --

function webhookVerification(ctx: AnalyzerContext): Finding[] {
  const { map } = ctx;
  const out: Finding[] = [];

  const VERIFY_RE = /\b(constructEvent|constructEventAsync|verifyHeader|createHmac|timingSafeEqual|verifySignature|verify_signature|Webhook\s*\(|svix|verifyWebhook|compareSignature)\b/;

  for (const r of map.routes) {
    if (!/webhook|callback\/(?:stripe|github|shopify|twilio|slack)/i.test(r.file + r.path)) continue;
    if (!routeIsStateChanging(r)) continue;

    const body = handlerSymbolText(map, r);
    if (VERIFY_RE.test(body)) continue;

    // Reading the signature header but not verifying it is the sharpest signal.
    const readsSignature = /(?:signature|x-hub-signature|x-signature|stripe-signature|webhook-signature)/i.test(body);

    out.push(ctx.finding({
      ruleId: 'security.webhook.unverified_signature',
      title: `${r.method} ${r.path} processes webhook payloads without verifying the signature`,
      severity: 'critical',
      confidence: readsSignature ? 'strong' : 'moderate',
      files: [r.file],
      symbol: r.handlerSymbol,
      evidence: [
        map.evidenceLine(r.file, r.line ?? 1,
          readsSignature
            ? 'the signature header is read but never passed to a verification function'
            : 'no signature verification appears in this webhook handler'),
      ],
      explanation:
        `The handler acts on the request body without verifying that it came from the provider.` +
        (readsSignature
          ? ' The signature header is read, which suggests verification was intended, but the value is never checked against the signing secret.'
          : ' No HMAC comparison or provider SDK verification call appears in the handler.') +
        ' A webhook URL is effectively public: it must be assumed that attackers know it.',
      userImpact:
        'Anyone can forge a request to this endpoint and cause whatever the handler does — marking orders paid, granting entitlements, ' +
        'or changing account state — without any real payment or provider event.',
      likelyRootCause: 'Verification is commonly skipped during local development and then not added before release.',
      downstreamConsequences: [
        'Financial state can be changed by an unauthenticated caller.',
        'Provider-side event logs will not show the forged events, making reconciliation misleading.',
      ],
      remediation:
        'Verify every delivery before acting on it: read the raw request body (not the parsed JSON, since re-serialising changes the bytes), ' +
        'compute or verify the HMAC against the provider signing secret with a constant-time compare — or use the provider SDK\'s own ' +
        'verification helper, such as Stripe\'s `constructEvent` — reject with 400 on failure, and enforce the provider\'s timestamp ' +
        'tolerance to prevent replay.',
      effort: 'small',
      verificationSteps: [
        'Send a payload with no signature and confirm it is rejected.',
        'Send a payload with a wrong signature and confirm it is rejected.',
        'Send a correctly signed payload and confirm it is processed exactly once.',
        'Confirm the handler reads the raw body, since parsing before verification breaks the HMAC.',
      ],
      references: [OWASP.integrity, 'CWE-345 Insufficient Verification of Data Authenticity'],
    }));
  }
  return out;
}

// ----------------------------------------------------------------- uploads --

function unsafeUploads(ctx: AnalyzerContext): Finding[] {
  const { map } = ctx;
  const out: Finding[] = [];

  for (const r of map.routes) {
    const body = handlerSymbolText(map, r);
    if (!body) continue;
    const handlesUpload = /\b(formData\(\)|multipart|multer|busboy|upload|createWriteStream|writeFile|putObject|request\.files)\b/.test(body);
    if (!handlesUpload) continue;

    const validatesType = /\b(mimetype|mimeType|content-?type|allowedTypes|accept|fileFilter|image\/|magic|sharp|fileTypeFrom)\b/i.test(body);
    const validatesSize = /\b(maxFileSize|limits|fileSize|size\s*[<>]|MAX_(?:FILE|UPLOAD)_SIZE|contentLength)\b/i.test(body);
    const usesClientName = /\b(?:file|upload)\w*\.(?:name|filename|originalname)\b/.test(body)
      && /(?:writeFile|createWriteStream|join|resolve|`[^`]*\$\{)/.test(body);

    if (validatesType && validatesSize && !usesClientName) continue;

    const problems: string[] = [];
    if (!validatesType) problems.push('no content-type or extension allowlist');
    if (!validatesSize) problems.push('no size limit');
    if (usesClientName) problems.push('the client-supplied filename is used to build the destination path');
    if (problems.length === 0) continue;

    out.push(ctx.finding({
      ruleId: 'security.upload.unsafe_handling',
      title: `${r.method} ${r.path} accepts uploads unsafely (${problems.length} issue${problems.length > 1 ? 's' : ''})`,
      severity: usesClientName ? 'high' : 'medium',
      confidence: 'strong',
      files: [r.file],
      symbol: r.handlerSymbol,
      evidence: [map.evidenceLine(r.file, r.line ?? 1, problems.join('; '))],
      explanation:
        `The upload handler has the following gaps: ${problems.join('; ')}. ` +
        (usesClientName
          ? 'Because the destination path is built from the client-supplied filename, a name containing path separators or `..` writes outside the intended directory. '
          : '') +
        'Without a type allowlist, content that the web server will execute or that browsers will treat as active content can be stored and then served.',
      userImpact: usesClientName
        ? 'An attacker can write a file to an arbitrary location the process can reach, which can overwrite application files or place executable content inside the served directory.'
        : 'An attacker can upload oversized or hostile files, exhausting disk and storing content that harms other users when it is served back.',
      likelyRootCause: 'Upload handling was written for the happy path with a trusted browser form in mind.',
      downstreamConsequences: [
        'Files stored now may already be hostile; existing contents need review, not just a code fix.',
        'A CDN or static route may serve stored files with a content type that makes them active.',
      ],
      remediation:
        'Generate the stored filename server-side (a UUID plus an extension derived from a verified type) and never use the client-supplied name ' +
        'in a path. Enforce an explicit content-type allowlist validated against the file\'s actual bytes rather than the declared header, ' +
        'cap the size before buffering the whole file, store uploads outside the web root or in object storage, and serve them with ' +
        '`Content-Disposition: attachment` and a restrictive content type.',
      effort: 'medium',
      verificationSteps: [
        'Upload a file named `../../evil.txt` and confirm it lands inside the upload directory under a generated name.',
        'Upload a disallowed type and confirm rejection.',
        'Upload a file over the limit and confirm it is rejected before being fully buffered.',
      ],
      references: [OWASP.insecureDesign, 'CWE-434 Unrestricted Upload of File with Dangerous Type', 'CWE-22 Path Traversal'],
    }));
  }
  return out;
}

// -------------------------------------------------------------------- SSRF --

function serverSideRequestForgery(ctx: AnalyzerContext): Finding[] {
  const { map } = ctx;
  const out: Finding[] = [];

  const FETCHERS = /(?:^|\.)(?:fetch|get|post|put|request|head|axios|got|urlopen|urlretrieve)$/;

  for (const mod of map.modules.values()) {
    if (!mod.parsed) continue;
    const routesHere = map.routes.filter((r) => r.file === mod.path);
    if (routesHere.length === 0) continue;

    for (const call of mod.calls) {
      if (!FETCHERS.test(call.callee)) continue;
      const arg = call.args[0];
      if (!arg) continue;
      // A literal URL is not SSRF.
      if (/^['"`]https?:\/\//.test(arg.trim())) continue;
      if (/^['"`]\//.test(arg.trim())) continue;

      // The URL must trace back to request input.
      const enclosing = mod.symbols.find((s) => s.startLine <= call.line && s.endLine >= call.line);
      const scope = enclosing?.text ?? '';
      const varName = /^([A-Za-z_$][\w$]*)$/.exec(arg.trim())?.[1];
      const requestDerived =
        /\breq\b|\brequest\b|\bbody\b|\bparams?\b|\bquery\b|\bsearchParams\b/.test(arg)
        || (!!varName && new RegExp(
          `(?:const|let|var)\\s*\\{[^}]*\\b${varName}\\b[^}]*\\}\\s*=\\s*await\\s+(?:req|request)\\.|` +
          `(?:const|let|var)\\s+${varName}\\s*=\\s*[^;\\n]*(?:req|request|body|params|query|searchParams)\\b`,
        ).test(scope));
      if (!requestDerived) continue;

      const route = routesHere.find((r) => r.line !== undefined && enclosing && r.line >= enclosing.startLine && r.line <= enclosing.endLine)
        ?? routesHere[0]!;

      out.push(ctx.finding({
        ruleId: 'security.ssrf.request_derived_url',
        title: `${route.method} ${route.path} fetches a URL supplied in the request`,
        severity: 'high',
        confidence: 'strong',
        detectionSource: 'graph',
        files: [mod.path],
        symbol: call.inSymbol,
        evidence: [
          map.evidenceLine(mod.path, call.line, 'the destination URL comes from request input and is fetched without validation'),
        ],
        trace: {
          kind: 'import',
          steps: [
            { file: mod.path, line: route.line, symbol: route.handlerSymbol, detail: `${route.method} ${route.path} reads a URL from the request` },
            { file: mod.path, line: call.line, symbol: call.inSymbol, detail: `${call.callee}() is called with that value` },
          ],
          complete: true,
        },
        explanation:
          'The handler issues a server-side request to a URL taken from the request body or query. The server can usually reach ' +
          'addresses the caller cannot: cloud instance metadata endpoints, internal services, and localhost-bound admin interfaces.',
        userImpact:
          'An attacker can make the server fetch internal addresses and return the response to them — on many cloud providers that ' +
          'includes the instance metadata service and therefore credentials. It also turns the server into a proxy for scanning the ' +
          'internal network.',
        likelyRootCause: 'A feature that legitimately needs to fetch a remote resource was implemented without constraining where it may point.',
        downstreamConsequences: [
          'A blocklist of IP literals is not sufficient: DNS names, redirects, and alternative encodings bypass it.',
          'Returning the response body to the caller turns the flaw into a direct read of internal services.',
        ],
        remediation:
          'Constrain the destination: require https, resolve the hostname and reject private, loopback, link-local, and metadata ranges ' +
          '(checking after DNS resolution, and again on every redirect), prefer an allowlist of permitted hosts, disable redirect following ' +
          'or re-validate each hop, set a timeout and response size cap, and do not return the raw upstream body to the caller. ' +
          'Where possible route such requests through an egress proxy that enforces these rules centrally.',
        effort: 'medium',
        verificationSteps: [
          'Request `http://127.0.0.1/` and confirm it is rejected.',
          'Request `http://169.254.169.254/` and confirm it is rejected.',
          'Request a URL that redirects to a private address and confirm the redirect is rejected.',
          'Confirm legitimate allowed destinations still work.',
        ],
        references: [OWASP.ssrf, 'CWE-918 Server-Side Request Forgery'],
      }));
    }
  }
  return out;
}

// --------------------------------------------------------------------- XSS --

function crossSiteScripting(ctx: AnalyzerContext): Finding[] {
  const { map } = ctx;
  const out: Finding[] = [];

  for (const mod of map.modules.values()) {
    if (!mod.parsed) continue;

    for (const el of mod.jsx) {
      const attr = el.attrs.find((a) => a.name === 'dangerouslySetInnerHTML');
      if (!attr) continue;
      // A static literal is not a vulnerability.
      if (!attr.expression) continue;
      const value = attr.value ?? '';
      // A constant string or an explicitly sanitised value is acceptable.
      if (/\b(DOMPurify|sanitize|sanitise|xss|purify|clean)\b/i.test(value)) continue;

      out.push(ctx.finding({
        ruleId: 'security.xss.dangerous_inner_html',
        title: `Unsanitised value rendered as HTML in <${el.tag}>`,
        severity: 'high',
        confidence: 'strong',
        files: [mod.path],
        symbol: el.tag,
        evidence: [map.evidenceLine(mod.path, el.line, 'dangerouslySetInnerHTML receives a dynamic value with no sanitisation in this expression')],
        explanation:
          `A dynamic value is passed to dangerouslySetInnerHTML on <${el.tag}>, which bypasses React's automatic escaping. ` +
          'If any part of that value originates from user input or from stored data that a user can influence, the markup it contains ' +
          'executes in the browser of whoever views the page.',
        userImpact:
          'A visitor viewing this content can have script run in their session: their token can be stolen, actions can be performed as ' +
          'them, or the page can be rewritten to phish them. Stored content makes it persistent, affecting every viewer.',
        likelyRootCause: 'Rich text or markdown needed to render as HTML and the value was passed through unsanitised.',
        downstreamConsequences: [
          'A Content-Security-Policy reduces but does not eliminate the impact.',
          'Already-stored values may contain payloads: existing data needs review as well as the code fix.',
        ],
        remediation:
          'Render the value as text if it does not need to be HTML. If it must be HTML, sanitise it with a maintained sanitiser ' +
          '(DOMPurify or equivalent) using a strict allowlist of tags and attributes — ideally on write, server-side, so stored data is ' +
          'clean — and add a Content-Security-Policy that forbids inline script as defence in depth.',
        effort: 'small',
        verificationSteps: [
          'Store a value containing `<img src=x onerror=alert(1)>`, render the page, and confirm no script executes.',
          'Confirm legitimate formatting still renders.',
          'Confirm existing stored rows have been sanitised.',
        ],
        references: ['OWASP A03:2021 Injection', 'CWE-79 Cross-site Scripting'],
      }));
    }

    // innerHTML assignment and Vue's v-html carry the same risk.
    for (const sym of mod.symbols) {
      const m = /\.innerHTML\s*=\s*(?!['"`])([A-Za-z_$][\w$.]*)/.exec(sym.text);
      if (!m) continue;
      if (/\b(DOMPurify|sanitize|sanitise|purify)\b/i.test(sym.text)) continue;
      out.push(ctx.finding({
        ruleId: 'security.xss.inner_html_assignment',
        title: 'Dynamic value assigned to innerHTML',
        severity: 'high',
        confidence: 'moderate',
        files: [mod.path],
        symbol: sym.name,
        evidence: [map.evidenceAt(mod.path, m[0], 'dynamic value assigned to innerHTML without sanitisation')],
        explanation:
          'A dynamic value is assigned to innerHTML, which parses it as markup. Any script in the value executes in the user\'s browser.',
        userImpact: 'A visitor can have script run in their session, exposing their token and allowing actions to be taken as them.',
        remediation:
          'Use textContent when the value is text. If markup is required, sanitise with a maintained allowlist-based sanitiser before assignment.',
        effort: 'small',
        verificationSteps: ['Supply a value containing a script tag and confirm it does not execute.'],
        references: ['CWE-79 Cross-site Scripting'],
      }));
    }
  }
  return out;
}

// ------------------------------------------------------- security headers ---

function securityHeaders(ctx: AnalyzerContext): Finding[] {
  const { map } = ctx;
  const out: Finding[] = [];

  const isNext = map.hasTech('Next.js');
  const isExpress = map.hasTech('Express');
  if (!isNext && !isExpress) return out;

  // Any evidence of security headers being set anywhere in the project.
  //
  // Comments are stripped before matching. Without that, a config file whose
  // comment explains that no CSP is set contains the very words this check
  // looks for, and the finding is silently suppressed.
  const HEADER_RE = /(?:helmet|Content-Security-Policy|Strict-Transport-Security|X-Content-Type-Options|Referrer-Policy|X-Frame-Options|contentSecurityPolicy)/i;
  let headerEvidence: { file: string; line: number } | undefined;

  for (const mod of map.modules.values()) {
    if (!mod.parsed) continue;
    // String literals and object keys are code, not prose.
    const literals = mod.stringLiterals.map((l) => l.value).join('\n');
    const keys = mod.objectLiterals.flatMap((o) => o.keys).join('\n');
    if (HEADER_RE.test(literals) || HEADER_RE.test(keys)
      || mod.imports.some((i) => /helmet|next-safe|nosniff/.test(i.specifier))) {
      headerEvidence = { file: mod.path, line: 1 };
      break;
    }
  }
  if (!headerEvidence) {
    for (const f of map.files) {
      if (!f.text) continue;
      if (f.role !== 'config' && f.role !== 'infrastructure') continue;
      if (map.modules.get(f.path)?.parsed) continue; // already checked via its AST
      if (HEADER_RE.test(codeText(f.text, f.language))) {
        headerEvidence = { file: f.path, line: 1 };
        break;
      }
    }
  }
  if (headerEvidence) return out;

  const configFile = map.files.find((f) => /^(?:src\/)?next\.config\.[cm]?[jt]s$/.test(f.path))
    ?? map.files.find((f) => f.role === 'config' && /next\.config/.test(f.path))
    ?? map.files.find((f) => f.role === 'manifest');
  if (!configFile) return out;

  out.push(ctx.finding({
    ruleId: 'security.config.missing_security_headers',
    title: 'No HTTP security headers are configured',
    severity: 'medium',
    confidence: 'strong',
    files: [configFile.path],
    evidence: [{
      file: configFile.path,
      startLine: 1,
      excerpt: configFile.text?.split('\n').find((l) => l.trim().length > 0)?.trim().slice(0, 200),
      note: isNext
        ? 'no headers() entry in the Next.js config and no header middleware found anywhere in the project'
        : 'no helmet or equivalent header middleware found anywhere in the project',
      verified: true,
    }],
    explanation:
      'No Content-Security-Policy, Strict-Transport-Security, X-Content-Type-Options, or Referrer-Policy header is set anywhere in the ' +
      'project. These headers are the browser-side defences that limit the damage of other flaws: CSP constrains what a successful ' +
      'script injection can do, HSTS prevents downgrade to plain HTTP, and nosniff stops a response being reinterpreted as script.',
    userImpact:
      'Users are more exposed to consequences of other defects: an injected script faces fewer restrictions, a first visit can be ' +
      'intercepted over HTTP, and the full URL — including any identifiers in it — leaks to third-party sites through the referrer.',
    likelyRootCause: 'Header configuration is not on by default in most frameworks and is easy to leave until later.',
    downstreamConsequences: [
      'A strict CSP usually needs iteration against the real page to avoid breaking legitimate scripts.',
      'HSTS is hard to roll back once a long max-age is cached by browsers: start with a short one.',
    ],
    remediation: isNext
      ? 'Add a `headers()` entry to next.config.js returning Content-Security-Policy, Strict-Transport-Security, X-Content-Type-Options: nosniff, ' +
        'Referrer-Policy: strict-origin-when-cross-origin, and a restrictive Permissions-Policy. Develop the CSP in report-only mode first, ' +
        'then enforce it, and begin HSTS with a short max-age before raising it.'
      : 'Add helmet (or equivalent) early in the middleware chain, then tune the Content-Security-Policy for the application\'s real asset ' +
        'origins. Develop the CSP in report-only mode first, and begin HSTS with a short max-age before raising it.',
    effort: 'small',
    verificationSteps: [
      'Request a page and inspect the response headers for each of the four headers.',
      'Confirm the page still works with the CSP enforced, checking the browser console for violations.',
      'Confirm HSTS is only sent over HTTPS.',
    ],
    references: [OWASP.misconfig, 'OWASP Secure Headers Project'],
  }));
  return out;
}

// --------------------------------------------------- credential storage -----

function credentialStorage(ctx: AnalyzerContext): Finding[] {
  const { map } = ctx;
  const out: Finding[] = [];

  for (const model of map.models) {
    const pwField = model.fields.find((f) => /^(?:password|passwd|pwd|secret)$/i.test(f.name));
    if (!pwField) continue;
    // A column named for a hash is the correct design.
    if (/hash|digest|encrypted/i.test(pwField.name)) continue;

    const hashingAnywhere = [...map.modules.values()].some(
      (m) => m.parsed && (
        m.imports.some((i) => /bcrypt|argon2|scrypt|pbkdf2|passlib|werkzeug\.security/.test(i.specifier))
        || m.calls.some((c) => /\b(hash|hashSync|genSalt|pbkdf2|argon2)\b/.test(c.callee))
      ),
    );

    out.push(ctx.finding({
      ruleId: 'security.storage.credential_column',
      title: `${model.name}.${pwField.name} stores a credential in a column with no hashing indicated`,
      severity: hashingAnywhere ? 'medium' : 'high',
      confidence: hashingAnywhere ? 'moderate' : 'strong',
      files: [model.file],
      symbol: model.name,
      evidence: [
        map.evidenceAt(model.file, pwField.name,
          hashingAnywhere
            ? 'column holds a credential; a hashing library is present elsewhere in the project, so confirm it is applied on this path'
            : 'column holds a credential and no password hashing library was found anywhere in the project'),
      ],
      explanation:
        `The ${model.name} model stores a credential in '${pwField.name}'. The column name does not indicate a hash, and ` +
        (hashingAnywhere
          ? 'although a hashing library exists in the project, it could not be tied to writes on this column — verify the write path.'
          : 'no password hashing library (bcrypt, argon2, scrypt, PBKDF2, or passlib) appears anywhere in the project, which indicates the ' +
            'value is stored as given.'),
      userImpact:
        'If this column holds raw credentials, a single read of the database — through a backup, a log, an injection flaw, or an insider — ' +
        'exposes every user\'s password, including on other services where those passwords are reused.',
      remediation:
        'Store only a verifier produced by a memory-hard password hash (argon2id preferred, otherwise scrypt or bcrypt) with a per-user salt. ' +
        `Rename the column to make that explicit (for example '${pwField.name}_hash'), migrate by hashing on next successful login, and drop ` +
        'the old column once no rows depend on it.',
      effort: 'medium',
      verificationSteps: [
        'Inspect a stored row and confirm the value carries an algorithm identifier rather than a readable password.',
        'Confirm login works after the migration for both new and migrated accounts.',
        'Confirm no code path writes the raw value.',
      ],
      references: [OWASP.crypto, 'CWE-257 Storing Passwords in a Recoverable Format'],
    }));
  }
  return out;
}
