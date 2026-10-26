import type { ApiEndpoint } from '@codelens/core';
import type { ParsedModule, SymbolInfo } from '../parse/types.ts';

/**
 * API surface extraction.
 *
 * Routes are read from the structures that actually define them — exported HTTP
 * handlers, router calls, framework decorators — not from file names. For each
 * route we also record whether authentication and authorisation are enforced
 * *inside that handler*, which is the input the authorisation analyzer needs.
 *
 * `authRequired: 'unknown'` is used wherever enforcement might happen somewhere
 * we cannot see (middleware we did not model). The analyzer treats `unknown`
 * differently from `public`, so an unresolved case cannot become a confirmed
 * finding.
 */

const HTTP_METHODS = new Set(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']);

/** Functions whose presence in a handler indicates an authentication check. */
const AUTH_CALLS = [
  'getSession', 'getServerSession', 'verifySession', 'auth', 'requireAuth',
  'requireUser', 'currentUser', 'getToken', 'getUser', 'authenticate',
  'verifyToken', 'verifyJWT', 'clerkClient', 'getAuth', 'validateRequest',
  'checkAuth', 'isAuthenticated', 'get_current_user', 'login_required',
];

/**
 * A project's *own* authentication helper, recognised by shape.
 *
 * The list above covers the framework helpers. It cannot cover what a project
 * calls its own: `sessionOr401`, `requireSession`, `ensureViewer`,
 * `assert_current_user` are all ordinary choices, and a route using one is
 * authenticated. Judging only by the fixed list reports those routes as
 * unauthenticated — a high-severity false positive on correct code, which is
 * the single most expensive kind this tool can emit.
 *
 * The shape required is deliberately narrow: a verb that means "obtain or
 * demand" next to a noun that means "caller identity". `getSessionId`,
 * `createSession` (issuing one, not checking one) and `sessionStorage` do not
 * match, so a route that merely mentions sessions is not credited with checking
 * one.
 */
const PROJECT_AUTH_CALL = new RegExp(
  '^(?:'
  + '(?:require|ensure|assert|current|read|load|resolve|verify|check|validate|get)'
  + '[_]?'
  + '(?:session|viewer|identity|principal|current[_]?user|auth(?:enticated)?[_]?(?:user|session)?)'
  + '|'
  + '(?:session|viewer|identity|principal)[_]?(?:or[_]?401|or[_]?throw|or[_]?fail|required|guard)'
  + ')$',
  'i',
);

/** Whether a called name is an authentication check, by list or by shape. */
function isAuthCall(name: string): boolean {
  return AUTH_CALLS.includes(name) || PROJECT_AUTH_CALL.test(name);
}

/**
 * Authorisation detection is bound to the *actual session variable*.
 *
 * Matching the bare word "user" is not good enough: in
 * `prisma.order.findMany({ where: { userId: user.id } })` inside a loop over
 * every user, `user` is a loop variable, not the caller. Reading that as an
 * ownership check would hide a critical authorisation hole. So we first find
 * what the auth call was assigned to, then require the check to reference that
 * binding.
 */
function authzPatternsFor(identityRoots: string[]): Array<{ re: RegExp; label: string }> {
  const roots = identityRoots.length > 0 ? identityRoots : [];
  const alt = roots.map((r) => r.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|');
  const patterns: Array<{ re: RegExp; label: string }> = [];

  if (alt) {
    patterns.push(
      { re: new RegExp(`\\b(?:userId|user_id|ownerId|owner_id|accountId|organizationId|tenantId)\\s*:\\s*(?:${alt})\\b`), label: 'query scoped to the authenticated identity' },
      { re: new RegExp(`\\b(?:${alt})\\??\\.(?:userId|id|sub)\\s*(?:===|==|!==|!=)`), label: 'identity comparison against the session' },
      { re: new RegExp(`(?:===|==|!==|!=)\\s*(?:${alt})\\??\\.(?:userId|id|sub)\\b`), label: 'identity comparison against the session' },
      { re: new RegExp(`\\b(?:${alt})\\??\\.(?:role|isAdmin|is_admin|permissions?|scopes?)\\b`), label: 'role or permission check on the session' },
    );
  }
  // Explicit authorisation helpers are meaningful regardless of binding.
  patterns.push(
    { re: /\b(?:can|authorize|authorise|enforce|assert)(?:Access|Owner|Permission|Can)?\s*\(/, label: 'authorisation helper call' },
    { re: /\b(?:ability|permit|policy)\.\w+\s*\(/, label: 'authorisation policy call' },
    { re: /\bforbidden\s*\(|\bthrow\s+new\s+ForbiddenException/, label: 'explicit forbidden path' },
  );
  return patterns;
}

/**
 * Names that hold the authenticated identity in this handler: whatever the auth
 * call was assigned to, plus destructured bindings from it.
 */
function identityRootsIn(body: string): string[] {
  const roots = new Set<string>();
  const authAlt = [
    ...AUTH_CALLS.map((c) => c.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')),
    // Keeps the identity-root scan in step with `isAuthCall`, so a project's
    // own helper also contributes the binding that ownership checks are
    // matched against.
    '(?:require|ensure|assert|current|read|load|resolve|verify|check|validate|get)_?(?:session|viewer|identity|principal|current_?user|auth(?:enticated)?_?(?:user|session)?)',
    '(?:session|viewer|identity|principal)_?(?:or_?401|or_?throw|or_?fail|required|guard)',
  ].join('|');

  // const session = await getSession(req)
  for (const m of body.matchAll(new RegExp(`(?:const|let|var)\\s+(\\w+)\\s*=\\s*(?:await\\s+)?(?:\\w+\\.)*(?:${authAlt})\\s*\\(`, 'g'))) {
    roots.add(m[1]!);
  }
  // const { user } = await auth()  /  const { userId } = getAuth(req)
  for (const m of body.matchAll(new RegExp(`(?:const|let|var)\\s*\\{([^}]{1,120})\\}\\s*=\\s*(?:await\\s+)?(?:\\w+\\.)*(?:${authAlt})\\s*\\(`, 'g'))) {
    for (const part of m[1]!.split(',')) {
      const name = part.split(':').pop()!.trim();
      if (/^\w+$/.test(name)) roots.add(name);
    }
  }
  // Python: user = Depends(get_current_user) / current_user injected as a param
  for (const m of body.matchAll(/(\w+)\s*[:=][^,)\n]*Depends\s*\(/g)) roots.add(m[1]!);
  if (/\bcurrent_user\b/.test(body)) roots.add('current_user');
  return [...roots];
}

/** Validation libraries and manual checks that indicate request validation. */
const VALIDATION_PATTERNS = [
  /\b(z|yup|joi|v)\.(object|string|number|array|boolean)\b/,
  /\.(safeParse|parseAsync|parse|validate|validateSync)\s*\(/,
  /\b(BaseModel|Field)\b/,
  /\bclass-validator\b/,
  /\bif\s*\(\s*!?\s*(body|payload|input|data)\b[^)]*\)\s*(return|throw)/,
];

function bodyOf(mod: ParsedModule, sym: SymbolInfo): string {
  return sym.text;
}

function detectAuth(mod: ParsedModule, sym: SymbolInfo): {
  authRequired: ApiEndpoint['authRequired'];
  authorizationChecks: string[];
} {
  const body = bodyOf(mod, sym);

  const callsInSymbol = mod.calls.filter(
    (c) => c.line >= sym.startLine && c.line <= sym.endLine,
  );
  const authCall = callsInSymbol.find((c) => {
    const leaf = c.callee.split('.').pop() ?? '';
    return isAuthCall(leaf) || isAuthCall(c.callee);
  });

  // Python decorators can carry the auth requirement.
  const decoratorAuth = (sym.decorators ?? []).some((d) =>
    /Depends\s*\(|login_required|requires_auth|permission_classes|IsAuthenticated/.test(d),
  );

  const identityRoots = identityRootsIn(body);
  const authorizationChecks: string[] = [];
  for (const { re, label } of authzPatternsFor(identityRoots)) {
    if (re.test(body) && !authorizationChecks.includes(label)) authorizationChecks.push(label);
  }

  let authRequired: ApiEndpoint['authRequired'];
  if (authCall || decoratorAuth) {
    // An auth call alone is not enforcement; there must be a rejection path.
    const rejects = /\b(return|throw)\b[^;]{0,120}(401|403|unauthoriz|unauthenticated|forbidden|redirect)/i.test(body)
      || /if\s*\(\s*!\s*(session|user|auth|currentUser|token)\b/.test(body)
      || decoratorAuth;
    authRequired = rejects ? 'required' : 'unknown';
  } else {
    authRequired = 'public';
  }

  return { authRequired, authorizationChecks };
}

function detectValidation(sym: SymbolInfo): ApiEndpoint['validation'] {
  const body = sym.text;
  const readsInput = /\b(req|request)\.(json|body|formData|query|params)|await\s+req\.json\(\)|request\.get_json/.test(body);
  if (!readsInput) return 'unknown';
  const hits = VALIDATION_PATTERNS.filter((re) => re.test(body)).length;
  if (hits >= 2) return 'present';
  if (hits === 1) return 'partial';
  return 'absent';
}

function detectErrorHandling(mod: ParsedModule, sym: SymbolInfo): ApiEndpoint['errorHandling'] {
  const body = sym.text;
  if (/\btry\s*[{:]/.test(body)) return 'present';
  if (/\.catch\s*\(/.test(body)) return 'present';
  if (/\b(status|HTTPException|abort)\b/.test(body) && /\b(4\d\d|5\d\d)\b/.test(body)) return 'partial';
  return 'absent';
}

/**
 * Response shape: the keys of the object actually handed to the response.
 *
 * The widest object literal in a handler is usually a query argument, not the
 * response body, so the response call is matched first. This shape is what the
 * contract analyzer compares against what the frontend reads, so getting it
 * from the wrong literal would produce false contract breaks.
 */
const RESPONSE_CALL_RE = /(?:NextResponse|Response|res|reply|response)\s*\.\s*json\s*\(|\bjsonify\s*\(|\bJSONResponse\s*\(|\bres\.send\s*\(/;

function detectResponseShape(mod: ParsedModule, sym: SymbolInfo): string | undefined {
  const body = sym.text;
  const keySets: string[][] = [];

  // Find each response call and take the keys of the object literal that
  // immediately follows it, by brace matching from the call's open paren.
  for (const m of body.matchAll(new RegExp(RESPONSE_CALL_RE.source, 'g'))) {
    const openParen = body.indexOf('(', m.index! + m[0].length - 1);
    if (openParen === -1) continue;
    const rest = body.slice(openParen + 1).trimStart();
    if (!rest.startsWith('{')) continue;
    const start = body.indexOf('{', openParen);
    let depth = 0;
    let end = -1;
    for (let i = start; i < body.length; i++) {
      if (body[i] === '{') depth++;
      else if (body[i] === '}') { depth--; if (depth === 0) { end = i; break; } }
    }
    if (end === -1) continue;
    const inner = body.slice(start + 1, end);
    // Top-level keys only: skip nested object contents.
    const keys: string[] = [];
    let nest = 0;
    let token = '';
    for (const ch of inner) {
      if (ch === '{' || ch === '[' || ch === '(') nest++;
      else if (ch === '}' || ch === ']' || ch === ')') nest--;
      if (ch === ',' && nest === 0) { pushKey(token, keys); token = ''; continue; }
      token += ch;
    }
    pushKey(token, keys);
    if (keys.length) keySets.push(keys);
  }

  if (keySets.length > 0) {
    // A handler with several response paths exposes the union of their keys.
    return [...new Set(keySets.flat())].join(',');
  }

  const literals = mod.objectLiterals.filter(
    (o) => o.line >= sym.startLine && o.line <= sym.endLine,
  );
  const widest = literals.sort((a, b) => b.keys.length - a.keys.length)[0];
  return widest && widest.keys.length > 0 ? widest.keys.join(',') : undefined;
}

function pushKey(token: string, keys: string[]): void {
  const t = token.trim();
  if (!t) return;
  if (t.startsWith('...')) return; // spread: contents unknown here
  const name = t.split(':')[0]!.trim().replace(/^['"`]|['"`]$/g, '');
  if (/^\w+$/.test(name)) keys.push(name);
}

function detectRequestShape(sym: SymbolInfo): string | undefined {
  const m = /\b(?:const|let)\s*\{([^}]{1,200})\}\s*=\s*await\s+(?:req|request)\.json\(\)/.exec(sym.text);
  if (m) return m[1]!.split(',').map((s) => s.trim().split(':')[0]!.trim()).filter(Boolean).join(',');
  return undefined;
}

/** Convert a Next.js app-router file path to its URL path. */
export function nextAppRoutePath(filePath: string): string | undefined {
  const m = /(?:^|\/)app\/(.+)\/route\.[cm]?[jt]sx?$/.exec(filePath);
  if (!m) return undefined;
  const segments = m[1]!.split('/')
    // Route groups `(group)` and private folders `_x` do not appear in the URL.
    .filter((s) => !(s.startsWith('(') && s.endsWith(')')))
    .filter((s) => !s.startsWith('_'));
  return `/${segments.join('/')}`;
}

/** Convert a Next.js pages/api file path to its URL path. */
export function nextPagesApiPath(filePath: string): string | undefined {
  const m = /(?:^|\/)pages\/api\/(.+)\.[cm]?[jt]sx?$/.exec(filePath);
  if (!m) return undefined;
  const p = m[1]!.replace(/\/index$/, '');
  return `/api/${p}`;
}

export function extractRoutes(modules: Map<string, ParsedModule>): ApiEndpoint[] {
  const out: ApiEndpoint[] = [];

  for (const mod of modules.values()) {
    if (!mod.parsed) continue;

    // ---- Next.js app router: exported GET/POST/... in app/**/route.ts ----
    const appPath = nextAppRoutePath(mod.path);
    if (appPath) {
      for (const sym of mod.symbols) {
        if (!HTTP_METHODS.has(sym.name) || !sym.exported) continue;
        const { authRequired, authorizationChecks } = detectAuth(mod, sym);
        out.push({
          method: sym.name, path: appPath, file: mod.path, line: sym.startLine,
          handlerSymbol: sym.name, authRequired, authorizationChecks,
          requestShape: detectRequestShape(sym),
          responseShape: detectResponseShape(mod, sym),
          validation: detectValidation(sym),
          errorHandling: detectErrorHandling(mod, sym),
        });
      }
      continue;
    }

    // ---- Next.js pages/api: default export handler ----
    const pagesPath = nextPagesApiPath(mod.path);
    if (pagesPath) {
      const sym = mod.symbols.find((s) => s.exported) ?? mod.symbols[0];
      if (sym) {
        const { authRequired, authorizationChecks } = detectAuth(mod, sym);
        // Methods are branched on inside the handler.
        const methods = [...sym.text.matchAll(/method\s*===?\s*['"](\w+)['"]/g)].map((m) => m[1]!.toUpperCase());
        for (const method of methods.length ? [...new Set(methods)] : ['ANY']) {
          out.push({
            method, path: pagesPath, file: mod.path, line: sym.startLine,
            handlerSymbol: sym.name, authRequired, authorizationChecks,
            requestShape: detectRequestShape(sym),
            responseShape: detectResponseShape(mod, sym),
            validation: detectValidation(sym),
            errorHandling: detectErrorHandling(mod, sym),
          });
        }
      }
      continue;
    }

    // ---- Express / Fastify / Koa router calls ----
    for (const call of mod.calls) {
      const m = /^(app|router|server|api|fastify|r)\.(get|post|put|patch|delete|all|use)$/.exec(call.callee);
      if (!m) continue;
      const method = m[2]!.toUpperCase();
      if (method === 'USE' || method === 'ALL') continue;
      const first = call.args[0] ?? '';
      const pathMatch = /^['"`](.+?)['"`]$/.exec(first.trim());
      if (!pathMatch) continue;
      // The handler is the enclosing symbol's text if we cannot isolate it;
      // the inline callback argument is a better approximation.
      const handlerText = call.args.slice(1).join(' ');
      const pseudo: SymbolInfo = {
        name: call.inSymbol ?? `${method} ${pathMatch[1]}`,
        kind: 'arrow', exported: false, async: /async/.test(handlerText),
        startLine: call.line, endLine: call.line, params: [], text: handlerText,
      };
      const { authRequired, authorizationChecks } = detectAuth(mod, pseudo);
      out.push({
        method, path: pathMatch[1]!, file: mod.path, line: call.line,
        handlerSymbol: call.inSymbol, authRequired, authorizationChecks,
        requestShape: detectRequestShape(pseudo),
        responseShape: undefined,
        validation: detectValidation(pseudo),
        errorHandling: detectErrorHandling(mod, pseudo),
      });
    }

    // ---- Python decorators: FastAPI / Flask ----
    for (const sym of mod.symbols) {
      for (const dec of sym.decorators ?? []) {
        const m = /@(?:\w+)\.(get|post|put|patch|delete|route)\s*\(\s*['"]([^'"]+)['"]/.exec(dec);
        if (!m) continue;
        let method = m[1]!.toUpperCase();
        if (method === 'ROUTE') {
          const mm = /methods\s*=\s*\[([^\]]+)\]/.exec(dec);
          method = mm ? mm[1]!.replace(/['"\s]/g, '').split(',')[0]!.toUpperCase() : 'GET';
        }
        const { authRequired, authorizationChecks } = detectAuth(mod, sym);
        out.push({
          method, path: m[2]!, file: mod.path, line: sym.startLine,
          handlerSymbol: sym.name, authRequired, authorizationChecks,
          requestShape: detectRequestShape(sym),
          responseShape: detectResponseShape(mod, sym),
          validation: detectValidation(sym),
          errorHandling: detectErrorHandling(mod, sym),
        });
      }
    }
  }

  // Deduplicate on (method, path, file).
  const seen = new Set<string>();
  return out.filter((e) => {
    const k = `${e.method} ${e.path} ${e.file}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}
