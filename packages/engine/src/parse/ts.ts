import ts from 'typescript';
import type {
  CallRef, ImportRef, JsxAttr, JsxElement, MemberAccess,
  ObjectLiteralShape, ParsedModule, SymbolInfo, SymbolKind,
} from './types.ts';
import { emptyModule } from './types.ts';

/**
 * TypeScript / JavaScript / TSX / JSX parsing via the TypeScript compiler API.
 *
 * Single-file parsing only: no type checker and no program-wide resolution, so
 * parsing one file never requires the whole repository to typecheck. Import
 * resolution is handled separately in graph/resolve.ts against the real file
 * list, which is what lets a cross-file claim cite both ends.
 */

const MAX_TEXT = 1200;
const MAX_ARG = 200;

function scriptKindFor(language: string): ts.ScriptKind {
  switch (language) {
    case 'tsx': return ts.ScriptKind.TSX;
    case 'jsx': return ts.ScriptKind.JSX;
    case 'javascript': return ts.ScriptKind.JS;
    default: return ts.ScriptKind.TS;
  }
}

/** Flatten `a.b.c` / `a?.b` into a dotted string. */
function calleeName(node: ts.Expression): string {
  if (ts.isIdentifier(node)) return node.text;
  if (ts.isPropertyAccessExpression(node)) {
    return `${calleeName(node.expression)}.${node.name.getText()}`;
  }
  if (ts.isElementAccessExpression(node)) return `${calleeName(node.expression)}[]`;
  if (ts.isCallExpression(node)) return `${calleeName(node.expression)}()`;
  if (ts.isNonNullExpression(node) || ts.isParenthesizedExpression(node)) {
    return calleeName(node.expression);
  }
  if (node.kind === ts.SyntaxKind.ThisKeyword) return 'this';
  return node.getText().slice(0, 60);
}

/** Root identifier of a member access chain. */
function rootObject(node: ts.Expression): string | undefined {
  if (ts.isIdentifier(node)) return node.text;
  if (ts.isPropertyAccessExpression(node)) return rootObject(node.expression);
  if (ts.isNonNullExpression(node) || ts.isParenthesizedExpression(node)) return rootObject(node.expression);
  return undefined;
}

function isExported(node: ts.Node): boolean {
  const mods = ts.canHaveModifiers(node) ? ts.getModifiers(node) : undefined;
  return !!mods?.some((m) => m.kind === ts.SyntaxKind.ExportKeyword);
}

function isAsync(node: ts.Node): boolean {
  const mods = ts.canHaveModifiers(node) ? ts.getModifiers(node) : undefined;
  return !!mods?.some((m) => m.kind === ts.SyntaxKind.AsyncKeyword);
}

const LOOP_KINDS = new Set<ts.SyntaxKind>([
  ts.SyntaxKind.ForStatement, ts.SyntaxKind.ForOfStatement,
  ts.SyntaxKind.ForInStatement, ts.SyntaxKind.WhileStatement,
  ts.SyntaxKind.DoStatement,
]);

const LOOP_CALLBACKS = new Set(['forEach', 'map', 'filter', 'reduce', 'flatMap', 'some', 'every']);

export function parseTypeScript(path: string, source: string, language: string): ParsedModule {
  let sf: ts.SourceFile;
  try {
    sf = ts.createSourceFile(path, source, ts.ScriptTarget.Latest, true, scriptKindFor(language));
  } catch (e) {
    return emptyModule(path, language, `TypeScript parse failed: ${(e as Error).message}`);
  }

  const imports: ImportRef[] = [];
  const exports: string[] = [];
  const symbols: SymbolInfo[] = [];
  const calls: CallRef[] = [];
  const jsx: JsxElement[] = [];
  const memberAccesses: MemberAccess[] = [];
  const objectLiterals: ObjectLiteralShape[] = [];
  const envVars = new Set<string>();
  const stringLiterals: Array<{ value: string; line: number }> = [];
  let hasTryCatch = false;

  const lineOf = (node: ts.Node): number =>
    sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1;

  // Walk state: current symbol and loop depth, so calls can be attributed.
  let currentSymbol: string | undefined;
  let loopDepth = 0;

  const recordSymbol = (
    name: string, kind: SymbolKind, node: ts.Node, params: string[], parent?: string,
  ): void => {
    symbols.push({
      name, kind,
      exported: isExported(node),
      async: isAsync(node),
      startLine: lineOf(node),
      endLine: sf.getLineAndCharacterOfPosition(node.getEnd()).line + 1,
      params,
      text: node.getText(sf).slice(0, MAX_TEXT),
      parent,
    });
    if (isExported(node)) exports.push(name);
  };

  const paramNames = (node: ts.SignatureDeclarationBase): string[] =>
    node.parameters.map((p) => p.name.getText(sf).slice(0, 60));

  const visit = (node: ts.Node): void => {
    // ---- imports / exports ----
    if (ts.isImportDeclaration(node) && ts.isStringLiteral(node.moduleSpecifier)) {
      const names: string[] = [];
      const clause = node.importClause;
      if (clause?.name) names.push('default');
      if (clause?.namedBindings) {
        if (ts.isNamespaceImport(clause.namedBindings)) names.push('*');
        else for (const el of clause.namedBindings.elements) names.push(el.name.text);
      }
      const spec = node.moduleSpecifier.text;
      imports.push({ specifier: spec, names, line: lineOf(node), external: !spec.startsWith('.') });
    }
    if (ts.isExportDeclaration(node) && node.exportClause && ts.isNamedExports(node.exportClause)) {
      for (const el of node.exportClause.elements) exports.push(el.name.text);
    }
    if (ts.isCallExpression(node) && node.expression.kind === ts.SyntaxKind.ImportKeyword) {
      const arg = node.arguments[0];
      if (arg && ts.isStringLiteral(arg)) {
        imports.push({ specifier: arg.text, names: ['*'], line: lineOf(node), external: !arg.text.startsWith('.') });
      }
    }
    if (ts.isCallExpression(node) && ts.isIdentifier(node.expression) && node.expression.text === 'require') {
      const arg = node.arguments[0];
      if (arg && ts.isStringLiteral(arg)) {
        imports.push({ specifier: arg.text, names: ['*'], line: lineOf(node), external: !arg.text.startsWith('.') });
      }
    }

    // ---- symbols ----
    let enteredSymbol: string | undefined;
    if (ts.isFunctionDeclaration(node) && node.name) {
      recordSymbol(node.name.text, 'function', node, paramNames(node));
      enteredSymbol = node.name.text;
    } else if (ts.isClassDeclaration(node) && node.name) {
      recordSymbol(node.name.text, 'class', node, []);
      enteredSymbol = node.name.text;
    } else if (ts.isMethodDeclaration(node) && ts.isIdentifier(node.name)) {
      const parent = ts.isClassDeclaration(node.parent) && node.parent.name ? node.parent.name.text : undefined;
      recordSymbol(node.name.text, 'method', node, paramNames(node), parent);
      enteredSymbol = node.name.text;
    } else if (ts.isInterfaceDeclaration(node)) {
      recordSymbol(node.name.text, 'interface', node, []);
      // Interface members are the declared contract: record them as the shape a
      // consumer expects, so a missing backend field is traceable.
      objectLiterals.push({
        keys: node.members
          .map((m) => (m.name && ts.isIdentifier(m.name) ? m.name.text : undefined))
          .filter((x): x is string => !!x),
        line: lineOf(node),
        inSymbol: node.name.text,
      });
    } else if (ts.isTypeAliasDeclaration(node)) {
      recordSymbol(node.name.text, 'type', node, []);
      if (ts.isTypeLiteralNode(node.type)) {
        objectLiterals.push({
          keys: node.type.members
            .map((m) => (m.name && ts.isIdentifier(m.name) ? m.name.text : undefined))
            .filter((x): x is string => !!x),
          line: lineOf(node),
          inSymbol: node.name.text,
        });
      }
    } else if (ts.isEnumDeclaration(node)) {
      recordSymbol(node.name.text, 'enum', node, []);
    } else if (ts.isVariableStatement(node)) {
      for (const decl of node.declarationList.declarations) {
        if (!ts.isIdentifier(decl.name)) continue;
        const init = decl.initializer;
        const isFn = !!init && (ts.isArrowFunction(init) || ts.isFunctionExpression(init));
        const kind: SymbolKind = isFn ? 'arrow' : 'const';
        symbols.push({
          name: decl.name.text, kind,
          exported: isExported(node),
          async: !!init && isAsync(init),
          startLine: lineOf(decl),
          endLine: sf.getLineAndCharacterOfPosition(decl.getEnd()).line + 1,
          params: isFn ? paramNames(init as ts.SignatureDeclarationBase) : [],
          text: decl.getText(sf).slice(0, MAX_TEXT),
        });
        if (isExported(node)) exports.push(decl.name.text);
        if (isFn) enteredSymbol = decl.name.text;
      }
    }

    // ---- calls ----
    if (ts.isCallExpression(node)) {
      const callee = calleeName(node.expression);
      const parent = node.parent;
      const awaited = !!parent && ts.isAwaitExpression(parent);
      const isLoopCallback = LOOP_CALLBACKS.has(callee.split('.').pop() ?? '');
      calls.push({
        callee,
        args: node.arguments.map((a) => a.getText(sf).slice(0, MAX_ARG)),
        line: lineOf(node),
        inSymbol: currentSymbol,
        insideLoop: loopDepth > 0,
        awaited,
      });
      // A call whose argument is a function body executed per element behaves
      // like a loop for N+1 purposes.
      if (isLoopCallback && node.arguments.some((a) => ts.isArrowFunction(a) || ts.isFunctionExpression(a))) {
        loopDepth++;
        for (const a of node.arguments) visit(a);
        loopDepth--;
        // Children already visited inside the elevated loop depth.
        ts.forEachChild(node.expression, visit);
        return;
      }
    }

    // ---- env vars ----
    if (ts.isPropertyAccessExpression(node)) {
      const chain = calleeName(node);
      const envMatch = /^process\.env\.([A-Za-z_][A-Za-z0-9_]*)$/.exec(chain);
      if (envMatch) envVars.add(envMatch[1]!);
      const root = rootObject(node.expression);
      if (root && ts.isIdentifier(node.name)) {
        memberAccesses.push({ object: root, property: node.name.text, line: lineOf(node), inSymbol: currentSymbol });
      }
    }
    if (ts.isElementAccessExpression(node)) {
      const chain = calleeName(node.expression);
      const arg = node.argumentExpression;
      if (chain === 'process.env' && arg && ts.isStringLiteral(arg)) envVars.add(arg.text);
    }

    // ---- object literals (response shapes) ----
    if (ts.isObjectLiteralExpression(node)) {
      const keys = node.properties
        .map((p) => (p.name && (ts.isIdentifier(p.name) || ts.isStringLiteral(p.name)) ? p.name.text : undefined))
        .filter((x): x is string => !!x);
      if (keys.length > 0) {
        objectLiterals.push({ keys, line: lineOf(node), inSymbol: currentSymbol });
      }
    }

    // ---- strings ----
    if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) {
      if (node.text.length > 0 && node.text.length < 500) {
        stringLiterals.push({ value: node.text, line: lineOf(node) });
      }
    }
    if (ts.isTemplateExpression(node)) {
      // Record the literal skeleton so SQL-injection analysis can see the
      // interpolation points.
      const skeleton = node.head.text + node.templateSpans.map((s) => `\${...}${s.literal.text}`).join('');
      if (skeleton.length < 500) stringLiterals.push({ value: skeleton, line: lineOf(node) });
    }

    // ---- JSX ----
    if (ts.isJsxElement(node) || ts.isJsxSelfClosingElement(node)) {
      const opening = ts.isJsxElement(node) ? node.openingElement : node;
      const tag = opening.tagName.getText(sf);
      const attrs: JsxAttr[] = [];
      for (const a of opening.attributes.properties) {
        if (!ts.isJsxAttribute(a)) continue;
        const name = a.name.getText(sf);
        const init = a.initializer;
        if (!init) { attrs.push({ name, expression: false }); continue; }
        if (ts.isStringLiteral(init)) { attrs.push({ name, value: init.text, expression: false }); continue; }
        attrs.push({ name, expression: true, value: init.getText(sf).slice(0, 120) });
      }
      const children = ts.isJsxElement(node) ? node.children : undefined;
      const text = children
        ?.filter(ts.isJsxText).map((c) => c.text.trim()).filter(Boolean).join(' ') || undefined;
      jsx.push({
        tag, attrs, line: lineOf(opening),
        hasChildren: !!children && children.some((c) => !ts.isJsxText(c) || c.text.trim().length > 0),
        text,
      });
    }

    if (ts.isTryStatement(node)) hasTryCatch = true;

    // ---- recurse with state ----
    const prevSymbol = currentSymbol;
    if (enteredSymbol) currentSymbol = enteredSymbol;
    const isLoop = LOOP_KINDS.has(node.kind);
    if (isLoop) loopDepth++;
    ts.forEachChild(node, visit);
    if (isLoop) loopDepth--;
    currentSymbol = prevSymbol;
  };

  ts.forEachChild(sf, visit);

  return {
    path, language, parsed: true,
    imports, exports: [...new Set(exports)], symbols, calls, jsx,
    memberAccesses, objectLiterals,
    envVars: [...envVars],
    stringLiterals,
    hasTryCatch,
    lines: sf.getLineAndCharacterOfPosition(sf.getEnd()).line + 1,
  };
}
