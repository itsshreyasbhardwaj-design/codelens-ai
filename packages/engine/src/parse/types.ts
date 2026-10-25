/**
 * Parser-agnostic AST facts.
 *
 * Any parser (TypeScript compiler API, python3's ast module, a future
 * tree-sitter grammar) produces this shape, so analyzers never depend on which
 * parser ran.
 */

export interface ImportRef {
  /** The module string as written, e.g. '../lib/db' or 'next/server'. */
  specifier: string;
  /** Repository-relative path, when the specifier resolves inside the project. */
  resolvedPath?: string;
  /** Imported binding names; ['*'] for a namespace import, ['default'] for default. */
  names: string[];
  line: number;
  external: boolean;
}

export type SymbolKind = 'function' | 'class' | 'method' | 'arrow' | 'const' | 'interface' | 'type' | 'enum';

export interface SymbolInfo {
  name: string;
  kind: SymbolKind;
  exported: boolean;
  async: boolean;
  startLine: number;
  endLine: number;
  params: string[];
  /** Source text of the symbol body, capped. Used as finding evidence. */
  text: string;
  /** Enclosing class, for methods. */
  parent?: string;
  /** Decorator source text, e.g. ['@app.get("/items")']. Python/Nest routes. */
  decorators?: string[];
}

export interface CallRef {
  /** Dotted callee as written, e.g. 'prisma.order.findUnique' or 'fetch'. */
  callee: string;
  /** Argument source text, capped. */
  args: string[];
  line: number;
  /** Name of the symbol containing the call. */
  inSymbol?: string;
  /** True when the call sits inside a for/while/forEach/map body. */
  insideLoop: boolean;
  /** True when the result is awaited. */
  awaited: boolean;
}

export interface JsxAttr {
  name: string;
  /** Literal value when statically known. */
  value?: string;
  /** True when the value is an expression rather than a literal. */
  expression: boolean;
}

export interface JsxElement {
  tag: string;
  attrs: JsxAttr[];
  line: number;
  hasChildren: boolean;
  /** Text content when statically known. */
  text?: string;
}

export interface MemberAccess {
  /** Root object name, e.g. 'order' in order.customerName. */
  object: string;
  property: string;
  line: number;
  inSymbol?: string;
}

export interface ObjectLiteralShape {
  /** Property names of an object literal, for response-shape comparison. */
  keys: string[];
  line: number;
  inSymbol?: string;
}

export interface ParsedModule {
  path: string;
  language: string;
  parsed: boolean;
  parseError?: string;
  imports: ImportRef[];
  exports: string[];
  symbols: SymbolInfo[];
  calls: CallRef[];
  jsx: JsxElement[];
  memberAccesses: MemberAccess[];
  objectLiterals: ObjectLiteralShape[];
  /** Names read from process.env / os.environ. */
  envVars: string[];
  /** String literal values, capped, for secret and URL analysis. */
  stringLiterals: Array<{ value: string; line: number }>;
  /** Whether the module contains any try/catch. */
  hasTryCatch: boolean;
  /** Line count. */
  lines: number;
}

export function emptyModule(path: string, language: string, parseError?: string): ParsedModule {
  return {
    path, language, parsed: false, parseError,
    imports: [], exports: [], symbols: [], calls: [], jsx: [],
    memberAccesses: [], objectLiterals: [], envVars: [], stringLiterals: [],
    hasTryCatch: false, lines: 0,
  };
}
