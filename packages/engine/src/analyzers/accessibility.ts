import type { Confidence, Evidence, Finding, RelationshipTrace, Severity } from '@codelens/core';
import type { RepoMap } from '../graph/repomap.ts';
import type { JsxAttr, JsxElement, ParsedModule } from '../parse/types.ts';
import type { Analyzer, AnalyzerContext } from './types.ts';
import { codeText } from './text.ts';

/**
 * Accessibility and UI/UX audit, targeting WCAG 2.2 AA.
 *
 * Every finding here is **source-derived**: no browser rendered the page, so
 * nothing in this analyzer has been seen. That distinction is carried in the
 * finding text and in `status`:
 *
 *   - a defect that the source settles on its own — an `<img>` with no `alt`
 *     attribute, a `<button>` whose only child is a static glyph, `onClick` on a
 *     `<div>` with no role, keyboard handler or `tabIndex` — is reported with
 *     `strong` confidence and the ordinary status, because the attribute list is
 *     complete in the AST and no rendering can add to it;
 *   - a defect whose truth depends on what a browser actually produces — colour
 *     contrast, real focus order, whether a label is *visually* associated with
 *     its field, whether a heading sequence is still wrong once the component is
 *     composed into a page, what an icon component renders internally — is
 *     reported with `moderate` confidence and status
 *     `needs_runtime_verification`, and says what a human has to open to settle
 *     it.
 *
 * Colour contrast is deliberately **not** reported at all. Contrast is a
 * property of computed styles against composited backgrounds; guessing it from
 * class names or hex literals in source would be a fabricated measurement, and
 * `docs/LIMITATIONS.md` forbids that. The gap is stated in the coverage note
 * rather than filled with a plausible number.
 *
 * Precision rules encoded below, because a false accessibility finding is
 * expensive — it trains a team to ignore the whole category:
 *   - `alt=""` is the correct markup for a decorative image and is never flagged;
 *   - `aria-hidden="true"` / `role="presentation"` marks an element as decorative
 *     and removes it from the accessibility tree, so it is never flagged for a
 *     missing name;
 *   - a control with real words as its child text has an accessible name;
 *   - a control whose children are dynamic (`{label}`) is never flagged: the name
 *     may be supplied at runtime and we cannot see it;
 *   - inputs of type hidden/submit/button/reset/image need no associated label;
 *   - `<Image>` from next/image needs `alt` exactly as `<img>` does;
 *   - test, story, generated and vendored files are not audited.
 */

const WCAG = {
  nonText: 'WCAG 2.2 1.1.1 Non-text Content (Level A)',
  infoRelationships: 'WCAG 2.2 1.3.1 Info and Relationships (Level A)',
  audioControl: 'WCAG 2.2 1.4.2 Audio Control (Level A)',
  pauseStopHide: 'WCAG 2.2 2.2.2 Pause, Stop, Hide (Level A)',
  keyboard: 'WCAG 2.2 2.1.1 Keyboard (Level A)',
  noKeyboardTrap: 'WCAG 2.2 2.1.2 No Keyboard Trap (Level A)',
  focusOrder: 'WCAG 2.2 2.4.3 Focus Order (Level A)',
  headingsLabels: 'WCAG 2.2 2.4.6 Headings and Labels (Level AA)',
  languageOfPage: 'WCAG 2.2 3.1.1 Language of Page (Level A)',
  labelsInstructions: 'WCAG 2.2 3.3.2 Labels or Instructions (Level A)',
  nameRoleValue: 'WCAG 2.2 4.1.2 Name, Role, Value (Level A)',
  statusMessages: 'WCAG 2.2 4.1.3 Status Messages (Level AA)',
  ariaPractices: 'WAI-ARIA Authoring Practices 1.2, keyboard interaction patterns',
} as const;

/** Appended wherever a reader could otherwise mistake a rule match for an observation. */
const SOURCE_ONLY =
  'This was derived from source only — no browser rendered the page during the scan, ' +
  'so the rendered result was not observed.';

// ---------------------------------------------------------------- plumbing ---

/** Tags that already carry an interactive role from the platform. */
const INTERACTIVE_TAGS = new Set([
  'a', 'button', 'input', 'select', 'textarea', 'option', 'optgroup', 'label',
  'summary', 'details', 'audio', 'video', 'iframe', 'area', 'dialog',
]);

/** ARIA roles whose widgets must be focusable and keyboard-operable. */
const INTERACTIVE_ROLES = new Set([
  'button', 'link', 'checkbox', 'radio', 'switch', 'tab', 'menuitem',
  'menuitemcheckbox', 'menuitemradio', 'option', 'slider', 'spinbutton', 'treeitem',
]);

/** Input types that are not labellable fields. */
const UNLABELLABLE_INPUT_TYPES = new Set(['hidden', 'submit', 'button', 'reset', 'image']);

const CLICK_ATTRS = ['onClick', 'onDoubleClick', 'onMouseDown', 'onMouseUp', 'onPointerDown'];
const KEY_ATTRS = ['onKeyDown', 'onKeyUp', 'onKeyPress'];
const NAME_ATTRS = ['aria-label', 'aria-labelledby', 'title'];

function attrOf(el: JsxElement, name: string): JsxAttr | undefined {
  const lower = name.toLowerCase();
  return el.attrs.find((a) => a.name.toLowerCase() === lower);
}

function hasAttr(el: JsxElement, name: string): boolean {
  return attrOf(el, name) !== undefined;
}

function hasAnyAttr(el: JsxElement, names: string[]): boolean {
  return names.some((n) => hasAttr(el, n));
}

/** Literal attribute value, or undefined when the value is an expression or absent. */
function literal(el: JsxElement, name: string): string | undefined {
  const a = attrOf(el, name);
  if (!a || a.expression) return undefined;
  return a.value;
}

/** Unwrap a braced expression value: `{200}` -> `200`. */
function unbrace(value: string | undefined): string | undefined {
  if (value === undefined) return undefined;
  const t = value.trim();
  return t.startsWith('{') && t.endsWith('}') ? t.slice(1, -1).trim() : t;
}

/** True when the element is deliberately removed from the accessibility tree. */
function isDecorative(el: JsxElement): boolean {
  const hidden = attrOf(el, 'aria-hidden');
  if (hidden) {
    const v = unbrace(hidden.value);
    // `aria-hidden` with no value, `="true"` or `={true}` all hide the element.
    if (v === undefined || v === 'true') return true;
  }
  const role = literal(el, 'role');
  if (role === 'presentation' || role === 'none') return true;
  return false;
}

/** True when an attribute that can carry a name is present and not obviously empty. */
function hasNameAttribute(el: JsxElement): boolean {
  for (const name of NAME_ATTRS) {
    const a = attrOf(el, name);
    if (!a) continue;
    if (a.expression) return true;          // computed at runtime; assume supplied
    if ((a.value ?? '').trim() !== '') return true;
  }
  return false;
}

const WORDLIKE = /[\p{L}\p{N}]/u;

/** True when static text contains at least one letter or digit (an emoji does not). */
function readsAsWords(text: string | undefined): boolean {
  return text !== undefined && WORDLIKE.test(text);
}

function tagIsComponent(tag: string): boolean {
  return /^[A-Z]/.test(tag) || tag.includes('.');
}

function enclosingSymbol(mod: ParsedModule, line: number): string | undefined {
  let best: string | undefined;
  let bestSpan = Number.MAX_SAFE_INTEGER;
  for (const s of mod.symbols) {
    if (s.startLine > line || s.endLine < line) continue;
    const span = s.endLine - s.startLine;
    if (span < bestSpan) { bestSpan = span; best = s.name; }
  }
  return best;
}

/** Files whose accessibility is not the shipped product's accessibility. */
function isNonProductUi(path: string): boolean {
  return (
    /(^|\/)(tests?|__tests__|__mocks__|spec|e2e|cypress|fixtures?|examples?|stories)\//i.test(path) ||
    /\.(test|spec|stories|story|bench)\.[cm]?[jt]sx?$/i.test(path)
  );
}

/** The modules worth auditing: real UI source with a parsed AST. */
function uiModules(map: RepoMap): ParsedModule[] {
  const out: ParsedModule[] = [];
  for (const mod of map.modules.values()) {
    if (!mod.parsed || mod.jsx.length === 0) continue;
    const file = map.filesByPath.get(mod.path);
    if (!file || file.generated || file.vendored) continue;
    if (file.role === 'test' || file.role === 'generated' || file.role === 'vendored') continue;
    if (isNonProductUi(mod.path)) continue;
    out.push(mod);
  }
  return out;
}

function moduleText(map: RepoMap, path: string): string {
  const file = map.filesByPath.get(path);
  return codeText(file?.text ?? null, file?.language);
}

/**
 * The static source between an element's opening and closing tag.
 *
 * Needed because `ParsedModule.jsx` is a flat list: it records an element's own
 * static text but not its element children, and "is this button's only child an
 * icon?" cannot be answered without them. Returns undefined whenever the span
 * cannot be pinned down exactly — two same-tag elements on one line, a nested
 * same tag, no closing tag nearby — so an unresolved case can never become a
 * finding.
 */
function innerSource(text: string, el: JsxElement): string | undefined {
  const lines = text.split('\n');
  const lineText = lines[el.line - 1];
  if (lineText === undefined) return undefined;

  let offset = 0;
  for (let i = 0; i < el.line - 1; i++) offset += lines[i]!.length + 1;

  const open = `<${el.tag}`;
  const first = lineText.indexOf(open);
  if (first === -1) return undefined;
  if (lineText.indexOf(open, first + 1) !== -1) return undefined; // ambiguous line

  const tagIdx = offset + first;
  let i = tagIdx + open.length;
  let depth = 0;
  let quote = '';
  const limit = Math.min(text.length, tagIdx + 4000);
  for (; i < limit; i++) {
    const c = text[i]!;
    if (quote) { if (c === quote) quote = ''; continue; }
    if (c === '"' || c === "'" || c === '`') { quote = c; continue; }
    if (c === '{') { depth++; continue; }
    if (c === '}') { depth--; continue; }
    if (depth !== 0) continue;
    if (c === '/' && text[i + 1] === '>') return '';  // self-closing: no children
    if (c === '>') break;
  }
  if (i >= limit) return undefined;

  const closeIdx = text.indexOf(`</${el.tag}`, i);
  if (closeIdx === -1 || closeIdx - i > 4000) return undefined;
  const inner = text.slice(i + 1, closeIdx);
  if (inner.includes(open)) return undefined;  // nested same tag: span is not ours
  return inner;
}

/**
 * The source of an element's opening tag, used for facts the attribute list
 * cannot carry. Falls back to the element's own line when the span cannot be
 * scanned, which keeps the spread check below conservative.
 */
function openingTagSource(text: string, el: JsxElement): string {
  const lines = text.split('\n');
  const lineText = lines[el.line - 1] ?? '';
  let offset = 0;
  for (let i = 0; i < el.line - 1; i++) offset += lines[i]!.length + 1;

  const tagIdx = text.indexOf(`<${el.tag}`, offset);
  if (tagIdx === -1 || tagIdx > offset + lineText.length) return lineText;

  let depth = 0;
  let quote = '';
  const limit = Math.min(text.length, tagIdx + 2000);
  for (let i = tagIdx; i < limit; i++) {
    const c = text[i]!;
    if (quote) { if (c === quote) quote = ''; continue; }
    if (c === '"' || c === "'" || c === '`') { quote = c; continue; }
    if (c === '{') { depth++; continue; }
    if (c === '}') { depth--; continue; }
    if (depth === 0 && c === '>') return text.slice(tagIdx, i + 1);
  }
  return lineText;
}

/**
 * True when the element spreads props (`<img {...rest} />`).
 *
 * The parser records only named attributes, so a spread leaves no trace in
 * `attrs` — and a spread can carry `alt`, `aria-label`, `role`, `tabIndex` or a
 * key handler. Every rule here that reasons from an *absent* attribute must
 * therefore stay silent on these elements, or it invents a defect out of an
 * attribute list it cannot see the whole of.
 */
function hasSpreadProps(map: RepoMap, mod: ParsedModule, el: JsxElement): boolean {
  const text = map.filesByPath.get(mod.path)?.text;
  if (!text) return true;             // cannot check: assume incomplete
  return /\{\s*\.\.\./.test(openingTagSource(text, el));
}

/**
 * True when the element sits inside a `<label>`.
 *
 * `<label>Email <input /></label>` is correct markup and supplies no htmlFor to
 * match against an id. The flat JSX list cannot express nesting, so this walks
 * the source before the element for an unclosed `<label`.
 */
function insideLabel(map: RepoMap, mod: ParsedModule, el: JsxElement): boolean {
  const text = map.filesByPath.get(mod.path)?.text;
  if (!text) return false;
  const lines = text.split('\n');
  let offset = 0;
  for (let i = 0; i < el.line - 1 && i < lines.length; i++) offset += lines[i]!.length + 1;
  const prefix = text.slice(0, offset + (lines[el.line - 1]?.indexOf(`<${el.tag}`) ?? 0) + 1);
  const open = prefix.lastIndexOf('<label');
  if (open === -1) return false;
  return open > prefix.lastIndexOf('</label');
}

/** Drop `{}` left behind by comment stripping, so it does not read as a dynamic child. */
function withoutEmptyBraces(inner: string): string {
  return inner.replace(/\{\s*\}/g, ' ');
}

/** Text a user would read, with tags removed. */
function visibleText(inner: string): string {
  return inner.replace(/<[^>]*>/g, ' ');
}

// ------------------------------------------------------------ aggregation ---

interface Hit {
  line: number;
  detail: string;
  symbol?: string;
}

interface Bucket {
  file: string;
  hits: Hit[];
}

/** Group hits per file so a file with twenty unlabelled images yields one finding. */
function bucket(groups: Map<string, Bucket>, file: string, tier: string, hit: Hit): void {
  const key = `${file}\u0000${tier}`;
  const existing = groups.get(key);
  if (existing) { existing.hits.push(hit); return; }
  groups.set(key, { file, hits: [hit] });
}

const MAX_EVIDENCE = 5;

function evidenceFor(map: RepoMap, b: Bucket, note: string): Evidence[] {
  return b.hits.slice(0, MAX_EVIDENCE).map((h) => {
    const e = map.evidenceLine(b.file, h.line, `${h.detail} — ${note}`);
    return h.symbol ? { ...e, symbol: h.symbol } : e;
  });
}

/** "line 14" / "lines 14, 22 and 3 more" — used in explanations, never invented. */
function lineList(hits: Hit[]): string {
  const lines = hits.map((h) => h.line);
  if (lines.length === 1) return `line ${lines[0]}`;
  const shown = lines.slice(0, 4).join(', ');
  const rest = lines.length - 4;
  return rest > 0 ? `lines ${shown} and ${rest} more` : `lines ${shown}`;
}

// ============================================================== analyzer ====

export const accessibilityAnalyzer: Analyzer = {
  id: 'accessibility',
  category: 'accessibility',
  description:
    'WCAG 2.2 AA source audit: text alternatives, accessible names, form labels, keyboard operability, ' +
    'focus management, heading structure, autoplaying media, and missing loading/error states.',

  precondition(map: RepoMap): string | undefined {
    const hasJsx = [...map.modules.values()].some((m) => m.parsed && m.jsx.length > 0);
    const hasHtml = map.files.some((f) => f.language === 'html' && f.text);
    if (!hasJsx && !hasHtml) {
      return 'no user interface found: the project contains no JSX/TSX markup and no HTML documents';
    }
    return undefined;
  },

  run(ctx: AnalyzerContext): Finding[] {
    const findings: Finding[] = [];
    const mods = uiModules(ctx.map);

    findings.push(...missingTextAlternatives(ctx, mods));
    findings.push(...controlsWithoutAccessibleName(ctx, mods));
    findings.push(...unlabelledFormFields(ctx, mods));
    findings.push(...nonSemanticInteractiveElements(ctx, mods));
    findings.push(...widgetsWithoutKeyboardSupport(ctx, mods));
    findings.push(...anchorsUsedAsButtons(ctx, mods));
    findings.push(...positiveTabIndex(ctx, mods));
    findings.push(...headingOrderJumps(ctx, mods));
    findings.push(...missingDocumentLanguage(ctx, mods));
    findings.push(...autoplayingMedia(ctx, mods));
    findings.push(...unmanagedDialogFocus(ctx, mods));
    findings.push(...missingLoadingAndErrorStates(ctx, mods));

    return findings;
  },
};

// ------------------------------------------------- 1. text alternatives -----

/** True when this module imports next/image, so `<Image>` is an image element. */
function importsNextImage(mod: ParsedModule): boolean {
  return mod.imports.some((i) => i.specifier === 'next/image');
}

function missingTextAlternatives(ctx: AnalyzerContext, mods: ParsedModule[]): Finding[] {
  const { map } = ctx;
  const out: Finding[] = [];

  for (const mod of mods) {
    const nextImage = importsNextImage(mod);
    const groups = new Map<string, Bucket>();

    for (const el of mod.jsx) {
      const tag = el.tag;
      const isImg = tag === 'img' || tag === 'area' || (nextImage && tag === 'Image');
      const isImageInput = tag === 'input' && literal(el, 'type') === 'image';
      const isSvgAsImage = tag === 'svg' && literal(el, 'role') === 'img';

      if (!isImg && !isImageInput && !isSvgAsImage) continue;
      if (hasSpreadProps(map, mod, el)) continue;   // a spread may carry alt
      if (isDecorative(el)) continue;   // aria-hidden / role=presentation: correct for decoration

      if (isSvgAsImage) {
        // role="img" promises a graphic with a text alternative; it needs a name.
        if (hasNameAttribute(el)) continue;
        const inner = innerSource(map.filesByPath.get(mod.path)?.text ?? '', el);
        if (inner === undefined || /<title[\s>]/i.test(inner)) continue;  // <title> names an SVG
        bucket(groups, mod.path, 'svg', {
          line: el.line,
          detail: '<svg role="img"> with no aria-label, aria-labelledby or <title> child',
          symbol: enclosingSymbol(mod, el.line),
        });
        continue;
      }

      // `alt` present in any form — including alt="" — is correct markup and is
      // never flagged: the empty string is how a decorative image is declared.
      if (hasAttr(el, 'alt')) continue;
      if (hasNameAttribute(el)) continue;   // aria-label on an image is unusual but does name it

      bucket(groups, mod.path, 'img', {
        line: el.line,
        detail: `<${tag}> with no alt attribute`,
        symbol: enclosingSymbol(mod, el.line),
      });
    }

    for (const [key, b] of groups) {
      const kind = key.endsWith('svg') ? 'svg' : 'img';
      const n = b.hits.length;
      out.push(ctx.finding({
        ruleId: 'accessibility.image.missing_text_alternative',
        title: kind === 'svg'
          ? `Graphic with role="img" has no text alternative in ${b.file}`
          : `Image without alt text in ${b.file}`,
        severity: 'medium',
        confidence: 'strong',
        files: [b.file],
        symbol: b.hits[0]!.symbol,
        evidence: evidenceFor(map, b, 'no text alternative is present on this element'),
        explanation:
          (kind === 'svg'
            ? `${n} <svg> element(s) in ${b.file} declare role="img" but carry no aria-label, aria-labelledby or <title> child (${lineList(b.hits)}). ` +
              'Declaring the role promises assistive technology a graphic with a text alternative, and then supplies none.'
            : `${n} image element(s) in ${b.file} have no alt attribute at all (${lineList(b.hits)}). ` +
              'An absent alt is not the same as alt="": the empty string declares the image decorative and is skipped, ' +
              'whereas an absent attribute leaves assistive technology nothing to announce, so most screen readers fall back ' +
              'to reading the file name or URL.') +
          ` ${SOURCE_ONLY} The attribute list is complete in the parsed markup, so the absence itself is not in doubt; ` +
          'what cannot be determined from source is whether the image carries information or is purely decorative.',
        userImpact:
          'A screen-reader user reaches this image and hears a file path, or nothing. Where the image identifies a product, ' +
          'a status or an action, that information is simply missing for them, and any task that depends on it cannot be completed. ' +
          'The same gap affects anyone whose images fail to load.',
        likelyRootCause:
          'Markup written for the visual result only, with no linting rule (jsx-a11y/alt-text) failing the build when alt is absent.',
        downstreamConsequences: [
          'Automated audits (axe, Lighthouse) will fail this page on a Level A criterion.',
          'Image-based navigation and search become unusable for assistive technology.',
        ],
        remediation:
          'Add alt text describing the information the image conveys in its context — for a product image, the product name, not "image" or "photo". ' +
          'For an image that adds nothing beyond the adjacent text, set alt="" explicitly so it is skipped deliberately rather than by accident. ' +
          'When the image is the only content of a link or button, the alt text must describe the destination or action, not the picture. ' +
          'Add eslint-plugin-jsx-a11y with alt-text enabled so the next occurrence fails review instead of shipping.',
        effort: 'small',
        verificationSteps: [
          `Open ${b.file} and confirm every image element now has an alt attribute, empty only where the image is decorative.`,
          'Run `npx @axe-core/cli <url>` (or Lighthouse accessibility) against the rendered page and confirm no image-alt violations remain.',
          'Navigate the page with a screen reader (VoiceOver: Ctrl+Option+Cmd+Arrow, NVDA: Insert+Down) and confirm each image announces something meaningful.',
        ],
        references: [WCAG.nonText, 'CWE-1100 Insufficient Isolation of System-Dependent Functions (accessibility)', 'EN 301 549 clause 9.1.1.1'],
      }));
    }
  }
  return out;
}

// ------------------------------------------------- 2. accessible names ------

function missingNameVerdict(
  map: RepoMap,
  mod: ParsedModule,
  el: JsxElement,
): { detail: string; conclusive: boolean } | undefined {
  // No children at all: nothing can supply a name.
  if (!el.hasChildren) {
    return { detail: `<${el.tag}> has no children and no aria-label, aria-labelledby or title`, conclusive: true };
  }

  const text = map.filesByPath.get(mod.path)?.text ?? '';
  const raw = innerSource(text, el);
  if (raw === undefined) return undefined;             // span unresolved: say nothing

  const inner = withoutEmptyBraces(codeText(raw, mod.language));
  // A nested name attribute, an alt, or an SVG <title> may name the control.
  if (/aria-label|aria-labelledby|\balt\s*=|<title[\s>]/i.test(inner)) return undefined;
  // Dynamic children: the name may be supplied at runtime and we cannot read it.
  if (/\{[^}]*\S[^}]*\}/.test(inner)) return undefined;
  // Real words anywhere in the static content give the control a name.
  if (readsAsWords(visibleText(inner))) return undefined;

  const childTags = [...inner.matchAll(/<\/?([A-Za-z][\w.]*)/g)].map((m) => m[1]!);
  const componentChild = childTags.find((t) => tagIsComponent(t));
  if (componentChild) {
    // An icon component may render its own aria-label internally; only a render settles it.
    return {
      detail: `<${el.tag}> whose only child is the <${componentChild}> component, with no aria-label, aria-labelledby or title`,
      conclusive: false,
    };
  }
  if (childTags.length > 0) {
    return {
      detail: `<${el.tag}> whose only child is <${childTags[0]}> with no text, and no aria-label, aria-labelledby or title`,
      conclusive: true,
    };
  }
  const glyph = (el.text ?? visibleText(inner)).trim().slice(0, 12);
  return {
    detail: `<${el.tag}> whose only child is the non-text glyph "${glyph}", with no aria-label, aria-labelledby or title`,
    conclusive: true,
  };
}

function controlsWithoutAccessibleName(ctx: AnalyzerContext, mods: ParsedModule[]): Finding[] {
  const { map } = ctx;
  const out: Finding[] = [];

  for (const mod of mods) {
    const groups = new Map<string, Bucket>();

    for (const el of mod.jsx) {
      const role = literal(el, 'role');
      const isButton = el.tag === 'button';
      const isAnchor = el.tag === 'a' && (hasAttr(el, 'href') || hasAnyAttr(el, CLICK_ATTRS));
      const isRoleWidget = role !== undefined && INTERACTIVE_ROLES.has(role);
      if (!isButton && !isAnchor && !isRoleWidget) continue;
      if (hasSpreadProps(map, mod, el)) continue;   // a spread may carry aria-label or title
      if (isDecorative(el)) continue;
      if (hasNameAttribute(el)) continue;
      // A submit/reset input is named by its value, or by the user agent's default.
      if (el.tag === 'input') continue;
      if (readsAsWords(el.text)) continue;   // real words as child text: named

      const verdict = missingNameVerdict(map, mod, el);
      if (!verdict) continue;

      bucket(groups, mod.path, verdict.conclusive ? 'conclusive' : 'runtime', {
        line: el.line,
        detail: verdict.detail,
        symbol: enclosingSymbol(mod, el.line),
      });
    }

    for (const [key, b] of groups) {
      const conclusive = key.endsWith('conclusive');
      const n = b.hits.length;
      const confidence: Confidence = conclusive ? 'strong' : 'moderate';
      out.push(ctx.finding({
        ruleId: 'accessibility.control.no_accessible_name',
        title: `Control with no accessible name in ${b.file}`,
        severity: 'medium',
        confidence,
        status: conclusive ? undefined : 'needs_runtime_verification',
        files: [b.file],
        symbol: b.hits[0]!.symbol,
        evidence: evidenceFor(map, b, 'no accessible name is available from children or attributes'),
        explanation:
          `${n} interactive element(s) in ${b.file} expose no accessible name (${lineList(b.hits)}). ` +
          'The accessible name is computed from the element\'s own labelling attributes and then from its content; here there is ' +
          'no aria-label, no aria-labelledby, no title, and the content contributes no text — an emoji, a symbol, an icon or nothing at all. ' +
          (conclusive
            ? 'The children are static in the source, so the computation can be followed to its end: the name is empty. ' +
              'A screen reader then announces only the role, for example "button", with nothing to distinguish it from any other button on the page. '
            : 'One child is a component whose own markup decides the outcome: if it renders an aria-label, a <title>, or visually hidden text, ' +
              'the control is named; if it renders a bare glyph or icon font, it is not. That cannot be settled from this file alone. ') +
          SOURCE_ONLY,
        userImpact:
          'A screen-reader user hears "button" with no indication of what it does, and a voice-control user has no name to speak to activate it. ' +
          'Where the control is a primary action — add to basket, submit, delete — the task behind it is unreachable without sighted guessing.',
        likelyRootCause:
          'An icon or emoji was used as the whole label because it reads clearly to a sighted user, and the text alternative was never added.',
        downstreamConsequences: [
          'Voice control ("click add to basket") cannot target the element.',
          'Automated audits fail the page on WCAG 4.1.2, a Level A criterion.',
          'Tests that query by accessible name (Testing Library getByRole) cannot address the control either, so it tends to stay untested.',
        ],
        remediation:
          'Give the control a name. Preferred: visible text alongside the icon, since it helps every user, not only assistive technology. ' +
          'Where the design requires icon-only, add aria-label="Add to basket" (the action, not the icon), or render visually hidden text inside the control ' +
          'with a .sr-only utility. Mark the icon itself aria-hidden="true" so it is not announced twice. ' +
          'Enable eslint-plugin-jsx-a11y rules control-has-associated-label and anchor-has-content to catch the next one at review time.',
        effort: 'small',
        verificationSteps: [
          `Open ${b.file} at ${lineList(b.hits)} and confirm each control now has visible text, an aria-label, or visually hidden text.`,
          'In the browser devtools accessibility pane, select the control and confirm its computed Name is non-empty and describes the action.',
          'Tab to the control with a screen reader running and confirm it announces a meaningful name, not just its role.',
          conclusive
            ? 'Run `npx @axe-core/cli <url>` and confirm no button-name or link-name violations remain.'
            : 'Render the icon component in isolation and inspect whether it emits a text alternative; this determines whether the finding applies.',
        ],
        references: [WCAG.nameRoleValue, WCAG.nonText, WCAG.ariaPractices],
      }));
    }
  }
  return out;
}

// ------------------------------------------------- 3. form field labels -----

function unlabelledFormFields(ctx: AnalyzerContext, mods: ParsedModule[]): Finding[] {
  const { map } = ctx;
  const out: Finding[] = [];

  for (const mod of mods) {
    const labels = mod.jsx.filter((e) => e.tag === 'label');
    const labelTargets = new Set<string>();
    let dynamicLabelTarget = false;
    for (const l of labels) {
      const htmlFor = attrOf(l, 'htmlFor') ?? attrOf(l, 'for');
      if (!htmlFor) continue;
      if (htmlFor.expression || htmlFor.value === undefined) { dynamicLabelTarget = true; continue; }
      labelTargets.add(htmlFor.value);
    }

    const groups = new Map<string, Bucket>();

    for (const el of mod.jsx) {
      if (el.tag !== 'input' && el.tag !== 'select' && el.tag !== 'textarea') continue;
      if (hasSpreadProps(map, mod, el)) continue;   // a spread may carry id or aria-label
      const type = literal(el, 'type');
      if (type !== undefined && UNLABELLABLE_INPUT_TYPES.has(type)) continue;
      if (attrOf(el, 'type')?.expression) continue;     // type unknown: do not guess
      if (isDecorative(el)) continue;
      if (hasNameAttribute(el)) continue;

      const id = attrOf(el, 'id');
      if (id?.expression) continue;                      // computed id; cannot match a label
      if (id?.value !== undefined && labelTargets.has(id.value)) continue;
      if (dynamicLabelTarget) continue;                  // a label targets a computed id somewhere

      if (insideLabel(map, mod, el)) continue;      // wrapped by a label: correctly associated

      const placeholder = literal(el, 'placeholder');
      bucket(groups, mod.path, labels.length > 0 ? 'labels_present' : 'no_labels', {
        line: el.line,
        detail: placeholder !== undefined
          ? `<${el.tag}> with placeholder "${placeholder}" and no associated label`
          : `<${el.tag}> with no associated label`,
        symbol: enclosingSymbol(mod, el.line),
      });
    }

    for (const [key, b] of groups) {
      const labelsNearby = key.endsWith('labels_present');
      const n = b.hits.length;
      out.push(ctx.finding({
        ruleId: 'accessibility.form.unlabelled_field',
        title: `Form field with no associated label in ${b.file}`,
        severity: 'medium',
        confidence: 'moderate',
        status: 'needs_runtime_verification',
        files: [b.file],
        symbol: b.hits[0]!.symbol,
        evidence: evidenceFor(map, b, 'no htmlFor/id pairing, aria-label or aria-labelledby found for this field'),
        explanation:
          `${n} form field(s) in ${b.file} have no label this analyzer can tie to them (${lineList(b.hits)}): ` +
          'no aria-label, no aria-labelledby, and no <label htmlFor> matching the field id. ' +
          (labelsNearby
            ? 'The file does contain <label> elements, so a labelling convention exists here and these fields may have been missed, ' +
              'or they may be labelled through a wrapper component this analyzer cannot follow. '
            : 'The file contains no <label> element at all, so if a label exists it comes from a wrapper component or from markup elsewhere. ') +
          'A placeholder is not a label: it disappears on input, is not reliably announced, and fails 1.3.1. ' +
          `Whether a visible label is genuinely associated with each field can only be settled on a rendered page, which is why this is marked for runtime verification. ${SOURCE_ONLY}`,
        userImpact:
          'A screen-reader user moving through the form hears "edit text, blank" with no indication of what to type, and corrections after a ' +
          'validation error are guesswork. Clicking the label text does not focus the field either, which makes the form harder for anyone ' +
          'using a pointer with limited precision.',
        likelyRootCause:
          'Fields styled with a placeholder standing in for the label, or a design-system field wrapper that was expected to add the label and does not.',
        downstreamConsequences: [
          'Autofill accuracy drops, because browsers infer field purpose partly from labels.',
          'Validation messages cannot be tied back to a named field for assistive technology.',
        ],
        remediation:
          'Give every field a programmatically associated label: <label htmlFor="email">Email</label> with a matching id, or wrap the input in the label. ' +
          'Where the design has no room for visible label text, use aria-label on the field, and keep the placeholder as an example value rather than the label. ' +
          'If a wrapper component is responsible, make the label prop required in its types so an unlabelled field fails type-checking. ' +
          'Enable eslint-plugin-jsx-a11y label-has-associated-control.',
        effort: 'small',
        verificationSteps: [
          `Open the rendered form and, in the devtools accessibility pane, confirm each field at ${lineList(b.hits)} has a non-empty computed Name.`,
          'Click each visible label and confirm focus moves into its field — that proves the association, not just the presence of text.',
          'Run `npx @axe-core/cli <url>` and confirm no label or form-field-multiple-label violations remain.',
        ],
        references: [WCAG.labelsInstructions, WCAG.infoRelationships, WCAG.nameRoleValue],
      }));
    }
  }
  return out;
}

// --------------------------------------- 4. non-semantic interactive --------

function nonSemanticInteractiveElements(ctx: AnalyzerContext, mods: ParsedModule[]): Finding[] {
  const { map } = ctx;
  const out: Finding[] = [];

  for (const mod of mods) {
    const groups = new Map<string, Bucket>();

    for (const el of mod.jsx) {
      if (tagIsComponent(el.tag)) continue;              // a component's own markup decides its semantics
      if (INTERACTIVE_TAGS.has(el.tag)) continue;
      if (!hasAnyAttr(el, CLICK_ATTRS)) continue;
      if (hasSpreadProps(map, mod, el)) continue;        // a spread may carry role or tabIndex
      if (hasAttr(el, 'role')) continue;                 // handled by the keyboard rule below
      if (hasAttr(el, 'tabIndex')) continue;
      if (hasAnyAttr(el, KEY_ATTRS)) continue;

      bucket(groups, mod.path, 'div', {
        line: el.line,
        detail: `<${el.tag}> with a click handler but no role, no tabIndex and no keyboard handler`,
        symbol: enclosingSymbol(mod, el.line),
      });
    }

    for (const [, b] of groups) {
      const n = b.hits.length;
      out.push(ctx.finding({
        ruleId: 'accessibility.interactive.non_semantic_element',
        title: `Click handler on a non-interactive element in ${b.file}`,
        severity: 'medium',
        confidence: 'strong',
        files: [b.file],
        symbol: b.hits[0]!.symbol,
        evidence: evidenceFor(map, b, 'click handler present; role, tabIndex and keyboard handlers all absent'),
        explanation:
          `${n} element(s) in ${b.file} attach a click handler to a tag with no interactive semantics (${lineList(b.hits)}), ` +
          'and add neither a role, a tabIndex, nor a keyboard handler. Three separate things are missing: the element is not in the ' +
          'tab order, so it cannot be reached by keyboard; it has no role, so assistive technology announces it as plain content; ' +
          'and it has no key handler, so Enter and Space do nothing even if focus arrives by some other route. ' +
          `The attribute list is complete in the parsed markup, so none of the three can be supplied elsewhere on this element. ${SOURCE_ONLY}`,
        userImpact:
          'Anyone who does not use a mouse cannot trigger this action at all — keyboard users, switch and sip-and-puff users, and screen-reader ' +
          'users, who are additionally never told the element is actionable. If this is the only path to a feature, the feature does not exist for them.',
        likelyRootCause:
          'A div or span styled to look like a button, usually to escape a default button style, with the platform behaviour that a real button ' +
          'would have provided never re-implemented.',
        downstreamConsequences: [
          'Keyboard-only paths through the feature break silently, and no test notices, because tests click by coordinates or test id.',
          'Any future keyboard shortcut or focus-management work has to special-case these elements.',
        ],
        remediation:
          'Use <button type="button"> and reset its appearance in CSS — that single change supplies the role, the tab order, Enter/Space activation, ' +
          'and the focus ring. Where the element genuinely cannot be a button, add role="button", tabIndex={0}, and an onKeyDown that activates on ' +
          'Enter and Space (calling preventDefault for Space so the page does not scroll), plus a visible :focus-visible style. ' +
          'Enable eslint-plugin-jsx-a11y rules click-events-have-key-events and no-static-element-interactions.',
        effort: 'small',
        verificationSteps: [
          `Load the page, press Tab repeatedly, and confirm focus now stops on each control at ${lineList(b.hits)} with a visible focus indicator.`,
          'With focus on the control, press Enter and then Space and confirm both activate it exactly once.',
          'In the devtools accessibility pane, confirm the computed Role is button (or the intended widget role) rather than generic.',
        ],
        references: [WCAG.keyboard, WCAG.nameRoleValue, WCAG.ariaPractices],
      }));
    }
  }
  return out;
}

// ------------------------------------------- 5. keyboard support on roles ---

function widgetsWithoutKeyboardSupport(ctx: AnalyzerContext, mods: ParsedModule[]): Finding[] {
  const { map } = ctx;
  const out: Finding[] = [];

  for (const mod of mods) {
    const groups = new Map<string, Bucket>();

    for (const el of mod.jsx) {
      const role = literal(el, 'role');
      if (role === undefined || !INTERACTIVE_ROLES.has(role)) continue;
      if (INTERACTIVE_TAGS.has(el.tag)) continue;        // a real button with role="button" is fine
      if (hasSpreadProps(map, mod, el)) continue;        // a spread may carry tabIndex or a key handler
      const focusable = hasAttr(el, 'tabIndex');
      const keyboard = hasAnyAttr(el, KEY_ATTRS);
      if (focusable && keyboard) continue;
      if (!hasAnyAttr(el, CLICK_ATTRS)) continue;        // no activation at all: not this rule's claim

      const missing = [!focusable ? 'no tabIndex' : undefined, !keyboard ? 'no keyboard handler' : undefined]
        .filter((x): x is string => x !== undefined)
        .join(' and ');
      bucket(groups, mod.path, 'role', {
        line: el.line,
        detail: `role="${role}" with a click handler but ${missing}`,
        symbol: enclosingSymbol(mod, el.line),
      });
    }

    for (const [, b] of groups) {
      const n = b.hits.length;
      out.push(ctx.finding({
        ruleId: 'accessibility.keyboard.widget_not_operable',
        title: `ARIA widget that cannot be operated by keyboard in ${b.file}`,
        severity: 'medium',
        confidence: 'strong',
        files: [b.file],
        symbol: b.hits[0]!.symbol,
        evidence: evidenceFor(map, b, 'interactive role declared; focusability or key handling absent'),
        explanation:
          `${n} element(s) in ${b.file} declare an interactive ARIA role and a click handler, but are missing the focusability or the key ` +
          `handling that role requires (${lineList(b.hits)}). An ARIA role is a promise about behaviour, not an implementation: adding ` +
          'role="button" tells assistive technology the element behaves like a button, and it is then announced as one and operated as one. ' +
          'Without tabIndex it never receives focus, and without a key handler Enter and Space do nothing. The declared role makes this worse ' +
          `than an unmarked div, because the user is told the control is actionable and then finds it is not. ${SOURCE_ONLY}`,
        userImpact:
          'A screen-reader user is told there is a button, moves to it, presses Enter, and nothing happens — a dead end that looks like a broken ' +
          'application rather than an inaccessible one. Keyboard-only users cannot reach the control at all when tabIndex is missing.',
        likelyRootCause:
          'The role attribute was added to satisfy an accessibility lint rule or audit without the keyboard behaviour it implies.',
        downstreamConsequences: [
          'The mismatch between announced role and actual behaviour erodes trust in the rest of the interface for assistive-technology users.',
          'Keyboard paths through the feature cannot be scripted, so end-to-end tests have to resort to synthetic clicks.',
        ],
        remediation:
          'Replace the element with the native control the role names — <button>, <a href>, <input type="checkbox"> — which brings focus, activation and ' +
          'state for free. Where the role must stay, add tabIndex={0} and an onKeyDown that handles Enter and Space (Space with preventDefault), keep ' +
          'aria-pressed/aria-checked in sync with visual state, and give the element a visible :focus-visible indicator. Follow the WAI-ARIA Authoring ' +
          'Practices pattern for the specific widget rather than inventing key bindings.',
        effort: 'small',
        verificationSteps: [
          `Tab to each element at ${lineList(b.hits)} and confirm it takes focus with a visible indicator.`,
          'Press Enter, then Space, and confirm each activates the control once and only once.',
          'With a screen reader, confirm the announced role matches what the control actually does.',
        ],
        references: [WCAG.keyboard, WCAG.noKeyboardTrap, WCAG.ariaPractices],
      }));
    }
  }
  return out;
}

// ------------------------------------------- 6. links versus buttons --------

const PLACEHOLDER_HREFS = new Set(['', '#', 'javascript:void(0)', 'javascript:;']);

function anchorsUsedAsButtons(ctx: AnalyzerContext, mods: ParsedModule[]): Finding[] {
  const { map } = ctx;
  const out: Finding[] = [];

  for (const mod of mods) {
    const groups = new Map<string, Bucket>();

    for (const el of mod.jsx) {
      if (el.tag !== 'a') continue;
      if (!hasAnyAttr(el, CLICK_ATTRS)) continue;
      if (hasSpreadProps(map, mod, el)) continue;        // a spread may carry href
      const href = attrOf(el, 'href');
      if (href?.expression) continue;                    // a computed href may well be a real URL
      const value = href?.value;
      const placeholder = href === undefined || value === undefined || PLACEHOLDER_HREFS.has(value.trim());
      if (!placeholder) continue;

      bucket(groups, mod.path, 'anchor', {
        line: el.line,
        detail: href === undefined
          ? '<a> with a click handler and no href attribute'
          : `<a href="${value}"> with a click handler and a placeholder href`,
        symbol: enclosingSymbol(mod, el.line),
      });
    }

    for (const [, b] of groups) {
      const n = b.hits.length;
      out.push(ctx.finding({
        ruleId: 'accessibility.link.anchor_used_as_button',
        title: `Anchor used as a button in ${b.file}`,
        severity: 'medium',
        confidence: 'strong',
        files: [b.file],
        symbol: b.hits[0]!.symbol,
        evidence: evidenceFor(map, b, 'click handler present with no real href'),
        explanation:
          `${n} anchor element(s) in ${b.file} carry a click handler with no destination (${lineList(b.hits)}). ` +
          'An anchor without an href is not a link: it is not focusable, it is not announced as a link, and Enter does not activate it. ' +
          'The distinction is not pedantry — a link navigates and a button acts, and users rely on that difference. A link can be opened in a ' +
          'new tab, copied, bookmarked and reached with the screen-reader links list; an action dressed as a link offers all of those and then ' +
          `does something else, or nothing. ${SOURCE_ONLY}`,
        userImpact:
          'Keyboard users cannot reach the control, because an href-less anchor is outside the tab order. Screen-reader users looking for it in the ' +
          'links list do not find it. Anyone who middle-clicks or Cmd-clicks expecting a new tab gets a blank page instead of the action.',
        likelyRootCause:
          'An anchor chosen for its default styling, with href="#" or no href added to suppress navigation.',
        downstreamConsequences: [
          'href="#" additionally appends a fragment to the URL and can scroll the page to the top on activation.',
          'Analytics and routing code that treats anchor clicks as navigation sees events that are not navigations.',
        ],
        remediation:
          'Use <button type="button"> for anything that performs an action in place, and style it to match the link appearance if the design requires it. ' +
          'Reserve <a href> for navigation, and give it a real destination so it works with middle-click, Cmd-click and browser history. ' +
          'In a Next.js application use <Link href> for internal navigation. Enable eslint-plugin-jsx-a11y anchor-is-valid.',
        effort: 'small',
        verificationSteps: [
          `Tab through the page and confirm each control at ${lineList(b.hits)} is reachable and activates with Enter and Space as appropriate.`,
          'Confirm the URL no longer gains a "#" fragment when the control is used.',
          'With a screen reader, confirm actions are announced as buttons and navigations as links.',
        ],
        references: [WCAG.keyboard, WCAG.nameRoleValue, WCAG.ariaPractices],
      }));
    }
  }
  return out;
}

// ------------------------------------------- 7. positive tabIndex -----------

function positiveTabIndex(ctx: AnalyzerContext, mods: ParsedModule[]): Finding[] {
  const { map } = ctx;
  const out: Finding[] = [];

  for (const mod of mods) {
    const groups = new Map<string, Bucket>();

    for (const el of mod.jsx) {
      const a = attrOf(el, 'tabIndex');
      if (!a) continue;
      const raw = unbrace(a.value);
      if (raw === undefined) continue;
      const n = Number(raw);
      if (!Number.isInteger(n) || n <= 0) continue;

      bucket(groups, mod.path, 'positive', {
        line: el.line,
        detail: `<${el.tag}> with tabIndex={${n}}`,
        symbol: enclosingSymbol(mod, el.line),
      });
    }

    for (const [, b] of groups) {
      const n = b.hits.length;
      out.push(ctx.finding({
        ruleId: 'accessibility.focus.positive_tabindex',
        title: `Positive tabIndex overrides document focus order in ${b.file}`,
        severity: 'low',
        confidence: 'strong',
        status: 'needs_runtime_verification',
        files: [b.file],
        symbol: b.hits[0]!.symbol,
        evidence: evidenceFor(map, b, 'tabIndex greater than zero found on this element'),
        explanation:
          `${n} element(s) in ${b.file} set a tabIndex greater than zero (${lineList(b.hits)}). ` +
          'Any positive tabIndex moves the element ahead of every element with tabIndex 0 across the whole document, not just within its own ' +
          'container, so the tab order stops following the visual and DOM order. Two components that each do this fight each other, and the ' +
          'result depends on what else is on the page. ' +
          `The attribute itself is certain from source; the resulting order can only be established by tabbing through the rendered page, which is why this is marked for runtime verification. ${SOURCE_ONLY}`,
        userImpact:
          'A keyboard user tabs forward and focus jumps to an unrelated part of the page, then back. In a form this means fields are visited out of ' +
          'order, which makes it easy to submit an incomplete form without noticing.',
        likelyRootCause:
          'A positive tabIndex used to force one control to be reached early, instead of ordering the markup to match the visual layout.',
        downstreamConsequences: [
          'Focus order becomes a global property of the page, so unrelated components can no longer be reasoned about in isolation.',
          'Adding or reordering components elsewhere can silently change this order.',
        ],
        remediation:
          'Remove the positive values. Use tabIndex={0} to make a custom control focusable, tabIndex={-1} for a programmatic focus target such as a ' +
          'dialog container or a skip-link destination, and order the DOM to match the visual order so the natural sequence is already correct. ' +
          'Where a region must be reached quickly, add a skip link rather than reordering focus.',
        effort: 'small',
        verificationSteps: [
          'Tab through the page from the address bar and confirm focus moves in the order the layout implies, with no jumps.',
          `Confirm no remaining tabIndex value in ${b.file} is greater than zero.`,
          'Run `npx @axe-core/cli <url>` and confirm no tabindex violations remain.',
        ],
        references: [WCAG.focusOrder, WCAG.keyboard],
      }));
    }
  }
  return out;
}

// ------------------------------------------- 8. heading order ---------------

function headingOrderJumps(ctx: AnalyzerContext, mods: ParsedModule[]): Finding[] {
  const { map } = ctx;
  const out: Finding[] = [];

  for (const mod of mods) {
    const headings = mod.jsx
      .map((el) => {
        const m = /^h([1-6])$/.exec(el.tag);
        return m ? { level: Number(m[1]), line: el.line } : undefined;
      })
      .filter((h): h is { level: number; line: number } => h !== undefined)
      .sort((a, b) => a.line - b.line);

    if (headings.length < 2) continue;

    const hits: Hit[] = [];
    for (let i = 1; i < headings.length; i++) {
      const prev = headings[i - 1]!;
      const cur = headings[i]!;
      const skipped = cur.level - prev.level - 1;
      if (skipped > 0) {
        hits.push({
          line: cur.line,
          detail: `h${cur.level} follows h${prev.level}, skipping ${skipped === 1 ? 'one level' : `${skipped} levels`}`,
          symbol: enclosingSymbol(mod, cur.line),
        });
      }
    }
    if (hits.length === 0) continue;

    const b: Bucket = { file: mod.path, hits };
    out.push(ctx.finding({
      ruleId: 'accessibility.heading.level_skipped',
      title: `Heading level skipped in ${mod.path}`,
      severity: 'low',
      confidence: 'moderate',
      status: 'needs_runtime_verification',
      files: [mod.path],
      symbol: hits[0]!.symbol,
      evidence: evidenceFor(map, b, 'heading level jumps by more than one from the preceding heading in this file'),
      explanation:
        `Headings in ${mod.path} skip a level (${lineList(hits)}). Headings are the document outline that assistive technology ` +
        'navigates by: a screen-reader user lists headings or jumps between them to find a section, and a skipped level implies a ' +
        'missing section, leaving them unsure whether content was missed. ' +
        'This file is one fragment of a page, so the final outline depends on the components it is composed with — a jump here may be ' +
        `closed by a parent, and a sequence that looks right here may still be wrong in the assembled page. The rendered document outline is what settles it. ${SOURCE_ONLY}`,
      userImpact:
        'A screen-reader user navigating by heading cannot tell whether a section is missing or merely mis-marked, and loses the structure they ' +
        'rely on to skim. Users of reading-mode and outline tools see the same broken hierarchy.',
      likelyRootCause: 'Heading levels chosen for their default font size rather than for document structure.',
      downstreamConsequences: [
        'Generated tables of contents and document outlines are wrong.',
        'Search engines and reader modes infer the wrong page structure.',
      ],
      remediation:
        'Set heading levels from the structure and control size with CSS. Within a page, go from h1 down one level at a time; where a component can ' +
        'appear at more than one depth, pass the level in as a prop (or compute it from context) rather than hard-coding one. ' +
        'Verify the whole-page outline, not the component in isolation.',
      effort: 'small',
      verificationSteps: [
        'Render the full page and list its headings (devtools accessibility pane, or an extension such as HeadingsMap) to confirm the outline descends one level at a time.',
        'Confirm the page has exactly one h1 that names the page.',
        'Run `npx @axe-core/cli <url>` and confirm no heading-order violations remain.',
      ],
      references: [WCAG.headingsLabels, WCAG.infoRelationships],
    }));
  }
  return out;
}

// ------------------------------------------- 9. document language -----------

function missingDocumentLanguage(ctx: AnalyzerContext, mods: ParsedModule[]): Finding[] {
  const { map } = ctx;
  const out: Finding[] = [];

  const emit = (file: string, evidence: Evidence, where: string): void => {
    if (!evidence.verified) return;
    out.push(ctx.finding({
      ruleId: 'accessibility.document.missing_lang',
      title: `Document root has no lang attribute in ${file}`,
      severity: 'medium',
      confidence: 'strong',
      files: [file],
      evidence: [evidence],
      explanation:
        `The <html> element in ${file} has no lang attribute (${where}). The document language is what tells a screen reader which ` +
        'pronunciation rules and voice to use; without it the user\'s default voice is applied to whatever the page contains, so English ' +
        'text can be read with French phonetics, or the reverse. It also drives hyphenation, quotation marks, and the language offered by ' +
        `translation tools. ${SOURCE_ONLY}`,
      userImpact:
        'Screen-reader output can become hard to follow or unintelligible for the entire page — not one component, every page served from this ' +
        'root. Users who rely on synthetic speech may have to change their voice settings manually to read the site at all.',
      likelyRootCause: 'A hand-written root layout or HTML template where the attribute was never added.',
      downstreamConsequences: [
        'Automated audits fail every page on a Level A criterion.',
        'Browser translation offers and spell-checking behave inconsistently.',
      ],
      remediation:
        'Add the primary language of the page as a BCP 47 tag on the root element: <html lang="en"> (or "en-GB", "fr", "hi" as appropriate). ' +
        'Where content is served in several languages, set it from the request or routing locale rather than hard-coding one, and mark passages ' +
        'in another language inline with lang on the containing element.',
      effort: 'trivial',
      verificationSteps: [
        'View source on a served page and confirm the <html> element carries a lang attribute with the correct language tag.',
        'Run `npx @axe-core/cli <url>` and confirm the html-has-lang violation is gone.',
        'With a screen reader, confirm the page is read with the expected voice.',
      ],
      references: [WCAG.languageOfPage, 'BCP 47 language tags'],
    }));
  };

  for (const mod of mods) {
    for (const el of mod.jsx) {
      if (el.tag !== 'html') continue;
      if (hasAttr(el, 'lang')) continue;
      if (hasSpreadProps(map, mod, el)) continue;        // a spread may carry lang
      emit(mod.path, map.evidenceLine(mod.path, el.line, 'root element rendered without a lang attribute'),
        `line ${el.line}`);
    }
  }

  // Static HTML documents are indexed but not parsed into modules, so match their text.
  for (const file of map.files) {
    if (file.language !== 'html' || !file.text) continue;
    if (file.generated || file.vendored || isNonProductUi(file.path)) continue;
    const m = /<html\b([^>]*)>/i.exec(file.text);
    if (!m || /\blang\s*=/i.test(m[1] ?? '')) continue;
    emit(file.path, map.evidenceAt(file.path, m[0], 'root element declared without a lang attribute'), 'document root');
  }

  return out;
}

// ------------------------------------------- 10. autoplaying media ----------

function autoplayingMedia(ctx: AnalyzerContext, mods: ParsedModule[]): Finding[] {
  const { map } = ctx;
  const out: Finding[] = [];

  for (const mod of mods) {
    const groups = new Map<string, Bucket>();

    for (const el of mod.jsx) {
      if (el.tag !== 'video' && el.tag !== 'audio') continue;
      const autoplay = attrOf(el, 'autoPlay') ?? attrOf(el, 'autoplay');
      if (!autoplay) continue;
      if (unbrace(autoplay.value) === 'false') continue;
      if (hasSpreadProps(map, mod, el)) continue;        // a spread may carry muted or controls

      const muted = attrOf(el, 'muted') !== undefined && unbrace(attrOf(el, 'muted')!.value) !== 'false';
      const controls = hasAttr(el, 'controls');
      const audible = el.tag === 'audio' || !muted;

      if (audible) {
        bucket(groups, mod.path, 'audible', {
          line: el.line,
          detail: `<${el.tag} autoPlay>${el.tag === 'video' ? ' without muted' : ''}` +
            `${controls ? '' : ' without controls'}`,
          symbol: enclosingSymbol(mod, el.line),
        });
      } else {
        bucket(groups, mod.path, 'muted', {
          line: el.line,
          detail: `<${el.tag} autoPlay muted>${controls ? '' : ' without controls'}`,
          symbol: enclosingSymbol(mod, el.line),
        });
      }
    }

    for (const [key, b] of groups) {
      const audible = key.endsWith('audible');
      const n = b.hits.length;
      out.push(ctx.finding({
        ruleId: 'accessibility.media.autoplay',
        title: audible
          ? `Media autoplays with sound in ${b.file}`
          : `Media autoplays without a pause control in ${b.file}`,
        severity: audible ? 'medium' : 'low',
        confidence: audible ? 'strong' : 'moderate',
        status: audible ? undefined : 'needs_runtime_verification',
        files: [b.file],
        symbol: b.hits[0]!.symbol,
        evidence: evidenceFor(map, b, 'autoplay attribute present on this media element'),
        explanation:
          (audible
            ? `${n} media element(s) in ${b.file} autoplay with audio (${lineList(b.hits)}). ` +
              'WCAG 1.4.2 requires that audio which plays automatically for more than three seconds can be paused, stopped, or have its volume ' +
              'controlled independently of the system volume. Audio starting unbidden also masks a screen reader\'s own speech, which is the one ' +
              'output its user cannot turn down selectively. '
            : `${n} media element(s) in ${b.file} autoplay (${lineList(b.hits)})${b.hits.some((h) => h.detail.includes('without controls')) ? ' with no visible controls' : ''}. ` +
              'Muted autoplay does not mask speech, but WCAG 2.2.2 requires a mechanism to pause moving content that plays for more than five ' +
              'seconds, and motion in the periphery is a known trigger for vestibular disorders and a distraction for readers with attention ' +
              'difficulties. Whether this clip exceeds five seconds depends on the media file, which no static analysis can measure. ')
          + SOURCE_ONLY,
        userImpact:
          audible
            ? 'A screen-reader user loses their own speech output under the media audio and has to find and silence it before they can navigate at all. ' +
              'Anyone in a shared or quiet space has sound played on their behalf without consent.'
            : 'Readers with vestibular sensitivity may experience dizziness or nausea from looping motion they cannot stop, and users with attention ' +
              'difficulties lose the ability to read the surrounding content.',
        likelyRootCause: 'Autoplay added for visual impact on a marketing surface, without a pause affordance.',
        downstreamConsequences: [
          'Browsers block audible autoplay by default, so the intended behaviour is inconsistent across users anyway.',
          'Autoplaying media consumes mobile data and battery before any user intent is expressed.',
        ],
        remediation:
          audible
            ? 'Do not autoplay audible media. Require an explicit play action, or if the media must start on load, add muted together with visible ' +
              'controls so the user can start the sound deliberately. Honour prefers-reduced-motion for the video itself.'
            : 'Add visible controls (or your own accessible play/pause button), keep the clip under five seconds if it must loop, and wrap autoplay in a ' +
              '`@media (prefers-reduced-motion: reduce)` check — or a matchMedia test — so users who ask for less motion get a static poster frame instead.',
        effort: 'small',
        verificationSteps: [
          'Load the page and confirm nothing plays audio until a user action starts it.',
          'Confirm a keyboard-reachable pause control exists for any media that starts on its own.',
          'Set the operating system "reduce motion" preference and confirm autoplay does not occur.',
        ],
        references: [audible ? WCAG.audioControl : WCAG.pauseStopHide, WCAG.keyboard],
      }));
    }
  }
  return out;
}

// ------------------------------------------- 11. dialog focus management ----

const FOCUS_MANAGEMENT_RE =
  /\b(useRef|createRef|\.focus\s*\(|autoFocus|inert|FocusTrap|FocusScope|focus-trap|focusTrap|useFocus|showModal|aria-modal|initialFocus|restoreFocus)\b/;

function unmanagedDialogFocus(ctx: AnalyzerContext, mods: ParsedModule[]): Finding[] {
  const { map } = ctx;
  const out: Finding[] = [];

  for (const mod of mods) {
    const dialogs = mod.jsx.filter((el) => {
      const role = literal(el, 'role');
      return el.tag === 'dialog' || role === 'dialog' || role === 'alertdialog';
    });
    if (dialogs.length === 0) continue;

    const text = moduleText(map, mod.path);
    if (FOCUS_MANAGEMENT_RE.test(text)) continue;        // some focus handling exists; leave it alone

    const hits: Hit[] = dialogs.map((el) => ({
      line: el.line,
      detail: `${el.tag === 'dialog' ? '<dialog>' : `role="${literal(el, 'role')}"`} rendered with no focus handling in this module`,
      symbol: enclosingSymbol(mod, el.line),
    }));
    const b: Bucket = { file: mod.path, hits };
    const missingAriaModal = dialogs.some((el) => el.tag !== 'dialog' && !hasAttr(el, 'aria-modal'));

    out.push(ctx.finding({
      ruleId: 'accessibility.focus.dialog_not_managed',
      title: `Dialog with no focus management in ${mod.path}`,
      severity: 'medium',
      confidence: 'moderate',
      status: 'needs_runtime_verification',
      files: [mod.path],
      symbol: hits[0]!.symbol,
      evidence: evidenceFor(map, b, 'no ref, focus() call, autoFocus, inert or focus-trap appears anywhere in this module'),
      explanation:
        `${mod.path} renders a dialog (${lineList(hits)}) and contains no sign of focus management: no ref, no focus() call, no autoFocus, ` +
        'no inert, no focus trap. A dialog has three obligations beyond appearing: move focus into itself when it opens, keep focus inside while ' +
        'it is open, and return focus to the element that opened it when it closes. ' +
        (missingAriaModal
          ? 'aria-modal="true" is also absent, so assistive technology is not told the rest of the page is unavailable. '
          : '') +
        'Focus may be handled by a dialog library used through a wrapper component, or in a parent this analyzer did not connect to this file, ' +
        `so this is a prompt to check rather than a confirmed defect — and real focus order can only be observed in a browser. ${SOURCE_ONLY}`,
      userImpact:
        'A keyboard user opens the dialog and focus stays behind it, so they tab through the page underneath without ever reaching the dialog\'s ' +
        'controls — and cannot dismiss it. A screen-reader user is not told the dialog opened, and continues reading the content behind it.',
      likelyRootCause: 'A dialog built from a positioned div, with the visual layer implemented and the focus contract left out.',
      downstreamConsequences: [
        'Content behind the dialog stays reachable, so users can act on a page they believe is blocked.',
        'Closing the dialog loses the user\'s place in the page entirely.',
      ],
      remediation:
        'Use the platform or a maintained primitive: the native <dialog> element with showModal(), or a library dialog (Radix, React Aria, Headless UI) ' +
        'that implements the pattern. Hand-rolled dialogs must set role="dialog" with aria-modal="true" and an accessible name via aria-labelledby, ' +
        'move focus to the dialog or its first control on open, confine Tab and Shift+Tab to the dialog, close on Escape, and restore focus to the ' +
        'triggering element on close.',
      effort: 'medium',
      verificationSteps: [
        'Open the dialog with the keyboard and confirm focus moves into it immediately.',
        'Press Tab repeatedly and confirm focus cycles within the dialog and never reaches the page behind it.',
        'Press Escape and confirm the dialog closes and focus returns to the control that opened it.',
        'With a screen reader, confirm the dialog is announced with a name when it opens.',
      ],
      references: [WCAG.focusOrder, WCAG.noKeyboardTrap, WCAG.ariaPractices],
    }));
  }
  return out;
}

// ------------------------------------------- 12. loading / error states -----

/**
 * Any affordance that tells the user work is in progress.
 *
 * Deliberately does not include `placeholder`: an input's placeholder attribute
 * is unrelated to pending state, and treating it as a pending affordance made
 * this rule silently skip any component containing a search box.
 */
const PENDING_RE =
  /\b(isLoading|loading|isPending|pending|isFetching|isValidating|isRefetching|busy|Skeleton|skeleton|Spinner|spinner|Suspense|fallback|progress|aria-busy|shimmer)\b/;

/** Any affordance that tells the user something failed. */
const FAILURE_RE = /(error|Error|catch|reject|failed|failure|onError|retry|fallbackRender|ErrorBoundary)/;

/** Callees that are data access rather than framework plumbing. */
const DATA_CALL_RE =
  /(^|\.)(fetch|query|queries|find|findMany|findUnique|findFirst|get|getAll|list|listAll|load|select|aggregate|count|search|read|request|execute|rpc)/i;

/** Next.js async request APIs: awaiting these is not data fetching. */
const NEXT_REQUEST_API = new Set([
  'cookies', 'headers', 'draftMode', 'params', 'searchParams', 'connection', 'after', 'revalidatePath', 'revalidateTag',
]);

function isAppRouterPage(path: string): boolean {
  return /(^|\/)app\/(.*\/)?(page|template)\.[cm]?[jt]sx$/.test(path);
}

/** A loading.tsx / error.tsx boundary in this route segment or any ancestor. */
function routeBoundary(map: RepoMap, pagePath: string): string | undefined {
  const parts = pagePath.split('/');
  parts.pop();
  while (parts.length > 0) {
    const dir = parts.join('/');
    for (const base of ['error', 'global-error', 'loading']) {
      for (const ext of ['tsx', 'jsx', 'js', 'ts']) {
        const candidate = `${dir}/${base}.${ext}`;
        if (map.filesByPath.has(candidate)) return candidate;
      }
    }
    // A layout in an ancestor segment may hold a Suspense or error boundary.
    for (const ext of ['tsx', 'jsx', 'js']) {
      const layout = `${dir}/layout.${ext}`;
      const file = map.filesByPath.get(layout);
      if (file?.text) {
        const t = codeText(file.text, file.language);
        if (/\bSuspense\b|ErrorBoundary/.test(t)) return layout;
      }
    }
    const last = parts.pop();
    if (last === 'app') break;      // stop at the App Router root
  }
  return undefined;
}

function missingLoadingAndErrorStates(ctx: AnalyzerContext, mods: ParsedModule[]): Finding[] {
  const { map } = ctx;
  const out: Finding[] = [];

  for (const mod of mods) {
    const text = moduleText(map, mod.path);
    if (PENDING_RE.test(text) || FAILURE_RE.test(text)) continue;   // some state exists; not this rule
    if (mod.hasTryCatch) continue;

    const serverPage = isAppRouterPage(mod.path);

    // The data access this component performs during render.
    const dataCalls = mod.calls.filter((c) => {
      const leaf = c.callee.split('.').pop() ?? c.callee;
      if (NEXT_REQUEST_API.has(leaf)) return false;
      if (!DATA_CALL_RE.test(c.callee)) return false;
      return c.awaited || /^fetch(\(|$)|axios|useQuery|useSWR/.test(c.callee);
    });
    if (dataCalls.length === 0) continue;

    // Earliest call, and the plainest spelling of it: the parser records
    // `fetch`, `fetch().then` and `fetch().then().then` for one chained request.
    dataCalls.sort((a, b) => (a.line - b.line) || (a.callee.length - b.callee.length));
    const call = dataCalls[0]!;
    const awaited = dataCalls.filter((c) => c.awaited);
    const boundary = serverPage ? routeBoundary(map, mod.path) : undefined;
    if (boundary) continue;         // the framework supplies the states

    const evidence: Evidence[] = [
      { ...map.evidenceLine(mod.path, call.line,
        awaited.length > 0
          ? 'data is awaited during render, and this module renders no pending or failure state'
          : 'data is requested during render, and this module renders no pending or failure state'),
        symbol: call.inSymbol },
    ];
    const firstJsx = mod.jsx[0];
    if (firstJsx) {
      evidence.push(map.evidenceLine(mod.path, firstJsx.line,
        'the rendered output has no branch for a pending or failed request'));
    }
    if (evidence.some((e) => !e.verified)) continue;

    let trace: RelationshipTrace | undefined;
    if (serverPage) {
      const impl = mod.imports.find((i) =>
        i.resolvedPath && i.names.some((n) => call.callee.startsWith(n)));
      const steps: RelationshipTrace['steps'] = [{
        file: mod.path,
        symbol: call.inSymbol,
        line: call.line,
        detail: `awaits ${call.callee}() while rendering, with no surrounding try/catch`,
      }];
      if (impl?.resolvedPath) {
        steps.push({
          file: impl.resolvedPath,
          detail: `${call.callee} is implemented here; a rejection or a slow response propagates to the caller unchanged`,
        });
      }
      steps.push({
        file: mod.path,
        detail: 'no error.tsx, global-error.tsx, loading.tsx, or Suspense/ErrorBoundary in an ancestor layout covers this route segment',
      });
      trace = { kind: 'call', steps, complete: impl?.resolvedPath !== undefined };
    }

    const confidence: Confidence = trace?.complete ? 'strong' : 'moderate';
    const severity: Severity = 'low';

    out.push(ctx.finding({
      ruleId: 'accessibility.ux.no_loading_or_error_state',
      title: `Data is rendered with no loading or error state in ${mod.path}`,
      severity,
      confidence,
      status: 'needs_runtime_verification',
      detectionSource: trace ? 'graph' : 'static',
      files: trace ? [...new Set(trace.steps.map((s) => s.file))] : [mod.path],
      symbol: call.inSymbol,
      evidence,
      trace,
      explanation:
        `${mod.path} ${awaited.length > 0 ? 'awaits' : 'requests'} data as part of rendering (${call.callee} at line ${call.line}) and ` +
        'renders neither a pending state nor a failure state. ' +
        (serverPage
          ? 'This is an App Router segment, where the framework would supply both if the files existed: a loading.tsx renders while the segment ' +
            'streams, and an error.tsx catches anything the segment throws. Neither is present in this segment or any ancestor, and there is no ' +
            'Suspense or error boundary in an ancestor layout, so a rejection becomes the framework\'s own error screen and a slow response shows ' +
            'nothing at all. '
          : 'There is no pending branch, no error branch, and no catch on the request, so a slow response renders nothing and a failure renders ' +
            'nothing — the same empty output means "working", "empty", and "broken". ') +
        'Two outcomes a user would experience differently are presented identically, with no text for assistive technology to announce. ' +
        `How long the request actually takes was not measured, and the failure path was not executed; those need a running system. ${SOURCE_ONLY}`,
      userImpact:
        'On a slow connection the user sees an empty region with no indication that anything is happening, so they wait, reload, or leave. ' +
        'When the request fails they see the same empty region, with nothing telling them to retry and no way to distinguish failure from ' +
        'genuinely having no data. A screen-reader user gets no announcement at all, because nothing is rendered to announce.',
      likelyRootCause:
        'The happy path was built first; the pending and failure paths were left for later because they are not visible in local development ' +
        'against fast, working data.',
      downstreamConsequences: [
        'Support cannot distinguish "no data" from "the request failed" in user reports.',
        'A transient backend failure looks like data loss to the user.',
        'Perceived performance is worse than measured performance, because nothing acknowledges the wait.',
      ],
      remediation:
        serverPage
          ? 'Add a loading.tsx beside the page so the segment streams a skeleton while data resolves, and an error.tsx with a retry action so a ' +
            'rejection is contained in this segment. Mark the loading region with role="status" and aria-live="polite" so the wait is announced, ' +
            'and give the error state real text — what failed and what to do next — rather than only an icon. Keep an empty state distinct from both.'
          : 'Track the request\'s three outcomes explicitly — pending, failed, loaded — and render a distinct state for each: a skeleton or spinner ' +
            'inside a role="status" region with aria-live="polite" while pending, a message with a retry action on failure, and a distinct empty state ' +
            'when the request succeeds with no rows. Attach a .catch (or try/catch with await) so a rejection becomes state rather than an unhandled rejection.',
      effort: 'small',
      verificationSteps: [
        'Throttle the network in devtools to "Slow 3G", load the view, and confirm a pending state appears and is announced by a screen reader.',
        'Make the request fail (block the URL in devtools, or stop the backend) and confirm an error message with a retry action is rendered.',
        'Return an empty result and confirm the empty state is distinguishable from both the pending and the failed state.',
      ],
      references: [WCAG.statusMessages, 'WCAG 2.2 3.3.1 Error Identification (Level A)'],
    }));
  }
  return out;
}
