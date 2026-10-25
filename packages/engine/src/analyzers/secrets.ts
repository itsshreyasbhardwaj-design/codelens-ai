/**
 * Secret detection: known credential shapes plus entropy.
 *
 * Kept separate from the rest of the security rules because it is the one place
 * that must never print the matched value. Findings carry a masked excerpt.
 */

export interface SecretMatch {
  kind: string;
  /** Masked representation; the raw secret is never stored. */
  masked: string;
  /** 0..1 — how certain the shape is. */
  shapeConfidence: number;
}

interface SecretRule {
  kind: string;
  re: RegExp;
  confidence: number;
}

/** Provider-specific shapes. A match here is unambiguous. */
const KNOWN_SHAPES: SecretRule[] = [
  { kind: 'Stripe live secret key', re: /\bsk_live_[A-Za-z0-9]{16,}\b/, confidence: 1.0 },
  { kind: 'Stripe test secret key', re: /\bsk_test_[A-Za-z0-9]{16,}\b/, confidence: 0.9 },
  { kind: 'OpenAI API key', re: /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b/, confidence: 0.95 },
  { kind: 'Anthropic API key', re: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/, confidence: 1.0 },
  { kind: 'GitHub token', re: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/, confidence: 1.0 },
  { kind: 'AWS access key id', re: /\bAKIA[0-9A-Z]{16}\b/, confidence: 1.0 },
  { kind: 'Google API key', re: /\bAIza[0-9A-Za-z_-]{35}\b/, confidence: 1.0 },
  { kind: 'Slack token', re: /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/, confidence: 1.0 },
  { kind: 'SendGrid API key', re: /\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b/, confidence: 1.0 },
  { kind: 'private key block', re: /-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----/, confidence: 1.0 },
  { kind: 'JSON web token', re: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/, confidence: 0.85 },
  { kind: 'database connection string with password', re: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp):\/\/[^:\s/]+:[^@\s]{4,}@/, confidence: 0.95 },
];

/** Names that indicate a value is meant to be secret. */
const SECRET_NAME_RE =
  /(?:^|_|\.|\b)(?:secret|password|passwd|pwd|api[_-]?key|apikey|access[_-]?token|auth[_-]?token|private[_-]?key|client[_-]?secret|signing[_-]?key|encryption[_-]?key|session[_-]?secret)(?:$|_|\b)/i;

/** Values that are clearly placeholders rather than live credentials. */
const PLACEHOLDER_RE =
  /^(?:|x+|y+|z+|changeme|change[_-]?me|your[_-]?.*|placeholder|example|sample|dummy|test|todo|none|null|undefined|secret|password|xxx+|\.\.\.|<[^>]*>|\$\{[^}]*\}|\{\{[^}]*\}\}|%[A-Z_]+%)$/i;

/** Shannon entropy in bits per character. */
export function entropy(value: string): number {
  if (value.length === 0) return 0;
  const counts = new Map<string, number>();
  for (const ch of value) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let h = 0;
  for (const n of counts.values()) {
    const p = n / value.length;
    h -= p * Math.log2(p);
  }
  return h;
}

export function maskSecret(value: string): string {
  if (value.length <= 8) return '*'.repeat(value.length);
  return `${value.slice(0, 4)}${'*'.repeat(Math.min(16, value.length - 8))}${value.slice(-4)}`;
}

/** True when a value looks like a real credential rather than a placeholder. */
export function looksLikeLiveSecret(value: string): boolean {
  if (value.length < 12) return false;
  if (PLACEHOLDER_RE.test(value.trim())) return false;
  // A path, URL without credentials, or sentence is not a secret.
  if (/\s/.test(value)) return false;
  if (/^\.{0,2}\//.test(value)) return false;
  if (/^https?:\/\//.test(value) && !/:[^@/]+@/.test(value)) return false;
  return entropy(value) >= 3.2;
}

/** Match a value against known credential shapes. */
export function matchKnownSecret(value: string): SecretMatch | undefined {
  for (const rule of KNOWN_SHAPES) {
    const m = rule.re.exec(value);
    if (m) return { kind: rule.kind, masked: maskSecret(m[0]), shapeConfidence: rule.confidence };
  }
  return undefined;
}

/**
 * Decide whether an assignment `name = value` holds a hardcoded secret.
 * Returns undefined when it does not.
 */
export function assessAssignment(name: string, value: string): SecretMatch | undefined {
  const known = matchKnownSecret(value);
  if (known) return known;
  if (!SECRET_NAME_RE.test(name)) return undefined;
  if (!looksLikeLiveSecret(value)) return undefined;
  return {
    kind: `hardcoded value assigned to '${name}'`,
    masked: maskSecret(value),
    // A secret-looking name plus a high-entropy value is strong but not
    // certain: it could still be a fixture.
    shapeConfidence: 0.75,
  };
}

export function isTestOrExamplePath(path: string): boolean {
  return /(?:^|\/)(?:tests?|__tests__|spec|fixtures?|examples?|mocks?|__mocks__|docs?)(?:\/|$)/i.test(path)
    || /\.(?:test|spec)\.[cm]?[jt]sx?$/.test(path)
    || /\.(?:example|sample|template|dist)$/.test(path);
}
