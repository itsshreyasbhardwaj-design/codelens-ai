import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from 'node:crypto';

/**
 * Provider credential encryption.
 *
 * Repository tokens are stored as AES-256-GCM ciphertext. The key is derived
 * from CODELENS_SECRET_KEY; with no key configured, token storage is refused
 * outright rather than silently falling back to plaintext.
 */

const SALT = 'codelens.credential.v1';

export class CredentialStorageUnavailable extends Error {
  constructor() {
    super(
      'CODELENS_SECRET_KEY is not set, so provider credentials cannot be stored encrypted. ' +
        'Refusing to store the token in plaintext. Set a 32+ character CODELENS_SECRET_KEY.',
    );
    this.name = 'CredentialStorageUnavailable';
  }
}

function key(): Buffer {
  const secret = process.env.CODELENS_SECRET_KEY;
  if (!secret || secret.length < 32) throw new CredentialStorageUnavailable();
  return scryptSync(secret, SALT, 32);
}

export function encryptToken(plaintext: string): { ciphertext: string; nonce: string } {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key(), iv);
  const enc = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    ciphertext: Buffer.concat([enc, tag]).toString('base64'),
    nonce: iv.toString('base64'),
  };
}

export function decryptToken(ciphertext: string, nonce: string): string {
  const raw = Buffer.from(ciphertext, 'base64');
  const tag = raw.subarray(raw.length - 16);
  const body = raw.subarray(0, raw.length - 16);
  const decipher = createDecipheriv('aes-256-gcm', key(), Buffer.from(nonce, 'base64'));
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(body), decipher.final()]).toString('utf8');
}

/** Redact secret-shaped substrings before anything is logged or stored as output. */
const SECRET_PATTERNS: Array<[RegExp, string]> = [
  [/\b(gh[pousr]_[A-Za-z0-9]{16,})\b/g, 'gh*_[REDACTED]'],
  [/\b(sk-[A-Za-z0-9_-]{16,})\b/g, 'sk-[REDACTED]'],
  [/\b(sk-ant-[A-Za-z0-9_-]{16,})\b/g, 'sk-ant-[REDACTED]'],
  [/\b(AKIA[0-9A-Z]{16})\b/g, 'AKIA[REDACTED]'],
  [/\b(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b/g, '[REDACTED_JWT]'],
  [/(["']?(?:password|passwd|secret|api[_-]?key|token|private[_-]?key)["']?\s*[:=]\s*["'])([^"']{6,})(["'])/gi, '$1[REDACTED]$3'],
  [/(postgres(?:ql)?:\/\/[^:]+:)([^@]+)(@)/gi, '$1[REDACTED]$3'],
  [/(mongodb(?:\+srv)?:\/\/[^:]+:)([^@]+)(@)/gi, '$1[REDACTED]$3'],
];

export function redactSecrets(text: string): string {
  let out = text;
  for (const [re, repl] of SECRET_PATTERNS) out = out.replace(re, repl);
  return out;
}
