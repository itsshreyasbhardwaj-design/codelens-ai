# Security

## Reporting a vulnerability

Open a private security advisory through GitHub's "Report a vulnerability"
button on the Security tab. Please do not open a public issue for a
vulnerability.

## Posture of this project

CodeLens processes source code, which is frequently sensitive.

- **Scans are offline by default.** No repository content leaves the machine
  unless an external AI provider is explicitly configured *and*
  `CODELENS_AI_ACCEPT_EXTERNAL_TRANSFER=true` is set.
- **Repository content is untrusted input** at every point. It never enters a
  model's system prompt, it is fenced with a per-request nonce, and model output
  is independently verified against the snapshot before it is stored.
- **Archives are treated as hostile.** Path traversal, symlinks, decompression
  bombs, lying size headers and CRC mismatches are each rejected by name.
- **Credentials are never stored in plaintext.** With no `CODELENS_SECRET_KEY`
  configured, token storage is refused outright.
- **Untrusted code is never executed.** Dynamic verification is off by default
  and refuses project dependency-installation and build scripts, because this
  host offers no container isolation.

## Authentication

Accounts use scrypt password verifiers and HMAC-signed session cookies. Every
request re-verifies the cookie and re-checks organisation membership against the
database, so removing someone from an organisation revokes their access
immediately rather than when their token expires. A wrong password and an
unknown account produce identical responses.

**Set `CODELENS_SECRET_KEY` (32+ characters) before exposing this to anyone.**
Without it the application refuses to issue sessions rather than signing them
with a weak key.

## Before hosting this for other people

- Sessions are stateless signed tokens. A single session cannot be revoked
  server-side; rotating `CODELENS_SECRET_KEY` signs everyone out. Add a sessions
  table if per-session revocation matters to you.
- There is no rate limiting on the sign-in route. Put one in front of it.
- There is no email verification, password reset, or multi-factor authentication.
- An organisation currently has exactly one member: the account that created it.

See `docs/STATUS.md` for the full list.
