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

## Before hosting this for other people

**Authentication is not implemented.** The schema models users, organisations
and roles, and the data layer enforces tenant scoping, but there is no sign-in.
This release is single-tenant and local. See `docs/STATUS.md` and
`docs/RUNBOOK.md`.
