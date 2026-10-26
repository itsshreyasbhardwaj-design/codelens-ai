# Deployment

This describes how to run CodeLens AI as a hosted service, and it is specific
about where it will not run. Read "What will not work" before choosing a host:
the constraints are architectural, not a matter of configuration.

## Before you trust this: the image has not been built

**The Dockerfile in this repository has never been run.** It was written on a
machine with no Docker installed, so there was no daemon and no registry access.
Everything else here was executed; the image itself was not.

What *was* verified, so you know what the gap actually is:

- The runtime file set, by assembling exactly the Dockerfile's runtime-stage
  `COPY` list into a clean directory, running `pnpm install --prod
  --frozen-lockfile`, starting the server, and confirming the landing page, the
  session guard, boot migrations, the WAL sidecars on the volume path, and
  `/api/health`.
- The same with the whole application tree made read-only, which is what running
  as the non-root `node` user against root-owned `/app` produces.
- `/api/health` across all three branches: 200 ok, 200 degraded (no secret key),
  and 503 (database unreachable, and separately, migrations pending).
- `docker-compose.yml` and `fly.toml` parse as YAML and TOML respectively, and
  every `COPY` source in the Dockerfile resolves against the repository.

What is therefore unproven: that the base image tag `node:24.16.0-bookworm-slim`
resolves, that the `apt-get install python3` layer succeeds, and that the build
completes end to end. The base image is pinned by patch tag and not by digest
for the same reason — the digest could not be resolved offline. The Dockerfile
carries the `docker buildx imagetools inspect` command to pin one.

**So: run `docker compose up --build` once on a machine with Docker before you
deploy anything to a customer.** If it fails, it will fail at build time with a
clear message, not silently in production.

## The constraint that decides your host

Two properties of the application, both recorded as decisions in
`docs/DECISIONS.md`, determine everything below.

**Storage is a file on disk.** The database is SQLite through `node:sqlite`
(ADR-001). It is not a managed service you point at with a URL; it is
`codelens.db` plus two sidecar files, living on a filesystem. It needs a
**persistent volume**, and SQLite permits **one writer**.

**A scan is long-running CPU work.** Scans run in-process and take seconds to
minutes (ADR-002). They need a process that outlives the request that started
one, not a function with a request timeout.

Together these mean the target is **a single container with a mounted volume**:
Fly.io, Railway, Render, or a VPS running Docker. That is the whole supported
shape. It is not a limitation to be worked around with configuration.

## Single writer: the rule that matters most

> **Run exactly one instance.** Never point two processes at one SQLite file,
> and never run two instances each with their own copy.

Both failure modes are quiet, which is what makes them dangerous:

- **Two processes, one file.** SQLite serialises writers with a lock. The second
  writer fails with `SQLITE_BUSY` under load, and WAL mode across two writers on
  a network filesystem can corrupt the database outright.
- **Two instances, two volumes.** This is the more likely accident, because it
  is what a platform does by default when you scale to two machines. Fly volumes
  are per-machine and are not shared. You then have two divergent databases
  behind one hostname, and a user's project appears or vanishes depending on
  which instance answered. Nothing logs an error, because from each instance's
  point of view nothing is wrong.

Scale by making the machine bigger, not by adding machines. Horizontal scaling
requires moving to PostgreSQL first — the reversal path is in ADR-001 and
`docs/ARCHITECTURE.md#postgres-migration`.

## Prerequisites

| | |
| --- | --- |
| Docker | 23 or newer. The Dockerfile uses BuildKit cache mounts, which older Docker does not understand. |
| A persistent volume | 10 GB is a reasonable start. Snapshots and scan results accumulate; `CODELENS_RETENTION_DAYS` prunes them. |
| CPU | Two cores minimum. One scan will saturate a core and starve the dashboard. |
| Memory | 2 GB minimum, 4 GB if you expect concurrent scans. |
| A secret | 32+ characters for `CODELENS_SECRET_KEY`. Without it the application refuses to issue sessions, so nobody can sign in. |

Node 24 is required and is baked into the image. The application uses
`node:sqlite` and imports workspace packages as TypeScript source; see `engines`
in `package.json`.

## Environment variables

Authoritative list is `.env.example`. Every variable there is optional **except**
`CODELENS_SECRET_KEY` for a hosted deployment.

### Required

| Variable | Notes |
| --- | --- |
| `CODELENS_SECRET_KEY` | 32+ characters. Signs session cookies and encrypts stored provider tokens. The app refuses to sign anything with a short or absent key rather than signing weakly. Rotating it logs every user out — sessions are stateless signed tokens, not rows. |
| `CODELENS_DB` | Absolute path to the database **inside the mounted volume**. The image sets `/data/codelens.db`. If this points anywhere in the image layer, every scan is lost on each deploy. |

### Optional, and off unless set

| Variable | Default | Notes |
| --- | --- | --- |
| `CODELENS_HOME` | `/data/codelens` in the image | Working directory for snapshots and artefacts. Keep it on the volume. |
| `CODELENS_RETENTION_DAYS` | `30` | How long scan data is kept. |
| `CODELENS_AI_PROVIDER` | `none` | `none`, `ollama`, `anthropic`, `openai`. Default is deterministic analysis only: no network, no cost. |
| `CODELENS_AI_MODEL` | provider default | |
| `CODELENS_OLLAMA_URL` | `http://127.0.0.1:11434` | Only for `ollama`. |
| `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` | unset | You are billed by the provider. Set as a platform secret, never in a config file. |
| `CODELENS_AI_ACCEPT_EXTERNAL_TRANSFER` | unset | Must be `true` before an external provider will run, because repository content would leave the machine. Do not set this on a user's behalf without disclosure. |
| `CODELENS_AI_TOKEN_BUDGET` | `120000` | Hard ceiling per scan; the AI layer aborts rather than exceeding it. |
| `CODELENS_PAYMENT_PROVIDER` | `none` | `stripe` or `none`. With `none`, billing is off and every account stays on the free plan. The UI says so plainly rather than offering an upgrade button that cannot work. |
| `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET` | unset | Both needed. The provider refuses to run with a secret key but no webhook secret, because entitlements would then rest on an unverified request. |
| `STRIPE_PRICE_<CODE>` | unset | Maps a plan or product code to a Stripe price id, e.g. `STRIPE_PRICE_PRO`. |
| `GITHUB_TOKEN` | unset | Read-only scopes only. Raises the GitHub API rate limit for repository ingestion. |
| `CODELENS_DYNAMIC_VERIFY` | `off` | Leave it off. It is not a sandbox (ADR-005) and it refuses project build scripts by design. |

Secrets belong in your platform's secret store (`fly secrets set`, a Railway or
Render secret, a Docker secret). They must never be written into `fly.toml`,
`docker-compose.yml`, or a `.env` file inside the build context — `.dockerignore`
excludes `.env*` precisely so a stray file cannot be baked into a layer where
`docker history` would reveal it.

## The health endpoint

`GET /api/health` is what the container `HEALTHCHECK` and the platform's load
balancer poll. It needs no session.

- **200** — the database is reachable and every migration this build carries has
  been applied. `status` is `ok`, or `degraded` when something is missing that
  does not stop the machine serving (for instance no secret key: the database is
  fine, but sign-in will fail). A degraded machine stays in rotation
  deliberately; taking it out would not fix a configuration problem.
- **503** — `status: unavailable`, with `reason` saying which: the database could
  not be opened, or migrations are still pending.

It reports whether a secret key, the AI layer and the payment provider are
configured as **booleans and reasons only**. No secret value, prefix or length
appears in the response.

Poll the exact path. `/api/health/` with a trailing slash answers **308**, and a
health check that follows no redirects will read that as a failure.

> **Integrator note.** This endpoint is only reachable without a session because
> `/api/health` is listed in `PUBLIC_PATHS` in `packages/web/middleware.ts`. The
> middleware `matcher` covers it, so removing that entry makes every health check
> return **401** and the platform will consider the machine permanently
> unhealthy. Keep the entry through any merge of that file.

## Running it

### Locally, with Compose

```bash
export CODELENS_SECRET_KEY="$(openssl rand -base64 48)"
docker compose up --build
curl -s localhost:3100/api/health
```

The named volume `codelens-data` holds the database. The port is **3100** and is
fixed: `packages/web/package.json` runs `next start --port 3100`, so `PORT` is
not consulted.

### Fly.io

```bash
fly launch --no-deploy --copy-config          # edit `app` in fly.toml first
fly volumes create codelens_data --size 10 --region iad
fly secrets set CODELENS_SECRET_KEY="$(openssl rand -base64 48)"
fly deploy
fly scale count 1                             # not optional, see below
fly status                                    # confirm: one machine, one volume
```

`fly scale count 1` is the step people skip. Fly will happily run two machines
for an HTTP service, and two machines means two volumes and two databases. Check
`fly status` after every deploy.

`fly.toml` sets `auto_stop_machines = "off"` and `auto_start_machines = false` on
purpose: a suspended machine cannot finish a scan, and stopping one mid-scan
leaves a job row that never completes.

### Any other container host

Provide: a persistent volume mounted at `/data`, `CODELENS_SECRET_KEY` as a
secret, port 3100 exposed, a health check on `/api/health`, and **a maximum
instance count of one**.

## Provisioning the volume

The volume must be mounted before first boot, at the directory `CODELENS_DB`
lives in. The image expects `/data`.

```bash
# Fly
fly volumes create codelens_data --size 10 --region iad

# Docker / Compose — a named volume, not a bind mount
docker volume create codelens-data
docker run -v codelens-data:/data ...
```

Prefer a named volume to a host bind mount. A bind mount from macOS or Windows
puts SQLite on a filesystem whose locking semantics it cannot rely on. On Linux
a bind mount is acceptable, but the directory must be writable by uid 1000 (the
`node` user the container runs as):

```bash
mkdir -p /srv/codelens/data && chown 1000:1000 /srv/codelens/data
```

The container runs as a non-root user and `/app` is root-owned, so the
application tree is read-only to the process. The only paths it writes are the
volume and `/tmp` — the Python extractor writes the embedded script and a copy
of the source into a private temporary directory. If you add `--read-only`,
mount a writable `/tmp` (`--tmpfs /tmp`) or Python parsing degrades.

## Migrations

**Migrations run on boot.** There is no separate migrate step and no command to
run. The first request to open the database applies `schema.sql` and every
numbered migration the build carries, inside a transaction each
(`packages/engine/src/db/index.ts`).

This is why the health check matters during a deploy: `/api/health` returns
**503** with `schema migrations pending` until they have been applied, so the
platform holds traffic off the machine for exactly that window. The schema
version and the pending list are in the response:

```json
"schema": { "applied": [1, 2], "pending": [], "current": 2 }
```

A migration that fails throws, the transaction rolls back, and the endpoint
reports 503 with the database unreachable. Nothing is half-applied.

Because the schema is applied forward on boot, **deploying an older image over a
newer database is not a rollback.** See below.

## Backup and restore

### The database is three files

In WAL mode SQLite keeps `codelens.db`, `codelens.db-wal` and `codelens.db-shm`.
They are one unit (`docs/RUNBOOK.md`). Copying or moving only `codelens.db`
leaves a stale journal beside a fresh database, and reads then return nothing
with no error — the symptom is an empty dashboard after a scan that clearly
succeeded.

This is not theoretical. On a live instance the main file can be 4 KB with a
megabyte of committed data sitting in the WAL. A backup of `codelens.db` alone
would restore an empty database that passes every health check.

Do not assume the sidecars are absent just because the process exited. A clean
exit checkpoints and removes them, but a process killed by `SIGTERM` or OOM
leaves them in place.

### Backing up

Use `VACUUM INTO`. It produces a **single consistent file** from a live database
with no need to stop the service, and it sidesteps the three-file problem
entirely because the output has no sidecars.

```bash
docker exec codelens-ai node -e "
  const { DatabaseSync } = require('node:sqlite');
  const out = '/data/backup-' + new Date().toISOString().replace(/[:.]/g, '-') + '.db';
  const db = new DatabaseSync(process.env.CODELENS_DB, { readOnly: true });
  db.exec(\"VACUUM INTO '\" + out + \"'\");
  db.close();
  console.log('wrote ' + out);
"
```

Then copy the resulting file off the volume (`fly ssh sftp get`, `docker cp`, or
your platform's equivalent) and verify it before trusting it:

```bash
node -e "
  const { DatabaseSync } = require('node:sqlite');
  const d = new DatabaseSync(process.argv[1], { readOnly: true });
  console.log(d.prepare('PRAGMA integrity_check').get());
  console.log(d.prepare('SELECT version FROM schema_migrations ORDER BY version').all());
" backup-2026-10-26T17-45-00-000Z.db
```

A backup you have not opened is not a backup. The integrity check and the
migration list together tell you the file is readable and which schema version
it belongs to.

If you would rather copy the live files than vacuum, stop the container first and
move **all three together**:

```bash
# Correct: all three, or none
cp /data/codelens.db /data/codelens.db-wal /data/codelens.db-shm /backup/
```

### Restoring

```bash
# 1. Stop the application. One writer; do not restore underneath a running one.
fly scale count 0            # or: docker compose stop app

# 2. Remove all three files. Leaving a stale -wal beside a restored db is the
#    failure mode this whole section exists to prevent.
rm -f /data/codelens.db /data/codelens.db-wal /data/codelens.db-shm

# 3. Put the snapshot in place under the name CODELENS_DB expects.
cp /backup/backup-2026-10-26T17-45-00-000Z.db /data/codelens.db
chown 1000:1000 /data/codelens.db

# 4. Start. Migrations run on boot, so a snapshot from an older schema is
#    brought forward automatically.
fly scale count 1

# 5. Confirm before announcing it.
curl -s https://your-app/api/health
```

Expect `"status": "ok"` with `"pending": []`.

## Rolling back

A rollback has two halves, and the schema half is the one that bites.

**Code only, same schema version.** Straightforward: redeploy the previous
image. The schema is unchanged, so nothing else is needed.

```bash
fly releases                      # find the previous version
fly deploy --image <previous-image-ref>
fly scale count 1
curl -s https://your-app/api/health
```

**Code that spans a schema change.** Migrations only go forward. There is no
`down` migration, by design — a reversible migration that nobody has tested is a
false promise. An older image against a database the newer image has already
migrated may read columns that have moved or are not there.

The supported procedure is therefore restore-then-redeploy:

1. Take a `VACUUM INTO` snapshot of the current state first, whatever you intend
   to do. You will want it if the rollback goes badly.
2. Restore the pre-deploy backup, using the steps above.
3. Deploy the previous image.
4. Check `/api/health` and confirm `schema.current` is the version that image
   expects.

Data written after the bad deploy is lost in step 2. That is the cost, and it is
the reason to take a backup immediately before any deploy that adds a migration.
Check whether a release adds one by comparing `schema.current` from
`/api/health` before and after it on a staging instance.

## What will not work

**Serverless and edge platforms.** Vercel Functions, AWS Lambda, Cloudflare
Workers, Netlify Functions, Deno Deploy. Two independent reasons, either
sufficient:

- The filesystem is ephemeral. The SQLite file is created, written and discarded
  with the instance. Every scan disappears, and no error is raised — the
  dashboard is simply empty again.
- Requests have a timeout measured in seconds, and a scan runs for minutes of
  in-process CPU work. It will be killed part-way, every time.

The project does not claim otherwise anywhere, and this document will not be the
first place to imply it.

**More than one instance.** Covered above, and worth repeating because every
platform's default is to scale out: two instances sharing one SQLite file
corrupt it; two instances with separate volumes silently serve different data.

**A shared network filesystem.** NFS, EFS, SMB. SQLite's locking is unreliable
on them. A network volume does not turn one SQLite file into a shared database.

**A read-only root filesystem with no writable `/tmp`.** The Python extractor
needs a temporary directory. Without one, Python files are indexed but never
parsed. This degrades honestly — they are reported as unparsed and counted
against parse coverage — but it is a real loss of analysis.

**Horizontal autoscaling of any kind.** Including Fly's `auto_start_machines`,
which is off in `fly.toml` for this reason.

## Before you expose it publicly

CodeLens processes other people's source code. `docs/RUNBOOK.md` has the full
list; these are the ones a deployment must not skip:

1. `CODELENS_SECRET_KEY` from a secret store, 32+ characters.
2. **A rate limiter in front of `/api/auth/login`.** There is none built in, and
   the product's own security analyzer reports that as a finding.
3. A reverse-proxy body size limit ahead of the ZIP upload path, on top of the
   engine's own bounds.
4. HTTPS, with the security headers the application sets in `next.config.ts`
   left intact. `fly.toml` sets `force_https = true`.
5. `CODELENS_DYNAMIC_VERIFY=off`. It is off by default; do not enable it without
   real container isolation.
6. One or two concurrent scans per core, no more.

## Image notes

The runtime image contains the compiled `.next` output, the production dependency
set, and the `packages/engine/src` and `packages/core/src` TypeScript sources.
The sources are not redundant: `next build` does not emit `schema.sql` or the
migration SQL into `.next`, and the server reads them from
`packages/engine/src/db/` at runtime. An image without them starts, serves the
landing page, and fails every database request.

For the same reason the build and runtime stages share `WORKDIR /app`. The path
to those SQL files is resolved relative to the compiled chunk's own location, so
the two stages must agree on the layout.

`python3` is installed in the runtime image rather than `python3-minimal`,
because the parser uses the interpreter's `ast` module and Debian keeps `ast` in
the full standard library package. Without it Python parsing degrades to indexed
but unparsed.
