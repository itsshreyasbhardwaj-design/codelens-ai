# syntax=docker/dockerfile:1.7

# CodeLens AI — container image.
#
# What this image is for, stated plainly: a long-running process on a host with
# a persistent volume. It is NOT a serverless bundle. Two properties of the
# application rule that out (docs/ARCHITECTURE.md, ADR-001 and ADR-002):
#
#   1. Storage is SQLite via node:sqlite — a file on disk, with one writer.
#      An ephemeral filesystem loses every scan; two instances on one file
#      corrupt each other.
#   2. A scan is CPU-bound, runs in-process and takes seconds to minutes. It
#      needs a process that outlives a request, not a function with a timeout.
#
# Base image pinning: a specific patch tag, no digest. I could not resolve a
# digest — there is no Docker daemon and no registry access on the machine this
# was authored on, so `docker buildx imagetools inspect` could not be run. To
# pin properly, resolve it once and append it here:
#
#   docker buildx imagetools inspect node:24.16.0-bookworm-slim \
#     --format '{{.Manifest.Digest}}'
#   # then: FROM node:24.16.0-bookworm-slim@sha256:<digest> AS ...
#
# Node 24 is required, not preferred: the application uses node:sqlite (stable
# in 24) and the workspace packages are imported as TypeScript source, which
# Next transpiles at build time — see package.json `engines`.
ARG NODE_IMAGE=node:24.16.0-bookworm-slim


# ---------------------------------------------------------------- build ----
FROM ${NODE_IMAGE} AS build

# The build must happen at the same path and depth as the runtime stage.
# `packages/engine/src/db/index.ts` reads schema.sql and migrations/*.sql
# relative to `import.meta.url`, and Next bakes that into the server chunks as a
# path relative to the chunk's own location. Keeping /app on both sides means
# the resolved location is identical in both. Changing WORKDIR in one stage and
# not the other breaks migrations at boot, and the symptom is a 503 from
# /api/health reading "database is not reachable".
WORKDIR /app

ENV NEXT_TELEMETRY_DISABLED=1 \
    CI=true

# pnpm comes from the version the repository pins in `packageManager`, so the
# lockfile is resolved by the same pnpm that wrote it.
RUN corepack enable && corepack prepare pnpm@11.17.0 --activate

# Manifests first, so a source-only change does not re-resolve dependencies.
# Every workspace package.json must be present or --frozen-lockfile refuses.
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY packages/core/package.json  packages/core/package.json
COPY packages/engine/package.json packages/engine/package.json
COPY packages/cli/package.json   packages/cli/package.json
COPY packages/web/package.json   packages/web/package.json

RUN --mount=type=cache,target=/root/.local/share/pnpm/store,sharing=locked \
    pnpm install --frozen-lockfile

# Sources. The .dockerignore keeps .env*, .codelens, node_modules, .next and
# the sample report out of the context, so nothing secret or stale arrives here.
COPY tsconfig.json ./
COPY packages/core   packages/core
COPY packages/engine packages/engine
COPY packages/cli    packages/cli
COPY packages/web    packages/web

# Typecheck before build: a type error that only shows up in `next build`
# output is harder to read than one tsc reports directly.
RUN pnpm typecheck && pnpm build:web

# The build cache is large and useless at runtime.
RUN rm -rf packages/web/.next/cache packages/web/.next/dev


# -------------------------------------------------------------- runtime ----
FROM ${NODE_IMAGE} AS runtime

WORKDIR /app

# CODELENS_DB points inside the mounted volume, not the image. A path in the
# image layer would look like it worked and be silently discarded on every
# deploy, taking every scan with it.
ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    CODELENS_DB=/data/codelens.db \
    CODELENS_HOME=/data/codelens

# python3, not python3-minimal. The parser shells out to the interpreter's own
# `ast` module (packages/engine/src/parse/py.ts), and `ast` lives in Debian's
# libpython3-stdlib, which python3-minimal does not pull in. ~25 MB, and the
# alternative is Python files being indexed but never parsed — reported honestly
# as unparsed, and counted against parse coverage, but a real loss of analysis.
# One layer, lists removed in the same layer so they are not committed.
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 \
 && rm -rf /var/lib/apt/lists/* \
 && python3 -I -c 'import ast,json,sys; assert sys.version_info[0] == 3'

RUN corepack enable && corepack prepare pnpm@11.17.0 --activate

# Production dependencies only. Tailwind, PostCSS and the type packages were
# build-time concerns; the CSS is already compiled into .next. `typescript`
# stays, because it is a real runtime dependency of @codelens/engine (the
# TypeScript compiler API is the parser) and next.config.ts marks it external.
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY packages/core/package.json  packages/core/package.json
COPY packages/engine/package.json packages/engine/package.json
COPY packages/cli/package.json   packages/cli/package.json
COPY packages/web/package.json   packages/web/package.json

RUN --mount=type=cache,target=/root/.local/share/pnpm/store,sharing=locked \
    pnpm install --prod --frozen-lockfile --ignore-scripts

# The compiled application, plus the engine and core sources.
#
# The sources are not decoration: `next build` does not emit schema.sql or the
# migration SQL into .next, and the server chunks read them from
# packages/engine/src/db/ at runtime. Dropping them produces an image that
# starts, serves the landing page, and fails every database request.
#
# There is no `output: 'standalone'` in next.config.ts, so there is no traced
# minimal bundle to copy instead. This layout is the whole runtime: ~23 MB of
# application on top of the production dependency set.
COPY --from=build /app/packages/web/.next      packages/web/.next
COPY --from=build /app/packages/web/next.config.ts packages/web/next.config.ts
COPY --from=build /app/packages/web/public     packages/web/public
COPY --from=build /app/packages/engine/src     packages/engine/src
COPY --from=build /app/packages/core/src       packages/core/src

# Non-root. The project's own DevOps analyzer reports a container running as
# root as a finding, and a tool that fails its own audit is not credible.
# `node` (uid 1000) ships with the base image.
#
# /app stays root-owned and is therefore read-only to this user: the only paths
# the process needs to write are the volume and /tmp (the Python extractor
# writes the embedded script and a copy of the source into a private temp
# directory). That matches docs/RUNBOOK.md, "run the web process with a
# read-only filesystem apart from the database path".
RUN mkdir -p /data && chown node:node /data
VOLUME ["/data"]
USER node

# Fixed, because packages/web/package.json runs `next start --port 3100`. $PORT
# is not consulted; do not set it and expect it to be honoured.
EXPOSE 3100

# /api/health is exempt from the session guard in packages/web/middleware.ts, so
# this needs no credentials. It answers 200 when the database is reachable and
# migrations are applied (including `degraded`, which reports missing
# configuration but is still serving), and 503 when it is not.
#
# node -e rather than curl: this base image has neither curl nor wget, and
# adding one to run a health check is a package more than the job needs.
# start-period covers first boot, when migrations are applied.
HEALTHCHECK --interval=30s --timeout=5s --start-period=45s --retries=3 \
  CMD ["node", "-e", "fetch('http://127.0.0.1:3100/api/health').then(r => process.exit(r.ok ? 0 : 1)).catch(() => process.exit(1))"]

CMD ["pnpm", "--filter", "@codelens/web", "start"]
