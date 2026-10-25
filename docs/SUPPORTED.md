# Supported Technology Matrix

A universal interface is not uniform diagnostic depth. This document states what
depth each technology actually gets, and every scan reports the same
classification for the project in front of it.

## Analysis depth, defined

| Depth | What it means |
| --- | --- |
| **Deep** | Full AST. Imports and symbols resolved, calls attributed, loops understood, cross-file relationships traced. All rule families apply. |
| **Shallow** | Structural and text-level analysis with comments stripped. Manifests, schemas, and configuration are parsed for their own structure. No AST, so no call-graph or symbol resolution. |
| **Detected only** | Presence is reported in the technology list. No rules run against the file contents. |

A file that could not be parsed is reported as unparsed in coverage. It is never
treated as a file with no problems.

## Languages

| Language | Depth | Parser |
| --- | --- | --- |
| TypeScript, TSX | Deep | TypeScript compiler API |
| JavaScript, JSX | Deep | TypeScript compiler API |
| Python | Deep | the interpreter's own `ast` module, via `python3 -I` |
| Go, Java, C#, Ruby, PHP, Rust, C, C++, Kotlin, Swift, Scala | Shallow | — |
| SQL, Prisma, GraphQL | Shallow (schema-aware) | purpose-built schema parsers |
| Vue, Svelte, Astro | Shallow | — |
| YAML, JSON, TOML, Dockerfile, Terraform, HCL, shell | Shallow (config-aware) | — |
| Everything else | Detected only | — |

Python depth degrades gracefully: with no usable `python3` on `PATH`, those files
are indexed and reported as unparsed with that reason, and coverage reflects it.

## Frameworks and platforms detected

**Frontend** — React, Next.js, Vue, Nuxt, Angular, Svelte, SvelteKit, Astro,
Remix, Tailwind CSS, Redux, Zustand, TanStack Query.

**Backend** — Express, NestJS, Fastify, Koa, Hono, tRPC, GraphQL/Apollo,
Socket.IO, FastAPI, Django, Flask, Starlette, Celery, Gin, Echo, Fiber, Chi,
Axum, Actix Web, Rocket, Laravel, Symfony, Ruby on Rails, Sinatra, Spring Boot,
ASP.NET Core.

**Data** — PostgreSQL, MySQL, SQLite, MongoDB, Redis, Supabase, Firebase,
Prisma, Drizzle, TypeORM, Sequelize, Knex, SQLAlchemy, Alembic, Django ORM,
GORM, SQLx, Diesel, Eloquent, ActiveRecord, Hibernate, Entity Framework Core.

**AI** — OpenAI, Anthropic, Google Generative AI, LangChain, LlamaIndex, Vercel
AI SDK, Ollama, Transformers, sentence-transformers, Pinecone, Weaviate, Qdrant,
ChromaDB, pgvector.

**Auth** — NextAuth/Auth.js, Clerk, Passport, jsonwebtoken, jose.

**Infrastructure and CI** — Docker, Docker Compose, Kubernetes, Helm, Terraform,
Vercel, Netlify, Fly.io, Render, Cloudflare Workers, AWS SAM, Serverless
Framework, GitHub Actions, GitLab CI, CircleCI, Jenkins.

**Testing** — Jest, Vitest, Playwright, Cypress, Testing Library, Mocha, pytest,
RSpec, JUnit.

Detection is evidence-first: each entry carries the file and line that supports
it, and a confidence reflecting how direct that evidence is — a declared
dependency plus a framework config file is 0.98, a config file alone is 0.70.

## Route extraction

Read from the structures that define routes, never from file names:

| Framework | How |
| --- | --- |
| Next.js App Router | exported `GET`/`POST`/… in `app/**/route.ts` |
| Next.js Pages API | default export in `pages/api/**`, methods from the branch conditions |
| Express, Fastify, Koa | `app.get(...)` / `router.post(...)` call sites |
| FastAPI, Flask | `@app.get("/path")` / `@router.post(...)` decorators |

For every route, CodeLens records whether authentication is enforced *inside
that handler*, which authorisation checks are present, whether the request is
validated, how errors are handled, and the response shape. `auth: unknown` is a
distinct, deliberate answer: it means enforcement might live in middleware that
was not modelled, and it is never treated as either safe or broken.

## Ingestion

| Method | State |
| --- | --- |
| Local directory | Supported. Symlinks are not followed. |
| GitHub repository | Supported, read-only. Public needs no token; private needs a read-scoped token. Only `api.github.com` and `codeload.github.com` are contacted. |
| ZIP upload | Supported. Path traversal, symlinks, decompression bombs, lying size headers, and CRC mismatches are all rejected with a named reason. ZIP64 is refused rather than mis-parsed. |
| Repository URL | Supported for github.com URLs, which are parsed to `owner/repo`. An arbitrary URL is never fetched. |
| Deployed website observation | **Not implemented in this release.** |
