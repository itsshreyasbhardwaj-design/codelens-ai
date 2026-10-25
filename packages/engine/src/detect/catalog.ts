import type { TechKind } from '@codelens/core';

/**
 * Technology catalogue.
 *
 * Maps a dependency/package name to what it means. Extending detection for a
 * new framework is adding a row here, not editing detection logic.
 */
export interface TechSpec {
  name: string;
  kind: TechKind;
  /** npm/PyPI/etc. package names that imply this technology. */
  packages: string[];
  /** Files whose presence alone implies it. */
  files?: string[];
}

export const NODE_CATALOG: TechSpec[] = [
  // Frontend
  { name: 'React', kind: 'frontend', packages: ['react'] },
  { name: 'Next.js', kind: 'frontend', packages: ['next'], files: ['next.config.js', 'next.config.ts', 'next.config.mjs'] },
  { name: 'Vue', kind: 'frontend', packages: ['vue'] },
  { name: 'Nuxt', kind: 'frontend', packages: ['nuxt', 'nuxt3'], files: ['nuxt.config.ts', 'nuxt.config.js'] },
  { name: 'Angular', kind: 'frontend', packages: ['@angular/core'], files: ['angular.json'] },
  { name: 'Svelte', kind: 'frontend', packages: ['svelte'] },
  { name: 'SvelteKit', kind: 'frontend', packages: ['@sveltejs/kit'], files: ['svelte.config.js'] },
  { name: 'Astro', kind: 'frontend', packages: ['astro'], files: ['astro.config.mjs'] },
  { name: 'Remix', kind: 'frontend', packages: ['@remix-run/react'] },
  { name: 'Tailwind CSS', kind: 'frontend', packages: ['tailwindcss'], files: ['tailwind.config.js', 'tailwind.config.ts'] },
  { name: 'Redux', kind: 'frontend', packages: ['redux', '@reduxjs/toolkit'] },
  { name: 'Zustand', kind: 'frontend', packages: ['zustand'] },
  { name: 'TanStack Query', kind: 'frontend', packages: ['@tanstack/react-query', 'react-query'] },
  // Backend
  { name: 'Express', kind: 'backend', packages: ['express'] },
  { name: 'NestJS', kind: 'backend', packages: ['@nestjs/core'], files: ['nest-cli.json'] },
  { name: 'Fastify', kind: 'backend', packages: ['fastify'] },
  { name: 'Koa', kind: 'backend', packages: ['koa'] },
  { name: 'Hono', kind: 'backend', packages: ['hono'] },
  { name: 'tRPC', kind: 'backend', packages: ['@trpc/server'] },
  { name: 'GraphQL', kind: 'backend', packages: ['graphql', 'apollo-server', '@apollo/server'] },
  { name: 'Socket.IO', kind: 'backend', packages: ['socket.io'] },
  // Databases & ORMs
  { name: 'PostgreSQL', kind: 'database', packages: ['pg', 'postgres', '@vercel/postgres'] },
  { name: 'MySQL', kind: 'database', packages: ['mysql', 'mysql2'] },
  { name: 'SQLite', kind: 'database', packages: ['sqlite3', 'better-sqlite3', '@libsql/client'] },
  { name: 'MongoDB', kind: 'database', packages: ['mongodb', 'mongoose'] },
  { name: 'Redis', kind: 'database', packages: ['redis', 'ioredis', '@upstash/redis'] },
  { name: 'Supabase', kind: 'database', packages: ['@supabase/supabase-js', '@supabase/ssr'] },
  { name: 'Firebase', kind: 'database', packages: ['firebase', 'firebase-admin'] },
  { name: 'Prisma', kind: 'orm', packages: ['prisma', '@prisma/client'], files: ['prisma/schema.prisma'] },
  { name: 'Drizzle ORM', kind: 'orm', packages: ['drizzle-orm'] },
  { name: 'TypeORM', kind: 'orm', packages: ['typeorm'] },
  { name: 'Sequelize', kind: 'orm', packages: ['sequelize'] },
  { name: 'Knex', kind: 'orm', packages: ['knex'] },
  // Auth
  { name: 'NextAuth / Auth.js', kind: 'library', packages: ['next-auth', '@auth/core'] },
  { name: 'Clerk', kind: 'library', packages: ['@clerk/nextjs', '@clerk/clerk-sdk-node'] },
  { name: 'Passport', kind: 'library', packages: ['passport'] },
  { name: 'jsonwebtoken', kind: 'library', packages: ['jsonwebtoken', 'jose'] },
  // AI
  { name: 'OpenAI SDK', kind: 'ai', packages: ['openai'] },
  { name: 'Anthropic SDK', kind: 'ai', packages: ['@anthropic-ai/sdk'] },
  { name: 'Google Generative AI', kind: 'ai', packages: ['@google/generative-ai', '@google-cloud/aiplatform'] },
  { name: 'LangChain', kind: 'ai', packages: ['langchain', '@langchain/core'] },
  { name: 'LlamaIndex', kind: 'ai', packages: ['llamaindex'] },
  { name: 'Vercel AI SDK', kind: 'ai', packages: ['ai', '@ai-sdk/openai', '@ai-sdk/anthropic'] },
  { name: 'Ollama', kind: 'ai', packages: ['ollama'] },
  { name: 'Pinecone', kind: 'ai', packages: ['@pinecone-database/pinecone'] },
  { name: 'Weaviate', kind: 'ai', packages: ['weaviate-ts-client', 'weaviate-client'] },
  { name: 'Qdrant', kind: 'ai', packages: ['@qdrant/js-client-rest'] },
  { name: 'ChromaDB', kind: 'ai', packages: ['chromadb'] },
  { name: 'pgvector', kind: 'ai', packages: ['pgvector'] },
  // Testing
  { name: 'Jest', kind: 'testing', packages: ['jest'], files: ['jest.config.js', 'jest.config.ts'] },
  { name: 'Vitest', kind: 'testing', packages: ['vitest'], files: ['vitest.config.ts'] },
  { name: 'Playwright', kind: 'testing', packages: ['@playwright/test'], files: ['playwright.config.ts'] },
  { name: 'Cypress', kind: 'testing', packages: ['cypress'], files: ['cypress.config.ts'] },
  { name: 'Testing Library', kind: 'testing', packages: ['@testing-library/react', '@testing-library/dom'] },
  { name: 'Mocha', kind: 'testing', packages: ['mocha'] },
  // Build
  { name: 'Vite', kind: 'build', packages: ['vite'], files: ['vite.config.ts', 'vite.config.js'] },
  { name: 'Webpack', kind: 'build', packages: ['webpack'] },
  { name: 'esbuild', kind: 'build', packages: ['esbuild'] },
  { name: 'Turborepo', kind: 'build', packages: ['turbo'], files: ['turbo.json'] },
  { name: 'TypeScript', kind: 'language', packages: ['typescript'], files: ['tsconfig.json'] },
];

export const PYTHON_CATALOG: TechSpec[] = [
  { name: 'FastAPI', kind: 'backend', packages: ['fastapi'] },
  { name: 'Django', kind: 'backend', packages: ['django'], files: ['manage.py'] },
  { name: 'Flask', kind: 'backend', packages: ['flask'] },
  { name: 'Starlette', kind: 'backend', packages: ['starlette'] },
  { name: 'Uvicorn', kind: 'backend', packages: ['uvicorn'] },
  { name: 'Celery', kind: 'backend', packages: ['celery'] },
  { name: 'SQLAlchemy', kind: 'orm', packages: ['sqlalchemy'] },
  { name: 'Alembic', kind: 'orm', packages: ['alembic'] },
  { name: 'Django ORM', kind: 'orm', packages: [], files: ['manage.py'] },
  { name: 'psycopg', kind: 'database', packages: ['psycopg2', 'psycopg2-binary', 'psycopg'] },
  { name: 'Redis', kind: 'database', packages: ['redis'] },
  { name: 'PyMongo', kind: 'database', packages: ['pymongo'] },
  { name: 'OpenAI SDK', kind: 'ai', packages: ['openai'] },
  { name: 'Anthropic SDK', kind: 'ai', packages: ['anthropic'] },
  { name: 'LangChain', kind: 'ai', packages: ['langchain', 'langchain-core'] },
  { name: 'Transformers', kind: 'ai', packages: ['transformers'] },
  { name: 'sentence-transformers', kind: 'ai', packages: ['sentence-transformers'] },
  { name: 'ChromaDB', kind: 'ai', packages: ['chromadb'] },
  { name: 'pytest', kind: 'testing', packages: ['pytest'] },
  { name: 'Pydantic', kind: 'library', packages: ['pydantic'] },
];
