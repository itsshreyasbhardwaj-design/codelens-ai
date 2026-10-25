import type { NextConfig } from 'next';

/**
 * The engine is imported directly as TypeScript source from the workspace, so
 * Next must transpile it. `node:sqlite` is a built-in and must stay external to
 * the server bundle.
 */
const nextConfig: NextConfig = {
  transpilePackages: ['@codelens/engine', '@codelens/core'],
  serverExternalPackages: ['typescript'],
  typedRoutes: false,
  async headers() {
    // The security analyzer reports a project with no security headers, so this
    // application sets its own. A tool that fails its own audit is not credible.
    return [
      {
        source: '/:path*',
        headers: [
          { key: 'X-Content-Type-Options', value: 'nosniff' },
          { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
          { key: 'X-Frame-Options', value: 'DENY' },
          { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=()' },
          {
            key: 'Content-Security-Policy',
            value: [
              "default-src 'self'",
              // Next injects inline bootstrap scripts; styles are Tailwind-generated.
              "script-src 'self' 'unsafe-inline'",
              "style-src 'self' 'unsafe-inline'",
              "img-src 'self' data:",
              "font-src 'self'",
              "connect-src 'self'",
              "frame-ancestors 'none'",
              "base-uri 'self'",
              "form-action 'self'",
            ].join('; '),
          },
        ],
      },
    ];
  },
};

export default nextConfig;
