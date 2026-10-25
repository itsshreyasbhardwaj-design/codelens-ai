/** @type {import('next').NextConfig} */
// DEFECT (security headers): no headers() block, so no CSP, HSTS,
// X-Content-Type-Options or Referrer-Policy is ever sent.
const nextConfig = {
  reactStrictMode: true,
  images: { domains: ['*'] },
};
module.exports = nextConfig;
