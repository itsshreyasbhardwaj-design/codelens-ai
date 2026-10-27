import { NextResponse, type NextRequest } from "next/server";
import { readSession, SESSION_COOKIE } from "@codelens/engine/db/auth.ts";

/**
 * Route guard.
 *
 * Verifies the cookie signature only — it does not touch the database, because
 * middleware runs on every request including static assets. Data access
 * re-verifies and re-checks membership in `lib/session.ts`; this layer exists so
 * an unauthenticated request never reaches a page that would query at all.
 */

const PUBLIC_PATHS = [
  "/",
  "/sign-in",
  "/pricing",
  "/api/auth/login",
  "/api/auth/register",
  "/api/auth/logout",
  // The payment provider has no session, and the health check is polled by a
  // load balancer. Both authenticate differently: the webhook by a mandatory
  // signature over the raw body, the health check by exposing nothing that
  // needs protecting. Neither may fall back to the cookie guard.
  "/api/billing/webhook",
  "/api/health",
];

export function middleware(request: NextRequest): NextResponse {
  const { pathname } = request.nextUrl;
  if (PUBLIC_PATHS.includes(pathname)) return NextResponse.next();

  const session = readSession(request.cookies.get(SESSION_COOKIE)?.value);
  if (session) return NextResponse.next();

  // An API caller gets a status it can act on; a browser gets the sign-in page
  // with somewhere to return to.
  if (pathname.startsWith("/api/")) {
    return NextResponse.json(
      { error: "authentication required" },
      { status: 401 },
    );
  }
  const url = request.nextUrl.clone();
  url.pathname = "/sign-in";
  url.searchParams.set("next", pathname);
  return NextResponse.redirect(url);
}

export const config = {
  // Everything except Next's own assets and the favicon.
  matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"],
  // Node, not Edge: session verification uses node:crypto, which the Edge
  // runtime does not provide. The build is happy either way — this only shows
  // up at request time, as a 500 on every route.
  runtime: "nodejs",
};
