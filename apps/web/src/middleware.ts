import { clientIp } from "@/lib/client-ip";
import { gate } from "@/lib/crawl-gateway";
import { meter } from "@/lib/throttle";
import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";

// Any request carrying a Next-Action header is a Server Action invocation.
// The current bundle defines no Server Actions, so every such request is a
// stale-bundle hit (cached clients or bots replaying old action IDs). Letting
// these reach Next's internal handler triggers an InvariantError on every hit
// and leaks RSS under sustained load. Reject with 410 Gone before any of that
// runs; the client framework treats a non-RSC response as a signal to reload.

/**
 * TC-35: there was no rate limiting anywhere, so the endpoints that cost money
 * or send mail (SMS codes, password resets, invoice creation, the scanner)
 * could be hammered for free.
 *
 * This is a per-instance in-memory limiter, so a multi-instance deployment
 * multiplies the effective ceiling by the instance count. It is a floor, not a
 * substitute for a limit at the reverse proxy.
 */
interface RateRule {
  /** Path prefix this rule applies to. */
  prefix: string;
  limit: number;
  windowMs: number;
}

// Most specific first — the first matching prefix wins.
const RATE_RULES: RateRule[] = [
  { prefix: "/api/auth/send-phone-code", limit: 5, windowMs: 60_000 },
  { prefix: "/api/auth/verify-phone", limit: 10, windowMs: 60_000 },
  { prefix: "/api/auth/forgot-password", limit: 5, windowMs: 60_000 },
  { prefix: "/api/auth/reset-password", limit: 10, windowMs: 60_000 },
  { prefix: "/api/auth/resend", limit: 5, windowMs: 60_000 },
  { prefix: "/api/auth/signup", limit: 10, windowMs: 60_000 },
  { prefix: "/api/auth/login", limit: 20, windowMs: 60_000 },
  { prefix: "/api/auth/refresh", limit: 30, windowMs: 60_000 },
  // Unauthenticated: start inserts a row; token is polled every 3s while a
  // terminal waits for approval.
  { prefix: "/api/auth/cli/start", limit: 10, windowMs: 60_000 },
  { prefix: "/api/auth/cli/token", limit: 40, windowMs: 60_000 },
  // Public fix reports: the token is the credential, so guessing is capped too.
  { prefix: "/r/", limit: 30, windowMs: 60_000 },
  // Invite tokens are credentials too.
  { prefix: "/api/invites/", limit: 30, windowMs: 60_000 },
  // Credit codes and invite codes: guessing is capped (codes are 60-80 bits anyway).
  { prefix: "/api/credits/redeem", limit: 10, windowMs: 60_000 },
  { prefix: "/api/credits/invites/accept", limit: 10, windowMs: 60_000 },
  { prefix: "/api/hooks/", limit: 60, windowMs: 60_000 },
  { prefix: "/api/scan", limit: 20, windowMs: 60_000 },
  // Anonymous CLI usage pings: one per ai-scan run, so 30/min per IP is generous.
  { prefix: "/api/telemetry", limit: 30, windowMs: 60_000 },
  { prefix: "/api/modules/fetch-meta", limit: 20, windowMs: 60_000 },
  { prefix: "/api/funding/", limit: 30, windowMs: 60_000 },
  // Public and unauthenticated: IP geolocation for the TUI and desktop maps,
  // and the homepage live map (polled every 5s while visible).
  { prefix: "/api/geo", limit: 30, windowMs: 60_000 },
  { prefix: "/api/attack-map/public", limit: 60, windowMs: 60_000 },
  { prefix: "/api/", limit: 300, windowMs: 60_000 },
];

const hits = new Map<string, { count: number; resetAt: number }>();

/** Bounded so a flood of unique keys cannot grow the map without limit. */
const MAX_TRACKED_KEYS = 10_000;

function rateLimit(req: NextRequest): NextResponse | undefined {
  const path = req.nextUrl.pathname;
  const rule = RATE_RULES.find((r) => path.startsWith(r.prefix));
  if (!rule) return undefined;

  const now = Date.now();
  const key = `${clientIp(req)}:${rule.prefix}`;
  const entry = hits.get(key);

  if (!entry || entry.resetAt <= now) {
    if (hits.size >= MAX_TRACKED_KEYS) {
      for (const [k, v] of hits) {
        if (v.resetAt <= now) hits.delete(k);
      }
      // Still full of live entries: drop the whole window rather than grow.
      if (hits.size >= MAX_TRACKED_KEYS) hits.clear();
    }
    hits.set(key, { count: 1, resetAt: now + rule.windowMs });
    return undefined;
  }

  entry.count++;
  if (entry.count > rule.limit) {
    const retryAfter = Math.max(1, Math.ceil((entry.resetAt - now) / 1000));
    return NextResponse.json(
      { error: "Too many requests" },
      { status: 429, headers: { "Retry-After": String(retryAfter) } },
    );
  }

  return undefined;
}

export async function middleware(req: NextRequest): Promise<Response | NextResponse | undefined> {
  // Crawl gateway first: AI training crawlers get 402 Payment Required (or the
  // sales page at /crawl) unless they present a paid pass. People, Googlebot
  // and retrieval crawlers fall through to everything below.
  const answer = await gate(req);
  if (answer) return answer;

  // Then the site-wide allowance on page routes: 100 requests a minute per
  // caller, and going over is answered 402 with the same offer (lib/throttle).
  const overLimit = await meter(req);
  if (overLimit) return overLimit;

  if (req.headers.get("next-action")) {
    return new NextResponse(null, { status: 410 });
  }
  return rateLimit(req);
}

export const config = {
  matcher: "/((?!_next/static|_next/image|favicon.ico).*)",
};
