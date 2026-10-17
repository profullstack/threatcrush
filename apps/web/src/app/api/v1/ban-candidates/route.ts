import { timingSafeEqual } from "node:crypto";
import { isIP } from "node:net";
import { NextRequest, NextResponse } from "next/server";
import { getSupabaseAdmin } from "@/lib/supabase";

// GET /api/v1/ban-candidates?cursor=<ip>&limit=1000
//
// Every address the fleet banned in the last 90 days, aggregated with its
// evidence, for nichedb.dev/traffic to review. This is NOT a public list: it is
// the input to a human review, and only nichedb's reviewers decide what gets
// published. It is gated by a shared token (TRAFFIC_FEED_TOKEN) and refuses
// everything when the token is unset.
//
// Paged by address: pass the last `ip` you saw as `cursor`; `next_cursor` is
// null on the last page.

export const dynamic = "force-dynamic";

// Read through a non-literal key: Next inlines `process.env.NAME` at build
// time, and this is a runtime secret from app.env.
const env = (name: string) => process.env[name];

function authorized(req: NextRequest): boolean {
  const expected = env("TRAFFIC_FEED_TOKEN") ?? "";
  if (expected.length < 32) return false;
  const given = req.headers.get("authorization")?.replace(/^Bearer\s+/i, "") ?? "";
  const a = Buffer.from(given);
  const b = Buffer.from(expected);
  return a.length === b.length && timingSafeEqual(a, b);
}

export async function GET(req: NextRequest) {
  if (!authorized(req)) {
    return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  }
  const params = req.nextUrl.searchParams;
  const cursor = params.get("cursor");
  if (cursor && !isIP(cursor)) {
    return NextResponse.json({ error: "cursor must be an IP address" }, { status: 400 });
  }
  const limit = Math.min(5000, Math.max(1, Number(params.get("limit")) || 1000));

  const { data, error } = await getSupabaseAdmin().rpc("ban_candidates", {
    p_after: cursor,
    p_limit: limit,
  });
  if (error) {
    console.error("ban-candidates:", error);
    return NextResponse.json({ error: "Failed to load candidates" }, { status: 500 });
  }
  const candidates = (data ?? []) as { ip: string }[];
  return NextResponse.json(
    {
      generated_at: new Date().toISOString(),
      window_days: 90,
      candidates,
      next_cursor: candidates.length === limit ? candidates[candidates.length - 1].ip : null,
    },
    { headers: { "cache-control": "no-store" } },
  );
}
