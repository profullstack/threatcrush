import { timingSafeEqual } from "node:crypto";
import { NextResponse, type NextRequest } from "next/server";
import { runWatches } from "@/lib/reputation-watches";
import { getSupabaseAdmin } from "@/lib/supabase";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export const maxDuration = 300;

function authorized(req: NextRequest): boolean {
  const name = "REPUTATION_CRON_TOKEN";
  const expected = process.env[name];
  const got = req.headers.get("authorization")?.replace(/^Bearer\s+/i, "").trim() ?? "";
  if (!expected || !got) return false;
  const a = Buffer.from(expected);
  const b = Buffer.from(got);
  return a.length === b.length && timingSafeEqual(a, b);
}

/** POST — the hourly watch-list pass, called by cron on dev2 with REPUTATION_CRON_TOKEN. */
export async function POST(req: NextRequest) {
  if (!authorized(req)) return NextResponse.json({ error: "Not authorized" }, { status: 401 });
  try {
    const result = await runWatches(getSupabaseAdmin());
    console.log("[reputation] watch pass", JSON.stringify(result));
    return NextResponse.json(result);
  } catch (err) {
    console.error("[reputation] watch pass failed", (err as Error).message);
    return NextResponse.json({ error: "watch pass failed" }, { status: 500 });
  }
}
