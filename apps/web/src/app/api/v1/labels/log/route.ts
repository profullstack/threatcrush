import { NextResponse, type NextRequest } from "next/server";
import { getAdminClient } from "@/lib/api-auth";
import { readLog } from "@/lib/labeler";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/**
 * GET /api/v1/labels/log?after=<id>&limit=<1..1000>   (public)
 * -> {labels: [Label & {id}], next: id|null}
 *
 * The append-only log of every label this labeler has issued or retracted,
 * oldest first. Nothing is ever deleted: a retraction is a later `neg` record.
 * Tail it with `after=<last id you saw>`.
 */
export async function GET(req: NextRequest) {
  const after = Number(req.nextUrl.searchParams.get("after") ?? "0");
  const limit = Number(req.nextUrl.searchParams.get("limit") ?? "200");
  if (!Number.isSafeInteger(after) || after < 0) return NextResponse.json({ error: "after must be a non-negative integer" }, { status: 400 });
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 1000) return NextResponse.json({ error: "limit must be 1..1000" }, { status: 400 });
  try {
    const page = await readLog(getAdminClient(), after, limit);
    return NextResponse.json(page, { headers: { "Access-Control-Allow-Origin": "*", "Cache-Control": "public, max-age=30" } });
  } catch (e) {
    console.error("[labeler] log failed", e instanceof Error ? e.message : e);
    return NextResponse.json({ error: "Label store unavailable; try again" }, { status: 503 });
  }
}
