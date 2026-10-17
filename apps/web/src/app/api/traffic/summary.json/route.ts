import { NextResponse } from "next/server";
import { loadCommunitySummary } from "@/lib/community-threats";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/**
 * Public, masked community-threat summary — counts, top rules and top source
 * networks (host octet hidden). No full host address is ever returned here;
 * the full blocklist lives at /api/traffic/blocklist.(json|txt) behind a key.
 */
export async function GET() {
  try {
    const summary = await loadCommunitySummary();
    return NextResponse.json(summary, {
      headers: {
        "cache-control": "public, max-age=60",
        "access-control-allow-origin": "*",
      },
    });
  } catch (err) {
    console.error("[traffic] summary unavailable", (err as Error).message);
    return NextResponse.json({ error: "summary unavailable" }, { status: 503 });
  }
}
