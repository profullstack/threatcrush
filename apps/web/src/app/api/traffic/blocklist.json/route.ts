import { NextResponse, type NextRequest } from "next/server";
import { loadBlocklist } from "@/lib/community-threats";
import { feedPrincipal } from "@/lib/feed-auth";
import { unauthorized } from "@/lib/api-auth";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/** Full-IP community blocklist (JSON). Key-gated: a tc_agent_ key is required. */
export async function GET(req: NextRequest) {
  const principal = await feedPrincipal(req);
  if (!principal) {
    return unauthorized("A ThreatCrush API key is required for the full blocklist. Create one at threatcrush.com.");
  }
  try {
    const entries = await loadBlocklist();
    return NextResponse.json(
      { generated_at: new Date().toISOString(), count: entries.length, entries },
      { headers: { "cache-control": "private, max-age=300" } },
    );
  } catch (err) {
    console.error("[traffic] blocklist unavailable", (err as Error).message);
    return NextResponse.json({ error: "blocklist unavailable" }, { status: 503 });
  }
}
