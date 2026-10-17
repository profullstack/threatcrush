import { NextResponse, type NextRequest } from "next/server";
import { loadBlocklist, MIN_REPORTERS_FOR_PUBLIC } from "@/lib/community-threats";
import { feedPrincipal } from "@/lib/feed-auth";
import { unauthorized } from "@/lib/api-auth";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/**
 * Full-IP community blocklist as plain text, one address per line — drop-in for
 * fail2ban/nftables/ipset. Key-gated with a tc_agent_ key.
 */
export async function GET(req: NextRequest) {
  const principal = await feedPrincipal(req);
  if (!principal) {
    return new NextResponse("# unauthorized: a ThreatCrush API key is required. Create one at threatcrush.com.\n", {
      status: 401,
      headers: { "content-type": "text/plain; charset=utf-8" },
    });
  }
  try {
    const entries = await loadBlocklist();
    const lines = [
      "# ThreatCrush community blocklist",
      `# generated ${new Date().toISOString()} — ${entries.length} addresses`,
      `# inclusion: corroborated by >= ${MIN_REPORTERS_FOR_PUBLIC} reporters, or high-severity with repeat hits`,
      "# https://threatcrush.com/traffic",
      ...entries.map((e) => e.ip),
    ];
    return new NextResponse(lines.join("\n") + "\n", {
      headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "private, max-age=300" },
    });
  } catch (err) {
    console.error("[traffic] blocklist.txt unavailable", (err as Error).message);
    return new NextResponse("# blocklist unavailable\n", {
      status: 503,
      headers: { "content-type": "text/plain; charset=utf-8" },
    });
  }
}
