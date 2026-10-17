import { isIP } from "node:net";
import { NextResponse, type NextRequest } from "next/server";
import { unauthorized } from "@/lib/api-auth";
import { loadBlocklist, loadServerIps, withoutProtected } from "@/lib/community-threats";
import { feedPrincipal } from "@/lib/feed-auth";
import { isPublicIp, lookupIps } from "@/lib/geoip";
import {
  buildReport,
  HISTORY_DAYS,
  loadDetectionsFor,
  readingOrgFor,
  takeLookup,
  tierFor,
} from "@/lib/reputation";
import { getSupabaseAdmin } from "@/lib/supabase";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/**
 * GET /api/v1/reputation/<ip>[?org=<id>] — one address against the community
 * database. Any ThreatCrush key gets the verdict; an org with Reputation Pro
 * gets history, neighbourhood, city and score reasons. A signed-in user names
 * the org to bill with `?org=`; an agent key is its own org.
 */
export async function GET(req: NextRequest, { params }: { params: Promise<{ ip: string }> }) {
  const principal = await feedPrincipal(req);
  if (!principal) {
    return unauthorized(
      "A ThreatCrush API key is required. Create one free at threatcrush.com; keyless lookups are at nichedb.dev/reputation.",
    );
  }
  const { ip: raw } = await params;
  const ip = decodeURIComponent(raw ?? "").trim().replace(/^\[|\]$/g, "").toLowerCase();
  if (!isIP(ip) || !isPublicIp(ip)) {
    return NextResponse.json({ error: "Give a public IPv4 or IPv6 address." }, { status: 400 });
  }

  const admin = getSupabaseAdmin();
  const orgId = await readingOrgFor(admin, principal, new URL(req.url).searchParams.get("org"));
  const tier = await tierFor(admin, orgId);
  const caller = orgId ?? (principal.kind === "agent" ? principal.keyId : principal.userId);
  const allowance = takeLookup(caller, tier);
  const headers = {
    "x-reputation-tier": tier,
    "x-ratelimit-limit": String(allowance.limit),
    "x-ratelimit-remaining": String(allowance.remaining),
    "cache-control": "private, no-store",
  };
  if (!allowance.ok) {
    return NextResponse.json(
      {
        error: `The ${allowance.limit} lookups a day included with ${tier === "pro" ? "Reputation Pro" : "a free key"} are used.`,
        upgrade: tier === "free" ? "https://threatcrush.com/reputation" : undefined,
      },
      { status: 429, headers },
    );
  }

  try {
    const [rows, blocklist, geo, serverIps] = await Promise.all([
      loadDetectionsFor(admin, ip, tier === "pro" ? HISTORY_DAYS : 7),
      tier === "pro" ? loadBlocklist() : Promise.resolve([]),
      lookupIps([ip], 3000),
      loadServerIps(),
    ]);
    // A server registered with ThreatCrush is never reported as an attacker.
    const evidence = withoutProtected(rows, serverIps);
    return NextResponse.json(buildReport(ip, evidence, blocklist, geo.get(ip) ?? null, tier), { headers });
  } catch (err) {
    console.error("[reputation] lookup failed", (err as Error).message);
    return NextResponse.json({ error: "reputation lookup unavailable" }, { status: 503, headers });
  }
}
