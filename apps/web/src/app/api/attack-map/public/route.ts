import { NextRequest, NextResponse } from "next/server";
import { demoMapData } from "@threatcrush/attack-map";
import { buildAttackMap, loadMapServers, parseWindow } from "@/lib/attack-map";
import { getSupabaseAdmin } from "@/lib/supabase";

// GET /api/attack-map/public?window=60 — the live map on threatcrush.com: what
// is attacking ThreatCrush's own servers right now. Unauthenticated, so source
// addresses are cut to their /24 and servers are named by city only.
//
// PUBLIC_ATTACK_MAP_ORG (an org slug, default "profullstack") picks whose
// servers are shown; "off" serves the labelled demo map instead.
export async function GET(req: NextRequest) {
  const windowMinutes = parseWindow(req.nextUrl.searchParams.get("window"));
  const headers = { "Cache-Control": "public, max-age=3, s-maxage=3" };
  // Non-literal key: a runtime setting, not one Next inlines at build time.
  const orgKey = "PUBLIC_ATTACK_MAP_ORG";
  const slug = process.env[orgKey] || "profullstack";
  if (slug === "off") return NextResponse.json(demoMapData(), { headers });

  try {
    const admin = getSupabaseAdmin();
    const { data: org, error } = await admin.from("organizations").select("id").eq("slug", slug).maybeSingle();
    if (error) throw new Error(`org: ${error.message}`);
    if (!org) return NextResponse.json(demoMapData(), { headers });

    const servers = await loadMapServers(admin, [org.id as string]);
    const data = await buildAttackMap(admin, servers, windowMinutes, { publicView: true });
    // No linked server can be placed yet: show the demo rather than an empty world.
    if (data.servers.length === 0) return NextResponse.json(demoMapData(), { headers });
    return NextResponse.json(data, { headers });
  } catch (err) {
    console.error("Public attack map error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
