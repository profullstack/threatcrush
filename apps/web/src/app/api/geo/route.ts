import { NextRequest, NextResponse } from "next/server";
import { isIP } from "node:net";
import { clientIp } from "@/lib/client-ip";
import { GEOIP_ATTRIBUTION, lookupIps } from "@/lib/geoip";

const MAX_IPS = 200;

// Public data and no credentials, so any origin may ask: the desktop app's
// renderer calls this cross-origin.
const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
};

export function OPTIONS() {
  return new NextResponse(null, { status: 204, headers: CORS });
}

// IP geolocation for the maps that run next to the daemon (TUI, desktop),
// which have attacker addresses but no database to place them with.
//
// GET  /api/geo        — where the caller is: the daemon's own server pin.
// POST /api/geo {ips}  — up to 200 addresses; private ones are skipped.
//
// Unauthenticated and rate limited (middleware); answers only with
// coordinates, city and country.
export async function GET(req: NextRequest) {
  const ip = clientIp(req);
  const geo = await lookupIps([ip]);
  return NextResponse.json({ ip, geo: geo.get(ip) ?? null, attribution: GEOIP_ATTRIBUTION }, { headers: CORS });
}

export async function POST(req: NextRequest) {
  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Body must be JSON" }, { status: 400, headers: CORS });
  }
  const raw = (body as { ips?: unknown } | null)?.ips;
  if (!Array.isArray(raw)) return NextResponse.json({ error: "ips array is required" }, { status: 400, headers: CORS });
  const ips = [...new Set(raw.filter((x): x is string => typeof x === "string" && isIP(x.trim()) !== 0).map((x) => x.trim()))].slice(
    0,
    MAX_IPS,
  );
  const geo = await lookupIps(ips);
  return NextResponse.json({ results: Object.fromEntries(geo), attribution: GEOIP_ATTRIBUTION }, { headers: CORS });
}
