import { NextResponse, type NextRequest } from "next/server";
import { unauthorized } from "@/lib/api-auth";
import { takeLookupShared } from "@/lib/reputation";
import { allowanceHeaders, KEY_REQUIRED, reputationCaller } from "@/lib/reputation-auth";
import { lookupIndicator, parseIndicator } from "@/lib/reputation-service";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/**
 * GET /api/v1/reputation/<ip-or-domain>[?org=<id>] — one address or domain
 * against the community database. Any ThreatCrush key gets the verdict; an
 * org with Reputation Pro gets history, neighbourhood, network owner, city
 * and score reasons. A domain is answered from its addresses plus nichedb's
 * public answer for the name. A signed-in user names the org with `?org=`;
 * an agent key is its own org.
 */
export async function GET(req: NextRequest, { params }: { params: Promise<{ ip: string }> }) {
  const who = await reputationCaller(req);
  if (!who) return unauthorized(KEY_REQUIRED);
  const { ip: raw } = await params;
  const ind = parseIndicator(raw ?? "");
  if (!ind) {
    return NextResponse.json({ error: "Give a public IPv4/IPv6 address or a domain." }, { status: 400 });
  }

  const allowance = await takeLookupShared(who.admin, who.caller, who.tier);
  const headers = allowanceHeaders(who.tier, allowance);
  if (!allowance.ok) {
    return NextResponse.json(
      {
        error:
          who.tier === "free"
            ? `The ${allowance.limit} free lookups a day are used. Reputation Pro ($15/mo) gives 10,000 a day: https://threatcrush.com/pricing`
            : `The ${allowance.limit} lookups a day included with Reputation Pro are used.`,
        upgrade: who.tier === "free" ? "https://threatcrush.com/pricing" : undefined,
      },
      { status: 429, headers },
    );
  }

  try {
    return NextResponse.json(await lookupIndicator(who.admin, ind, who.tier), { headers });
  } catch (err) {
    console.error("[reputation] lookup failed", (err as Error).message);
    return NextResponse.json({ error: "reputation lookup unavailable" }, { status: 503, headers });
  }
}
