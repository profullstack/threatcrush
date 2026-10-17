import { NextResponse, type NextRequest } from "next/server";
import { unauthorized } from "@/lib/api-auth";
import { feedPrincipal } from "@/lib/feed-auth";
import { entitlementFor, orgsOf, paidModule } from "@/lib/paid-modules";
import { getSupabaseAdmin } from "@/lib/supabase";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/**
 * GET /api/v1/entitlements/<module>: may the caller run this paid module?
 * Asked by the daemon module itself with the tc_agent_ key or the session it
 * already has. A user is entitled through any org they belong to.
 */
export async function GET(req: NextRequest, { params }: { params: Promise<{ module: string }> }) {
  const mod = paidModule((await params).module);
  if (!mod) return NextResponse.json({ error: "Not a paid module." }, { status: 404 });
  const principal = await feedPrincipal(req);
  if (!principal) return unauthorized("Sign in or use a ThreatCrush API key.");
  const admin = getSupabaseAdmin();
  const ent = await entitlementFor(admin, mod, await orgsOf(admin, principal));
  return NextResponse.json({ ...ent, name: mod.name, buy: mod.url });
}
