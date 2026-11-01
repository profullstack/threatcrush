import { NextResponse, type NextRequest } from "next/server";
import { getPrincipal, orgRoleOf } from "@/lib/access";
import { getSupabaseAdmin } from "@/lib/supabase";
import { settingsCryptoConfigured } from "@/lib/settings-crypto";
import { testHaloIntegration } from "@/lib/psa/halo";

export const runtime = "nodejs";

export async function POST(req: NextRequest, { params }: { params: Promise<{ id: string; integration_id: string }> }) {
  const { id: orgId, integration_id: integrationId } = await params;
  const admin = getSupabaseAdmin();
  const principal = await getPrincipal(req, admin);
  if (!principal) return NextResponse.json({ error: "Not authenticated" }, { status: 401 });
  if (principal.kind !== "user" || !["owner", "admin"].includes((await orgRoleOf(admin, principal, orgId)) ?? "")) {
    return NextResponse.json({ error: "Organization admin access required" }, { status: 403 });
  }
  if (!settingsCryptoConfigured()) return NextResponse.json({ error: "PSA integrations require SETTINGS_ENCRYPTION_KEY" }, { status: 503 });
  const { data, error } = await admin.from("psa_integrations").select("*").eq("id", integrationId).eq("organization_id", orgId).maybeSingle();
  if (error || !data) return NextResponse.json({ error: "PSA integration not found" }, { status: 404 });
  try {
    await testHaloIntegration(data);
    return NextResponse.json({ success: true, message: "Halo credentials and API access are working." });
  } catch (cause) {
    return NextResponse.json({ error: `Halo test failed: ${(cause as Error).message}` }, { status: 502 });
  }
}
