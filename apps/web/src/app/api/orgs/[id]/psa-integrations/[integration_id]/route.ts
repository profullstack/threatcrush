import { NextResponse, type NextRequest } from "next/server";
import { getPrincipal, orgRoleOf } from "@/lib/access";
import { getSupabaseAdmin } from "@/lib/supabase";
import { decryptSettingsSecret, encryptSettingsSecret, settingsCryptoConfigured } from "@/lib/settings-crypto";
import { parseHaloConfig } from "@/lib/psa/halo";

export const runtime = "nodejs";
type Ctx = { params: Promise<{ id: string; integration_id: string }> };

async function authorize(req: NextRequest, orgId: string) {
  const admin = getSupabaseAdmin();
  const principal = await getPrincipal(req, admin);
  if (!principal) return { admin, error: NextResponse.json({ error: "Not authenticated" }, { status: 401 }) };
  if (principal.kind !== "user" || !["owner", "admin"].includes((await orgRoleOf(admin, principal, orgId)) ?? "")) {
    return { admin, error: NextResponse.json({ error: "Organization admin access required" }, { status: 403 }) };
  }
  return { admin, error: null };
}

export async function PATCH(req: NextRequest, { params }: Ctx) {
  const { id: orgId, integration_id: integrationId } = await params;
  const access = await authorize(req, orgId);
  if (access.error) return access.error;
  if (!settingsCryptoConfigured()) return NextResponse.json({ error: "PSA integrations require SETTINGS_ENCRYPTION_KEY" }, { status: 503 });
  const body = await req.json().catch(() => null) as Record<string, unknown> | null;
  if (!body || typeof body !== "object" || Array.isArray(body)) return NextResponse.json({ error: "Body must be a JSON object" }, { status: 400 });
  const { data: existing, error: readError } = await access.admin.from("psa_integrations").select("*")
    .eq("id", integrationId).eq("organization_id", orgId).maybeSingle();
  if (readError || !existing) return NextResponse.json({ error: "PSA integration not found" }, { status: 404 });
  const patch: Record<string, unknown> = { updated_at: new Date().toISOString() };
  if (body.name !== undefined) {
    if (typeof body.name !== "string" || !body.name.trim()) return NextResponse.json({ error: "name must be a non-empty string" }, { status: 400 });
    patch.name = body.name.trim().slice(0, 100);
  }
  if (body.enabled !== undefined) patch.enabled = body.enabled === true;
  if (body.config !== undefined) {
    try { patch.config = await parseHaloConfig(body.config); }
    catch (error) { return NextResponse.json({ error: (error as Error).message }, { status: 400 }); }
  }
  if (body.credentials !== undefined) {
    const incoming = body.credentials && typeof body.credentials === "object" && !Array.isArray(body.credentials) ? body.credentials as Record<string, unknown> : {};
    const current = decryptSettingsSecret({ ciphertext: existing.credential_ciphertext, iv: existing.credential_iv, tag: existing.credential_tag });
    const clientId = typeof incoming.client_id === "string" && incoming.client_id.trim() ? incoming.client_id.trim() : current.client_id;
    const clientSecret = typeof incoming.client_secret === "string" && incoming.client_secret.trim() ? incoming.client_secret.trim() : current.client_secret;
    if (!clientId || !clientSecret || clientId.length > 250 || clientSecret.length > 1000) return NextResponse.json({ error: "Invalid Halo API credentials" }, { status: 400 });
    const encrypted = encryptSettingsSecret({ client_id: clientId, client_secret: clientSecret });
    patch.credential_ciphertext = encrypted.ciphertext;
    patch.credential_iv = encrypted.iv;
    patch.credential_tag = encrypted.tag;
  }
  if (Object.keys(patch).length === 1) return NextResponse.json({ error: "No changes supplied" }, { status: 400 });
  const { data, error } = await access.admin.from("psa_integrations").update(patch)
    .eq("id", integrationId).eq("organization_id", orgId)
    .select("id, organization_id, provider, name, enabled, config, created_at, updated_at").single();
  if (error) return NextResponse.json({ error: "Could not update PSA integration" }, { status: 500 });
  return NextResponse.json({ integration: { ...data, has_credentials: true } });
}

export async function DELETE(req: NextRequest, { params }: Ctx) {
  const { id: orgId, integration_id: integrationId } = await params;
  const access = await authorize(req, orgId);
  if (access.error) return access.error;
  const { error } = await access.admin.from("psa_integrations").delete().eq("id", integrationId).eq("organization_id", orgId);
  if (error) return NextResponse.json({ error: "Could not delete PSA integration" }, { status: 500 });
  return NextResponse.json({ success: true });
}
