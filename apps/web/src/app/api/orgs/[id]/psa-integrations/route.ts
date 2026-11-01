import { NextResponse, type NextRequest } from "next/server";
import { getPrincipal, orgRoleOf } from "@/lib/access";
import { getSupabaseAdmin } from "@/lib/supabase";
import { encryptSettingsSecret, settingsCryptoConfigured } from "@/lib/settings-crypto";
import { normalizePsaCredentials, parsePsaConfig, type PsaConfig, type PsaProvider } from "@/lib/psa/halo";

export const runtime = "nodejs";

async function adminUser(req: NextRequest, orgId: string) {
  const admin = getSupabaseAdmin();
  const principal = await getPrincipal(req, admin);
  if (!principal) return { admin, error: NextResponse.json({ error: "Not authenticated" }, { status: 401 }) };
  if (principal.kind !== "user" || !["owner", "admin"].includes((await orgRoleOf(admin, principal, orgId)) ?? "")) {
    return { admin, error: NextResponse.json({ error: "Organization admin access required" }, { status: 403 }) };
  }
  return { admin, principal, error: null };
}

// GET /api/orgs/:id/psa-integrations — configuration without credentials.
export async function GET(req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const { id: orgId } = await params;
  const admin = getSupabaseAdmin();
  const principal = await getPrincipal(req, admin);
  if (!principal) return NextResponse.json({ error: "Not authenticated" }, { status: 401 });
  const orgRole = principal.kind === "user" ? await orgRoleOf(admin, principal, orgId) : null;
  if (!orgRole) return NextResponse.json({ error: "Not authorized" }, { status: 403 });
  const { data, error } = await admin.from("psa_integrations")
    .select("id, organization_id, provider, name, enabled, config, created_at, updated_at")
    .eq("organization_id", orgId).order("created_at", { ascending: false });
  if (error) return NextResponse.json({ error: "Could not load PSA integrations" }, { status: 500 });
  const ids = (data ?? []).map((item) => item.id);
  const { data: links, error: linksError } = ids.length
    ? await admin.from("psa_ticket_links").select("integration_id, incident_id, detection_id, external_ticket_id, sync_status, last_error, last_synced_at, updated_at")
      .in("integration_id", ids).order("updated_at", { ascending: false }).limit(200)
    : { data: [], error: null };
  if (linksError) return NextResponse.json({ error: "Could not load PSA ticket sync history" }, { status: 500 });
  return NextResponse.json({ integrations: (data ?? []).map((item) => ({
    ...item,
    has_credentials: true,
    recent_links: (links ?? []).filter((link) => link.integration_id === item.id).slice(0, 20),
  })), can_manage: ["owner", "admin"].includes(orgRole) });
}

// POST /api/orgs/:id/psa-integrations — add an encrypted PSA connection.
export async function POST(req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const { id: orgId } = await params;
  const access = await adminUser(req, orgId);
  if (access.error) return access.error;
  if (!settingsCryptoConfigured()) return NextResponse.json({ error: "PSA integrations require SETTINGS_ENCRYPTION_KEY" }, { status: 503 });
  const body = await req.json().catch(() => null) as Record<string, unknown> | null;
  if (!body || typeof body !== "object" || Array.isArray(body)) return NextResponse.json({ error: "Body must be a JSON object" }, { status: 400 });
  const name = typeof body.name === "string" ? body.name.trim().slice(0, 100) : "";
  const provider = (body.provider ?? "halopsa") as PsaProvider;
  if (!["halopsa", "connectwise", "autotask"].includes(provider)) return NextResponse.json({ error: "Unsupported PSA provider" }, { status: 400 });
  if (!name) return NextResponse.json({ error: "name is required" }, { status: 400 });
  let config: PsaConfig;
  let credentials: Record<string, string>;
  try {
    config = await parsePsaConfig(provider, body.config);
    credentials = normalizePsaCredentials(provider, body.credentials);
  }
  catch (error) { return NextResponse.json({ error: (error as Error).message }, { status: 400 }); }
  const encrypted = encryptSettingsSecret(credentials);
  const { data, error } = await access.admin.from("psa_integrations").insert({
    organization_id: orgId, provider, name, enabled: body.enabled !== false, config,
    credential_ciphertext: encrypted.ciphertext, credential_iv: encrypted.iv, credential_tag: encrypted.tag,
  }).select("id, organization_id, provider, name, enabled, config, created_at, updated_at").single();
  if (error) return NextResponse.json({ error: error.code === "23505" ? "An integration with that name already exists" : "Could not create PSA integration" }, { status: 500 });
  return NextResponse.json({ integration: { ...data, has_credentials: true } }, { status: 201 });
}
