import "server-only";
import { decryptSettingsSecret, type CipherBlob } from "@/lib/settings-crypto";
import { safeFetch, validatePublicHttpsUrl } from "@/lib/ssrf-guard";
import { appUrl } from "@/lib/teams";
import { findSecret } from "@/lib/incidents/secret-guard";
import type { SupabaseClient } from "@supabase/supabase-js";

export interface HaloConfig {
  api_url: string;
  auth_url: string;
  ticket_type_id: number;
  default_client_id: number | null;
  client_mappings: Record<string, number>;
  open_status_id: number | null;
  resolved_status_id: number | null;
  auto_close: boolean;
}

interface HaloCredentials { client_id: string; client_secret: string }
interface StoredIntegration {
  id: string;
  organization_id: string;
  provider: "halopsa";
  name: string;
  enabled: boolean;
  config: HaloConfig;
  credential_ciphertext: string;
  credential_iv: string;
  credential_tag: string;
}

const positiveInteger = (value: unknown): number | null => {
  const n = typeof value === "number" ? value : typeof value === "string" && /^\d+$/.test(value) ? Number(value) : NaN;
  return Number.isSafeInteger(n) && n > 0 ? n : null;
};

export async function parseHaloConfig(raw: unknown): Promise<HaloConfig> {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) throw new Error("Configuration must be an object");
  const input = raw as Record<string, unknown>;
  if (typeof input.api_url !== "string" || typeof input.auth_url !== "string") throw new Error("api_url and auth_url are required");
  const apiUrl = await validatePublicHttpsUrl(input.api_url.trim());
  const authUrl = await validatePublicHttpsUrl(input.auth_url.trim());
  if (apiUrl.username || apiUrl.password || authUrl.username || authUrl.password) throw new Error("URLs cannot contain usernames or passwords");
  if (apiUrl.search || apiUrl.hash || authUrl.hash) throw new Error("api_url cannot have a query or fragment, and auth_url cannot have a fragment");
  const apiPath = apiUrl.pathname.replace(/\/+$/, "");
  if (!apiPath.endsWith("/api")) throw new Error("api_url must point to your Halo /api endpoint");
  const ticketTypeId = positiveInteger(input.ticket_type_id);
  if (!ticketTypeId) throw new Error("ticket_type_id must be a positive integer");
  const autoClose = input.auto_close === true;
  const resolvedStatusId = input.resolved_status_id == null || input.resolved_status_id === "" ? null : positiveInteger(input.resolved_status_id);
  if (input.resolved_status_id != null && input.resolved_status_id !== "" && !resolvedStatusId) throw new Error("resolved_status_id must be a positive integer");
  if (autoClose && !resolvedStatusId) throw new Error("resolved_status_id is required when auto_close is enabled");
  const openStatusId = input.open_status_id == null || input.open_status_id === "" ? null : positiveInteger(input.open_status_id);
  if (input.open_status_id != null && input.open_status_id !== "" && !openStatusId) throw new Error("open_status_id must be a positive integer");
  const defaultClientId = input.default_client_id == null || input.default_client_id === "" ? null : positiveInteger(input.default_client_id);
  if (input.default_client_id != null && input.default_client_id !== "" && !defaultClientId) throw new Error("default_client_id must be a positive integer");
  const mappings = input.client_mappings && typeof input.client_mappings === "object" && !Array.isArray(input.client_mappings)
    ? input.client_mappings as Record<string, unknown>
    : {};
  if (Object.keys(mappings).length > 200) throw new Error("At most 200 team/fleet client mappings are allowed");
  const clientMappings: Record<string, number> = {};
  for (const [key, value] of Object.entries(mappings)) {
    if (!/^(team|fleet):[0-9a-f-]{36}$/i.test(key)) throw new Error(`Invalid mapping key ${key}; use team:<UUID> or fleet:<UUID>`);
    const clientId = positiveInteger(value);
    if (!clientId) throw new Error(`Mapping ${key} must have a positive Halo client ID`);
    clientMappings[key] = clientId;
  }
  return {
    api_url: apiUrl.toString().replace(/\/+$/, ""),
    auth_url: authUrl.toString(),
    ticket_type_id: ticketTypeId,
    default_client_id: defaultClientId,
    client_mappings: clientMappings,
    open_status_id: openStatusId,
    resolved_status_id: resolvedStatusId,
    auto_close: autoClose,
  };
}

function credentialsFor(row: StoredIntegration): HaloCredentials {
  const decrypted = decryptSettingsSecret({
    ciphertext: row.credential_ciphertext,
    iv: row.credential_iv,
    tag: row.credential_tag,
  } satisfies CipherBlob);
  if (!decrypted.client_id || !decrypted.client_secret) throw new Error("Halo API credentials are missing");
  return { client_id: decrypted.client_id, client_secret: decrypted.client_secret };
}

async function accessToken(config: HaloConfig, credentials: HaloCredentials): Promise<string> {
  const body = new URLSearchParams({
    grant_type: "client_credentials",
    client_id: credentials.client_id,
    client_secret: credentials.client_secret,
    scope: "all",
  });
  const response = await safeFetch(config.auth_url, {
    method: "POST", redirect: "manual", signal: AbortSignal.timeout(10_000),
    headers: { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" },
    body: body.toString(),
  });
  if (!response.ok) throw new Error(`Halo token endpoint returned HTTP ${response.status}`);
  const payload = await response.json().catch(() => null) as { access_token?: unknown } | null;
  if (typeof payload?.access_token !== "string" || !payload.access_token) throw new Error("Halo token endpoint did not return an access token");
  return payload.access_token;
}

async function haloRequest(config: HaloConfig, token: string, path: string, init: RequestInit = {}) {
  const root = `${config.api_url.replace(/\/+$/, "")}/`;
  const target = new URL(path.replace(/^\/+/, ""), root).toString();
  const response = await safeFetch(target, {
    ...init,
    redirect: "manual",
    signal: init.signal ?? AbortSignal.timeout(15_000),
    headers: { Accept: "application/json", Authorization: `Bearer ${token}`, ...(init.headers as Record<string, string> | undefined) },
  });
  if (!response.ok) throw new Error(`Halo API returned HTTP ${response.status}`);
  return response;
}

export async function testHaloIntegration(row: StoredIntegration): Promise<void> {
  const token = await accessToken(row.config, credentialsFor(row));
  await haloRequest(row.config, token, "client?count=1");
}

function incidentTicket(row: Record<string, unknown>, config: HaloConfig, clientId: number, statusId: number | null) {
  const humanCode = typeof row.human_code === "string" ? row.human_code : String(row.id ?? "unknown");
  const title = typeof row.title === "string" ? row.title.slice(0, 180) : "ThreatCrush incident";
  const severity = typeof row.severity === "string" ? row.severity.toUpperCase() : "UNKNOWN";
  const host = typeof row.host === "string" ? row.host : "host not recorded";
  const summary = typeof row.summary === "string" ? row.summary.slice(0, 8000) : "No incident summary was recorded.";
  const url = `${appUrl()}/ic/${encodeURIComponent(humanCode)}`;
  return {
    summary: `[ThreatCrush ${humanCode}] ${title}`.slice(0, 250),
    details: `Severity: ${severity}\nHost: ${host}\nStatus: ${String(row.status ?? "open")}\n\n${summary}\n\nThreatCrush incident: ${url}`.slice(0, 12_000),
    client_id: clientId,
    tickettype_id: config.ticket_type_id,
    ...(statusId ? { status_id: statusId } : {}),
  };
}

function externalTicketId(payload: unknown): string | null {
  const candidate = Array.isArray(payload) ? payload[0] : payload;
  if (!candidate || typeof candidate !== "object") return null;
  const item = candidate as Record<string, unknown>;
  for (const key of ["id", "faultid", "ticket_id"]) {
    const value = item[key];
    if (typeof value === "number" && Number.isSafeInteger(value) && value > 0) return String(value);
    if (typeof value === "string" && value.length > 0 && value.length <= 100) return value;
  }
  return null;
}

async function claimLink(admin: SupabaseClient, row: StoredIntegration, incidentId: string) {
  const { data: existing, error } = await admin.from("psa_ticket_links").select("*")
    .eq("integration_id", row.id).eq("incident_id", incidentId).maybeSingle();
  if (error) throw new Error(`PSA link lookup failed: ${error.message}`);
  const now = new Date().toISOString();
  const staleBefore = new Date(Date.now() - 10 * 60_000).toISOString();
  if (!existing) {
    const { data, error: insertError } = await admin.from("psa_ticket_links").insert({
      organization_id: row.organization_id, integration_id: row.id, incident_id: incidentId, sync_status: "syncing", updated_at: now,
    }).select("*").single();
    if (!insertError && data) return data;
    if ((insertError as { code?: string } | null)?.code !== "23505") throw new Error(`PSA link reserve failed: ${insertError?.message}`);
    return null;
  }
  if (existing.sync_status === "syncing" && existing.updated_at > staleBefore) return null;
  let update = admin.from("psa_ticket_links").update({ sync_status: "syncing", last_error: null, updated_at: now }).eq("id", existing.id);
  if (existing.sync_status === "syncing") update = update.lt("updated_at", staleBefore);
  else update = update.eq("updated_at", existing.updated_at);
  const { data, error: updateError } = await update.select("*").maybeSingle();
  if (updateError) throw new Error(`PSA link claim failed: ${updateError.message}`);
  return data;
}

async function syncOneIntegration(admin: SupabaseClient, row: StoredIntegration, incident: Record<string, unknown>) {
  const incidentId = String(incident.id ?? "");
  const claim = await claimLink(admin, row, incidentId);
  if (!claim) return;
  const save = async (patch: Record<string, unknown>) => {
    const { error } = await admin.from("psa_ticket_links").update({ ...patch, updated_at: new Date().toISOString() }).eq("id", claim.id);
    if (error) throw new Error(`PSA link update failed: ${error.message}`);
  };
  try {
    const config = row.config;
    let fleetId: string | null = null;
    if (typeof incident.server_id === "string") {
      const { data: server, error } = await admin.from("servers").select("fleet_id").eq("id", incident.server_id).eq("org_id", row.organization_id).maybeSingle();
      if (error) throw new Error(`Server mapping lookup failed: ${error.message}`);
      fleetId = typeof server?.fleet_id === "string" ? server.fleet_id : null;
    }
    const mapping = config.client_mappings;
    const clientId = (typeof incident.team_id === "string" ? mapping[`team:${incident.team_id}`] : undefined)
      ?? (fleetId ? mapping[`fleet:${fleetId}`] : undefined)
      ?? config.default_client_id;
    if (!clientId) {
      await save({ sync_status: "skipped", last_error: "No Halo client mapped for this incident's team or fleet" });
      return;
    }
    const isResolved = incident.status === "resolved";
    const currentExternalId = typeof claim.external_ticket_id === "string" ? claim.external_ticket_id : null;
    if (isResolved && !currentExternalId) {
      await save({ sync_status: "skipped", last_error: "Incident was resolved before a Halo ticket was linked" });
      return;
    }
    if (isResolved && (!config.auto_close || !config.resolved_status_id)) {
      await save({ sync_status: "synced", last_error: null, last_synced_at: new Date().toISOString() });
      return;
    }
    const token = await accessToken(config, credentialsFor(row));
    const statusId = isResolved ? config.resolved_status_id : incident.status === "open" ? config.open_status_id : null;
    const ticket = incidentTicket(incident, config, clientId, statusId);
    if (findSecret(ticket)) throw new Error("Incident contains secret material; refused to send it to Halo");
    if (currentExternalId) {
      const id = Number(currentExternalId);
      if (!Number.isSafeInteger(id) || id <= 0) throw new Error("Stored Halo ticket ID is invalid");
      const response = await haloRequest(config, token, "tickets", {
        method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify([{ ...ticket, id }]),
      });
      await response.arrayBuffer();
      await save({ sync_status: "synced", last_error: null, last_synced_at: new Date().toISOString() });
      return;
    }
    const response = await haloRequest(config, token, "tickets", {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify([ticket]),
    });
    const ticketId = externalTicketId(await response.json().catch(() => null));
    if (!ticketId) throw new Error("Halo created a ticket but returned no ticket ID");
    await save({ external_ticket_id: ticketId, sync_status: "synced", last_error: null, last_synced_at: new Date().toISOString() });
  } catch (error) {
    const detail = (error as Error).message || "Halo ticket sync failed";
    await save({ sync_status: "failed", last_error: detail.slice(0, 500) });
    console.error("[psa] Halo ticket sync failed");
  }
}

/** Create/update mapped Halo tickets after an incident change; never blocks the caller's response. */
export async function syncPsaIncident(admin: SupabaseClient, incidentId: string, integrationId?: string): Promise<void> {
  try {
    const { data: incident, error: incidentError } = await admin.from("incidents")
      .select("id, org_id, team_id, server_id, human_code, title, severity, status, host, summary")
      .eq("id", incidentId).maybeSingle();
    if (incidentError || !incident) return;
    let query = admin.from("psa_integrations").select("*")
      .eq("organization_id", incident.org_id).eq("provider", "halopsa").eq("enabled", true);
    if (integrationId) query = query.eq("id", integrationId);
    const { data: integrations, error } = await query;
    if (error) throw new Error(`PSA integrations lookup failed: ${error.message}`);
    for (const row of (integrations ?? []) as StoredIntegration[]) await syncOneIntegration(admin, row, incident as Record<string, unknown>);
  } catch (error) {
    console.error("[psa] Incident sync failed");
  }
}
