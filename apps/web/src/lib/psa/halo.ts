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

export type PsaProvider = "halopsa" | "connectwise" | "autotask";
export interface PsaConfig extends HaloConfig {
  board_id?: number;
  priority_id?: number | null;
  company_id?: number;
  ticket_category_id?: number | null;
  queue_id?: number | null;
}

type PsaCredentials = Record<string, string>;
interface StoredIntegration {
  id: string;
  organization_id: string;
  provider: PsaProvider;
  name: string;
  enabled: boolean;
  config: PsaConfig;
  credential_ciphertext: string;
  credential_iv: string;
  credential_tag: string;
}

export interface PsaDetectionRecord {
  id: string;
  organization_id: string;
  server_id: string;
  severity: string;
  title: string;
  description: string | null;
  status?: string;
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

function parseMappedClients(input: Record<string, unknown>, label: string) {
  const mappings = input.client_mappings && typeof input.client_mappings === "object" && !Array.isArray(input.client_mappings)
    ? input.client_mappings as Record<string, unknown> : {};
  if (Object.keys(mappings).length > 200) throw new Error("At most 200 team/fleet client mappings are allowed");
  const result: Record<string, number> = {};
  for (const [key, value] of Object.entries(mappings)) {
    if (!/^(team|fleet):[0-9a-f-]{36}$/i.test(key)) throw new Error(`Invalid mapping key ${key}; use team:<UUID> or fleet:<UUID>`);
    const id = positiveInteger(value);
    if (!id) throw new Error(`Mapping ${key} must have a positive ${label} ID`);
    result[key] = id;
  }
  return result;
}

async function parseApiRoot(value: unknown, expectedPath: RegExp, label: string): Promise<string> {
  if (typeof value !== "string") throw new Error(`${label} is required`);
  const url = await validatePublicHttpsUrl(value.trim());
  if (url.username || url.password || url.search || url.hash || !expectedPath.test(url.pathname.replace(/\/+$/, ""))) {
    throw new Error(`${label} must be an HTTPS API URL with the required API path`);
  }
  return url.toString().replace(/\/+$/, "");
}

export async function parsePsaConfig(provider: PsaProvider, raw: unknown): Promise<PsaConfig> {
  if (provider === "halopsa") return parseHaloConfig(raw);
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) throw new Error("Configuration must be an object");
  const input = raw as Record<string, unknown>;
  const autoClose = input.auto_close === true;
  const resolvedStatusId = input.resolved_status_id == null || input.resolved_status_id === "" ? null : positiveInteger(input.resolved_status_id);
  if (input.resolved_status_id != null && input.resolved_status_id !== "" && !resolvedStatusId) throw new Error("resolved_status_id must be a positive integer");
  if (autoClose && !resolvedStatusId) throw new Error("resolved_status_id is required when auto_close is enabled");
  const openStatusId = input.open_status_id == null || input.open_status_id === "" ? null : positiveInteger(input.open_status_id);
  if (input.open_status_id != null && input.open_status_id !== "" && !openStatusId) throw new Error("open_status_id must be a positive integer");
  const defaultClientId = input.default_client_id == null || input.default_client_id === "" ? null : positiveInteger(input.default_client_id);
  if (input.default_client_id != null && input.default_client_id !== "" && !defaultClientId) throw new Error("default_client_id must be a positive integer");
  const api_url = provider === "connectwise"
    ? await parseApiRoot(input.api_url, /\/(?:v4_6_release|v\d{4}_\d+)\/apis\/3\.0$/i, "api_url")
    : await parseApiRoot(input.api_url, /\/atservicesrest\/v1\.0$/i, "api_url");
  const board_id = provider === "connectwise" ? positiveInteger(input.board_id) : undefined;
  if (provider === "connectwise" && !board_id) throw new Error("board_id must be a positive integer");
  const ticket_category_id = provider === "autotask" && input.ticket_category_id != null && input.ticket_category_id !== ""
    ? positiveInteger(input.ticket_category_id) : null;
  if (provider === "autotask" && input.ticket_category_id != null && input.ticket_category_id !== "" && !ticket_category_id) throw new Error("ticket_category_id must be a positive integer");
  const queue_id = provider === "autotask" && input.queue_id != null && input.queue_id !== ""
    ? positiveInteger(input.queue_id) : null;
  if (provider === "autotask" && input.queue_id != null && input.queue_id !== "" && !queue_id) throw new Error("queue_id must be a positive integer");
  const priority_id = input.priority_id == null || input.priority_id === "" ? null : positiveInteger(input.priority_id);
  if (input.priority_id != null && input.priority_id !== "" && !priority_id) throw new Error("priority_id must be a positive integer");
  return {
    api_url, auth_url: "", ticket_type_id: 1, default_client_id: defaultClientId,
    client_mappings: parseMappedClients(input, provider === "connectwise" ? "ConnectWise company" : "Autotask company"),
    open_status_id: openStatusId, resolved_status_id: resolvedStatusId, auto_close: autoClose,
    ...(board_id ? { board_id } : {}), priority_id, ...(ticket_category_id ? { ticket_category_id } : {}), ...(queue_id ? { queue_id } : {}),
  };
}

function credentialsFor(row: StoredIntegration): PsaCredentials {
  const decrypted = decryptSettingsSecret({
    ciphertext: row.credential_ciphertext,
    iv: row.credential_iv,
    tag: row.credential_tag,
  } satisfies CipherBlob);
  return decrypted;
}

export function normalizePsaCredentials(provider: PsaProvider, incoming: unknown, current: Record<string, string> = {}): PsaCredentials {
  const values = incoming && typeof incoming === "object" && !Array.isArray(incoming) ? incoming as Record<string, unknown> : {};
  const fields = provider === "halopsa" ? ["client_id", "client_secret"]
    : provider === "connectwise" ? ["company_id", "public_key", "private_key", "client_id"]
      : ["username", "secret", "integration_code"];
  const result: PsaCredentials = {};
  for (const field of fields) {
    const value = typeof values[field] === "string" && (values[field] as string).trim()
      ? (values[field] as string).trim() : current[field] ?? "";
    if (!value || value.length > 1000) throw new Error(`${field} is required and must be at most 1000 characters`);
    result[field] = value;
  }
  return result;
}

async function accessToken(config: HaloConfig, credentials: PsaCredentials): Promise<string> {
  if (!credentials.client_id || !credentials.client_secret) throw new Error("Halo API credentials are missing");
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

export async function testPsaIntegration(row: StoredIntegration): Promise<void> {
  if (row.provider === "halopsa") {
    const token = await accessToken(row.config, credentialsFor(row));
    await haloRequest(row.config, token, "client?count=1");
    return;
  }
  const credentials = credentialsFor(row);
  const path = row.provider === "connectwise" ? "service/boards?pageSize=1" : "Tickets/entityInformation";
  await psaRequest(row, credentials, path);
}

async function psaRequest(row: StoredIntegration, credentials: PsaCredentials, path: string, init: RequestInit = {}) {
  const target = `${row.config.api_url.replace(/\/+$/, "")}/${path.replace(/^\/+/, "")}`;
  const headers: Record<string, string> = { Accept: "application/json" };
  if (row.provider === "connectwise") {
    const { company_id, public_key, private_key, client_id } = credentials;
    if (!company_id || !public_key || !private_key || !client_id) throw new Error("ConnectWise company ID, public key, private key, and client ID are required");
    headers.Authorization = `Basic ${Buffer.from(`${company_id}+${public_key}:${private_key}`).toString("base64")}`;
    headers.clientId = client_id;
  } else if (row.provider === "autotask") {
    const { username, secret, integration_code } = credentials;
    if (!username || !secret || !integration_code) throw new Error("Autotask username, secret, and integration code are required");
    headers.Username = username;
    headers.Secret = secret;
    headers.APIIntegrationcode = integration_code;
    headers["API-Tracking-Identifier"] = "ThreatCrush PSA integration";
  }
  const response = await safeFetch(target, {
    ...init,
    redirect: "manual",
    signal: init.signal ?? AbortSignal.timeout(15_000),
    headers: { ...headers, ...(init.headers as Record<string, string> | undefined) },
  });
  if (!response.ok) throw new Error(`${row.provider} API returned HTTP ${response.status}`);
  return response;
}

function psaTicket(row: Record<string, unknown>, integration: StoredIntegration, clientId: number, statusId: number | null, kind: "incident" | "detection"): Record<string, unknown> {
  const config = integration.config;
  const code = typeof row.human_code === "string" ? row.human_code : String(row.id ?? "unknown");
  const title = typeof row.title === "string" ? row.title.slice(0, 180) : `ThreatCrush ${kind}`;
  const severity = typeof row.severity === "string" ? row.severity.toUpperCase() : "UNKNOWN";
  const host = typeof row.host === "string" ? row.host : "host not recorded";
  const description = typeof row.description === "string" ? row.description.slice(0, 8000)
    : typeof row.summary === "string" ? row.summary.slice(0, 8000) : "No details were recorded.";
  const externalUrl = kind === "incident" ? `${appUrl()}/ic/${encodeURIComponent(code)}` : `${appUrl()}/`;
  const summary = `[ThreatCrush ${kind} ${code}] ${title}`.slice(0, 250);
  const details = `Severity: ${severity}\nHost: ${host}\nStatus: ${String(row.status ?? "new")}\n\n${description}\n\nThreatCrush ${kind}: ${externalUrl}`.slice(0, 12_000);
  if (integration.provider === "halopsa") return {
    summary, details, client_id: clientId, tickettype_id: config.ticket_type_id,
    ...(statusId ? { status_id: statusId } : {}),
  };
  if (integration.provider === "connectwise") return {
    summary, initialDescription: details, recordType: "ServiceTicket",
    board: { id: config.board_id }, company: { id: clientId },
    ...(statusId ? { status: { id: statusId } } : {}),
    ...(config.priority_id ? { priority: { id: config.priority_id } } : {}),
  };
  return {
    title: summary.slice(0, 100), description: details.slice(0, 8000), companyID: clientId,
    ...(config.ticket_category_id ? { ticketCategory: config.ticket_category_id } : {}),
    ...(config.queue_id ? { queueID: config.queue_id } : {}),
    ...(statusId ? { status: statusId } : {}),
    ...(config.priority_id ? { priority: config.priority_id } : {}),
  };
}

function externalTicketId(payload: unknown): string | null {
  const candidate = Array.isArray(payload) ? payload[0] : payload;
  if (!candidate || typeof candidate !== "object") return null;
  const item = candidate as Record<string, unknown>;
  for (const key of ["id", "itemId", "faultid", "ticket_id"]) {
    const value = item[key];
    if (typeof value === "number" && Number.isSafeInteger(value) && value > 0) return String(value);
    if (typeof value === "string" && value.length > 0 && value.length <= 100) return value;
  }
  return null;
}

async function claimLink(admin: SupabaseClient, row: StoredIntegration, kind: "incident" | "detection", recordId: string) {
  const field = kind === "incident" ? "incident_id" : "detection_id";
  const { data: existing, error } = await admin.from("psa_ticket_links").select("*")
    .eq("integration_id", row.id).eq(field, recordId).maybeSingle();
  if (error) throw new Error(`PSA link lookup failed: ${error.message}`);
  const now = new Date().toISOString();
  const staleBefore = new Date(Date.now() - 10 * 60_000).toISOString();
  if (!existing) {
    const { data, error: insertError } = await admin.from("psa_ticket_links").insert({
      organization_id: row.organization_id, integration_id: row.id, [field]: recordId, sync_status: "syncing", updated_at: now,
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

async function syncOneIntegration(admin: SupabaseClient, row: StoredIntegration, record: Record<string, unknown>, kind: "incident" | "detection") {
  const recordId = String(record.id ?? "");
  if (!recordId) return;
  const claim = await claimLink(admin, row, kind, recordId);
  if (!claim) return;
  const save = async (patch: Record<string, unknown>) => {
    const { error } = await admin.from("psa_ticket_links").update({ ...patch, updated_at: new Date().toISOString() }).eq("id", claim.id);
    if (error) throw new Error(`PSA link update failed: ${error.message}`);
  };
  try {
    const config = row.config;
    let fleetId: string | null = null;
    let teamId = typeof record.team_id === "string" ? record.team_id : null;
    if (typeof record.server_id === "string") {
      const { data: server, error } = await admin.from("servers").select("fleet_id").eq("id", record.server_id).eq("org_id", row.organization_id).maybeSingle();
      if (error) throw new Error(`Server mapping lookup failed: ${error.message}`);
      fleetId = typeof server?.fleet_id === "string" ? server.fleet_id : null;
      if (fleetId && !teamId) {
        const { data: fleet, error: fleetError } = await admin.from("fleets").select("team_id").eq("id", fleetId).eq("org_id", row.organization_id).maybeSingle();
        if (fleetError) throw new Error(`Fleet mapping lookup failed: ${fleetError.message}`);
        teamId = typeof fleet?.team_id === "string" ? fleet.team_id : null;
      }
    }
    const mapping = config.client_mappings;
    const clientId = (teamId ? mapping[`team:${teamId}`] : undefined)
      ?? (fleetId ? mapping[`fleet:${fleetId}`] : undefined)
      ?? config.default_client_id;
    if (!clientId) {
      await save({ sync_status: "skipped", last_error: `No ${row.provider} client mapped for this team's or fleet's alert` });
      return;
    }
    const isResolved = record.status === "resolved";
    const currentExternalId = typeof claim.external_ticket_id === "string" ? claim.external_ticket_id : null;
    if (isResolved && !currentExternalId) {
      await save({ sync_status: "skipped", last_error: "Incident was resolved before a PSA ticket was linked" });
      return;
    }
    if (isResolved && (!config.auto_close || !config.resolved_status_id)) {
      await save({ sync_status: "synced", last_error: null, last_synced_at: new Date().toISOString() });
      return;
    }
    const credentials = credentialsFor(row);
    const statusId = isResolved ? config.resolved_status_id
      : record.status === "open" || (kind === "detection" && ["new", "acknowledged"].includes(String(record.status))) ? config.open_status_id : null;
    const ticket = psaTicket(record, row, clientId, statusId, kind);
    if (findSecret(ticket)) throw new Error("Alert contains secret material; refused to send it to the PSA");
    if (currentExternalId) {
      const id = Number(currentExternalId);
      if (!Number.isSafeInteger(id) || id <= 0) throw new Error("Stored PSA ticket ID is invalid");
      let response: Response;
      if (row.provider === "halopsa") {
        const token = await accessToken(config, credentials);
        response = await haloRequest(config, token, "tickets", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify([{ ...ticket, id }]) });
      } else if (row.provider === "connectwise") {
        const operations: Array<{ op: string; path: string; value: unknown }> = [];
        if (typeof ticket.summary === "string") operations.push({ op: "replace", path: "/summary", value: ticket.summary });
        if (statusId) operations.push({ op: "replace", path: "/status", value: { id: statusId } });
        response = await psaRequest(row, credentials, `service/tickets/${id}`, { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify(operations) });
      } else {
        const fields = Object.entries(ticket).filter(([key]) => !["companyID", "ticketCategory", "queueID"].includes(key)).map(([name, value]) => ({ name, value }));
        response = await psaRequest(row, credentials, "Tickets", { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify([{ id, fields }]) });
      }
      await response.arrayBuffer();
      await save({ sync_status: "synced", last_error: null, last_synced_at: new Date().toISOString() });
      return;
    }
    let response: Response;
    if (row.provider === "halopsa") {
      const token = await accessToken(config, credentials);
      response = await haloRequest(config, token, "tickets", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify([ticket]) });
    } else {
      const endpoint = row.provider === "connectwise" ? "service/tickets" : "Tickets";
      response = await psaRequest(row, credentials, endpoint, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(ticket) });
    }
    const ticketId = externalTicketId(await response.json().catch(() => null));
    if (!ticketId) throw new Error(`${row.provider} created a ticket but returned no ticket ID`);
    await save({ external_ticket_id: ticketId, sync_status: "synced", last_error: null, last_synced_at: new Date().toISOString() });
  } catch (error) {
    const detail = (error as Error).message || "Halo ticket sync failed";
    await save({ sync_status: "failed", last_error: detail.slice(0, 500) });
    console.error(`[psa] ${row.provider} ticket sync failed`);
  }
}

/** Create/update mapped PSA tickets after an incident change; never blocks the caller's response. */
export async function syncPsaIncident(admin: SupabaseClient, incidentId: string, integrationId?: string): Promise<void> {
  try {
    const { data: incident, error: incidentError } = await admin.from("incidents")
      .select("id, org_id, team_id, server_id, human_code, title, severity, status, host, summary")
      .eq("id", incidentId).maybeSingle();
    if (incidentError || !incident) return;
    let query = admin.from("psa_integrations").select("*")
      .eq("organization_id", incident.org_id).eq("enabled", true);
    if (integrationId) query = query.eq("id", integrationId);
    const { data: integrations, error } = await query;
    if (error) throw new Error(`PSA integrations lookup failed: ${error.message}`);
    for (const row of (integrations ?? []) as StoredIntegration[]) await syncOneIntegration(admin, row, incident as Record<string, unknown>, "incident");
  } catch (error) {
    console.error("[psa] Incident sync failed");
  }
}

/** Create one deduplicated PSA ticket for each newly inserted low-severity alert. */
export async function syncPsaDetections(admin: SupabaseClient, detections: PsaDetectionRecord[], integrationId?: string): Promise<void> {
  for (const detection of detections) {
    if ((detection.severity !== "low" && integrationId === undefined) || typeof detection.organization_id !== "string") continue;
    let record: Record<string, unknown> = detection as unknown as Record<string, unknown>;
    if (typeof detection.server_id === "string") {
      const { data: server } = await admin.from("servers").select("name, hostname")
        .eq("id", detection.server_id).eq("org_id", detection.organization_id).maybeSingle();
      record = { ...detection, host: server?.name || server?.hostname || "host not recorded" };
    }
    let query = admin.from("psa_integrations").select("*")
      .eq("organization_id", detection.organization_id).eq("enabled", true);
    if (integrationId) query = query.eq("id", integrationId);
    const { data, error } = await query;
    if (error) { console.error("[psa] Detection integrations lookup failed"); continue; }
    for (const row of (data ?? []) as StoredIntegration[]) await syncOneIntegration(admin, row, record, "detection");
  }
}
