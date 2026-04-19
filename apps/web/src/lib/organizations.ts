/**
 * Client-side helpers for organizations and servers API.
 * Uses the same token-based auth pattern as auth-client.ts.
 */

import { authHeaders } from "./auth-client";

const API_BASE = "";

// ─── Types ───

export interface Server {
  id: string;
  name: string;
  hostname: string | null;
  ip_address: string | null;
  port: number;
  ssh_username: string | null;
  status: "online" | "offline" | "unreachable";
  last_seen: string | null;
  threatcrushd_version: string | null;
  org_id: string;
  created_by: string;
  created_at: string;
}

// ─── Organizations ───

export async function listOrganizations() {
  const res = await fetch(`${API_BASE}/api/orgs`, { headers: authHeaders() });
  if (!res.ok) throw new Error("Failed to list organizations");
  return res.json() as Promise<{ organizations: Array<Record<string, unknown>> }>;
}

export async function createOrganization(name: string, slug?: string) {
  const res = await fetch(`${API_BASE}/api/orgs`, {
    method: "POST",
    headers: { ...authHeaders(), "Content-Type": "application/json" },
    body: JSON.stringify({ name, slug }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: "Failed to create organization" }));
    throw new Error(err.error || "Failed to create organization");
  }
  return res.json() as Promise<{ organization: Record<string, unknown> }>;
}

export async function getOrganization(id: string) {
  const res = await fetch(`${API_BASE}/api/orgs/${id}`, { headers: authHeaders() });
  if (!res.ok) throw new Error("Failed to get organization");
  return res.json() as Promise<{ organization: Record<string, unknown> }>;
}

export async function updateOrganization(id: string, updates: { name?: string; slug?: string }) {
  const res = await fetch(`${API_BASE}/api/orgs/${id}`, {
    method: "PATCH",
    headers: { ...authHeaders(), "Content-Type": "application/json" },
    body: JSON.stringify(updates),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: "Failed to update organization" }));
    throw new Error(err.error || "Failed to update organization");
  }
  return res.json() as Promise<{ organization: Record<string, unknown> }>;
}

export async function deleteOrganization(id: string) {
  const res = await fetch(`${API_BASE}/api/orgs/${id}`, {
    method: "DELETE",
    headers: authHeaders(),
  });
  if (!res.ok) throw new Error("Failed to delete organization");
  return res.json() as Promise<{ success: boolean }>;
}

// ─── Members ───

export async function listMembers(orgId: string) {
  const res = await fetch(`${API_BASE}/api/orgs/${orgId}/members`, { headers: authHeaders() });
  if (!res.ok) throw new Error("Failed to list members");
  return res.json() as Promise<{ members: Array<Record<string, unknown>> }>;
}

export async function addMember(orgId: string, email: string, role = "member") {
  const res = await fetch(`${API_BASE}/api/orgs/${orgId}/members`, {
    method: "POST",
    headers: { ...authHeaders(), "Content-Type": "application/json" },
    body: JSON.stringify({ email, role }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: "Failed to add member" }));
    throw new Error(err.error || "Failed to add member");
  }
  return res.json() as Promise<{ member: Record<string, unknown> }>;
}

export async function updateMemberRole(orgId: string, userId: string, role: string) {
  const res = await fetch(`${API_BASE}/api/orgs/${orgId}/members/${userId}`, {
    method: "PATCH",
    headers: { ...authHeaders(), "Content-Type": "application/json" },
    body: JSON.stringify({ role }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: "Failed to update member role" }));
    throw new Error(err.error || "Failed to update member role");
  }
  return res.json() as Promise<{ member: Record<string, unknown> }>;
}

export async function removeMember(orgId: string, userId: string) {
  const res = await fetch(`${API_BASE}/api/orgs/${orgId}/members/${userId}`, {
    method: "DELETE",
    headers: authHeaders(),
  });
  if (!res.ok) throw new Error("Failed to remove member");
  return res.json() as Promise<{ success: boolean }>;
}

// ─── Servers ───

export async function listServers(orgId: string) {
  const res = await fetch(`${API_BASE}/api/orgs/${orgId}/servers`, { headers: authHeaders() });
  if (!res.ok) throw new Error("Failed to list servers");
  return res.json() as Promise<{ servers: Array<Record<string, unknown>> }>;
}

export async function createServer(orgId: string, data: {
  name: string;
  hostname?: string;
  ip_address?: string;
  port?: number;
  ssh_username?: string;
}) {
  const res = await fetch(`${API_BASE}/api/orgs/${orgId}/servers`, {
    method: "POST",
    headers: { ...authHeaders(), "Content-Type": "application/json" },
    body: JSON.stringify(data),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: "Failed to create server" }));
    throw new Error(err.error || "Failed to create server");
  }
  return res.json() as Promise<{ server: Record<string, unknown> }>;
}

export async function getServer(orgId: string, id: string) {
  const res = await fetch(`${API_BASE}/api/orgs/${orgId}/servers/${id}`, { headers: authHeaders() });
  if (!res.ok) throw new Error("Failed to get server");
  return res.json() as Promise<{ server: Record<string, unknown> }>;
}

export async function updateServer(orgId: string, id: string, updates: Record<string, unknown>) {
  const res = await fetch(`${API_BASE}/api/orgs/${orgId}/servers/${id}`, {
    method: "PATCH",
    headers: { ...authHeaders(), "Content-Type": "application/json" },
    body: JSON.stringify(updates),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: "Failed to update server" }));
    throw new Error(err.error || "Failed to update server");
  }
  return res.json() as Promise<{ server: Record<string, unknown> }>;
}

export async function deleteServer(orgId: string, id: string) {
  const res = await fetch(`${API_BASE}/api/orgs/${orgId}/servers/${id}`, {
    method: "DELETE",
    headers: authHeaders(),
  });
  if (!res.ok) throw new Error("Failed to delete server");
  return res.json() as Promise<{ success: boolean }>;
}

export async function sendHeartbeat(id: string, data: { version?: string; status?: string }) {
  const res = await fetch(`${API_BASE}/api/servers/${id}/heartbeat`, {
    method: "POST",
    headers: { ...authHeaders(), "Content-Type": "application/json" },
    body: JSON.stringify(data),
  });
  if (!res.ok) throw new Error("Failed to send heartbeat");
  return res.json() as Promise<{ server: Record<string, unknown> }>;
}

export async function submitEvents(id: string, events: Array<Record<string, unknown>>) {
  const res = await fetch(`${API_BASE}/api/servers/${id}/events`, {
    method: "POST",
    headers: { ...authHeaders(), "Content-Type": "application/json" },
    body: JSON.stringify({ events }),
  });
  if (!res.ok) throw new Error("Failed to submit events");
  return res.json() as Promise<{ success: boolean; received: number }>;
}

export async function getServerEvents(id: string) {
  const res = await fetch(`${API_BASE}/api/servers/${id}/events`, { headers: authHeaders() });
  if (!res.ok) throw new Error("Failed to get events");
  return res.json() as Promise<{ events: Array<Record<string, unknown>> }>;
}

// ─── Properties ───

export type PropertyKind = "url" | "api" | "domain" | "ip" | "repo";
export type PropertySchedule = "hourly" | "daily" | "weekly" | "monthly" | null;

export interface Property {
  id: string;
  org_id: string;
  name: string;
  kind: PropertyKind;
  target: string;
  description: string | null;
  tags: string[];
  enabled: boolean;
  schedule: PropertySchedule;
  next_run_at: string | null;
  last_run_at: string | null;
  last_run_status: string | null;
  created_by: string | null;
  created_at: string;
  updated_at: string;
}

export async function listProperties(orgId: string, opts: { kind?: PropertyKind } = {}) {
  const qs = opts.kind ? `?kind=${encodeURIComponent(opts.kind)}` : "";
  const res = await fetch(`${API_BASE}/api/orgs/${orgId}/properties${qs}`, { headers: authHeaders() });
  if (!res.ok) throw new Error("Failed to list properties");
  return res.json() as Promise<{ properties: Property[] }>;
}

export async function createProperty(orgId: string, data: {
  name: string;
  kind: PropertyKind;
  target: string;
  description?: string;
  tags?: string[];
  enabled?: boolean;
  schedule?: PropertySchedule;
}) {
  const res = await fetch(`${API_BASE}/api/orgs/${orgId}/properties`, {
    method: "POST",
    headers: { ...authHeaders(), "Content-Type": "application/json" },
    body: JSON.stringify(data),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: "Failed to create property" }));
    throw new Error(err.error || "Failed to create property");
  }
  return res.json() as Promise<{ property: Property }>;
}

export async function getProperty(orgId: string, id: string) {
  const res = await fetch(`${API_BASE}/api/orgs/${orgId}/properties/${id}`, { headers: authHeaders() });
  if (!res.ok) throw new Error("Failed to get property");
  return res.json() as Promise<{ property: Property }>;
}

export async function updateProperty(orgId: string, id: string, updates: Partial<{
  name: string;
  kind: PropertyKind;
  target: string;
  description: string | null;
  tags: string[];
  enabled: boolean;
  schedule: PropertySchedule;
  last_run_at: string | null;
  last_run_status: string | null;
}>) {
  const res = await fetch(`${API_BASE}/api/orgs/${orgId}/properties/${id}`, {
    method: "PATCH",
    headers: { ...authHeaders(), "Content-Type": "application/json" },
    body: JSON.stringify(updates),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: "Failed to update property" }));
    throw new Error(err.error || "Failed to update property");
  }
  return res.json() as Promise<{ property: Property }>;
}

export async function deleteProperty(orgId: string, id: string) {
  const res = await fetch(`${API_BASE}/api/orgs/${orgId}/properties/${id}`, {
    method: "DELETE",
    headers: authHeaders(),
  });
  if (!res.ok) throw new Error("Failed to delete property");
  return res.json() as Promise<{ success: boolean }>;
}

// ─── Property Runs ───

export type RunType = "scan" | "pentest";
export type RunStatus = "queued" | "running" | "succeeded" | "failed" | "cancelled";

export interface PropertyRun {
  id: string;
  org_id: string;
  property_id: string;
  type: RunType;
  status: RunStatus;
  trigger: string;
  source: string | null;
  worker_id: string | null;
  queued_at: string;
  started_at: string | null;
  completed_at: string | null;
  findings_count: number;
  severity_summary: Record<string, number> | null;
  summary: string | null;
  output: string | null;
  findings: unknown;
  error: string | null;
  created_at: string;
}

export async function listRuns(orgId: string, propertyId: string, limit = 25) {
  const res = await fetch(
    `${API_BASE}/api/orgs/${orgId}/properties/${propertyId}/runs?limit=${limit}`,
    { headers: authHeaders() },
  );
  if (!res.ok) throw new Error("Failed to list runs");
  return res.json() as Promise<{ runs: PropertyRun[] }>;
}

export async function enqueueRun(orgId: string, propertyId: string, type?: RunType) {
  const res = await fetch(`${API_BASE}/api/orgs/${orgId}/properties/${propertyId}/runs`, {
    method: "POST",
    headers: { ...authHeaders(), "Content-Type": "application/json" },
    body: JSON.stringify({ type, trigger: "manual" }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: "Failed to enqueue run" }));
    throw new Error(err.error || "Failed to enqueue run");
  }
  return res.json() as Promise<{ run: PropertyRun }>;
}

export async function getRun(orgId: string, propertyId: string, runId: string) {
  const res = await fetch(
    `${API_BASE}/api/orgs/${orgId}/properties/${propertyId}/runs/${runId}`,
    { headers: authHeaders() },
  );
  if (!res.ok) throw new Error("Failed to get run");
  return res.json() as Promise<{ run: PropertyRun }>;
}

// ─── Current Org ───

export async function setCurrentOrg(orgId: string) {
  const res = await fetch(`${API_BASE}/api/auth/me`, {
    method: "PATCH",
    headers: { ...authHeaders(), "Content-Type": "application/json" },
    body: JSON.stringify({ current_org_id: orgId }),
  });
  if (!res.ok) throw new Error("Failed to set current organization");
  return res.json() as Promise<{ profile: Record<string, unknown> }>;
}
