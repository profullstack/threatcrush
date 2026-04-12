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
