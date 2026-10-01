import { authHeaders } from "@/lib/auth-client";

/** Browser-side calls for the teams, fleets, invites and agent-key API. */

export type TeamRole = "read" | "write" | "admin";

export const ROLE_LABEL: Record<TeamRole, string> = {
  read: "Read-only",
  write: "Write",
  admin: "Admin",
};

export const ROLE_HELP: Record<TeamRole, string> = {
  read: "See the team's fleets, servers, detections and findings",
  write: "Also act on them: daemons reporting in, resolving findings, queuing bans",
  admin: "Also manage the team: fleets, members, invites and agent keys",
};

export interface TeamSummary {
  id: string;
  name: string;
  slug: string;
  created_at: string;
  my_role: TeamRole;
  member_count: number;
  fleet_count: number;
}

export interface TeamDetail {
  team: { id: string; org_id: string; name: string; slug: string; created_at: string; my_role: TeamRole };
  members: Array<{ user_id: string; role: TeamRole; added_at: string; email: string | null; display_name: string | null }>;
  fleets: Array<{ id: string; name: string; slug: string; created_at: string; server_count: number }>;
  invites?: Array<{ id: string; email: string; role: TeamRole; created_at: string; expires_at: string }>;
  agent_keys?: Array<{ id: string; name: string; role: TeamRole; key_prefix: string; created_at: string; last_used_at: string | null }>;
}

async function call<T>(path: string, init: { method?: string; body?: unknown } = {}): Promise<T> {
  const res = await fetch(path, {
    method: init.method ?? "GET",
    headers: authHeaders(init.body !== undefined ? { "Content-Type": "application/json" } : undefined),
    body: init.body !== undefined ? JSON.stringify(init.body) : undefined,
    cache: "no-store",
  });
  const data = (await res.json().catch(() => ({}))) as T & { error?: string };
  if (!res.ok) throw new Error(data.error || `Request failed (${res.status})`);
  return data;
}

const base = (orgId: string) => `/api/orgs/${orgId}`;

export const teamsApi = {
  list: (orgId: string) => call<{ teams: TeamSummary[] }>(`${base(orgId)}/teams`),
  create: (orgId: string, name: string) => call<{ team: TeamSummary }>(`${base(orgId)}/teams`, { method: "POST", body: { name } }),
  get: (orgId: string, teamId: string) => call<TeamDetail>(`${base(orgId)}/teams/${teamId}`),
  rename: (orgId: string, teamId: string, name: string) =>
    call(`${base(orgId)}/teams/${teamId}`, { method: "PATCH", body: { name } }),
  remove: (orgId: string, teamId: string) => call(`${base(orgId)}/teams/${teamId}`, { method: "DELETE" }),

  addMember: (orgId: string, teamId: string, email: string, role: TeamRole) =>
    call(`${base(orgId)}/teams/${teamId}/members`, { method: "POST", body: { email, role } }),
  setMemberRole: (orgId: string, teamId: string, userId: string, role: TeamRole) =>
    call(`${base(orgId)}/teams/${teamId}/members/${userId}`, { method: "PATCH", body: { role } }),
  removeMember: (orgId: string, teamId: string, userId: string) =>
    call(`${base(orgId)}/teams/${teamId}/members/${userId}`, { method: "DELETE" }),

  invite: (orgId: string, teamId: string, email: string, role: TeamRole) =>
    call<{ url: string; emailed: boolean }>(`${base(orgId)}/teams/${teamId}/invites`, { method: "POST", body: { email, role } }),
  revokeInvite: (orgId: string, teamId: string, inviteId: string) =>
    call(`${base(orgId)}/teams/${teamId}/invites/${inviteId}`, { method: "DELETE" }),

  createAgentKey: (orgId: string, teamId: string, name: string, role: TeamRole) =>
    call<{ key: string }>(`${base(orgId)}/teams/${teamId}/agents`, { method: "POST", body: { name, role } }),
  revokeAgentKey: (orgId: string, teamId: string, keyId: string) =>
    call(`${base(orgId)}/teams/${teamId}/agents/${keyId}`, { method: "DELETE" }),

  createFleet: (orgId: string, teamId: string, name: string) =>
    call(`${base(orgId)}/fleets`, { method: "POST", body: { team_id: teamId, name } }),
  renameFleet: (orgId: string, fleetId: string, name: string) =>
    call(`${base(orgId)}/fleets/${fleetId}`, { method: "PATCH", body: { name } }),
  removeFleet: (orgId: string, fleetId: string) => call(`${base(orgId)}/fleets/${fleetId}`, { method: "DELETE" }),
  moveServer: (orgId: string, serverId: string, fleetId: string | null) =>
    call(`${base(orgId)}/servers/${serverId}/fleet`, { method: "PUT", body: { fleet_id: fleetId } }),
};
