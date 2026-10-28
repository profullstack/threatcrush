import "server-only";
import { createHash, randomBytes } from "node:crypto";
import type { NextRequest } from "next/server";
import type { SupabaseClient } from "@supabase/supabase-js";
import { getAuthenticatedRequestUser } from "@/lib/api-auth";

/**
 * Who is calling, and what may they do. One place for the rules in
 * supabase/migrations/*_teams_fleets_invites_agents.sql:
 *
 *   org owner/admin   admin on everything in the org
 *   org member        write on servers in no fleet (today's behaviour)
 *   org guest         nothing outside their teams
 *   team read/write/admin   that role on the team's fleets and their servers
 *   agent key         its role on its one team's fleets, nothing else
 */

export type TeamRole = "read" | "write" | "admin";
export type OrgRole = "owner" | "admin" | "member" | "guest";

export type Principal =
  | { kind: "user"; userId: string; email: string | null }
  | { kind: "agent"; keyId: string; orgId: string; teamId: string; role: TeamRole; name: string };

const RANK: Record<TeamRole, number> = { read: 1, write: 2, admin: 3 };
export const TEAM_ROLES: TeamRole[] = ["read", "write", "admin"];

export function isTeamRole(value: unknown): value is TeamRole {
  return typeof value === "string" && (TEAM_ROLES as string[]).includes(value);
}

export function atLeast(role: TeamRole | null | undefined, min: TeamRole): boolean {
  return Boolean(role) && RANK[role as TeamRole] >= RANK[min];
}

function higher(a: TeamRole | null, b: TeamRole | null): TeamRole | null {
  if (!a) return b;
  if (!b) return a;
  return RANK[a] >= RANK[b] ? a : b;
}

// ─── Secrets (invites, agent keys) ───

export const AGENT_KEY_PREFIX = "tc_agent_";

/** 32 random bytes, base64url. Only its hash is ever stored. */
export function newSecret(): string {
  return randomBytes(32).toString("base64url");
}

export function hashSecret(secret: string): string {
  return createHash("sha256").update(secret).digest("hex");
}

// ─── Who is calling ───

export async function getPrincipal(req: NextRequest, admin: SupabaseClient): Promise<Principal | null> {
  const bearer = req.headers.get("authorization")?.replace(/^Bearer\s+/i, "") ?? "";
  if (bearer.startsWith(AGENT_KEY_PREFIX)) {
    const { data: key } = await admin
      .from("agent_keys")
      .select("id, org_id, team_id, role, name")
      .eq("key_hash", hashSecret(bearer))
      .is("revoked_at", null)
      .maybeSingle();
    if (!key || !isTeamRole(key.role)) return null;
    await admin.from("agent_keys").update({ last_used_at: new Date().toISOString() }).eq("id", key.id);
    return { kind: "agent", keyId: key.id, orgId: key.org_id, teamId: key.team_id, role: key.role, name: key.name };
  }

  const user = await getAuthenticatedRequestUser(req);
  return user ? { kind: "user", userId: user.userId, email: user.email } : null;
}

// ─── Roles ───

export async function orgRoleOf(admin: SupabaseClient, p: Principal, orgId: string): Promise<OrgRole | null> {
  if (p.kind === "agent") return null;
  const { data } = await admin
    .from("organization_members")
    .select("role")
    .eq("org_id", orgId)
    .eq("user_id", p.userId)
    .maybeSingle();
  return (data?.role as OrgRole | undefined) ?? null;
}

const isOrgAdmin = (role: OrgRole | null) => role === "owner" || role === "admin";

/**
 * The caller's role on an org's scan findings (scan, pentest, ai-scan). They
 * hang off properties, which are org-wide rather than in a fleet, so: org
 * owner/admin = admin, member = write (triage + upload), guest = nothing,
 * agent key = its own role, inside its own org only.
 */
export async function findingsRoleOf(admin: SupabaseClient, p: Principal, orgId: string): Promise<TeamRole | null> {
  if (p.kind === "agent") return p.orgId === orgId ? p.role : null;
  const role = await orgRoleOf(admin, p, orgId);
  if (isOrgAdmin(role)) return "admin";
  return role === "member" ? "write" : null;
}

/**
 * The caller's role on an incident. A team's incident takes the caller's role
 * on that team (org owner/admin = admin, agent key = its role on its own team);
 * an incident with no team (an unfleeted server, an org-wide investigation)
 * follows the findings rule: owner/admin admin, member write, guest nothing.
 */
export async function incidentRoleOf(
  admin: SupabaseClient,
  p: Principal,
  incident: { org_id: string; team_id: string | null },
): Promise<TeamRole | null> {
  if (incident.team_id) {
    if (p.kind === "agent" && p.orgId !== incident.org_id) return null;
    return teamRoleOf(admin, p, { id: incident.team_id, org_id: incident.org_id });
  }
  return findingsRoleOf(admin, p, incident.org_id);
}

/**
 * Which of an org's incidents the caller can see, as a filter: everything (org
 * owner/admin), or these teams' incidents plus (when `teamless`) the ones with
 * no team. Same rules as incidentRoleOf, loaded once for a list.
 */
export interface IncidentScope {
  all: boolean;
  teamRoles: Map<string, TeamRole>;
  teamless: TeamRole | null;
}

export async function incidentScopeIn(admin: SupabaseClient, p: Principal, orgId: string): Promise<IncidentScope | null> {
  if (p.kind === "agent") {
    if (p.orgId !== orgId) return null;
    return { all: false, teamRoles: new Map([[p.teamId, p.role]]), teamless: p.role };
  }
  const orgRole = await orgRoleOf(admin, p, orgId);
  if (!orgRole) return null;
  if (isOrgAdmin(orgRole)) return { all: true, teamRoles: new Map(), teamless: "admin" };
  const { data: seats } = await admin
    .from("team_members")
    .select("team_id, role, teams!inner(org_id)")
    .eq("user_id", p.userId)
    .eq("teams.org_id", orgId);
  const teamRoles = new Map<string, TeamRole>();
  for (const seat of (seats ?? []) as Array<{ team_id: string; role: string }>) {
    if (isTeamRole(seat.role)) teamRoles.set(seat.team_id, seat.role);
  }
  return { all: false, teamRoles, teamless: orgRole === "member" ? "write" : null };
}

/** The caller's role on one incident, given a scope already loaded for its org. */
export function incidentRoleInScope(scope: IncidentScope, incident: { team_id: string | null }): TeamRole | null {
  if (scope.all) return "admin";
  return incident.team_id ? scope.teamRoles.get(incident.team_id) ?? null : scope.teamless;
}

/** The caller's role on a team, or null. Org owners and admins are admin everywhere. */
export async function teamRoleOf(
  admin: SupabaseClient,
  p: Principal,
  team: { id: string; org_id: string },
): Promise<TeamRole | null> {
  if (p.kind === "agent") return p.teamId === team.id ? p.role : null;
  if (isOrgAdmin(await orgRoleOf(admin, p, team.org_id))) return "admin";
  const { data } = await admin
    .from("team_members")
    .select("role")
    .eq("team_id", team.id)
    .eq("user_id", p.userId)
    .maybeSingle();
  return isTeamRole(data?.role) ? data.role : null;
}

/** The caller's role on one server. */
export async function serverRoleOf(
  admin: SupabaseClient,
  p: Principal,
  server: { org_id: string; fleet_id?: string | null },
): Promise<TeamRole | null> {
  if (server.fleet_id) {
    const { data: fleet } = await admin.from("fleets").select("team_id").eq("id", server.fleet_id).maybeSingle();
    if (!fleet) return null;
    return teamRoleOf(admin, p, { id: fleet.team_id, org_id: server.org_id });
  }
  if (p.kind === "agent") return null;
  const role = await orgRoleOf(admin, p, server.org_id);
  if (isOrgAdmin(role)) return "admin";
  return role === "member" ? "write" : null;
}

/**
 * Which servers in an org the caller can see, as a filter: everything, or
 * these fleets plus (optionally) the servers in no fleet.
 */
export interface ServerScope {
  all: boolean;
  fleetRoles: Map<string, TeamRole>;
  unfleeted: TeamRole | null;
}

export async function serverScopeIn(admin: SupabaseClient, p: Principal, orgId: string): Promise<ServerScope | null> {
  if (p.kind === "agent") {
    if (p.orgId !== orgId) return null;
    const { data: fleets } = await admin.from("fleets").select("id").eq("team_id", p.teamId);
    return { all: false, fleetRoles: new Map((fleets ?? []).map((f) => [f.id as string, p.role])), unfleeted: null };
  }

  const orgRole = await orgRoleOf(admin, p, orgId);
  if (!orgRole) return null;
  if (isOrgAdmin(orgRole)) return { all: true, fleetRoles: new Map(), unfleeted: "admin" };

  const { data: seats } = await admin
    .from("team_members")
    .select("role, teams!inner(id, org_id, fleets(id))")
    .eq("user_id", p.userId)
    .eq("teams.org_id", orgId);

  const fleetRoles = new Map<string, TeamRole>();
  type Embedded = { fleets?: Array<{ id: string }> | null };
  for (const seat of (seats ?? []) as unknown as Array<{ role: string; teams: Embedded | Embedded[] | null }>) {
    if (!isTeamRole(seat.role)) continue;
    // A many-to-one embed is an object at runtime; the inferred type says array.
    const team = Array.isArray(seat.teams) ? seat.teams[0] : seat.teams;
    for (const f of team?.fleets ?? []) fleetRoles.set(f.id, higher(fleetRoles.get(f.id) ?? null, seat.role)!);
  }
  return { all: false, fleetRoles, unfleeted: orgRole === "member" ? "write" : null };
}

/** The caller's role on a server row, given a scope already loaded for its org. */
export function roleInScope(scope: ServerScope, server: { fleet_id?: string | null }): TeamRole | null {
  if (scope.all) return "admin";
  return server.fleet_id ? scope.fleetRoles.get(server.fleet_id) ?? null : scope.unfleeted;
}

/** Filter rows that carry a fleet_id (servers) down to what the scope can see. */
export function visibleIn<T extends { fleet_id?: string | null }>(scope: ServerScope, rows: T[]): T[] {
  return scope.all ? rows : rows.filter((r) => roleInScope(scope, r) !== null);
}
