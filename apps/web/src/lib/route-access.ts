import "server-only";
import type { NextRequest, NextResponse } from "next/server";
import type { SupabaseClient } from "@supabase/supabase-js";
import { getSupabaseAdmin } from "@/lib/supabase";
import {
  atLeast,
  getPrincipal,
  roleInScope,
  serverScopeIn,
  type Principal,
  type ServerScope,
  type TeamRole,
} from "@/lib/access";
import { fail } from "@/lib/teams";

/** Route-level guards on top of lib/access: each returns what the route needs, or the response to send. */

export interface ServerAccess {
  admin: SupabaseClient;
  p: Principal;
  server: Record<string, unknown> & { id: string; org_id: string; fleet_id: string | null };
  role: TeamRole;
}

/** Load a server in an org and require at least `min` on it. Unknown and forbidden look the same. */
export async function requireServer(
  req: NextRequest,
  orgId: string,
  serverId: string,
  min: TeamRole,
  columns = "*",
): Promise<ServerAccess | { error: NextResponse }> {
  const admin = getSupabaseAdmin();
  const p = await getPrincipal(req, admin);
  if (!p) return { error: fail(401, "Not authenticated") };

  const { data: server } = await admin.from("servers").select(columns).eq("id", serverId).eq("org_id", orgId).maybeSingle();
  if (!server) return { error: fail(404, "Server not found") };
  const row = server as unknown as ServerAccess["server"];

  const scope = await serverScopeIn(admin, p, orgId);
  const role = scope ? roleInScope(scope, row) : null;
  if (!role) return { error: fail(404, "Server not found") };
  if (!atLeast(role, min)) return { error: fail(403, `This needs ${min} access to the server`) };
  return { admin, p, server: row, role };
}

export interface OrgScope {
  admin: SupabaseClient;
  p: Principal;
  scope: ServerScope;
}

/** The caller's view of an org's servers. 403 when they have none at all. */
export async function requireOrgScope(req: NextRequest, orgId: string): Promise<OrgScope | { error: NextResponse }> {
  const admin = getSupabaseAdmin();
  const p = await getPrincipal(req, admin);
  if (!p) return { error: fail(401, "Not authenticated") };
  const scope = await serverScopeIn(admin, p, orgId);
  if (!scope) return { error: fail(403, "Not a member of this organization") };
  return { admin, p, scope };
}

/** Ids of the org's servers the scope can see (all of them for org admins). */
export async function visibleServerIds(admin: SupabaseClient, orgId: string, scope: ServerScope): Promise<string[] | null> {
  if (scope.all) return null; // no filter needed
  const { data } = await admin.from("servers").select("id, fleet_id").eq("org_id", orgId);
  return (data ?? []).filter((s) => roleInScope(scope, s) !== null).map((s) => s.id as string);
}

/** The caller's role on each of the org's servers, for checking a batch. */
export async function serverRolesIn(admin: SupabaseClient, orgId: string, scope: ServerScope): Promise<Map<string, TeamRole>> {
  const { data } = await admin.from("servers").select("id, fleet_id").eq("org_id", orgId);
  const roles = new Map<string, TeamRole>();
  for (const s of data ?? []) {
    const role = roleInScope(scope, s);
    if (role) roles.set(s.id as string, role);
  }
  return roles;
}
