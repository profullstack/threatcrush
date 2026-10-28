import type { SupabaseClient } from "@supabase/supabase-js";
import { orgRoleOf, type OrgRole, type Principal } from "@/lib/access";

/**
 * Who may see and change an org's OpenDevice inventory (fleet_inventories).
 * Costs are org-wide rather than per fleet, so: owner/admin read + write,
 * member read, guest nothing, agent keys nothing (the inventory belongs to
 * people; daemons and CI never need it). Mirrors the table's RLS policies.
 */

export const INVENTORY_MAX_BYTES = 1024 * 1024;

export function canReadInventory(role: OrgRole | null): boolean {
  return role === "owner" || role === "admin" || role === "member";
}

export function canWriteInventory(role: OrgRole | null): boolean {
  return role === "owner" || role === "admin";
}

/** The subset of `orgIds` whose inventory the principal may read. */
export async function inventoryOrgIds(admin: SupabaseClient, p: Principal, orgIds: string[]): Promise<string[]> {
  if (p.kind !== "user" || orgIds.length === 0) return [];
  const { data } = await admin
    .from("organization_members")
    .select("org_id, role")
    .eq("user_id", p.userId)
    .in("org_id", orgIds);
  return (data ?? []).filter((m) => canReadInventory(m.role as OrgRole)).map((m) => m.org_id as string);
}

/** The principal's role in one org, for the inventory routes. */
export async function inventoryRoleOf(admin: SupabaseClient, p: Principal, orgId: string): Promise<OrgRole | null> {
  return orgRoleOf(admin, p, orgId);
}
