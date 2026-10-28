import "server-only";
import type { SupabaseClient } from "@supabase/supabase-js";
import { orgRoleOf, type Principal } from "@/lib/access";

/**
 * The org whose webhooks a caller manages, or why not. Webhooks are org-wide
 * (they carry every server's detections), so it takes what alert destinations
 * take: org owner/admin, or a tc_agent_ key with the admin role (in its own
 * org only). `asked` is ?org_id= / X-Org-Id / an MCP org_id; without it a
 * person gets the first org they administer.
 */
export async function webhookOrgFor(
  admin: SupabaseClient,
  p: Principal,
  asked: string | null | undefined,
): Promise<{ orgId: string } | { error: string; status: 403 | 404 }> {
  if (p.kind === "agent") {
    if (asked && asked !== p.orgId) return { error: "This key belongs to another organization", status: 403 };
    if (p.role !== "admin") return { error: "Managing webhooks needs an admin key", status: 403 };
    return { orgId: p.orgId };
  }
  if (asked) {
    const role = await orgRoleOf(admin, p, asked);
    if (role !== "owner" && role !== "admin") return { error: "Only org owners and admins manage webhooks", status: 403 };
    return { orgId: asked };
  }
  const { data } = await admin
    .from("organization_members")
    .select("org_id, role")
    .eq("user_id", p.userId)
    .in("role", ["owner", "admin"])
    .order("joined_at", { ascending: true })
    .limit(1);
  const orgId = (data as { org_id: string }[] | null)?.[0]?.org_id;
  return orgId ? { orgId } : { error: "No organization you administer: pass org_id", status: 404 };
}
