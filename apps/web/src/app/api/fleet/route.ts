import { NextRequest, NextResponse } from "next/server";
import { unauthorized } from "@/lib/api-auth";
import { getSupabaseAdmin } from "@/lib/supabase";
import { getPrincipal, serverScopeIn, visibleIn } from "@/lib/access";
import { buildFleet, type InventoryRow, type PatchFindingRow } from "@/lib/fleet";
import { inventoryOrgIds } from "@/lib/fleet-inventory";
import { latestPublishedVersion } from "@/lib/latest-release";

// GET /api/fleet — every ThreatCrush install the caller can see, across every
// organization they belong to (an agent key: its team's fleets), with a
// summary for the dashboard. Orgs with an OpenDevice inventory add every
// machine in it: matched servers carry their device + monthly cost, devices
// with no daemon come back as extra rows (connection "no-agent"), and the
// summary gains the monthly total. Inventories are for owners, admins and
// members (not guests or agent keys): costs are org-wide.
export async function GET(req: NextRequest) {
  try {
    const admin = getSupabaseAdmin();
    const p = await getPrincipal(req, admin);
    if (!p) return unauthorized();

    let orgIds: string[];
    if (p.kind === "agent") {
      orgIds = [p.orgId];
    } else {
      const { data: memberships, error: memberError } = await admin
        .from("organization_members")
        .select("org_id")
        .eq("user_id", p.userId);
      if (memberError) {
        console.error("Fleet: failed to load memberships:", memberError);
        return NextResponse.json({ error: "Failed to load fleet" }, { status: 500 });
      }
      orgIds = (memberships ?? []).map((m) => m.org_id as string);
    }

    const orgs = new Map<string, { name: string; slug: string }>();
    if (orgIds.length === 0) return NextResponse.json(buildFleet([], orgs));

    const [{ data: orgRows }, { data: rows, error }, { data: fleets }] = await Promise.all([
      admin.from("organizations").select("id, name, slug").in("id", orgIds),
      admin
        .from("servers")
        .select("id, name, hostname, ip_address, public_ip, org_id, fleet_id, last_seen, threatcrushd_version, config, config_saved_at, created_at")
        .in("org_id", orgIds),
      admin.from("fleets").select("id, name").in("org_id", orgIds),
    ]);
    if (error) {
      console.error("Fleet: failed to load servers:", error);
      return NextResponse.json({ error: "Failed to load fleet" }, { status: 500 });
    }
    for (const o of orgRows ?? []) orgs.set(o.id, { name: o.name, slug: o.slug });

    const visible = [];
    for (const orgId of orgIds) {
      const scope = await serverScopeIn(admin, p, orgId);
      if (!scope) continue;
      visible.push(...visibleIn(scope, (rows ?? []).filter((r) => r.org_id === orgId)));
    }

    // Patch status rides on each server's `os-patches` finding. A failure here
    // (say the details column is not migrated yet) costs the column, not the page.
    let patchRows: PatchFindingRow[] = [];
    if (visible.length > 0) {
      const { data, error: patchError } = await admin
        .from("hardening_findings")
        .select("server_id, status, observed_at, details")
        .eq("finding_key", "os-patches")
        .in("server_id", visible.map((s) => s.id));
      if (patchError) console.error("Fleet: failed to load patch status:", patchError);
      else patchRows = (data ?? []) as PatchFindingRow[];
    }

    // The inventory half. A failure (table not migrated yet) costs the extra
    // rows and the cost column, not the page.
    let inventories: InventoryRow[] = [];
    const invOrgs = await inventoryOrgIds(admin, p, orgIds);
    if (invOrgs.length > 0) {
      const { data, error: invError } = await admin
        .from("fleet_inventories")
        .select("org_id, document, updated_at")
        .in("org_id", invOrgs);
      if (invError) console.error("Fleet: failed to load inventories:", invError);
      else inventories = (data ?? []) as InventoryRow[];
    }
    const visibleIds = new Set(visible.map((s) => s.id));
    const hidden = (rows ?? []).filter((r) => !visibleIds.has(r.id) && invOrgs.includes(r.org_id));

    const fleetNames = new Map((fleets ?? []).map((f) => [f.id as string, f.name as string]));
    return NextResponse.json(buildFleet(visible, orgs, Date.now(), fleetNames, patchRows, inventories, hidden, await latestPublishedVersion()));
  } catch (err) {
    console.error("Fleet error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
