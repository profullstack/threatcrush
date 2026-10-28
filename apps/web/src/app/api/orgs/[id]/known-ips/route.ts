import { NextRequest, NextResponse } from "next/server";
import { getSupabaseAdmin } from "@/lib/supabase";
import { getPrincipal, orgRoleOf } from "@/lib/access";

// GET /api/orgs/[id]/known-ips?days=7 — the org's Known IPs (its never-ban
// allowlist, servers added automatically) with what each one did: attack
// detections from that address or range across the org. Attack traffic from
// a known IP is the choke point: one of our own addresses running exploits.
export async function GET(req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const admin = getSupabaseAdmin();
  const p = await getPrincipal(req, admin);
  if (!p) return NextResponse.json({ error: "Not authenticated" }, { status: 401 });
  const { id: orgId } = await params;
  const role = await orgRoleOf(admin, p, orgId);
  if (!role || role === "guest") return NextResponse.json({ error: "Not authorized" }, { status: 403 });

  const days = Math.min(30, Math.max(1, Number(new URL(req.url).searchParams.get("days")) || 7));
  const [entriesRes, activityRes, serversRes] = await Promise.all([
    admin.from("allowlists").select("id, type, value, label, note, source, server_id, created_at")
      .eq("organization_id", orgId).in("type", ["ip", "cidr"]).order("created_at", { ascending: true }),
    admin.rpc("known_ip_activity", { p_org: orgId, p_days: days }),
    admin.from("servers").select("id, name, last_seen").eq("org_id", orgId),
  ]);
  if (entriesRes.error) return NextResponse.json({ error: "Failed to load known IPs" }, { status: 500 });
  const activity = new Map(((activityRes.data ?? []) as Array<{ entry_id: string }>).map((a) => [a.entry_id, a]));
  const servers = new Map(((serversRes.data ?? []) as Array<{ id: string; name: string; last_seen: string | null }>).map((s) => [s.id, s]));
  const entries = (entriesRes.data ?? []).map((e) => ({
    ...e,
    server: e.server_id ? servers.get(e.server_id) ?? null : null,
    activity: activity.get(e.id) ?? null,
  }));
  return NextResponse.json({ days, entries, can_edit: role === "owner" || role === "admin" });
}
