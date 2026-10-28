import { NextResponse, type NextRequest } from "next/server";
import { getSupabaseAdmin } from "@/lib/supabase";
import { getPrincipal } from "@/lib/access";
import { isUuid } from "@/lib/incidents/report";

export const runtime = "nodejs";

/**
 * The signed-in person's incident paging settings: the channels they get
 * pages on (user_profiles: notification_email / notification_sms, phone and
 * whether it is verified) and, per team they are on, whether that team's
 * incidents page them (team_members.notify_incidents).
 */
export async function GET(req: NextRequest) {
  const admin = getSupabaseAdmin();
  const p = await getPrincipal(req, admin);
  if (!p || p.kind !== "user") return NextResponse.json({ error: "Not authenticated" }, { status: 401 });
  const [{ data: profile }, { data: seats }] = await Promise.all([
    admin.from("user_profiles").select("email, phone, phone_verified, notification_email, notification_sms").eq("id", p.userId).maybeSingle(),
    admin.from("team_members").select("team_id, role, notify_incidents, teams(name, org_id, organizations(name, slug))").eq("user_id", p.userId),
  ]);
  type Seat = { team_id: string; role: string; notify_incidents: boolean | null; teams: unknown };
  const teams = ((seats ?? []) as Seat[]).map((s) => {
    const t = (Array.isArray(s.teams) ? s.teams[0] : s.teams) as { name?: string; org_id?: string; organizations?: unknown } | null;
    const o = (Array.isArray(t?.organizations) ? t?.organizations[0] : t?.organizations) as { name?: string; slug?: string } | null;
    return { team_id: s.team_id, team_name: t?.name ?? null, org_name: o?.name ?? null, org_slug: o?.slug ?? null, role: s.role, notify_incidents: s.notify_incidents !== false };
  });
  const prof = (profile ?? {}) as { email?: string; phone?: string | null; phone_verified?: boolean; notification_email?: boolean; notification_sms?: boolean };
  return NextResponse.json({
    email: prof.email ?? null,
    phone: prof.phone ?? null,
    phone_verified: Boolean(prof.phone_verified),
    notification_email: prof.notification_email !== false,
    notification_sms: prof.notification_sms !== false,
    sms_reachable: Boolean(prof.phone && prof.phone_verified && prof.notification_sms !== false),
    teams,
  });
}

// PATCH { team_id, notify_incidents: boolean } — mute or unmute one team's pages for yourself.
export async function PATCH(req: NextRequest) {
  const admin = getSupabaseAdmin();
  const p = await getPrincipal(req, admin);
  if (!p || p.kind !== "user") return NextResponse.json({ error: "Not authenticated" }, { status: 401 });
  const body = (await req.json().catch(() => null)) as Record<string, unknown> | null;
  if (!body || !isUuid(body.team_id) || typeof body.notify_incidents !== "boolean") {
    return NextResponse.json({ error: "team_id (uuid) and notify_incidents (boolean) are required" }, { status: 400 });
  }
  const { data, error } = await admin
    .from("team_members")
    .update({ notify_incidents: body.notify_incidents })
    .eq("team_id", body.team_id)
    .eq("user_id", p.userId)
    .select("team_id, notify_incidents");
  if (error) return NextResponse.json({ error: "Failed to save" }, { status: 500 });
  if (!data || data.length === 0) return NextResponse.json({ error: "You are not on that team" }, { status: 404 });
  return NextResponse.json({ team_id: body.team_id, notify_incidents: body.notify_incidents });
}
