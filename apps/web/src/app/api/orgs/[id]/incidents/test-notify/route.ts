import { NextResponse, type NextRequest } from "next/server";
import { getSupabaseAdmin } from "@/lib/supabase";
import { getPrincipal, orgRoleOf } from "@/lib/access";
import { sendTestPage } from "@/lib/incidents/notify";
import { isUuid } from "@/lib/incidents/report";

export const runtime = "nodejs";

// POST /api/orgs/[id]/incidents/test-notify { user_id? } — one TEST page (SMS +
// email, per that person's settings) to ONE member, default the caller. Org
// owner/admin only; a person, not an agent key.
export async function POST(req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const admin = getSupabaseAdmin();
  const p = await getPrincipal(req, admin);
  if (!p) return NextResponse.json({ error: "Not authenticated" }, { status: 401 });
  if (p.kind !== "user") return NextResponse.json({ error: "Test pages are sent by a person, not an agent key" }, { status: 403 });
  const { id: orgId } = await params;
  const role = await orgRoleOf(admin, p, orgId);
  if (role !== "owner" && role !== "admin") return NextResponse.json({ error: "Org owners and admins only" }, { status: 403 });
  const body = ((await req.json().catch(() => ({}))) ?? {}) as Record<string, unknown>;
  const userId = body.user_id === undefined ? p.userId : body.user_id;
  if (!isUuid(userId)) return NextResponse.json({ error: "user_id must be a uuid" }, { status: 400 });
  const { data: member } = await admin.from("organization_members").select("user_id").eq("org_id", orgId).eq("user_id", userId).maybeSingle();
  if (!member) return NextResponse.json({ error: "That person is not in this organization" }, { status: 404 });
  const result = await sendTestPage(admin, orgId, userId);
  return NextResponse.json({ user_id: userId, ...result });
}
