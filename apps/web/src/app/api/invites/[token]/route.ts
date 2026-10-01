import { NextRequest, NextResponse } from "next/server";
import { getSupabaseAdmin } from "@/lib/supabase";
import { getPrincipal, hashSecret, isTeamRole, type TeamRole } from "@/lib/access";
import { fail } from "@/lib/teams";

type Params = { params: Promise<{ token: string }> };
const TOKEN = /^[A-Za-z0-9_-]{43}$/;
const RANK: Record<TeamRole, number> = { read: 1, write: 2, admin: 3 };

async function findInvite(token: string) {
  if (!TOKEN.test(token)) return null;
  const { data } = await getSupabaseAdmin()
    .from("team_invites")
    .select("id, org_id, team_id, email, role, expires_at, accepted_at, revoked_at, organizations(name), teams(name)")
    .eq("token_hash", hashSecret(token))
    .maybeSingle();
  return data;
}

function one<T>(v: T | T[] | null | undefined): T | null {
  return Array.isArray(v) ? v[0] ?? null : v ?? null;
}

// GET /api/invites/[token] — what the invite is for, so the accept page can
// say so before anyone signs in. Works without auth; reveals nothing else.
export async function GET(_req: NextRequest, { params }: Params) {
  try {
    const invite = await findInvite((await params).token);
    if (!invite) return fail(404, "This invite link is not valid");
    const status = invite.accepted_at ? "accepted" : invite.revoked_at ? "revoked"
      : Date.parse(invite.expires_at) <= Date.now() ? "expired" : "pending";
    return NextResponse.json({
      invite: {
        org_name: one(invite.organizations as { name: string } | { name: string }[] | null)?.name ?? null,
        team_name: one(invite.teams as { name: string } | { name: string }[] | null)?.name ?? null,
        email: invite.email,
        role: invite.role,
        expires_at: invite.expires_at,
        status,
      },
    });
  } catch (err) {
    console.error("Invite preview error:", err);
    return fail(500, "Internal server error");
  }
}

// POST /api/invites/[token] — the signed-in user accepts. The claim is one
// conditional update, so a link can never be used twice.
export async function POST(req: NextRequest, { params }: Params) {
  try {
    const admin = getSupabaseAdmin();
    const p = await getPrincipal(req, admin);
    if (!p) return fail(401, "Sign in to accept this invite");
    if (p.kind !== "user") return fail(403, "Agent keys cannot accept invites");

    const invite = await findInvite((await params).token);
    if (!invite) return fail(404, "This invite link is not valid");

    const { data: claimed } = await admin
      .from("team_invites")
      .update({ accepted_at: new Date().toISOString(), accepted_by: p.userId })
      .eq("id", invite.id)
      .is("accepted_at", null)
      .is("revoked_at", null)
      .gt("expires_at", new Date().toISOString())
      .select("id")
      .maybeSingle();
    if (!claimed) return fail(410, "This invite has expired or was already used");

    // Into the organization as a guest, unless already in it.
    const { data: membership } = await admin
      .from("organization_members")
      .select("role")
      .eq("org_id", invite.org_id)
      .eq("user_id", p.userId)
      .maybeSingle();
    if (!membership) {
      await admin.from("organization_members").insert({ org_id: invite.org_id, user_id: p.userId, role: "guest" });
    }

    // Onto the team, never lowering a role they already have there.
    const role = isTeamRole(invite.role) ? invite.role : "read";
    const { data: seat } = await admin
      .from("team_members")
      .select("role")
      .eq("team_id", invite.team_id)
      .eq("user_id", p.userId)
      .maybeSingle();
    const keep = seat && isTeamRole(seat.role) && RANK[seat.role] > RANK[role] ? seat.role : role;
    await admin
      .from("team_members")
      .upsert({ team_id: invite.team_id, user_id: p.userId, role: keep }, { onConflict: "team_id,user_id" });

    const { data: org } = await admin.from("organizations").select("slug").eq("id", invite.org_id).maybeSingle();
    return NextResponse.json({ accepted: true, org_slug: org?.slug ?? null, team_id: invite.team_id, role: keep });
  } catch (err) {
    console.error("Accept invite error:", err);
    return fail(500, "Internal server error");
  }
}
