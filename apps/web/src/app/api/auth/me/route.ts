import { NextRequest, NextResponse } from "next/server";
import type { User } from "@supabase/supabase-js";
import { createSupabaseAuthClient, getSupabaseClient, getSupabaseAdmin } from "@/lib/supabase";

/**
 * The caller's Supabase user, from the bearer token only. No getSession()
 * fallback: the anon client is a process-wide singleton, so "its" session is
 * never the caller's.
 */
async function requestUser(req: NextRequest): Promise<User | null> {
  const token = req.headers.get("authorization")?.replace(/^Bearer\s+/i, "");
  if (!token) return null;
  const { data: { user } } = await getSupabaseClient().auth.getUser(token);
  return user ?? null;
}

/** True when the account signs in with email + password (vs. OAuth only). */
function hasPasswordLogin(user: User): boolean {
  const providers = user.app_metadata?.providers;
  if (Array.isArray(providers)) return providers.includes("email");
  return user.app_metadata?.provider === "email";
}

export async function GET(req: NextRequest) {
  try {
    const user = await requestUser(req);
    if (!user) {
      return NextResponse.json({ error: "Not authenticated" }, { status: 401 });
    }

    const admin = getSupabaseAdmin();
    const { data: profile, error } = await admin
      .from("user_profiles")
      .select("*")
      .eq("id", user.id)
      .single();

    if (error || !profile) {
      return NextResponse.json({ error: "Profile not found" }, { status: 404 });
    }

    return NextResponse.json({ profile, has_password: hasPasswordLogin(user) });
  } catch (err) {
    console.error("Me error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}

export async function PATCH(req: NextRequest) {
  try {
    const user = await requestUser(req);
    if (!user) {
      return NextResponse.json({ error: "Not authenticated" }, { status: 401 });
    }

    const body = await req.json();
    const allowedFields = [
      "display_name",
      "wallet_address",
      "payout_crypto",
      "notification_email",
      "notification_sms",
      "notification_webhook_url",
      "current_org_id",
    ];

    const updates: Record<string, unknown> = { updated_at: new Date().toISOString() };
    for (const field of allowedFields) {
      if (field in body) {
        updates[field] = body[field];
      }
    }

    const admin = getSupabaseAdmin();
    const { data: profile, error } = await admin
      .from("user_profiles")
      .update(updates)
      .eq("id", user.id)
      .select("*")
      .single();

    if (error) {
      return NextResponse.json({ error: "Failed to update profile" }, { status: 500 });
    }

    return NextResponse.json({ profile });
  } catch (err) {
    console.error("Profile update error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}

/**
 * Checks a password with a GoTrue password grant, on a throwaway client so the
 * session it mints never lands on a shared one.
 */
async function passwordMatches(email: string, password: string): Promise<boolean> {
  const { error } = await createSupabaseAuthClient().auth.signInWithPassword({ email, password });
  if (!error) return true;
  if (error.status === 400) return false;
  throw error;
}

type OrgRow = { id: string; name: string; slug: string; created_by: string | null };
type MemberRow = { org_id: string; user_id: string; role: string; joined_at: string | null };

type DeletionPlan = {
  /** Orgs nobody else belongs to: deleted with the account. */
  deleteOrgIds: string[];
  /** Shared orgs the user created: created_by moves to a remaining member. */
  reassign: { orgId: string; to: string }[];
  /** Shared orgs where the user is the only owner: deletion is refused. */
  blocked: { id: string; name: string; slug: string }[];
};

async function planOrgCleanup(userId: string): Promise<DeletionPlan> {
  const admin = getSupabaseAdmin();

  const [memberships, created] = await Promise.all([
    admin.from("organization_members").select("org_id").eq("user_id", userId),
    admin.from("organizations").select("id").eq("created_by", userId),
  ]);
  if (memberships.error) throw memberships.error;
  if (created.error) throw created.error;

  const orgIds = [
    ...new Set([
      ...(memberships.data ?? []).map((m: { org_id: string }) => m.org_id),
      ...(created.data ?? []).map((o: { id: string }) => o.id),
    ]),
  ];
  const plan: DeletionPlan = { deleteOrgIds: [], reassign: [], blocked: [] };
  if (orgIds.length === 0) return plan;

  const [orgs, members] = await Promise.all([
    admin.from("organizations").select("id, name, slug, created_by").in("id", orgIds),
    admin.from("organization_members").select("org_id, user_id, role, joined_at").in("org_id", orgIds),
  ]);
  if (orgs.error) throw orgs.error;
  if (members.error) throw members.error;

  for (const org of (orgs.data ?? []) as OrgRow[]) {
    const orgMembers = ((members.data ?? []) as MemberRow[]).filter((m) => m.org_id === org.id);
    const others = orgMembers
      .filter((m) => m.user_id !== userId)
      .sort((a, b) => (a.joined_at ?? "").localeCompare(b.joined_at ?? ""));
    const mine = orgMembers.find((m) => m.user_id === userId);

    if (others.length === 0) {
      plan.deleteOrgIds.push(org.id);
      continue;
    }

    const otherOwners = others.filter((m) => m.role === "owner");
    if (mine?.role === "owner" && otherOwners.length === 0) {
      plan.blocked.push({ id: org.id, name: org.name, slug: org.slug });
      continue;
    }

    if (org.created_by === userId) {
      plan.reassign.push({ orgId: org.id, to: (otherOwners[0] ?? others[0]).user_id });
    }
  }

  return plan;
}

/**
 * DELETE /api/auth/me — permanently delete the caller's account.
 *
 * Body: `{ password }` for accounts that sign in with a password, otherwise
 * (OAuth-only accounts) `{ confirm_email }` equal to the account email.
 *
 * Refused (409) while the caller is the only owner of an org that has other
 * members. Orgs only the caller belongs to are deleted (servers, detections and
 * the rest cascade); shared orgs they created are handed to a remaining owner.
 * Deleting the GoTrue user cascades to user_profiles, org memberships and push
 * subscriptions.
 */
export async function DELETE(req: NextRequest) {
  try {
    const user = await requestUser(req);
    if (!user) {
      return NextResponse.json({ error: "Not authenticated" }, { status: 401 });
    }

    let body: { password?: unknown; confirm_email?: unknown };
    try {
      const parsed: unknown = await req.json();
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
        return NextResponse.json({ error: "Invalid JSON body" }, { status: 400 });
      }
      body = parsed as typeof body;
    } catch {
      return NextResponse.json({ error: "Invalid JSON body" }, { status: 400 });
    }

    const usesPassword = hasPasswordLogin(user);
    if (usesPassword) {
      if (typeof body.password !== "string" || !body.password) {
        return NextResponse.json(
          { error: "Enter your password to delete your account" },
          { status: 400 },
        );
      }
    } else {
      const typed = typeof body.confirm_email === "string" ? body.confirm_email.trim().toLowerCase() : "";
      if (!user.email || typed !== user.email.toLowerCase()) {
        return NextResponse.json(
          { error: "Type your account email to confirm deletion" },
          { status: 400 },
        );
      }
    }

    // Refuse before checking the password, so a refusal never mints a session.
    const plan = await planOrgCleanup(user.id);
    if (plan.blocked.length > 0) {
      const names = plan.blocked.map((o) => o.name).join(", ");
      return NextResponse.json(
        {
          error:
            `You are the only owner of ${plan.blocked.length === 1 ? "an organization" : "organizations"} ` +
            `that other people belong to: ${names}. Make another member an owner or delete the ` +
            `organization, then try again.`,
          organizations: plan.blocked,
        },
        { status: 409 },
      );
    }

    if (usesPassword && !(await passwordMatches(user.email ?? "", body.password as string))) {
      return NextResponse.json({ error: "Incorrect password" }, { status: 403 });
    }

    const admin = getSupabaseAdmin();

    for (const { orgId, to } of plan.reassign) {
      const { error } = await admin
        .from("organizations")
        .update({ created_by: to })
        .eq("id", orgId)
        .eq("created_by", user.id);
      if (error) throw error;
    }

    if (plan.deleteOrgIds.length > 0) {
      const { error } = await admin.from("organizations").delete().in("id", plan.deleteOrgIds);
      if (error) throw error;
    }

    const { error: deleteError } = await admin.auth.admin.deleteUser(user.id);
    if (deleteError) {
      console.error("Account deletion failed:", deleteError);
      return NextResponse.json({ error: "Failed to delete account" }, { status: 500 });
    }

    return NextResponse.json({ success: true });
  } catch (err) {
    console.error("Account deletion error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
