import { NextRequest, NextResponse } from "next/server";
import { getSupabaseAdmin } from "@/lib/supabase";
import { createOrgInvite, type OrgRole } from "@/lib/invites";

// GET /api/orgs/[id]/members — List organization members
export async function GET(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const authHeader = req.headers.get("authorization");
    const token = authHeader?.replace("Bearer ", "");

    if (!token) {
      return NextResponse.json({ error: "Not authenticated" }, { status: 401 });
    }

    const { data: { user } } = await getSupabaseAdmin().auth.getUser(token);
    if (!user) {
      return NextResponse.json({ error: "Not authenticated" }, { status: 401 });
    }

    const { id: orgId } = await params;

    // Check membership
    const { data: membership } = await getSupabaseAdmin()
      .from("organization_members")
      .select("role")
      .eq("org_id", orgId)
      .eq("user_id", user.id)
      .single();

    if (!membership) {
      return NextResponse.json({ error: "Not a member of this organization" }, { status: 403 });
    }

    const { data: members, error } = await getSupabaseAdmin()
      .from("organization_members")
      .select(`
        id,
        role,
        joined_at,
        user_profiles (
          id,
          email,
          display_name,
          avatar_url
        )
      `)
      .eq("org_id", orgId)
      .order("joined_at", { ascending: true });

    if (error) {
      console.error("Failed to fetch members:", error);
      return NextResponse.json({ error: "Failed to fetch members" }, { status: 500 });
    }

    const formattedMembers = (members || []).map((m: Record<string, unknown>) => {
      const up = m.user_profiles as Record<string, unknown> | null;
      return {
        id: up?.id as string,
        email: up?.email as string,
        display_name: up?.display_name as string | null,
        avatar_url: up?.avatar_url as string | null,
        role: m.role as string,
        joined_at: m.joined_at as string,
      };
    });

    return NextResponse.json({ members: formattedMembers });
  } catch (err) {
    console.error("List members error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}

// POST /api/orgs/[id]/members — Add/invite member
export async function POST(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const authHeader = req.headers.get("authorization");
    const token = authHeader?.replace("Bearer ", "");

    if (!token) {
      return NextResponse.json({ error: "Not authenticated" }, { status: 401 });
    }

    const { data: { user } } = await getSupabaseAdmin().auth.getUser(token);
    if (!user) {
      return NextResponse.json({ error: "Not authenticated" }, { status: 401 });
    }

    const { id: orgId } = await params;

    // Check user is admin/owner
    const { data: membership } = await getSupabaseAdmin()
      .from("organization_members")
      .select("role")
      .eq("org_id", orgId)
      .eq("user_id", user.id)
      .single();

    if (!membership || !["owner", "admin"].includes(membership.role)) {
      return NextResponse.json({ error: "Not authorized to add members" }, { status: 403 });
    }

    const body = await req.json();
    const { email, role = "member" } = body as { email: string; role?: string };

    if (!email) {
      return NextResponse.json({ error: "Email is required" }, { status: 400 });
    }

    if (!["owner", "admin", "member"].includes(role)) {
      return NextResponse.json({ error: "Invalid role" }, { status: 400 });
    }

    // TC-07: an admin could grant `owner` to a second account they controlled
    // and then remove the real owner. Only an owner may create another owner.
    if (role === "owner" && membership.role !== "owner") {
      return NextResponse.json(
        { error: "Only an owner can assign the owner role" },
        { status: 403 },
      );
    }

    // Find user by email
    const normalizedEmail = email.toLowerCase().trim();
    const { data: targetUser } = await getSupabaseAdmin()
      .from("user_profiles")
      .select("id, email")
      .eq("email", normalizedEmail)
      .maybeSingle();

    if (targetUser) {
      const { data: existingMember } = await getSupabaseAdmin()
        .from("organization_members")
        .select("id")
        .eq("org_id", orgId)
        .eq("user_id", targetUser.id)
        .maybeSingle();
      if (existingMember) {
        return NextResponse.json({ error: "User is already a member of this organization" }, { status: 409 });
      }
    }

    // Everyone joins through an invite they accept, account or not. Adding an
    // existing account directly let anyone put any ThreatCrush user in an org
    // of theirs without asking, and a member's daemon works for every org its
    // user belongs to (property runs), so that was a way onto their machines.
    const { data: org } = await getSupabaseAdmin().from("organizations").select("name").eq("id", orgId).maybeSingle();
    const invite = await createOrgInvite(getSupabaseAdmin(), {
      orgId,
      email: normalizedEmail,
      role: role as OrgRole,
      invitedBy: user.id,
      inviterEmail: user.email ?? null,
      orgName: org?.name ?? "your organization",
    });
    if (!invite) return NextResponse.json({ error: "Could not create the invite" }, { status: 500 });
    return NextResponse.json({ invited: true, email: normalizedEmail, url: invite.url, emailed: invite.emailed }, { status: 201 });
  } catch (err) {
    console.error("Add member error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
