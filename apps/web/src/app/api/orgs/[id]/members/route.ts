import { NextRequest, NextResponse } from "next/server";
import { getSupabaseAdmin } from "@/lib/supabase";

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

    // Find user by email
    const { data: targetUser, error: userError } = await getSupabaseAdmin()
      .from("user_profiles")
      .select("id, email")
      .eq("email", email.toLowerCase())
      .single();

    if (userError || !targetUser) {
      return NextResponse.json({ error: "User with this email not found. They need to sign up first." }, { status: 404 });
    }

    // Check if already a member
    const { data: existingMember } = await getSupabaseAdmin()
      .from("organization_members")
      .select("id")
      .eq("org_id", orgId)
      .eq("user_id", targetUser.id)
      .single();

    if (existingMember) {
      return NextResponse.json({ error: "User is already a member of this organization" }, { status: 409 });
    }

    // Add member
    const { data: newMember, error: insertError } = await getSupabaseAdmin()
      .from("organization_members")
      .insert({
        org_id: orgId,
        user_id: targetUser.id,
        role,
      })
      .select(`
        role,
        joined_at,
        user_profiles (
          id,
          email,
          display_name,
          avatar_url
        )
      `)
      .single();

    if (insertError) {
      console.error("Failed to add member:", insertError);
      return NextResponse.json({ error: "Failed to add member" }, { status: 500 });
    }

    return NextResponse.json({
      member: {
        id: ((newMember as Record<string, unknown>).user_profiles as Record<string, unknown> | null)?.id as string,
        email: ((newMember as Record<string, unknown>).user_profiles as Record<string, unknown> | null)?.email as string,
        display_name: ((newMember as Record<string, unknown>).user_profiles as Record<string, unknown> | null)?.display_name as string | null,
        avatar_url: ((newMember as Record<string, unknown>).user_profiles as Record<string, unknown> | null)?.avatar_url as string | null,
        role: (newMember as Record<string, unknown>).role as string,
        joined_at: (newMember as Record<string, unknown>).joined_at as string,
      },
    }, { status: 201 });
  } catch (err) {
    console.error("Add member error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
