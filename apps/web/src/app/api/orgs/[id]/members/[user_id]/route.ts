import { NextRequest, NextResponse } from "next/server";
import { getSupabaseAdmin } from "@/lib/supabase";

// PATCH /api/orgs/[id]/members/[user_id] — Update member role
export async function PATCH(
  req: NextRequest,
  { params }: { params: Promise<{ id: string; user_id: string }> }
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

    const { id: orgId, user_id: targetUserId } = await params;

    // Check requester is owner (only owners can change roles)
    const { data: membership } = await getSupabaseAdmin()
      .from("organization_members")
      .select("role")
      .eq("org_id", orgId)
      .eq("user_id", user.id)
      .single();

    if (!membership || membership.role !== "owner") {
      return NextResponse.json({ error: "Only organization owners can change member roles" }, { status: 403 });
    }

    const body = await req.json();
    const { role } = body as { role: string };

    if (!["owner", "admin", "member"].includes(role)) {
      return NextResponse.json({ error: "Invalid role" }, { status: 400 });
    }

    const { data: updatedMember, error: updateError } = await getSupabaseAdmin()
      .from("organization_members")
      .update({ role })
      .eq("org_id", orgId)
      .eq("user_id", targetUserId)
      .select(`
        role,
        user_profiles (
          id,
          email,
          display_name
        )
      `)
      .single();

    if (updateError || !updatedMember) {
      return NextResponse.json({ error: "Member not found" }, { status: 404 });
    }

    return NextResponse.json({
      member: {
        id: ((updatedMember as Record<string, unknown>).user_profiles as Record<string, unknown> | null)?.id as string,
        email: ((updatedMember as Record<string, unknown>).user_profiles as Record<string, unknown> | null)?.email as string,
        display_name: ((updatedMember as Record<string, unknown>).user_profiles as Record<string, unknown> | null)?.display_name as string | null,
        role: (updatedMember as Record<string, unknown>).role as string,
      },
    });
  } catch (err) {
    console.error("Update member error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}

// DELETE /api/orgs/[id]/members/[user_id] — Remove member
export async function DELETE(
  req: NextRequest,
  { params }: { params: Promise<{ id: string; user_id: string }> }
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

    const { id: orgId, user_id: targetUserId } = await params;

    // Can't remove yourself
    if (targetUserId === user.id) {
      return NextResponse.json({ error: "You cannot remove yourself from an organization. Transfer ownership first or delete the organization." }, { status: 400 });
    }

    // Check requester is admin/owner
    const { data: membership } = await getSupabaseAdmin()
      .from("organization_members")
      .select("role")
      .eq("org_id", orgId)
      .eq("user_id", user.id)
      .single();

    if (!membership || !["owner", "admin"].includes(membership.role)) {
      return NextResponse.json({ error: "Not authorized to remove members" }, { status: 403 });
    }

    const { error: deleteError } = await getSupabaseAdmin()
      .from("organization_members")
      .delete()
      .eq("org_id", orgId)
      .eq("user_id", targetUserId);

    if (deleteError) {
      console.error("Failed to remove member:", deleteError);
      return NextResponse.json({ error: "Failed to remove member" }, { status: 500 });
    }

    return NextResponse.json({ success: true });
  } catch (err) {
    console.error("Remove member error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
