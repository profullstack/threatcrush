import { NextRequest, NextResponse } from "next/server";
import { getSupabaseAdmin } from "@/lib/supabase";

function slugify(name: string): string {
  return name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "")
    .slice(0, 64);
}

// GET /api/orgs/[id] — Get organization details
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

    const { id } = await params;

    const { data: membership, error: memberError } = await getSupabaseAdmin()
      .from("organization_members")
      .select("role")
      .eq("org_id", id)
      .eq("user_id", user.id)
      .single();

    if (memberError || !membership) {
      return NextResponse.json({ error: "Organization not found or access denied" }, { status: 404 });
    }

    const { data: org, error: orgError } = await getSupabaseAdmin()
      .from("organizations")
      .select("*")
      .eq("id", id)
      .single();

    if (orgError || !org) {
      return NextResponse.json({ error: "Organization not found" }, { status: 404 });
    }

    // Get member count
    const { count: memberCount } = await getSupabaseAdmin()
      .from("organization_members")
      .select("*", { count: "exact", head: true })
      .eq("org_id", id);

    // Get server count
    const { count: serverCount } = await getSupabaseAdmin()
      .from("servers")
      .select("*", { count: "exact", head: true })
      .eq("org_id", id);

    return NextResponse.json({
      organization: {
        ...org,
        user_role: membership.role,
        member_count: memberCount || 0,
        server_count: serverCount || 0,
      },
    });
  } catch (err) {
    console.error("Get organization error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}

// PATCH /api/orgs/[id] — Update organization
export async function PATCH(
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

    const { id } = await params;

    // Check user is admin/owner
    const { data: membership, error: memberError } = await getSupabaseAdmin()
      .from("organization_members")
      .select("role")
      .eq("org_id", id)
      .eq("user_id", user.id)
      .single();

    if (memberError || !membership || !["owner", "admin"].includes(membership.role)) {
      return NextResponse.json({ error: "Not authorized to update this organization" }, { status: 403 });
    }

    const body = await req.json();
    const updates: Record<string, unknown> = {};

    if (body.name) {
      if (body.name.trim().length < 2) {
        return NextResponse.json({ error: "Organization name must be at least 2 characters" }, { status: 400 });
      }
      updates.name = body.name.trim();
    }

    if (body.slug) {
      if (!/^[a-z0-9-]+$/.test(body.slug)) {
        return NextResponse.json({ error: "Slug can only contain lowercase letters, numbers, and hyphens" }, { status: 400 });
      }
      updates.slug = body.slug;
    } else if (body.name) {
      updates.slug = slugify(body.name);
    }

    if (Object.keys(updates).length === 0) {
      return NextResponse.json({ error: "No valid fields to update" }, { status: 400 });
    }

    const { data: updatedOrg, error: updateError } = await getSupabaseAdmin()
      .from("organizations")
      .update(updates)
      .eq("id", id)
      .select()
      .single();

    if (updateError) {
      if (updateError.code === "23505") {
        return NextResponse.json({ error: "An organization with this slug already exists" }, { status: 409 });
      }
      console.error("Failed to update organization:", updateError);
      return NextResponse.json({ error: "Failed to update organization" }, { status: 500 });
    }

    return NextResponse.json({ organization: updatedOrg });
  } catch (err) {
    console.error("Update organization error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}

// DELETE /api/orgs/[id] — Delete organization
export async function DELETE(
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

    const { id } = await params;

    // Check user is creator
    const { data: org, error: orgError } = await getSupabaseAdmin()
      .from("organizations")
      .select("created_by")
      .eq("id", id)
      .single();

    if (orgError || !org || org.created_by !== user.id) {
      return NextResponse.json({ error: "Not authorized to delete this organization" }, { status: 403 });
    }

    const { error: deleteError } = await getSupabaseAdmin()
      .from("organizations")
      .delete()
      .eq("id", id);

    if (deleteError) {
      console.error("Failed to delete organization:", deleteError);
      return NextResponse.json({ error: "Failed to delete organization" }, { status: 500 });
    }

    return NextResponse.json({ success: true });
  } catch (err) {
    console.error("Delete organization error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
