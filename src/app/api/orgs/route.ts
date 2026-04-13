import { NextRequest, NextResponse } from "next/server";
import { getSupabaseAdmin } from "@/lib/supabase";

function slugify(name: string): string {
  return name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "")
    .slice(0, 64);
}

// POST /api/orgs — Create a new organization
export async function POST(req: NextRequest) {
  try {
    const authHeader = req.headers.get("authorization");
    const token = authHeader?.replace("Bearer ", "");

    if (!token) {
      return NextResponse.json({ error: "Not authenticated" }, { status: 401 });
    }

    // Get authenticated user
    const { data: { user } } = await getSupabaseAdmin().auth.getUser(token);
    if (!user) {
      return NextResponse.json({ error: "Not authenticated" }, { status: 401 });
    }

    const body = await req.json();
    const { name } = body as { name: string };

    if (!name || name.trim().length < 2) {
      return NextResponse.json({ error: "Organization name must be at least 2 characters" }, { status: 400 });
    }

    const slug = body.slug || slugify(name);
    if (!/^[a-z0-9-]+$/.test(slug)) {
      return NextResponse.json({ error: "Slug can only contain lowercase letters, numbers, and hyphens" }, { status: 400 });
    }

    const { data: org, error } = await getSupabaseAdmin()
      .from("organizations")
      .insert({
        name: name.trim(),
        slug,
        created_by: user.id,
      })
      .select()
      .single();

    if (error) {
      if (error.code === "23505") { // unique violation
        return NextResponse.json({ error: "An organization with this slug already exists" }, { status: 409 });
      }
      console.error("Failed to create organization:", error);
      return NextResponse.json({ error: "Failed to create organization" }, { status: 500 });
    }

    return NextResponse.json({ organization: org }, { status: 201 });
  } catch (err) {
    console.error("Create organization error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}

// GET /api/orgs — List user's organizations
export async function GET(req: NextRequest) {
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

    const { data: memberships, error } = await getSupabaseAdmin()
      .from("organization_members")
      .select(`
        role,
        organizations (
          id,
          name,
          slug,
          created_by,
          created_at
        )
      `)
      .eq("user_id", user.id)
      .order("joined_at", { ascending: false });

    if (error) {
      console.error("Failed to fetch organizations:", error);
      return NextResponse.json({ error: "Failed to fetch organizations" }, { status: 500 });
    }

    const organizations = (memberships || [])
      .filter(m => m.organizations)
      .map(m => ({
        ...m.organizations,
        user_role: m.role,
      }));

    return NextResponse.json({ organizations });
  } catch (err) {
    console.error("List organizations error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
