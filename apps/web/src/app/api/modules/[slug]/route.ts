import { NextRequest, NextResponse } from "next/server";
import { getSupabaseAdmin } from "@/lib/supabase";

type RouteContext = { params: Promise<{ slug: string }> };

/**
 * GET /api/modules/[slug]
 * Module details with versions and reviews.
 */
export async function GET(
  _request: NextRequest,
  context: RouteContext
) {
  const { slug } = await context.params;
  const sb = getSupabaseAdmin();

  const { data: mod, error } = await sb
    .from("modules")
    .select("*")
    .eq("slug", slug)
    .eq("published", true)
    .single();

  if (error || !mod) {
    return NextResponse.json({ error: "Module not found" }, { status: 404 });
  }

  // Fetch versions
  const { data: versions } = await sb
    .from("module_versions")
    .select("*")
    .eq("module_id", mod.id)
    .order("created_at", { ascending: false });

  // Fetch reviews
  const { data: reviews } = await sb
    .from("module_reviews")
    .select("*")
    .eq("module_id", mod.id)
    .order("created_at", { ascending: false })
    .limit(20);

  return NextResponse.json({
    module: mod,
    versions: versions || [],
    reviews: reviews || [],
  });
}

/**
 * PATCH /api/modules/[slug]
 * Update a module.
 */
export async function PATCH(
  request: NextRequest,
  context: RouteContext
) {
  const { slug } = await context.params;
  let body: Record<string, unknown>;
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }

  const author_email = body.author_email as string;
  if (!author_email) {
    return NextResponse.json({ error: "author_email is required" }, { status: 400 });
  }

  const sb = getSupabaseAdmin();

  // Verify ownership
  const { data: existing } = await sb
    .from("modules")
    .select("id, author_email")
    .eq("slug", slug)
    .single();

  if (!existing) {
    return NextResponse.json({ error: "Module not found" }, { status: 404 });
  }
  if (existing.author_email !== author_email) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 403 });
  }

  // Only allow updating certain fields
  const allowedFields = [
    "display_name", "description", "long_description", "homepage_url", "git_url",
    "logo_url", "banner_url", "screenshot_url", "license", "pricing_type",
    "price_usd", "category", "tags", "keywords", "version",
    "min_threatcrush_version", "os_support", "capabilities",
  ];

  const updates: Record<string, unknown> = { updated_at: new Date().toISOString() };
  for (const field of allowedFields) {
    if (field in body) {
      updates[field] = body[field];
    }
  }

  const { data, error } = await sb
    .from("modules")
    .update(updates)
    .eq("id", existing.id)
    .select()
    .single();

  if (error) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }

  return NextResponse.json({ module: data });
}

/**
 * DELETE /api/modules/[slug]
 * Remove a module.
 */
export async function DELETE(
  request: NextRequest,
  context: RouteContext
) {
  const { slug } = await context.params;
  const { searchParams } = new URL(request.url);
  const author_email = searchParams.get("author_email");

  if (!author_email) {
    return NextResponse.json({ error: "author_email is required" }, { status: 400 });
  }

  const sb = getSupabaseAdmin();

  const { data: existing } = await sb
    .from("modules")
    .select("id, author_email")
    .eq("slug", slug)
    .single();

  if (!existing) {
    return NextResponse.json({ error: "Module not found" }, { status: 404 });
  }
  if (existing.author_email !== author_email) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 403 });
  }

  const { error } = await sb
    .from("modules")
    .delete()
    .eq("id", existing.id);

  if (error) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }

  return NextResponse.json({ deleted: true });
}
