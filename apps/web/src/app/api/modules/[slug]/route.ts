import { NextRequest, NextResponse } from "next/server";
import { getSupabaseAdmin } from "@/lib/supabase";
import { getAuthenticatedRequestUser } from "@/lib/api-auth";
import { isPubliclyListed, paidModuleError, toPublicModule } from "@/lib/module-marketplace";

type RouteContext = { params: Promise<{ slug: string }> };

/**
 * GET /api/modules/[slug]
 * Module details with versions and reviews.
 *
 * Only approved + published modules are public. The author (signed in) can
 * also load their own pending, rejected or unpublished module, including the
 * reviewer's note.
 */
export async function GET(
  request: NextRequest,
  context: RouteContext
) {
  const { slug } = await context.params;
  const sb = getSupabaseAdmin();

  const { data: mod, error } = await sb
    .from("modules")
    .select("*")
    .eq("slug", slug)
    .single();

  if (error || !mod) {
    return NextResponse.json({ error: "Module not found" }, { status: 404 });
  }

  let isAuthor = false;
  if (request.headers.get("authorization")) {
    const user = await getAuthenticatedRequestUser(request);
    isAuthor = !!user?.email && user.email === mod.author_email;
  }
  if (!isAuthor && !isPubliclyListed(mod)) {
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
    module: isAuthor ? mod : toPublicModule(mod),
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
  const user = await getAuthenticatedRequestUser(request);
  if (!user) {
    return NextResponse.json(
      { error: "You must be logged in to update modules." },
      { status: 401 }
    );
  }

  const { slug } = await context.params;
  let body: Record<string, unknown>;
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }

  const sb = getSupabaseAdmin();

  // Verify ownership
  const { data: existing } = await sb
    .from("modules")
    .select("id, author_email, review_status, git_url")
    .eq("slug", slug)
    .single();

  if (!existing) {
    return NextResponse.json({ error: "Module not found" }, { status: 404 });
  }
  if (!user.email || existing.author_email !== user.email) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 403 });
  }

  const pricingError = paidModuleError(body);
  if (pricingError) {
    return NextResponse.json({ error: pricingError }, { status: 400 });
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

  // The reviewer approved a specific source. Pointing the listing somewhere
  // else sends it back through review; editing a rejected module resubmits it.
  const sourceChanged = "git_url" in body && (body.git_url || null) !== (existing.git_url || null);
  if (existing.review_status === "rejected" || (existing.review_status === "approved" && sourceChanged)) {
    Object.assign(updates, {
      review_status: "pending",
      published: false,
      reviewed_by: null,
      reviewed_at: null,
      review_note: null,
    });
  }
  if (sourceChanged) {
    Object.assign(updates, { source_status: null, source_checked_at: null, source_check_detail: null });
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
  const user = await getAuthenticatedRequestUser(request);
  if (!user) {
    return NextResponse.json(
      { error: "You must be logged in to delete modules." },
      { status: 401 }
    );
  }

  const { slug } = await context.params;
  const sb = getSupabaseAdmin();

  const { data: existing } = await sb
    .from("modules")
    .select("id, author_email")
    .eq("slug", slug)
    .single();

  if (!existing) {
    return NextResponse.json({ error: "Module not found" }, { status: 404 });
  }
  if (!user.email || existing.author_email !== user.email) {
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
