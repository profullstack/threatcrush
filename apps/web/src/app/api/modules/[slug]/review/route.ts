import { NextRequest, NextResponse } from "next/server";
import { getSupabaseAdmin } from "@/lib/supabase";

type RouteContext = { params: Promise<{ slug: string }> };

async function getAuthenticatedUser(request: NextRequest) {
  const sb = getSupabaseAdmin();
  const authHeader = request.headers.get("authorization");
  const tokenFromHeader = authHeader?.replace("Bearer ", "");
  const tokenFromCookie = request.cookies?.get?.("sb-access-token")?.value
    || request.cookies?.get?.("supabase-auth-token")?.value;

  for (const token of [tokenFromHeader, tokenFromCookie]) {
    if (!token) continue;
    const { data } = await sb.auth.getUser(token);
    if (data?.user) return data.user;
  }

  return null;
}

/**
 * GET /api/modules/[slug]/review
 * List reviews for a module.
 */
export async function GET(
  request: NextRequest,
  context: RouteContext
) {
  const { slug } = await context.params;
  const { searchParams } = new URL(request.url);
  const parsedPage = parseInt(searchParams.get("page") || "1", 10);
  const page = Number.isNaN(parsedPage) ? 1 : Math.max(1, parsedPage);
  const limit = 20;
  const offset = (page - 1) * limit;

  const sb = getSupabaseAdmin();

  const { data: mod } = await sb
    .from("modules")
    .select("id")
    .eq("slug", slug)
    .single();

  if (!mod) {
    return NextResponse.json({ error: "Module not found" }, { status: 404 });
  }

  const { data: reviews, error, count } = await sb
    .from("module_reviews")
    .select("*", { count: "exact" })
    .eq("module_id", mod.id)
    .order("created_at", { ascending: false })
    .range(offset, offset + limit - 1);

  if (error) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }

  return NextResponse.json({
    reviews: reviews || [],
    total: count || 0,
    page,
  });
}

/**
 * POST /api/modules/[slug]/review
 * Submit a review (rating 1-5 + optional title/body).
 */
export async function POST(
  request: NextRequest,
  context: RouteContext
) {
  const user = await getAuthenticatedUser(request);
  if (!user) {
    return NextResponse.json({ error: "You must be logged in to leave reviews." }, { status: 401 });
  }

  const { slug } = await context.params;
  let body: { rating?: number; title?: string; body?: string };
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }

  if (!body.rating || body.rating < 1 || body.rating > 5) {
    return NextResponse.json({ error: "rating must be 1-5" }, { status: 400 });
  }

  const sb = getSupabaseAdmin();

  const { data: profile } = await sb
    .from("user_profiles")
    .select("id, email")
    .eq("id", user.id)
    .single();

  if (!profile?.email) {
    return NextResponse.json(
      { error: "You must create an account to leave reviews." },
      { status: 401 }
    );
  }

  const { data: mod } = await sb
    .from("modules")
    .select("id, rating_avg, rating_count")
    .eq("slug", slug)
    .eq("published", true)
    .single();

  if (!mod) {
    return NextResponse.json({ error: "Module not found" }, { status: 404 });
  }

  // Upsert review (one per user per module)
  const { data: review, error } = await sb
    .from("module_reviews")
    .upsert(
      {
        module_id: mod.id,
        user_email: profile.email,
        rating: body.rating,
        title: body.title || null,
        body: body.body || null,
      },
      { onConflict: "module_id,user_email" }
    )
    .select()
    .single();

  if (error) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }

  // Recalculate average rating
  const { data: allReviews } = await sb
    .from("module_reviews")
    .select("rating")
    .eq("module_id", mod.id);

  if (allReviews && allReviews.length > 0) {
    const avg = allReviews.reduce((sum, r) => sum + r.rating, 0) / allReviews.length;
    await sb
      .from("modules")
      .update({
        rating_avg: Math.round(avg * 100) / 100,
        rating_count: allReviews.length,
        updated_at: new Date().toISOString(),
      })
      .eq("id", mod.id);
  }

  return NextResponse.json({ review }, { status: 201 });
}
