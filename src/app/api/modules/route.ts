import { NextRequest, NextResponse } from "next/server";
import { getSupabaseAdmin, slugify } from "@/lib/supabase";

/**
 * GET /api/modules
 * List modules with search, category filter, sorting, and pagination.
 */
export async function GET(request: NextRequest) {
  const { searchParams } = new URL(request.url);
  const search = searchParams.get("search") || "";
  const category = searchParams.get("category") || "";
  const sort = searchParams.get("sort") || "newest"; // newest | popular | top-rated
  const page = Math.max(1, parseInt(searchParams.get("page") || "1", 10));
  const limit = Math.min(50, Math.max(1, parseInt(searchParams.get("limit") || "20", 10)));
  const offset = (page - 1) * limit;

  const sb = getSupabaseAdmin();

  let query = sb
    .from("modules")
    .select("*", { count: "exact" })
    .eq("published", true);

  if (search) {
    query = query.or(
      `name.ilike.%${search}%,display_name.ilike.%${search}%,description.ilike.%${search}%,keywords.ilike.%${search}%`
    );
  }

  if (category && category !== "all") {
    query = query.eq("category", category);
  }

  switch (sort) {
    case "popular":
      query = query.order("downloads", { ascending: false });
      break;
    case "top-rated":
      query = query.order("rating_avg", { ascending: false });
      break;
    case "newest":
    default:
      query = query.order("created_at", { ascending: false });
      break;
  }

  query = query.range(offset, offset + limit - 1);

  const { data, error, count } = await query;

  if (error) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }

  return NextResponse.json({
    modules: data || [],
    total: count || 0,
    page,
    limit,
    totalPages: Math.ceil((count || 0) / limit),
  });
}

/**
 * POST /api/modules
 * Publish a new module. Accepts name + git_url/homepage_url + optional overrides.
 */
export async function POST(request: NextRequest) {
  let body: Record<string, unknown>;
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }

  const name = body.name as string;
  const author_email = body.author_email as string;

  if (!name) {
    return NextResponse.json({ error: "name is required" }, { status: 400 });
  }
  if (!author_email) {
    return NextResponse.json({ error: "author_email is required" }, { status: 400 });
  }

  const slug = slugify(name);

  const sb = getSupabaseAdmin();

  // Check if slug already exists
  const { data: existing } = await sb
    .from("modules")
    .select("id")
    .eq("slug", slug)
    .single();

  if (existing) {
    return NextResponse.json(
      { error: `Module "${slug}" already exists` },
      { status: 409 }
    );
  }

  const moduleData = {
    name: (body.name as string) || name,
    slug,
    display_name: (body.display_name as string) || name,
    description: (body.description as string) || null,
    long_description: (body.long_description as string) || null,
    author_name: (body.author_name as string) || null,
    author_email,
    author_url: (body.author_url as string) || null,
    homepage_url: (body.homepage_url as string) || null,
    git_url: (body.git_url as string) || null,
    logo_url: (body.logo_url as string) || null,
    banner_url: (body.banner_url as string) || null,
    screenshot_url: (body.screenshot_url as string) || null,
    license: (body.license as string) || "MIT",
    pricing_type: (body.pricing_type as string) || "free",
    price_usd: body.price_usd ? Number(body.price_usd) : null,
    category: (body.category as string) || "security",
    tags: (body.tags as string[]) || [],
    keywords: (body.keywords as string) || null,
    version: (body.version as string) || "0.1.0",
    min_threatcrush_version: (body.min_threatcrush_version as string) || ">=0.1.0",
    os_support: (body.os_support as string[]) || ["linux"],
    capabilities: (body.capabilities as string[]) || [],
  };

  const { data, error } = await sb
    .from("modules")
    .insert(moduleData)
    .select()
    .single();

  if (error) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }

  // Also create the first version entry
  if (data) {
    await sb.from("module_versions").insert({
      module_id: data.id,
      version: moduleData.version,
      changelog: "Initial release",
      git_tag: moduleData.git_url ? `v${moduleData.version}` : null,
    });
  }

  return NextResponse.json({ module: data }, { status: 201 });
}
