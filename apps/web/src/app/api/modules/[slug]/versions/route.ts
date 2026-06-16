import { NextRequest, NextResponse } from "next/server";
import { getSupabaseAdmin } from "@/lib/supabase";

type RouteContext = { params: Promise<{ slug: string }> };

const SEMVER_PATTERN =
  /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;

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
 * GET /api/modules/[slug]/versions
 * List release records newest first for a published marketplace module.
 */
export async function GET(
  _request: NextRequest,
  context: RouteContext
) {
  const { slug } = await context.params;
  const sb = getSupabaseAdmin();

  const { data: mod, error: moduleError } = await sb
    .from("modules")
    .select("id")
    .eq("slug", slug)
    .eq("published", true)
    .single();

  if (moduleError || !mod) {
    return NextResponse.json({ error: "Module not found" }, { status: 404 });
  }

  const { data: versions, error } = await sb
    .from("module_versions")
    .select("*")
    .eq("module_id", mod.id)
    .order("created_at", { ascending: false });

  if (error) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }

  return NextResponse.json({ versions: versions || [] });
}

/**
 * POST /api/modules/[slug]/versions
 * Publish a new release record for the authenticated module author.
 */
export async function POST(
  request: NextRequest,
  context: RouteContext
) {
  const user = await getAuthenticatedUser(request);
  if (!user) {
    return NextResponse.json({ error: "You must be logged in to publish module versions." }, { status: 401 });
  }

  const { slug } = await context.params;
  let body: Record<string, unknown>;
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }

  const version = typeof body.version === "string" ? body.version.trim() : "";
  if (!version) {
    return NextResponse.json({ error: "version is required" }, { status: 400 });
  }
  if (!SEMVER_PATTERN.test(version)) {
    return NextResponse.json({ error: "version must be a semantic version" }, { status: 400 });
  }

  const sb = getSupabaseAdmin();
  const { data: profile } = await sb
    .from("user_profiles")
    .select("id, email, email_verified")
    .eq("id", user.id)
    .single();

  if (!profile) {
    return NextResponse.json(
      { error: "You must create an account at threatcrush.com/auth/signup before publishing module versions." },
      { status: 401 }
    );
  }

  if (!profile.email_verified) {
    return NextResponse.json(
      { error: "Please verify your email before publishing module versions." },
      { status: 403 }
    );
  }

  const { data: mod, error: moduleError } = await sb
    .from("modules")
    .select("id, author_email")
    .eq("slug", slug)
    .single();

  if (moduleError || !mod) {
    return NextResponse.json({ error: "Module not found" }, { status: 404 });
  }

  if (mod.author_email !== profile.email) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 403 });
  }

  const { data: duplicate } = await sb
    .from("module_versions")
    .select("id")
    .eq("module_id", mod.id)
    .eq("version", version)
    .maybeSingle();

  if (duplicate) {
    return NextResponse.json({ error: `Version ${version} already exists` }, { status: 409 });
  }

  const release = {
    module_id: mod.id,
    version,
    changelog: typeof body.changelog === "string" ? body.changelog : null,
    package_url: typeof body.package_url === "string" ? body.package_url : null,
    git_tag: typeof body.git_tag === "string" ? body.git_tag : null,
    min_threatcrush_version:
      typeof body.min_threatcrush_version === "string" ? body.min_threatcrush_version : null,
  };

  const { data: created, error } = await sb
    .from("module_versions")
    .insert(release)
    .select()
    .single();

  if (error) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }

  const moduleUpdates: Record<string, unknown> = {
    version,
    updated_at: new Date().toISOString(),
  };
  if (release.min_threatcrush_version) {
    moduleUpdates.min_threatcrush_version = release.min_threatcrush_version;
  }

  const { error: updateError } = await sb
    .from("modules")
    .update(moduleUpdates)
    .eq("id", mod.id);

  if (updateError) {
    return NextResponse.json({ error: updateError.message }, { status: 500 });
  }

  return NextResponse.json({ version: created }, { status: 201 });
}
