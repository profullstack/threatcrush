import { NextRequest, NextResponse } from "next/server";
import { getSupabaseAdmin } from "@/lib/supabase";

type RouteContext = { params: Promise<{ slug: string }> };

const SEMVER_RE = /^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/;

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
 * List module releases newest first.
 */
export async function GET(
  _request: NextRequest,
  context: RouteContext
) {
  const { slug } = await context.params;
  const sb = getSupabaseAdmin();

  const { data: mod } = await sb
    .from("modules")
    .select("id")
    .eq("slug", slug)
    .eq("published", true)
    .single();

  if (!mod) {
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
 * Publish a first-class module release. Requires the verified module author.
 */
export async function POST(
  request: NextRequest,
  context: RouteContext
) {
  const user = await getAuthenticatedUser(request);
  if (!user) {
    return NextResponse.json({ error: "You must be logged in to publish module versions." }, { status: 401 });
  }

  let body: Record<string, unknown>;
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }

  const version = body.version as string | undefined;
  if (!version) {
    return NextResponse.json({ error: "version is required" }, { status: 400 });
  }
  if (!SEMVER_RE.test(version)) {
    return NextResponse.json({ error: "version must be semantic version format, for example 1.2.3" }, { status: 400 });
  }

  const sb = getSupabaseAdmin();

  const { data: profile } = await sb
    .from("user_profiles")
    .select("id, email, email_verified")
    .eq("id", user.id)
    .single();

  if (!profile) {
    return NextResponse.json(
      { error: "You must create an account before publishing module versions." },
      { status: 401 }
    );
  }

  if (!profile.email_verified) {
    return NextResponse.json(
      { error: "Please verify your email before publishing module versions." },
      { status: 403 }
    );
  }

  const { slug } = await context.params;
  const { data: mod } = await sb
    .from("modules")
    .select("id, author_email")
    .eq("slug", slug)
    .single();

  if (!mod) {
    return NextResponse.json({ error: "Module not found" }, { status: 404 });
  }
  if (mod.author_email !== profile.email) {
    return NextResponse.json({ error: "Only the module author can publish versions." }, { status: 403 });
  }

  const { data: existingVersion } = await sb
    .from("module_versions")
    .select("id")
    .eq("module_id", mod.id)
    .eq("version", version)
    .maybeSingle();

  if (existingVersion) {
    return NextResponse.json({ error: `Version ${version} already exists for this module.` }, { status: 409 });
  }

  const releaseData = {
    module_id: mod.id,
    version,
    changelog: (body.changelog as string) || null,
    package_url: (body.package_url as string) || null,
    git_tag: (body.git_tag as string) || null,
    min_threatcrush_version: (body.min_threatcrush_version as string) || null,
  };

  const { data: release, error: releaseError } = await sb
    .from("module_versions")
    .insert(releaseData)
    .select()
    .single();

  if (releaseError) {
    if ("code" in releaseError && releaseError.code === "23505") {
      return NextResponse.json({ error: `Version ${version} already exists for this module.` }, { status: 409 });
    }
    return NextResponse.json({ error: releaseError.message }, { status: 500 });
  }

  const moduleUpdates: Record<string, unknown> = {
    version,
    updated_at: new Date().toISOString(),
  };
  if (body.min_threatcrush_version) {
    moduleUpdates.min_threatcrush_version = body.min_threatcrush_version;
  }

  const { data: updatedModule, error: updateError } = await sb
    .from("modules")
    .update(moduleUpdates)
    .eq("id", mod.id)
    .select()
    .single();

  if (updateError) {
    return NextResponse.json({ error: updateError.message }, { status: 500 });
  }

  return NextResponse.json({ version: release, module: updatedModule }, { status: 201 });
}
