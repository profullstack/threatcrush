import { NextRequest, NextResponse } from "next/server";
import { getAuthenticatedRequestUser } from "@/lib/api-auth";
import { getSupabaseAdmin } from "@/lib/supabase";

type RouteContext = { params: Promise<{ slug: string }> };

const SEMVER_PATTERN =
  /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;

function isHttpUrl(value: string): boolean {
  try {
    const url = new URL(value);
    return url.protocol === "http:" || url.protocol === "https:";
  } catch {
    return false;
  }
}

/**
 * GET /api/modules/[slug]/versions
 * List published versions for a marketplace module.
 */
export async function GET(
  _request: NextRequest,
  context: RouteContext,
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
 * Publish a version for a module owned by the authenticated user.
 */
export async function POST(
  request: NextRequest,
  context: RouteContext,
) {
  const user = await getAuthenticatedRequestUser(request);
  if (!user) {
    return NextResponse.json(
      { error: "You must be logged in to publish module versions." },
      { status: 401 },
    );
  }

  let body: Record<string, unknown>;
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }

  const version = typeof body.version === "string" ? body.version.trim() : "";
  if (!SEMVER_PATTERN.test(version)) {
    return NextResponse.json(
      { error: "version must be a valid semantic version" },
      { status: 400 },
    );
  }

  const packageUrl =
    typeof body.package_url === "string" && body.package_url.trim()
      ? body.package_url.trim()
      : null;
  if (packageUrl && !isHttpUrl(packageUrl)) {
    return NextResponse.json(
      { error: "package_url must be a valid HTTP(S) URL" },
      { status: 400 },
    );
  }

  const { slug } = await context.params;
  const sb = getSupabaseAdmin();
  const { data: mod, error: moduleError } = await sb
    .from("modules")
    .select("id, author_email")
    .eq("slug", slug)
    .single();

  if (moduleError || !mod) {
    return NextResponse.json({ error: "Module not found" }, { status: 404 });
  }
  if (!user.email || user.email.toLowerCase() !== mod.author_email?.toLowerCase()) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 403 });
  }

  const versionData = {
    module_id: mod.id,
    version,
    changelog:
      typeof body.changelog === "string" && body.changelog.trim()
        ? body.changelog.trim()
        : null,
    package_url: packageUrl,
    git_tag:
      typeof body.git_tag === "string" && body.git_tag.trim()
        ? body.git_tag.trim()
        : null,
    min_threatcrush_version:
      typeof body.min_threatcrush_version === "string" &&
      body.min_threatcrush_version.trim()
        ? body.min_threatcrush_version.trim()
        : null,
  };

  const { data: created, error } = await sb
    .from("module_versions")
    .insert(versionData)
    .select()
    .single();

  if (error) {
    const status = error.code === "23505" ? 409 : 500;
    const message =
      status === 409 ? `Version ${version} already exists` : error.message;
    return NextResponse.json({ error: message }, { status });
  }

  const moduleUpdates: Record<string, unknown> = {
    version,
    updated_at: new Date().toISOString(),
  };
  if (versionData.min_threatcrush_version) {
    moduleUpdates.min_threatcrush_version = versionData.min_threatcrush_version;
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
