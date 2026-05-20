import { NextRequest, NextResponse } from "next/server";
import { getSupabaseAdmin } from "@/lib/supabase";

type RouteContext = { params: Promise<{ slug: string }> };

const MODULE_INSTALL_COLUMNS =
  "id, name, slug, version, downloads, git_url, min_threatcrush_version, os_support, license";

function installPayload(mod: {
  name: string;
  slug: string;
  version: string;
  downloads?: number | null;
  git_url?: string | null;
  min_threatcrush_version?: string | null;
  os_support?: string[] | null;
  license?: string | null;
}) {
  return {
    name: mod.name,
    slug: mod.slug,
    version: mod.version,
    downloads: mod.downloads || 0,
    license: mod.license,
    min_threatcrush_version: mod.min_threatcrush_version,
    os_support: mod.os_support,
    install: {
      npm_package: null,
      git_url: mod.git_url || null,
      tarball_url: null,
    },
  };
}

/**
 * GET /api/modules/[slug]/install
 * Query module install info without incrementing download count.
 */
export async function GET(
  _request: NextRequest,
  context: RouteContext
) {
  const { slug } = await context.params;
  const sb = getSupabaseAdmin();

  const { data: mod, error: modError } = await sb
    .from("modules")
    .select(MODULE_INSTALL_COLUMNS)
    .eq("slug", slug)
    .eq("published", true)
    .single();

  if (modError || !mod) {
    return NextResponse.json({ error: "Module not found" }, { status: 404 });
  }

  return NextResponse.json({
    module: installPayload(mod),
  });
}

/**
 * POST /api/modules/[slug]/install
 * Register an install and return the module's installable artifact info.
 * The client uses the returned data to actually install the module.
 */
export async function POST(
  request: NextRequest,
  context: RouteContext
) {
  const { slug } = await context.params;
  let body: { user_email?: string; version?: string; platform?: string } = {};
  try {
    body = await request.json();
  } catch { /* empty body is fine */ }

  const sb = getSupabaseAdmin();

  // Get module with full install info
  const { data: mod, error: modError } = await sb
    .from("modules")
    .select(MODULE_INSTALL_COLUMNS)
    .eq("slug", slug)
    .eq("published", true)
    .single();

  if (modError || !mod) {
    return NextResponse.json({ error: "Module not found" }, { status: 404 });
  }

  // Increment download count
  const newCount = (mod.downloads || 0) + 1;
  await sb
    .from("modules")
    .update({ downloads: newCount, updated_at: new Date().toISOString() })
    .eq("id", mod.id);

  // Log the install
  await sb.from("module_installs").insert({
    module_id: mod.id,
    user_email: body.user_email || null,
    version: body.version || mod.version,
    platform: body.platform || "unknown",
  });

  return NextResponse.json({
    success: true,
    downloads: newCount,
    module: installPayload({ ...mod, downloads: newCount }),
  });
}
