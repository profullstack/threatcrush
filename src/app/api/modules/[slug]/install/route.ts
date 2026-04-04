import { NextRequest, NextResponse } from "next/server";
import { getSupabaseAdmin } from "@/lib/supabase";

type RouteContext = { params: Promise<{ slug: string }> };

/**
 * POST /api/modules/[slug]/install
 * Register an install — increment download count and log it.
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

  // Get module
  const { data: mod, error: modError } = await sb
    .from("modules")
    .select("id, downloads, version")
    .eq("slug", slug)
    .eq("published", true)
    .single();

  if (modError || !mod) {
    return NextResponse.json({ error: "Module not found" }, { status: 404 });
  }

  // Increment download count
  await sb
    .from("modules")
    .update({ downloads: (mod.downloads || 0) + 1, updated_at: new Date().toISOString() })
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
    downloads: (mod.downloads || 0) + 1,
  });
}
