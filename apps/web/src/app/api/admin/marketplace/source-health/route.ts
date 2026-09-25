import { NextRequest, NextResponse } from "next/server";
import { requireAdmin } from "@/lib/admin-guard";
import { getSupabaseAdmin } from "@/lib/supabase";
import { checkModuleSource, type SourceCheckResult } from "@/lib/module-source-health";

export const runtime = "nodejs";

/** Checks run a few at a time: enough to finish quickly, not enough to hammer one host. */
const CONCURRENCY = 4;

/**
 * POST /api/admin/marketplace/source-health
 * Body (optional): { slug: string } to check one listing; otherwise every listing.
 *
 * Resolves each module's install source (npm package, git repository, tarball,
 * or the homepage when there is none) through the SSRF guard and records
 * source_status (ok / unreachable / not_found) with the time and a short reason.
 * The install endpoint refuses listings whose source is recorded as broken.
 */
export async function POST(req: NextRequest) {
  const guard = await requireAdmin(req);
  if (guard instanceof NextResponse) return guard;

  const body = (await req.json().catch(() => ({}))) as { slug?: unknown } | null;
  const slug = typeof body?.slug === "string" && body.slug ? body.slug : null;

  const sb = getSupabaseAdmin();
  let query = sb.from("modules").select("id, slug, npm_package, git_url, tarball_url, homepage_url");
  if (slug) query = query.eq("slug", slug);
  const { data: modules, error } = await query;

  if (error) {
    return NextResponse.json({ error: "Failed to load modules" }, { status: 500 });
  }
  if (slug && !modules?.length) {
    return NextResponse.json({ error: "Module not found" }, { status: 404 });
  }

  const checkedAt = new Date().toISOString();
  const results: Array<SourceCheckResult & { slug: string }> = [];
  const queue = [...(modules ?? [])];

  async function worker() {
    for (let mod = queue.shift(); mod; mod = queue.shift()) {
      const result = await checkModuleSource(mod);
      await sb
        .from("modules")
        .update({
          source_status: result.status,
          source_checked_at: checkedAt,
          source_check_detail: result.detail,
        })
        .eq("id", mod.id);
      results.push({ slug: mod.slug, ...result });
    }
  }
  await Promise.all(Array.from({ length: CONCURRENCY }, worker));

  results.sort((a, b) => a.slug.localeCompare(b.slug));
  return NextResponse.json({ checked_at: checkedAt, results });
}
