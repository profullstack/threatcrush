import { NextRequest, NextResponse } from "next/server";
import { requireAdmin } from "@/lib/admin-guard";
import { getSupabaseAdmin } from "@/lib/supabase";
import { ADMIN_MODULE_COLUMNS } from "@/lib/module-marketplace";

export const runtime = "nodejs";

/**
 * GET /api/admin/marketplace/modules
 * Every module-store listing in every review state, for the review queue.
 * `?review_status=pending|approved|rejected` narrows the list.
 */
export async function GET(req: NextRequest) {
  const guard = await requireAdmin(req);
  if (guard instanceof NextResponse) return guard;

  const reviewStatus = new URL(req.url).searchParams.get("review_status");
  if (reviewStatus && !["pending", "approved", "rejected"].includes(reviewStatus)) {
    return NextResponse.json({ error: "review_status must be pending, approved or rejected" }, { status: 400 });
  }

  let query = getSupabaseAdmin()
    .from("modules")
    .select(ADMIN_MODULE_COLUMNS)
    .order("created_at", { ascending: false })
    .limit(500);
  if (reviewStatus) query = query.eq("review_status", reviewStatus);

  const { data, error } = await query;
  if (error) {
    return NextResponse.json({ error: "Failed to load modules" }, { status: 500 });
  }
  return NextResponse.json({ modules: data ?? [] });
}
