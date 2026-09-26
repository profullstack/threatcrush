import { NextRequest, NextResponse } from "next/server";
import { requireAdmin } from "@/lib/admin-guard";
import { getSupabaseAdmin } from "@/lib/supabase";
import { ADMIN_MODULE_COLUMNS } from "@/lib/module-marketplace";

export const runtime = "nodejs";

const ACTIONS = {
  approve: { review_status: "approved", published: true },
  reject: { review_status: "rejected", published: false },
  unpublish: { published: false },
} as const;

type Action = keyof typeof ACTIONS;

/**
 * PATCH /api/admin/marketplace/modules/[slug]
 * Body: { action: "approve" | "reject" | "unpublish", note?: string }
 *
 * approve publishes the listing; reject hides it and needs a note the author
 * will see; unpublish takes a listing out of the store without changing its
 * review verdict (approve again to restore it). Every action records who,
 * when and why.
 */
export async function PATCH(
  req: NextRequest,
  { params }: { params: Promise<{ slug: string }> },
) {
  const guard = await requireAdmin(req);
  if (guard instanceof NextResponse) return guard;

  const body = (await req.json().catch(() => null)) as { action?: unknown; note?: unknown } | null;
  const action = body?.action;
  if (typeof action !== "string" || !Object.hasOwn(ACTIONS, action)) {
    return NextResponse.json({ error: "action must be approve, reject or unpublish" }, { status: 400 });
  }
  const note = typeof body?.note === "string" ? body.note.trim() : "";
  if (action === "reject" && !note) {
    return NextResponse.json({ error: "A note is required when rejecting, so the author knows what to fix." }, { status: 400 });
  }

  const { slug } = await params;
  const now = new Date().toISOString();
  const { data, error } = await getSupabaseAdmin()
    .from("modules")
    .update({
      ...ACTIONS[action as Action],
      reviewed_by: guard.id,
      reviewed_at: now,
      review_note: note || null,
      updated_at: now,
    })
    .eq("slug", slug)
    .select(ADMIN_MODULE_COLUMNS)
    .maybeSingle();

  if (error) {
    return NextResponse.json({ error: "Failed to update module" }, { status: 500 });
  }
  if (!data) {
    return NextResponse.json({ error: "Module not found" }, { status: 404 });
  }
  return NextResponse.json({ module: data });
}
