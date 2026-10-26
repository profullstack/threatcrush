import { NextResponse, type NextRequest } from "next/server";
import { requireAdmin } from "@/lib/admin-guard";
import { getCreditDeps } from "@/lib/credit-codes";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/** DELETE /api/admin/credit-codes/{id}: revoke a code (credits already granted stay). */
export async function DELETE(req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const guard = await requireAdmin(req);
  if (guard instanceof NextResponse) return guard;
  const { id } = await params;
  try {
    await getCreditDeps().credits.revoke(id);
    return NextResponse.json({ ok: true });
  } catch {
    return NextResponse.json({ error: "No such code." }, { status: 404 });
  }
}
