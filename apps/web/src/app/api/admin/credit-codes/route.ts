import { NextResponse, type NextRequest } from "next/server";
import { requireAdmin } from "@/lib/admin-guard";
import { getCreditDeps, mintCreditCode, SCAN_CREDITS_UNIT } from "@/lib/credit-codes";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/** GET /api/admin/credit-codes: every minted code (never the code itself, only its hash is stored). */
export async function GET(req: NextRequest) {
  const guard = await requireAdmin(req);
  if (guard instanceof NextResponse) return guard;
  const codes = (await getCreditDeps().credits.list()).filter((c) => c.grant.unit === SCAN_CREDITS_UNIT);
  return NextResponse.json({ codes });
}

/**
 * POST /api/admin/credit-codes { credits, label?, maxRedemptions?, expiresInDays? }
 * Mint a code. The plaintext code is returned ONCE here; only its sha256 is stored.
 */
export async function POST(req: NextRequest) {
  const guard = await requireAdmin(req);
  if (guard instanceof NextResponse) return guard;
  const body = (await req.json().catch(() => ({}))) as Record<string, unknown>;
  const days = Number(body.expiresInDays ?? 0);
  try {
    const minted = await mintCreditCode({
      credits: Number(body.credits),
      label: typeof body.label === "string" && body.label.trim() ? body.label.trim() : undefined,
      maxRedemptions: body.maxRedemptions == null ? 1 : Number(body.maxRedemptions),
      expiresAt: days > 0 ? Date.now() + days * 24 * 60 * 60 * 1000 : null,
      createdBy: guard.email,
    });
    return NextResponse.json({ ok: true, ...minted });
  } catch (err) {
    if (err instanceof TypeError) return NextResponse.json({ error: err.message }, { status: 400 });
    console.error("[admin/credit-codes] POST", err);
    return NextResponse.json({ error: "Could not mint the code." }, { status: 500 });
  }
}
