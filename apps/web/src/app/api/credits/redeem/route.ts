import { NextResponse, type NextRequest } from "next/server";
import { getAuthenticatedRequestUser, unauthorized } from "@/lib/api-auth";
import { redeemCreditCode } from "@/lib/credit-codes";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/**
 * POST /api/credits/redeem { code }: redeem a credit code into the account's
 * credit balance (1 scan credit = $1.00). Bearer: the signed-in session token
 * (web, or the `threatcrush login` token for the CLI).
 */
export async function POST(req: NextRequest) {
  const user = await getAuthenticatedRequestUser(req);
  if (!user) return unauthorized();
  const body = (await req.json().catch(() => ({}))) as { code?: unknown };
  const code = typeof body.code === "string" ? body.code : "";
  if (!code.trim()) return NextResponse.json({ error: "Enter a code.", reason: "invalid" }, { status: 400 });

  try {
    const r = await redeemCreditCode(user.userId, code);
    if (!r.ok) return NextResponse.json({ error: r.message, reason: r.reason }, { status: 400 });
    return NextResponse.json({
      ok: true,
      credits: r.credits,
      balance_usd: r.balance,
      message: `Code redeemed: ${r.credits} credits ($${r.credits.toFixed(2)}) added.`,
    });
  } catch (err) {
    console.error("[credits/redeem]", err);
    return NextResponse.json({ error: "Could not redeem the code. Try again." }, { status: 500 });
  }
}
