import { NextResponse, type NextRequest } from "next/server";
import { getAuthenticatedRequestUser, unauthorized } from "@/lib/api-auth";
import { acceptInvite, cleanInviteCode, INVITE_COOKIE, inviteCookie } from "@/lib/credit-codes";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/** POST /api/credits/invites/accept { code }: join on an invite (new accounts only, once). */
export async function POST(req: NextRequest) {
  const user = await getAuthenticatedRequestUser(req);
  if (!user) return unauthorized();
  const body = (await req.json().catch(() => ({}))) as { code?: unknown };
  const code = cleanInviteCode(body.code ?? inviteCookie(req));
  if (!code) return NextResponse.json({ error: "Enter an invite code.", reason: "invalid" }, { status: 400 });
  try {
    const r = await acceptInvite(user.userId, code);
    const res = r.ok
      ? NextResponse.json({ ok: true, bonus: r.bonus, message: r.message })
      : NextResponse.json({ error: r.message, reason: r.reason }, { status: 400 });
    res.cookies.set(INVITE_COOKIE, "", { path: "/", maxAge: 0 });
    return res;
  } catch (err) {
    console.error("[credits/invites/accept]", err);
    return NextResponse.json({ error: "Could not accept the invite." }, { status: 500 });
  }
}
