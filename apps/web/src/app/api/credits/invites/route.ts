import { NextResponse, type NextRequest } from "next/server";
import { getAuthenticatedRequestUser, unauthorized } from "@/lib/api-auth";
import {
  createInvite,
  inviteOverview,
  InviteError,
  inviteUrl,
  originFromHeaders,
  settleInvitesSentBy,
} from "@/lib/credit-codes";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/** GET /api/credits/invites: quota, invites sent and their bonus status. */
export async function GET(req: NextRequest) {
  const user = await getAuthenticatedRequestUser(req);
  if (!user) return unauthorized();
  try {
    // Opening the page pays any bonus whose invitee has since qualified.
    await settleInvitesSentBy(user.userId);
    return NextResponse.json(await inviteOverview(user.userId), { headers: { "cache-control": "private, no-store" } });
  } catch (err) {
    console.error("[credits/invites] GET", err);
    return NextResponse.json({ error: "Could not load invites." }, { status: 500 });
  }
}

/** POST /api/credits/invites { note? }: create one invite (scarce). */
export async function POST(req: NextRequest) {
  const user = await getAuthenticatedRequestUser(req);
  if (!user) return unauthorized();
  const body = (await req.json().catch(() => ({}))) as { note?: unknown };
  try {
    const inv = await createInvite(user.userId, typeof body.note === "string" ? body.note : "");
    return NextResponse.json({
      ok: true,
      id: inv.id,
      code: inv.code,
      url: inviteUrl(originFromHeaders(req.headers), inv.code),
      expiresAt: inv.expiresAt,
    });
  } catch (err) {
    if (err instanceof InviteError) {
      return NextResponse.json({ error: err.message, reason: err.reason }, { status: err.status });
    }
    console.error("[credits/invites] POST", err);
    return NextResponse.json({ error: "Could not create an invite." }, { status: 500 });
  }
}
