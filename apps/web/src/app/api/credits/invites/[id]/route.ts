import { NextResponse, type NextRequest } from "next/server";
import { getAuthenticatedRequestUser, unauthorized } from "@/lib/api-auth";
import { InviteError, revokeInvite } from "@/lib/credit-codes";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/** DELETE /api/credits/invites/{id}: withdraw an unused invite (it does not come back to the quota). */
export async function DELETE(req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const user = await getAuthenticatedRequestUser(req);
  if (!user) return unauthorized();
  const { id } = await params;
  try {
    await revokeInvite(user.userId, id);
    return NextResponse.json({ ok: true });
  } catch (err) {
    if (err instanceof InviteError) {
      return NextResponse.json({ error: err.message, reason: err.reason }, { status: err.status });
    }
    console.error("[credits/invites] DELETE", err);
    return NextResponse.json({ error: "Could not revoke the invite." }, { status: 500 });
  }
}
