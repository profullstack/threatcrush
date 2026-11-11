import { NextResponse, type NextRequest } from "next/server";
import { getAuthenticatedRequestUser, unauthorized } from "@/lib/api-auth";
import { listGrants, revokeGrant } from "@/lib/mcp-oauth";
import { getSupabaseAdmin } from "@/lib/supabase";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// GET /api/oauth/grants: the signed-in user's connected apps (ChatGPT, Claude, …).
export async function GET(req: NextRequest) {
  const user = await getAuthenticatedRequestUser(req);
  if (!user) return unauthorized();
  return NextResponse.json({ grants: await listGrants(getSupabaseAdmin(), user.userId) }, { headers: { "cache-control": "no-store" } });
}

// DELETE /api/oauth/grants?id=<grant id>: disconnect one app; its tokens stop working at once.
export async function DELETE(req: NextRequest) {
  const user = await getAuthenticatedRequestUser(req);
  if (!user) return unauthorized();
  const id = req.nextUrl.searchParams.get("id") ?? "";
  if (!UUID.test(id)) return NextResponse.json({ error: "id is required" }, { status: 400 });
  const ok = await revokeGrant(getSupabaseAdmin(), user.userId, id);
  return ok ? NextResponse.json({ revoked: true }) : NextResponse.json({ error: "No such connected app" }, { status: 404 });
}
