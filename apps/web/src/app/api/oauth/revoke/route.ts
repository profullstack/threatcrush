import { NextResponse, type NextRequest } from "next/server";
import { CORS_HEADERS, revokeToken } from "@/lib/mcp-oauth";
import { getSupabaseAdmin } from "@/lib/supabase";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

// POST /api/oauth/revoke: RFC 7009. Always 200; revoking either token ends the grant.
export async function POST(req: NextRequest) {
  const type = req.headers.get("content-type") ?? "";
  const p = type.includes("application/json")
    ? (((await req.json().catch(() => null)) as Record<string, unknown> | null) ?? {})
    : Object.fromEntries(new URLSearchParams(await req.text()));
  if (typeof p.token === "string" && p.token) await revokeToken(getSupabaseAdmin(), p.token);
  return new NextResponse(null, { status: 200, headers: CORS_HEADERS });
}

export function OPTIONS() {
  return new NextResponse(null, { status: 204, headers: CORS_HEADERS });
}
