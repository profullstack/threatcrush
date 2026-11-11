import { NextResponse, type NextRequest } from "next/server";
import { CORS_HEADERS, exchangeCode, OAuthError, refreshTokens } from "@/lib/mcp-oauth";
import { getSupabaseAdmin } from "@/lib/supabase";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const NO_STORE = { ...CORS_HEADERS, "cache-control": "no-store", pragma: "no-cache" };

/** The token endpoint takes application/x-www-form-urlencoded (RFC 6749); JSON is accepted too. */
async function params(req: NextRequest): Promise<Record<string, unknown>> {
  const type = req.headers.get("content-type") ?? "";
  if (type.includes("application/json")) {
    const body = await req.json().catch(() => null);
    return body && typeof body === "object" ? (body as Record<string, unknown>) : {};
  }
  return Object.fromEntries(new URLSearchParams(await req.text()));
}

// POST /api/oauth/token: authorization_code (PKCE S256) and refresh_token grants.
export async function POST(req: NextRequest) {
  try {
    const p = await params(req);
    const admin = getSupabaseAdmin();
    let out;
    if (p.grant_type === "authorization_code") out = await exchangeCode(admin, p);
    else if (p.grant_type === "refresh_token") out = await refreshTokens(admin, p);
    else throw new OAuthError("unsupported_grant_type", "grant_type must be authorization_code or refresh_token");
    return NextResponse.json(out, { headers: NO_STORE });
  } catch (err) {
    if (err instanceof OAuthError) return NextResponse.json(err.body(), { status: err.status, headers: NO_STORE });
    console.error("[oauth] token failed", (err as Error).message);
    return NextResponse.json({ error: "server_error" }, { status: 500, headers: NO_STORE });
  }
}

export function OPTIONS() {
  return new NextResponse(null, { status: 204, headers: CORS_HEADERS });
}
