import { NextResponse, type NextRequest } from "next/server";
import { CORS_HEADERS, OAuthError, registerClient } from "@/lib/mcp-oauth";
import { getSupabaseAdmin } from "@/lib/supabase";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

// POST /api/oauth/register: RFC 7591 dynamic client registration (public clients).
export async function POST(req: NextRequest) {
  let body: Record<string, unknown>;
  try {
    body = (await req.json()) as Record<string, unknown>;
    if (!body || typeof body !== "object" || Array.isArray(body)) throw new Error();
  } catch {
    return NextResponse.json(
      { error: "invalid_client_metadata", error_description: "Send the client metadata as a JSON object" },
      { status: 400, headers: CORS_HEADERS },
    );
  }
  try {
    const client = await registerClient(getSupabaseAdmin(), body);
    return NextResponse.json(client, { status: 201, headers: { ...CORS_HEADERS, "cache-control": "no-store" } });
  } catch (err) {
    if (err instanceof OAuthError) return NextResponse.json(err.body(), { status: err.status, headers: CORS_HEADERS });
    console.error("[oauth] register failed", (err as Error).message);
    return NextResponse.json({ error: "server_error" }, { status: 500, headers: CORS_HEADERS });
  }
}

export function OPTIONS() {
  return new NextResponse(null, { status: 204, headers: CORS_HEADERS });
}
