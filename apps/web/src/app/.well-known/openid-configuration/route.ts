import { NextResponse } from "next/server";
import { CORS_HEADERS, openidConfiguration } from "@/lib/mcp-oauth";

export const dynamic = "force-dynamic";

// For MCP clients that only try OpenID discovery. OAuth only: no id_token.
export function GET() {
  return NextResponse.json(openidConfiguration(), {
    headers: { ...CORS_HEADERS, "cache-control": "public, max-age=3600" },
  });
}

export function OPTIONS() {
  return new NextResponse(null, { status: 204, headers: CORS_HEADERS });
}
