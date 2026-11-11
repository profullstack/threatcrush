import { NextResponse } from "next/server";
import { CORS_HEADERS, protectedResourceMetadata } from "@/lib/mcp-oauth";

export const dynamic = "force-dynamic";

// RFC 9728 protected-resource metadata for the MCP server at /api/mcp. The
// [...path] sibling answers the path-suffixed form (/.well-known/oauth-protected-resource/api/mcp).
export function GET() {
  return NextResponse.json(protectedResourceMetadata(), {
    headers: { ...CORS_HEADERS, "cache-control": "public, max-age=3600" },
  });
}

export function OPTIONS() {
  return new NextResponse(null, { status: 204, headers: CORS_HEADERS });
}
