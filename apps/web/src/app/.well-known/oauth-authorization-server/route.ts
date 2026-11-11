import { NextResponse } from "next/server";
import { authorizationServerMetadata, CORS_HEADERS } from "@/lib/mcp-oauth";

export const dynamic = "force-dynamic";

// RFC 8414 authorization server metadata. The [...path] sibling answers the
// path-suffixed form some clients try first.
export function GET() {
  return NextResponse.json(authorizationServerMetadata(), {
    headers: { ...CORS_HEADERS, "cache-control": "public, max-age=3600" },
  });
}

export function OPTIONS() {
  return new NextResponse(null, { status: 204, headers: CORS_HEADERS });
}
