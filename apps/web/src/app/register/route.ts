import { NextResponse } from "next/server";

export const dynamic = "force-dynamic";

// Reached only by a JSON POST (next.config sends browsers to /auth/signup):
// an OAuth client guessing the default registration path. Answer in RFC 7591's
// error shape and point it at the advertised endpoint.
export function POST() {
  return NextResponse.json(
    {
      error: "invalid_request",
      error_description: "Dynamic client registration is at /api/oauth/register (see /.well-known/oauth-authorization-server)",
    },
    { status: 404 },
  );
}
