import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";

// Any request carrying a Next-Action header is a Server Action invocation.
// The current bundle defines no Server Actions, so every such request is a
// stale-bundle hit (cached clients or bots replaying old action IDs). Letting
// these reach Next's internal handler triggers an InvariantError on every hit
// and leaks RSS under sustained load. Reject with 410 Gone before any of that
// runs; the client framework treats a non-RSC response as a signal to reload.
export function middleware(req: NextRequest): NextResponse | undefined {
  if (req.headers.get("next-action")) {
    return new NextResponse(null, { status: 410 });
  }
  return undefined;
}

export const config = {
  matcher: "/((?!_next/static|_next/image|favicon.ico).*)",
};
