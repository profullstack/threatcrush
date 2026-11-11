import { NextResponse, type NextRequest } from "next/server";
import { getAuthenticatedRequestUser, unauthorized } from "@/lib/api-auth";
import { checkAuthorize, errorRedirect, issueCode, OAuthError, type AuthorizeParams } from "@/lib/mcp-oauth";
import { getSupabaseAdmin } from "@/lib/supabase";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const NO_STORE = { "cache-control": "no-store" };

/**
 * The consent page at /oauth/authorize (the advertised authorization_endpoint)
 * is a client page, because a ThreatCrush session lives in the browser
 * (localStorage), not in a cookie. It asks here:
 *
 *   GET  ?client_id&redirect_uri&…  public: is this request valid, and who is the client?
 *   POST { …the same params, approve }  with the session as a Bearer header:
 *        issue the code (or access_denied) and return where to send the browser.
 *
 * CSRF: the POST needs the Bearer session from localStorage, which a
 * cross-site form or image cannot attach; the page refuses to be framed
 * (frame-ancestors 'self'), so it cannot be clickjacked either.
 */
export async function GET(req: NextRequest) {
  const p = Object.fromEntries(req.nextUrl.searchParams) as AuthorizeParams;
  const check = await checkAuthorize(getSupabaseAdmin(), p);
  if (!check.ok) {
    return "redirect" in check
      ? NextResponse.json({ redirect: check.redirect }, { headers: NO_STORE })
      : NextResponse.json({ error: check.error, error_description: check.description }, { status: 400, headers: NO_STORE });
  }
  return NextResponse.json(
    {
      client: { name: check.client.client_name, uri: check.client.client_uri },
      redirect_host: new URL(check.redirectUri).host,
    },
    { headers: NO_STORE },
  );
}

export async function POST(req: NextRequest) {
  const user = await getAuthenticatedRequestUser(req);
  if (!user) return unauthorized();
  let body: AuthorizeParams & { approve?: unknown };
  try {
    body = (await req.json()) as typeof body;
  } catch {
    return NextResponse.json({ error: "Invalid JSON body" }, { status: 400 });
  }
  if (typeof body.approve !== "boolean") return NextResponse.json({ error: "approve is required" }, { status: 400 });
  const admin = getSupabaseAdmin();
  const check = await checkAuthorize(admin, body);
  if (!check.ok) {
    return "redirect" in check
      ? NextResponse.json({ redirect: check.redirect }, { headers: NO_STORE })
      : NextResponse.json({ error: check.error, error_description: check.description }, { status: 400, headers: NO_STORE });
  }
  if (!body.approve) {
    return NextResponse.json(
      { redirect: errorRedirect(check.redirectUri, "access_denied", "The user denied the request", check.state) },
      { headers: NO_STORE },
    );
  }
  try {
    return NextResponse.json({ redirect: await issueCode(admin, check, user.userId) }, { headers: NO_STORE });
  } catch (err) {
    if (err instanceof OAuthError) return NextResponse.json(err.body(), { status: err.status, headers: NO_STORE });
    console.error("[oauth] authorize failed", (err as Error).message);
    return NextResponse.json({ error: "server_error" }, { status: 500, headers: NO_STORE });
  }
}
