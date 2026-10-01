import { NextRequest, NextResponse } from "next/server";
import { getSupabaseAdmin } from "@/lib/supabase";
import { isExpired, isRequestId, isValidVerifier, mintSession, verifierMatches } from "@/lib/cli-login";

// POST /api/auth/cli/token { request_id, code_verifier } — the CLI polls this
// until the request is approved, then receives a session of its own. Error
// codes follow RFC 8628 so the CLI can tell "keep waiting" from "give up".
//
// "Keep waiting" is a 202, not RFC 8628's 400: a terminal polling every 3s
// produced 20 4xx responses a minute, which is exactly what ThreatCrush's own
// web-scanner-detection rule bans, and on 2026-10-01 dev2 banned four of our
// own servers mid-login.
export async function POST(req: NextRequest) {
  try {
    let body: { request_id?: unknown; code_verifier?: unknown };
    try {
      body = (await req.json()) as typeof body;
    } catch {
      return NextResponse.json({ error: "invalid_request" }, { status: 400 });
    }
    if (!body || !isRequestId(body.request_id) || !isValidVerifier(body.code_verifier)) {
      return NextResponse.json({ error: "invalid_request" }, { status: 400 });
    }

    const admin = getSupabaseAdmin();
    const { data: request } = await admin
      .from("cli_login_requests")
      .select("id, code_challenge, status, user_id, expires_at")
      .eq("id", body.request_id)
      .maybeSingle();

    // An unknown id and a wrong verifier answer the same, so the endpoint
    // cannot be used to learn which request ids exist.
    if (!request || !verifierMatches(body.code_verifier, request.code_challenge)) {
      return NextResponse.json({ error: "invalid_grant" }, { status: 400 });
    }
    if (request.status === "denied") {
      return NextResponse.json({ error: "access_denied" }, { status: 400 });
    }
    if (request.status === "consumed") {
      return NextResponse.json({ error: "invalid_grant" }, { status: 400 });
    }
    if (request.status === "pending") {
      return isExpired(request.expires_at)
        ? NextResponse.json({ error: "expired_token" }, { status: 400 })
        : NextResponse.json({ error: "authorization_pending" }, { status: 202 });
    }

    // Approved. Claim it before minting, so a replayed poll can never mint twice.
    const { data: claimed } = await admin
      .from("cli_login_requests")
      .update({ status: "consumed", consumed_at: new Date().toISOString() })
      .eq("id", request.id)
      .eq("status", "approved")
      .select("user_id")
      .maybeSingle();
    if (!claimed?.user_id) {
      return NextResponse.json({ error: "invalid_grant" }, { status: 400 });
    }

    const { data: owner } = await admin.auth.admin.getUserById(claimed.user_id);
    const email = owner?.user?.email;
    const minted = email ? await mintSession(admin, email) : null;
    if (!minted) {
      console.error("CLI login: could not mint a session for", claimed.user_id);
      return NextResponse.json({ error: "server_error" }, { status: 500 });
    }

    return NextResponse.json(minted);
  } catch (err) {
    console.error("CLI login token error:", err);
    return NextResponse.json({ error: "server_error" }, { status: 500 });
  }
}
