import { NextRequest, NextResponse } from "next/server";
import { getAuthenticatedRequestUser, unauthorized } from "@/lib/api-auth";
import { getSupabaseAdmin } from "@/lib/supabase";
import { isRequestId } from "@/lib/cli-login";

// POST /api/auth/cli/approve { request_id, approve } — the signed-in browser
// approves (or denies) a pending CLI login. The CLI then redeems it.
export async function POST(req: NextRequest) {
  try {
    const user = await getAuthenticatedRequestUser(req);
    if (!user) return unauthorized();

    let body: { request_id?: unknown; approve?: unknown };
    try {
      body = (await req.json()) as typeof body;
    } catch {
      return NextResponse.json({ error: "Invalid JSON body" }, { status: 400 });
    }
    if (!body || !isRequestId(body.request_id) || typeof body.approve !== "boolean") {
      return NextResponse.json({ error: "request_id and approve are required" }, { status: 400 });
    }

    // Only a pending, unexpired request changes, and only once: the filters are
    // the guard, so two tabs racing cannot both decide it.
    const { data, error } = await getSupabaseAdmin()
      .from("cli_login_requests")
      .update(
        body.approve
          ? { status: "approved", user_id: user.userId, approved_at: new Date().toISOString() }
          : { status: "denied" },
      )
      .eq("id", body.request_id)
      .eq("status", "pending")
      .gt("expires_at", new Date().toISOString())
      .select("id, status")
      .maybeSingle();

    if (error) {
      console.error("CLI login approve failed:", error);
      return NextResponse.json({ error: "Could not update login request" }, { status: 500 });
    }
    if (!data) {
      return NextResponse.json(
        { error: "This login request has expired or was already used" },
        { status: 409 },
      );
    }

    return NextResponse.json({ status: data.status });
  } catch (err) {
    console.error("CLI login approve error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
