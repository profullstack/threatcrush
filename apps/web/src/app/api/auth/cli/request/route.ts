import { NextRequest, NextResponse } from "next/server";
import { getAuthenticatedRequestUser, unauthorized } from "@/lib/api-auth";
import { getSupabaseAdmin } from "@/lib/supabase";
import { isExpired, isRequestId } from "@/lib/cli-login";

// GET /api/auth/cli/request?id= — what the approval page shows: which machine
// is asking and the code it printed. Signed-in users only.
export async function GET(req: NextRequest) {
  try {
    const user = await getAuthenticatedRequestUser(req);
    if (!user) return unauthorized();

    const id = req.nextUrl.searchParams.get("id");
    if (!isRequestId(id)) {
      return NextResponse.json({ error: "Unknown login request" }, { status: 404 });
    }

    const { data } = await getSupabaseAdmin()
      .from("cli_login_requests")
      .select("id, user_code, device_name, status, created_at, expires_at")
      .eq("id", id)
      .maybeSingle();

    if (!data) return NextResponse.json({ error: "Unknown login request" }, { status: 404 });

    const status = data.status === "pending" && isExpired(data.expires_at) ? "expired" : data.status;
    return NextResponse.json({
      request: {
        id: data.id,
        user_code: data.user_code,
        device_name: data.device_name,
        status,
        created_at: data.created_at,
      },
    });
  } catch (err) {
    console.error("CLI login request error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
