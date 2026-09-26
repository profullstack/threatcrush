import { NextRequest, NextResponse } from "next/server";
import { issuePhoneCode, resolveUserId, CODE_TTL_SECONDS } from "@/lib/phone-verification";
import { SIGNUP_GRANT_COOKIE } from "@/lib/signup-grant";

export async function POST(req: NextRequest) {
  try {
    const body = await req.json().catch(() => ({}));
    const rawPhone: string | undefined = body.phone;
    if (!rawPhone) {
      return NextResponse.json({ error: "Phone is required" }, { status: 400 });
    }

    const token = req.headers.get("authorization")?.replace("Bearer ", "");
    const userId = await resolveUserId({
      bearerToken: token,
      grantToken: req.cookies.get(SIGNUP_GRANT_COOKIE)?.value,
    });
    if (!userId) {
      return NextResponse.json({ error: "Could not identify user" }, { status: 401 });
    }

    try {
      await issuePhoneCode({ userId, phone: rawPhone });
    } catch (err) {
      const { status = 502, retryAfterSeconds } = err as Error & {
        status?: number;
        retryAfterSeconds?: number;
      };
      return NextResponse.json(
        { error: (err as Error).message || "Could not send SMS" },
        {
          status,
          headers: retryAfterSeconds ? { "Retry-After": String(retryAfterSeconds) } : undefined,
        },
      );
    }

    return NextResponse.json({ ok: true, expires_in: CODE_TTL_SECONDS });
  } catch (err) {
    console.error("send-phone-code error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
