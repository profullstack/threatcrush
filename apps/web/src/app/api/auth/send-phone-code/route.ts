import { NextRequest, NextResponse } from "next/server";
import { issuePhoneCode, resolveUserId, CODE_TTL_SECONDS } from "@/lib/phone-verification";

export async function POST(req: NextRequest) {
  try {
    const body = await req.json().catch(() => ({}));
    const rawPhone: string | undefined = body.phone;
    const email: string | undefined = body.email;
    if (!rawPhone) {
      return NextResponse.json({ error: "Phone is required" }, { status: 400 });
    }

    const token = req.headers.get("authorization")?.replace("Bearer ", "");
    const userId = await resolveUserId({ bearerToken: token, email });
    if (!userId) {
      return NextResponse.json({ error: "Could not identify user" }, { status: 401 });
    }

    try {
      await issuePhoneCode({ userId, phone: rawPhone });
    } catch (err) {
      const status = (err as Error & { status?: number }).status ?? 502;
      return NextResponse.json(
        { error: (err as Error).message || "Could not send SMS" },
        { status },
      );
    }

    return NextResponse.json({ ok: true, expires_in: CODE_TTL_SECONDS });
  } catch (err) {
    console.error("send-phone-code error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
