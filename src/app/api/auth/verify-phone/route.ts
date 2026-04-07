import { NextRequest, NextResponse } from "next/server";
import { getSupabaseAdmin } from "@/lib/supabase";
import { resolveUserId, sha256 } from "@/lib/phone-verification";

const MAX_ATTEMPTS = 5;

export async function POST(req: NextRequest) {
  try {
    const body = await req.json().catch(() => ({}));
    const code: string | undefined = body.code;
    const email: string | undefined = body.email;
    if (!code || !/^\d{6}$/.test(code)) {
      return NextResponse.json({ error: "Enter the 6-digit code" }, { status: 400 });
    }

    const token = req.headers.get("authorization")?.replace("Bearer ", "");
    const userId = await resolveUserId({ bearerToken: token, email });
    if (!userId) {
      return NextResponse.json({ error: "Could not identify user" }, { status: 401 });
    }

    const admin = getSupabaseAdmin();

    const { data: record, error: selectError } = await admin
      .from("phone_verification_codes")
      .select("id, code_hash, expires_at, attempts, phone")
      .eq("user_id", userId)
      .order("created_at", { ascending: false })
      .limit(1)
      .maybeSingle();

    if (selectError) {
      console.error("phone_verification_codes select failed:", selectError);
      return NextResponse.json({ error: "Verification lookup failed" }, { status: 500 });
    }
    if (!record) {
      return NextResponse.json(
        { error: "No verification code found. Request a new one." },
        { status: 400 },
      );
    }

    if (new Date(record.expires_at).getTime() < Date.now()) {
      await admin.from("phone_verification_codes").delete().eq("id", record.id);
      return NextResponse.json({ error: "Code expired. Request a new one." }, { status: 400 });
    }

    if (record.attempts >= MAX_ATTEMPTS) {
      await admin.from("phone_verification_codes").delete().eq("id", record.id);
      return NextResponse.json(
        { error: "Too many attempts. Request a new code." },
        { status: 429 },
      );
    }

    if (sha256(code) !== record.code_hash) {
      await admin
        .from("phone_verification_codes")
        .update({ attempts: record.attempts + 1 })
        .eq("id", record.id);
      return NextResponse.json({ error: "Invalid code" }, { status: 400 });
    }

    const { error: updateError } = await admin
      .from("user_profiles")
      .update({
        phone: record.phone,
        phone_verified: true,
        updated_at: new Date().toISOString(),
      })
      .eq("id", userId);

    if (updateError) {
      console.error("user_profiles update failed:", updateError);
      return NextResponse.json({ error: "Failed to mark phone verified" }, { status: 500 });
    }

    await admin.from("phone_verification_codes").delete().eq("id", record.id);

    return NextResponse.json({ verified: true });
  } catch (err) {
    console.error("Phone verification error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
