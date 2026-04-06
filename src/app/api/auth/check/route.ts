import { NextRequest, NextResponse } from "next/server";
import { getSupabaseClient, getSupabaseAdmin } from "@/lib/supabase";

export async function GET(req: NextRequest) {
  try {
    const authHeader = req.headers.get("authorization");
    const supabase = getSupabaseClient();

    const token = authHeader?.replace("Bearer ", "");
    let userId: string | null = null;

    if (token) {
      const { data: { user } } = await supabase.auth.getUser(token);
      userId = user?.id ?? null;
    } else {
      const { data: { session } } = await supabase.auth.getSession();
      userId = session?.user?.id ?? null;
    }

    if (!userId) {
      return NextResponse.json({ error: "Not authenticated" }, { status: 401 });
    }

    const admin = getSupabaseAdmin();
    const { data: profile, error } = await admin
      .from("user_profiles")
      .select("email, phone, email_verified, phone_verified, license_status")
      .eq("id", userId)
      .single();

    if (error || !profile) {
      return NextResponse.json({ error: "Profile not found" }, { status: 404 });
    }

    const canPay = profile.email_verified && profile.phone_verified;

    return NextResponse.json({
      email: profile.email,
      phone: profile.phone,
      email_verified: profile.email_verified,
      phone_verified: profile.phone_verified,
      license_status: profile.license_status,
      can_proceed_to_payment: canPay,
    });
  } catch (err) {
    console.error("Auth check error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
