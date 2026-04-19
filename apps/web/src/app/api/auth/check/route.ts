import { NextRequest, NextResponse } from "next/server";
import { getSupabaseClient, getSupabaseAdmin } from "@/lib/supabase";

export async function GET(req: NextRequest) {
  try {
    const authHeader = req.headers.get("authorization");
    const supabase = getSupabaseClient();

    const token = authHeader?.replace("Bearer ", "");
    const emailParam = req.nextUrl.searchParams.get("email");
    let userId: string | null = null;

    if (token) {
      const { data: { user } } = await supabase.auth.getUser(token);
      userId = user?.id ?? null;
    } else if (!emailParam) {
      const { data: { session } } = await supabase.auth.getSession();
      userId = session?.user?.id ?? null;
    }

    const admin = getSupabaseAdmin();

    // Email fallback: when the verify page polls right after signup it has
    // no Bearer token (signUp() returned no session). Look up by email.
    let query = admin
      .from("user_profiles")
      .select("email, phone, email_verified, phone_verified, license_status");
    if (userId) {
      query = query.eq("id", userId);
    } else if (emailParam) {
      query = query.eq("email", emailParam.toLowerCase().trim());
    } else {
      return NextResponse.json({ error: "Not authenticated" }, { status: 401 });
    }

    const { data: profile, error } = await query.single();

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
