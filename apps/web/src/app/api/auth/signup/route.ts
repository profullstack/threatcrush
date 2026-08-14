import { NextRequest, NextResponse } from "next/server";
import { getSupabaseClient, getSupabaseAdmin } from "@/lib/supabase";
import { randomInt } from "node:crypto";
import { issuePhoneCode } from "@/lib/phone-verification";
import { setSignupGrantCookie } from "@/lib/signup-grant";

function generateReferralCode(): string {
  // TC-30: Math.random() is not a CSPRNG, and referral codes are guessable
  // credentials for attributing payouts.
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789";
  let code = "";
  for (let i = 0; i < 8; i++) {
    code += chars.charAt(randomInt(0, chars.length));
  }
  return code;
}

export async function POST(req: NextRequest) {
  try {
    const { email, phone, password, display_name, referral_code } = await req.json();

    if (!email || !password) {
      return NextResponse.json({ error: "Email and password are required" }, { status: 400 });
    }

    // Use the anon client so Supabase actually sends the confirmation email.
    // admin.createUser silently creates users without sending any email.
    const anon = getSupabaseClient();
    const { data: authData, error: authError } = await anon.auth.signUp({
      email,
      password,
      options: {
        emailRedirectTo: `${new URL(req.url).origin}/auth/verify`,
      },
    });

    if (authError) {
      return NextResponse.json({ error: authError.message }, { status: 400 });
    }

    const userId = authData.user?.id;
    if (!userId) {
      return NextResponse.json(
        { error: "Signup did not return a user id" },
        { status: 500 },
      );
    }

    const supabase = getSupabaseAdmin();

    // Generate unique referral code
    let userReferralCode = generateReferralCode();
    let attempts = 0;
    while (attempts < 5) {
      const { data: existing } = await supabase
        .from("user_profiles")
        .select("id")
        .eq("referral_code", userReferralCode)
        .single();
      if (!existing) break;
      userReferralCode = generateReferralCode();
      attempts++;
    }

    // Create user profile
    const { error: profileError } = await supabase.from("user_profiles").insert({
      id: userId,
      email,
      phone: phone || null,
      display_name: display_name || null,
      referral_code: userReferralCode,
      referred_by: referral_code || null,
      email_verified: false,
      phone_verified: false,
    });

    if (profileError) {
      // Cleanup auth user if profile creation fails
      await supabase.auth.admin.deleteUser(userId);
      return NextResponse.json({ error: "Failed to create profile: " + profileError.message }, { status: 500 });
    }

    // Verification email is sent automatically by auth.signUp above.

    // Send the phone verification SMS server-side immediately. With email
    // confirmation enabled, auth.signUp() returns no session, so the verify
    // page has no Bearer token and cannot trigger an SMS itself. Doing it
    // here guarantees one SMS goes out the moment the account is created.
    let sms_sent = false;
    let sms_error: string | null = null;
    if (phone) {
      try {
        await issuePhoneCode({ userId, phone, bypassCooldown: true });
        sms_sent = true;
      } catch (err) {
        sms_error = (err as Error).message || "SMS send failed";
        console.error("[signup] phone code send failed:", err);
      }
    }

    // signUp() returns no session while email confirmation is pending, so hand
    // the verify page a signed grant instead. It is the only thing that lets
    // that page poll status and verify a phone without a Bearer token.
    return setSignupGrantCookie(
      NextResponse.json({
        user: { id: userId, email },
        referral_code: userReferralCode,
        needs_email_verification: true,
        needs_phone_verification: !!phone,
        sms_sent,
        sms_error,
      }),
      { userId, email },
    );
  } catch (err) {
    console.error("Signup error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
