import { NextRequest, NextResponse } from "next/server";
import { getSupabaseClient, getSupabaseAdmin } from "@/lib/supabase";
import { setSignupGrantCookie } from "@/lib/signup-grant";

export async function POST(req: NextRequest) {
  try {
    let body: { email?: unknown; password?: unknown };
    try {
      const parsed: unknown = await req.json();
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
        return NextResponse.json({ error: "Invalid JSON body" }, { status: 400 });
      }
      body = parsed as { email?: unknown; password?: unknown };
    } catch {
      return NextResponse.json({ error: "Invalid JSON body" }, { status: 400 });
    }

    const { email, password } = body;

    if (typeof email !== "string" || typeof password !== "string" || !email || !password) {
      return NextResponse.json({ error: "Email and password are required" }, { status: 400 });
    }

    const supabase = getSupabaseClient();
    const { data, error } = await supabase.auth.signInWithPassword({ email, password });

    if (error) {
      // The password was right but the address is still unconfirmed. Supabase
      // withholds a session here, so without a grant the user could never
      // finish phone verification from a new browser. Correct credentials are
      // proof enough to re-issue one.
      if (error.code === "email_not_confirmed") {
        const admin = getSupabaseAdmin();
        const { data: pending } = await admin
          .from("user_profiles")
          .select("id")
          .eq("email", email.toLowerCase().trim())
          .maybeSingle();
        if (pending?.id) {
          return setSignupGrantCookie(
            NextResponse.json(
              { error: error.message, needs_email_verification: true },
              { status: 401 },
            ),
            { userId: pending.id, email },
          );
        }
      }
      return NextResponse.json({ error: error.message }, { status: 401 });
    }

    // Fetch profile for verification status and phone number
    const admin = getSupabaseAdmin();
    const { data: profile } = await admin
      .from("user_profiles")
      .select("email_verified, phone_verified, phone")
      .eq("id", data.user.id)
      .single();

    return NextResponse.json({
      user: data.user,
      session: data.session,
      verified: {
        email: profile?.email_verified ?? false,
        phone: profile?.phone_verified ?? false,
      },
      phone: profile?.phone ?? null,
    });
  } catch (err) {
    console.error("Login error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
