import { NextRequest, NextResponse } from "next/server";
import { createClient } from "@supabase/supabase-js";

function getSupabase() {
  const url = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!url || !key) throw new Error("Supabase not configured");
  return createClient(url, key);
}

const COINPAY_API = "https://coinpayportal.com/api";
const PRICE_FULL = 499;
const PRICE_REFERRAL = 399;

function generateReferralCode(): string {
  return Math.random().toString(36).substring(2, 10);
}

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { email, payment_method, referral_code } = body;

    if (!email || typeof email !== "string" || !email.includes("@")) {
      return NextResponse.json({ error: "Valid email is required" }, { status: 400 });
    }

    const supabase = getSupabase();

    // Check for existing signup
    const { data: existing } = await supabase
      .from("waitlist")
      .select("id, paid, referral_code")
      .eq("email", email.toLowerCase())
      .maybeSingle();

    if (existing?.paid) {
      return NextResponse.json({
        error: "Already purchased",
        paid: true,
        referral_code: existing.referral_code,
      }, { status: 409 });
    }

    // Check referral code validity
    let referredBy: string | null = null;
    let price = PRICE_FULL;

    if (referral_code) {
      const { data: referrer } = await supabase
        .from("waitlist")
        .select("id, email, referral_code, paid")
        .eq("referral_code", referral_code)
        .maybeSingle();

      if (referrer) {
        referredBy = referral_code;
        price = PRICE_REFERRAL;
      }
    }

    // ─── Step 1: Email-only signup (no payment_method) ───
    if (!payment_method) {
      // If already exists, just return existing referral code
      if (existing) {
        return NextResponse.json({
          success: true,
          waitlist_id: existing.id,
          referral_code: existing.referral_code,
          price,
          discount: referredBy ? true : false,
          existing: true,
        });
      }

      const newReferralCode = generateReferralCode();
      const { data: entry, error: insertError } = await supabase
        .from("waitlist")
        .upsert(
          {
            email: email.toLowerCase(),
            paid: false,
            referred_by: referredBy,
            amount_usd: price,
            referral_code: newReferralCode,
          },
          { onConflict: "email" }
        )
        .select()
        .single();

      if (insertError) {
        console.error("[waitlist] Insert error:", insertError);
        return NextResponse.json({ error: "Failed to join waitlist" }, { status: 500 });
      }

      return NextResponse.json({
        success: true,
        waitlist_id: entry.id,
        referral_code: newReferralCode,
        price,
        discount: referredBy ? true : false,
      });
    }

    // ─── Step 2: Payment initiation (with payment_method) ───
    if (!["stripe", "crypto"].includes(payment_method)) {
      return NextResponse.json({ error: "Invalid payment method" }, { status: 400 });
    }

    // Upsert waitlist entry with payment method
    const newReferralCode = existing?.referral_code || generateReferralCode();
    const { data: entry, error: insertError } = await supabase
      .from("waitlist")
      .upsert(
        {
          email: email.toLowerCase(),
          payment_method,
          paid: false,
          referred_by: referredBy,
          amount_usd: price,
          referral_code: newReferralCode,
        },
        { onConflict: "email" }
      )
      .select()
      .single();

    if (insertError) {
      console.error("[waitlist] Insert error:", insertError);
      return NextResponse.json({ error: "Failed to join waitlist" }, { status: 500 });
    }

    // Initiate payment
    if (payment_method === "crypto") {
      const apiKey = process.env.COINPAYPORTAL_API_KEY;
      const businessId = process.env.COINPAYPORTAL_BUSINESS_ID;

      if (!apiKey || !businessId) {
        return NextResponse.json({
          success: true,
          message: "Joined waitlist. Crypto checkout is temporarily unavailable — we'll email you when it's back online.",
          waitlist_id: entry.id,
          referral_code: newReferralCode,
          price,
        });
      }

      const res = await fetch(`${COINPAY_API}/payments/create`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${apiKey}`,
        },
        body: JSON.stringify({
          business_id: businessId,
          amount_usd: price,
          currency: "usdc_sol",
          description: `ThreatCrush Lifetime Access${referredBy ? " (Referral)" : ""}`,
          redirect_url: `${process.env.NEXT_PUBLIC_APP_URL || "https://threatcrush.com"}?paid=true&ref=${newReferralCode}`,
          webhook_url: `${process.env.NEXT_PUBLIC_APP_URL || "https://threatcrush.com"}/api/webhooks/coinpay`,
          metadata: {
            waitlist_id: entry.id,
            email: email.toLowerCase(),
            product: "lifetime_access",
            referral_code: referredBy,
          },
        }),
      });

      const paymentData = await res.json();
      const payment = paymentData.payment || paymentData;
      const paymentAddress = payment.payment_address || payment.address;

      await supabase
        .from("waitlist")
        .update({ payment_id: payment.id || paymentData.payment_id })
        .eq("id", entry.id);

      return NextResponse.json({
        success: true,
        waitlist_id: entry.id,
        referral_code: newReferralCode,
        price,
        discount: referredBy ? true : false,
        payment: {
          address: paymentAddress,
          checkout_url: paymentData.checkout_url || payment.checkout_url,
          amount_usd: price,
          currency: "USDC (Solana)",
          payment_id: payment.id || paymentData.payment_id,
        },
      });
    }

    // Stripe flow
    if (payment_method === "stripe") {
      const apiKey = process.env.COINPAYPORTAL_API_KEY;
      const businessId = process.env.COINPAYPORTAL_BUSINESS_ID;

      if (apiKey && businessId) {
        const res = await fetch(`${COINPAY_API}/stripe/payments/create`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${apiKey}`,
          },
          body: JSON.stringify({
            business_id: businessId,
            amount: price * 100,
            currency: "usd",
            description: `ThreatCrush Lifetime Access${referredBy ? " (Referral)" : ""}`,
            success_url: `${process.env.NEXT_PUBLIC_APP_URL || "https://threatcrush.com"}?paid=true&ref=${newReferralCode}`,
            cancel_url: `${process.env.NEXT_PUBLIC_APP_URL || "https://threatcrush.com"}?cancelled=true`,
            metadata: {
              waitlist_id: entry.id,
              email: email.toLowerCase(),
              product: "lifetime_access",
              referral_code: referredBy,
            },
          }),
        });

        const stripeData = await res.json();

        if (stripeData.checkout_url) {
          await supabase
            .from("waitlist")
            .update({ payment_id: stripeData.checkout_session_id })
            .eq("id", entry.id);

          return NextResponse.json({
            success: true,
            waitlist_id: entry.id,
            referral_code: newReferralCode,
            price,
            discount: referredBy ? true : false,
            payment: { checkout_url: stripeData.checkout_url, amount_usd: price },
          });
        }
      }

      return NextResponse.json({
        success: true,
        message: "Joined waitlist. Card checkout is temporarily unavailable — we'll email you when it's back online.",
        waitlist_id: entry.id,
        referral_code: newReferralCode,
        price,
      });
    }

    return NextResponse.json({
      success: true,
      waitlist_id: entry.id,
      referral_code: newReferralCode,
      price,
    });
  } catch (err) {
    console.error("[waitlist] Error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}

export async function GET() {
  return NextResponse.json({
    message: "ThreatCrush Waitlist API",
    pricing: "Contact sales for pricing",
  });
}
