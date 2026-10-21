import { NextRequest, NextResponse } from "next/server";
import { randomBytes } from "node:crypto";
import { createClient, type SupabaseClient } from "@supabase/supabase-js";
import {
  createCoinpayPayment,
  isCoinpayCurrency,
  SUPPORTED_CURRENCIES,
  type CoinpayCurrency,
} from "@/lib/coinpay-client";

let supabase: SupabaseClient | undefined;
function getSupabase() {
  if (supabase) return supabase;
  const url = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!url || !key) throw new Error("Supabase not configured");
  // Memoized: a new client per request leaks auth/realtime timers → OOM.
  supabase = createClient(url, key, {
    auth: { persistSession: false, autoRefreshToken: false },
  });
  return supabase;
}

const PRICE_FULL = 499;
const PRICE_REFERRAL = 399;

function generateReferralCode(): string {
  // TC-30: Math.random() is not a CSPRNG. A referral code decides who gets paid
  // and unlocks the discounted price, so it must not be predictable.
  return randomBytes(6).toString("base64url");
}

export async function POST(request: NextRequest) {
  let body: { email?: unknown; payment_method?: string; referral_code?: string; currency?: unknown };
  try {
    const parsed: unknown = await request.json();
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      return NextResponse.json({ error: "JSON object is required" }, { status: 400 });
    }
    body = parsed as typeof body;
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }

  try {
    const { email, payment_method, referral_code, currency: rawCurrency } = body;

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
    if (!["stripe", "crypto", "paypal"].includes(payment_method)) {
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

    // Initiate payment: any coin the business takes, or PayPal. "stripe" is
    // the old card option; there is no card rail any more, so it opens PayPal.
    const site = process.env.NEXT_PUBLIC_APP_URL || "https://threatcrush.com";
    const currency: CoinpayCurrency =
      payment_method === "crypto"
        ? isCoinpayCurrency(rawCurrency) && rawCurrency !== "paypal"
          ? rawCurrency
          : "usdc_sol"
        : "paypal";
    try {
      const cp = await createCoinpayPayment({
        amount_usd: price,
        currency,
        description: `ThreatCrush Lifetime Access${referredBy ? " (Referral)" : ""}`,
        redirect_url: `${site}?paid=true&ref=${newReferralCode}`,
        cancel_url: `${site}?cancelled=true`,
        metadata: {
          type: "waitlist",
          waitlist_id: entry.id,
          email: email.toLowerCase(),
          account_id: entry.id,
          product: "lifetime_access",
          referral_code: referredBy,
        },
      });
      const payment = (cp.payment ?? {}) as Record<string, unknown>;
      const paymentId = (payment.id as string | undefined) ?? cp.payment_id;
      await supabase.from("waitlist").update({ payment_id: paymentId }).eq("id", entry.id);
      return NextResponse.json({
        success: true,
        waitlist_id: entry.id,
        referral_code: newReferralCode,
        price,
        discount: referredBy ? true : false,
        payment: {
          address: (payment.payment_address as string | undefined) ?? cp.address ?? null,
          checkout_url: cp.checkout_url ?? (payment.checkout_url as string | undefined) ?? null,
          amount_usd: price,
          currency: SUPPORTED_CURRENCIES[currency].name,
          payment_id: paymentId,
        },
      });
    } catch (err) {
      console.error("[waitlist] payment create failed", (err as Error).message);
      return NextResponse.json({
        success: true,
        message: "Joined waitlist. Checkout is temporarily unavailable; we'll email you when it's back online.",
        waitlist_id: entry.id,
        referral_code: newReferralCode,
        price,
      });
    }
  } catch (err) {
    console.error("[waitlist] Error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}

export async function GET() {
  return NextResponse.json({
    message: "ThreatCrush Waitlist API",
    pricing: "https://threatcrush.com/pricing",
  });
}
