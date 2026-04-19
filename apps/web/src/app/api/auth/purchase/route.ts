import { NextRequest, NextResponse } from "next/server";
import { getSupabaseAdmin, getSupabaseClient } from "@/lib/supabase";
import { createCoinpayPayment, type CoinpayCurrency } from "@/lib/coinpay-client";

const LICENSE_PRICE_USD = 499;

export async function POST(req: NextRequest) {
  try {
    const authHeader = req.headers.get("authorization");
    if (!authHeader) {
      return NextResponse.json({ error: "Authentication required" }, { status: 401 });
    }

    const supabase = getSupabaseClient();
    const {
      data: { user },
    } = await supabase.auth.getUser(authHeader.replace("Bearer ", ""));

    if (!user) {
      return NextResponse.json({ error: "Invalid token" }, { status: 401 });
    }

    const admin = getSupabaseAdmin();
    const { data: profile, error: profileErr } = await admin
      .from("user_profiles")
      .select("email, license_status, wallet_address, payout_crypto")
      .eq("id", user.id)
      .single();

    if (profileErr || !profile) {
      return NextResponse.json({ error: "Profile not found" }, { status: 404 });
    }

    if (profile.license_status === "active") {
      return NextResponse.json({ error: "License already active" }, { status: 409 });
    }

    const body = await req.json().catch(() => ({}));
    const currency: CoinpayCurrency = body.currency || "usdc_sol";
    const validCurrencies: CoinpayCurrency[] = ["usdc_sol", "usdc_eth", "usdc_pol", "usdt", "btc", "eth", "sol", "pol"];
    if (!validCurrencies.includes(currency)) {
      return NextResponse.json(
        { error: `Invalid currency. Supported: ${validCurrencies.join(", ")}` },
        { status: 400 },
      );
    }

    const cp = await createCoinpayPayment({
      amount_usd: LICENSE_PRICE_USD,
      currency,
      description: "ThreatCrush Lifetime License",
      redirect_url: `${process.env.NEXT_PUBLIC_APP_URL || "https://threatcrush.com"}/account?payment=success`,
      metadata: {
        type: "license_purchase",
        user_id: user.id,
        email: profile.email,
        product: "lifetime_license",
      },
    });

    // Extract payment info from various response shapes
    const payment = (cp as any).payment || cp;
    const paymentId = payment.id || cp.payment_id;
    const checkoutUrl =
      payment.stripe_checkout_url || cp.checkout_url || payment.checkout_url;
    const paymentAddress =
      payment.payment_address || payment.address || cp.address;

    // Store purchase intent for webhook reconciliation
    const { error: insertErr } = await admin.from("license_purchases").insert({
      user_id: user.id,
      email: profile.email,
      coinpay_payment_id: paymentId,
      amount_usd: LICENSE_PRICE_USD,
      currency,
      status: "pending",
    });

    if (insertErr) {
      console.error("[purchase] Could not store purchase intent:", insertErr);
      // Continue anyway — webhook can still process
    }

    return NextResponse.json({
      success: true,
      payment_id: paymentId,
      checkout_url: checkoutUrl,
      payment_address: paymentAddress,
      amount_usd: LICENSE_PRICE_USD,
      currency,
    });
  } catch (err) {
    console.error("[purchase] Error:", err);
    return NextResponse.json(
      { error: (err as Error).message || "Internal server error" },
      { status: 500 },
    );
  }
}
