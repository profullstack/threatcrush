import { NextRequest, NextResponse } from "next/server";
import { createCoinpayPayment, type CoinpayCurrency } from "@/lib/coinpay-client";
import { getSupabaseClient, getSupabaseAdmin } from "@/lib/supabase";

export async function POST(request: NextRequest) {
  try {
    // Authenticate user
    const authHeader = request.headers.get("authorization");
    const token = authHeader?.replace("Bearer ", "");
    if (!token) {
      return NextResponse.json({ error: "Not authenticated" }, { status: 401 });
    }

    const supabase = getSupabaseClient();
    const { data: { user }, error: authError } = await supabase.auth.getUser(token);
    if (authError || !user?.email) {
      return NextResponse.json({ error: "Invalid or expired token" }, { status: 401 });
    }

    const body = await request.json();
    const { currency } = body;

    // Coerce and validate the amount (mirrors funding/create-invoice/route.ts).
    // Without Number()/isFinite, a non-numeric amount_usd like "abc" is truthy
    // (so it passes the presence check) and both "abc" < 1 and "abc" > 10000 are
    // false, so it slipped through and was sent to CoinPay / stored on the
    // credit_deposits row as a garbage amount.
    const amount_usd = Number(body.amount_usd);
    if (!Number.isFinite(amount_usd) || amount_usd < 1 || amount_usd > 10000) {
      return NextResponse.json({ error: "Amount must be between $1 and $10,000" }, { status: 400 });
    }

    const coinpayCurrency: CoinpayCurrency = currency || "usdc_sol";
    const validCurrencies: CoinpayCurrency[] = ["usdc_sol", "usdc_eth", "usdc_pol", "usdt", "btc", "eth", "sol", "pol"];
    if (!validCurrencies.includes(coinpayCurrency)) {
      return NextResponse.json(
        { error: `Invalid currency. Supported: ${validCurrencies.join(", ")}` },
        { status: 400 },
      );
    }

    const cp = await createCoinpayPayment({
      amount_usd,
      currency: coinpayCurrency,
      description: `ThreatCrush AI Usage Credits — $${amount_usd}`,
      redirect_url: `${process.env.NEXT_PUBLIC_APP_URL || "https://threatcrush.com"}/usage?topup=success`,
      metadata: { type: "usage_topup", user_id: user.id, email: user.email },
    });

    const payment = (cp as any).payment || cp;
    const checkoutUrl = payment.stripe_checkout_url || cp.checkout_url || payment.checkout_url;
    const paymentAddress = payment.payment_address || payment.address || cp.address;
    const paymentId = payment.id || cp.payment_id;
    const amountCrypto = payment.amount_crypto ?? payment.crypto_amount ?? cp.amount_crypto ?? null;

    if (!paymentId) {
      return NextResponse.json({ error: "CoinPay did not return a payment id" }, { status: 502 });
    }

    // Store pending credit deposit locally
    const admin = getSupabaseAdmin();
    await admin.from("credit_deposits").insert({
      user_id: user.id,
      email: user.email,
      coinpay_payment_id: paymentId,
      amount_usd,
      status: "pending",
    });

    return NextResponse.json({
      success: true,
      payment_id: paymentId,
      checkout_url: checkoutUrl,
      payment_address: paymentAddress,
      amount_usd,
      amount_crypto: amountCrypto,
      currency: coinpayCurrency,
    });
  } catch (error) {
    console.error("[topup] Error:", error);
    return NextResponse.json({ error: (error as Error).message || "Internal server error" }, { status: 500 });
  }
}
