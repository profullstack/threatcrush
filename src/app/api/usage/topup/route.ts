import { NextRequest, NextResponse } from "next/server";
import { createCoinpayPayment, type CoinpayCurrency } from "@/lib/coinpay-client";

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { amount_usd, currency } = body;

    if (!amount_usd) {
      return NextResponse.json({ error: "amount_usd required" }, { status: 400 });
    }

    if (amount_usd < 5 || amount_usd > 10000) {
      return NextResponse.json({ error: "Amount must be between $5 and $10,000" }, { status: 400 });
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
      metadata: { type: "usage_topup" },
    });

    const payment = (cp as any).payment || cp;
    const checkoutUrl = payment.stripe_checkout_url || cp.checkout_url || payment.checkout_url;
    const paymentAddress = payment.payment_address || payment.address || cp.address;
    const paymentId = payment.id || cp.payment_id;

    if (!paymentId) {
      return NextResponse.json({ error: "CoinPay did not return a payment id" }, { status: 502 });
    }

    return NextResponse.json({
      success: true,
      payment_id: paymentId,
      checkout_url: checkoutUrl,
      payment_address: paymentAddress,
      amount_usd,
      currency: coinpayCurrency,
    });
  } catch (error) {
    console.error("[topup] Error:", error);
    return NextResponse.json({ error: (error as Error).message || "Internal server error" }, { status: 500 });
  }
}
