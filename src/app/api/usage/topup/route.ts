import { NextRequest, NextResponse } from "next/server";

const COINPAY_API_URL = process.env.COINPAYPORTAL_API_URL || "https://api.coinpayportal.com";
const COINPAY_API_KEY = process.env.COINPAYPORTAL_API_KEY;
const COINPAY_BUSINESS_ID = process.env.COINPAYPORTAL_BUSINESS_ID;

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { email, amount_usd } = body;

    if (!email || !amount_usd) {
      return NextResponse.json({ error: "email and amount_usd required" }, { status: 400 });
    }

    if (amount_usd < 5 || amount_usd > 1000) {
      return NextResponse.json({ error: "Amount must be between $5 and $1,000" }, { status: 400 });
    }

    if (!COINPAY_API_KEY || !COINPAY_BUSINESS_ID) {
      return NextResponse.json({
        error: "Top-up not available. Set COINPAYPORTAL_API_KEY and COINPAYPORTAL_BUSINESS_ID.",
      }, { status: 503 });
    }

    // Create a top-up payment via CoinPayPortal
    const res = await fetch(
      `${COINPAY_API_URL}/api/businesses/${COINPAY_BUSINESS_ID}/usage/credits`,
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${COINPAY_API_KEY}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          email,
          amount_usd,
          description: `ThreatCrush AI usage credits — $${amount_usd}`,
          redirect_url: `${process.env.NEXT_PUBLIC_APP_URL || "https://threatcrush.com"}/usage?topup=success`,
        }),
      }
    );

    if (!res.ok) {
      const err = await res.text();
      console.error("[topup] CoinPayPortal error:", err);
      return NextResponse.json({ error: "Payment creation failed" }, { status: 502 });
    }

    const data = await res.json();

    return NextResponse.json({
      success: true,
      payment_url: data.payment_url || data.url,
      payment_id: data.payment_id || data.id,
      amount_usd,
    });
  } catch (error) {
    console.error("[topup] Error:", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
