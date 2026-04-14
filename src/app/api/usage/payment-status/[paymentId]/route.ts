import { NextRequest, NextResponse } from "next/server";

const COINPAY_BASE_URL = (process.env.COINPAYPORTAL_API_URL || "https://coinpayportal.com").replace(/\/$/, '') + '/api';
const COINPAY_API_KEY = process.env.COINPAYPORTAL_API_KEY;

export async function GET(
  _req: NextRequest,
  { params }: { params: Promise<{ paymentId: string }> }
) {
  try {
    const { paymentId } = await params;

    if (!paymentId) {
      return NextResponse.json({ error: "paymentId required" }, { status: 400 });
    }

    if (!COINPAY_API_KEY) {
      return NextResponse.json({ error: "Not configured" }, { status: 503 });
    }

    const res = await fetch(`${COINPAY_BASE_URL}/payments/${paymentId}`, {
      headers: {
        Authorization: `Bearer ${COINPAY_API_KEY}`,
      },
      cache: "no-store",
    });

    if (!res.ok) {
      const text = await res.text();
      console.error("[payment-status] CoinPay error:", res.status, text);
      return NextResponse.json({ error: "Failed to fetch payment status" }, { status: 502 });
    }

    const data = await res.json();
    const payment = data.payment || data;

    return NextResponse.json({
      status: payment.status || "pending",
      amount_usd: payment.amount_usd,
      currency: payment.currency,
      payment_address: payment.payment_address,
      tx_hash: payment.tx_hash,
    });
  } catch (error) {
    console.error("[payment-status] Error:", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
