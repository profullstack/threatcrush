import { NextRequest, NextResponse } from "next/server";
import { getSupabaseAdmin } from "@/lib/supabase";
import { getCoinpayPaymentStatus } from "@/lib/coinpay-client";

export async function GET(
  _req: NextRequest,
  { params }: { params: Promise<{ paymentId: string }> }
) {
  try {
    const { paymentId } = await params;

    if (!paymentId) {
      return NextResponse.json({ error: "paymentId required" }, { status: 400 });
    }

    // Always check CoinPay first — it's the source of truth
    const cpStatus = await getCoinpayPaymentStatus(paymentId);

    // Sync local record
    const admin = getSupabaseAdmin();
    const { data: deposit } = await admin
      .from("credit_deposits")
      .select("user_id, amount_usd")
      .eq("coinpay_payment_id", paymentId)
      .maybeSingle();

    if (deposit && (cpStatus.status === "confirmed" || cpStatus.status === "forwarded")) {
      await admin
        .from("credit_deposits")
        .update({ status: cpStatus.status, confirmed_at: new Date().toISOString() })
        .eq("coinpay_payment_id", paymentId);
    }

    return NextResponse.json({
      status: cpStatus.status,
      amount_usd: deposit?.amount_usd ?? null,
      currency: "usdc_sol",
      payment_id: paymentId,
      tx_hash: cpStatus.tx_hash ?? null,
    });
  } catch (error) {
    console.error("[payment-status] Error:", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
