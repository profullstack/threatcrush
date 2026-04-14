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

    const admin = getSupabaseAdmin();

    // Check the credit_deposits table for this payment
    const { data: deposit, error } = await admin
      .from("credit_deposits")
      .select("*")
      .eq("coinpay_payment_id", paymentId)
      .single();

    if (error && error.code !== "PGRST116") {
      console.error("[payment-status] DB error:", error);
    }

    // If we have a local deposit, check its status first
    if (deposit) {
      // If already confirmed/forwarded locally, return immediately
      if (deposit.status === "confirmed" || deposit.status === "forwarded") {
        return NextResponse.json({
          status: deposit.status,
          amount_usd: deposit.amount_usd,
          currency: "usdc_sol",
          payment_id: deposit.coinpay_payment_id,
        });
      }

      // If pending locally, also check CoinPay for real-time status
      try {
        const cpStatus = await getCoinpayPaymentStatus(paymentId);
        if (cpStatus.status === "confirmed" || cpStatus.status === "forwarded") {
          // Update local record to match
          await admin
            .from("credit_deposits")
            .update({ status: cpStatus.status, confirmed_at: new Date().toISOString() })
            .eq("coinpay_payment_id", paymentId);
        }
        return NextResponse.json({
          status: cpStatus.status,
          amount_usd: deposit.amount_usd,
          currency: "usdc_sol",
          payment_id: deposit.coinpay_payment_id,
        });
      } catch {
        // CoinPay check failed, return local status
        return NextResponse.json({
          status: deposit.status,
          amount_usd: deposit.amount_usd,
          currency: "usdc_sol",
          payment_id: deposit.coinpay_payment_id,
        });
      }
    }

    // No local deposit found, check CoinPay directly
    try {
      const cpStatus = await getCoinpayPaymentStatus(paymentId);
      return NextResponse.json({
        status: cpStatus.status,
        payment_id: paymentId,
      });
    } catch {
      return NextResponse.json({ status: "pending", payment_id: paymentId });
    }
  } catch (error) {
    console.error("[payment-status] Error:", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
