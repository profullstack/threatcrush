import { NextRequest, NextResponse } from "next/server";
import { getSupabaseAdmin } from "@/lib/supabase";

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
      return NextResponse.json({ error: "Failed to fetch payment status" }, { status: 502 });
    }

    if (!deposit) {
      return NextResponse.json({ status: "pending", payment_id: paymentId });
    }

    return NextResponse.json({
      status: deposit.status,
      amount_usd: deposit.amount_usd,
      currency: "usdc_sol",
      payment_id: deposit.coinpay_payment_id,
    });
  } catch (error) {
    console.error("[payment-status] Error:", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
