import { NextRequest, NextResponse } from "next/server";
import { getCoinpayPaymentStatus } from "@/lib/coinpay-client";
import { getSupabaseAdmin } from "@/lib/supabase";

export async function GET(
  req: NextRequest,
  { params }: { params: Promise<{ paymentId: string }> }
) {
  const { paymentId } = await params;

  if (!paymentId) {
    return NextResponse.json({ error: "paymentId required" }, { status: 400 });
  }

  // TC-23: this proxied CoinPay for any payment id with no session at all.
  // Only the user the deposit belongs to may poll it.
  const token = req.headers.get("authorization")?.replace("Bearer ", "");
  if (!token) {
    return NextResponse.json({ error: "Not authenticated" }, { status: 401 });
  }

  const admin = getSupabaseAdmin();
  const { data: { user } } = await admin.auth.getUser(token);
  if (!user) {
    return NextResponse.json({ error: "Not authenticated" }, { status: 401 });
  }

  const { data: deposit } = await admin
    .from("credit_deposits")
    .select("id")
    .eq("coinpay_payment_id", paymentId)
    .eq("user_id", user.id)
    .maybeSingle();

  if (!deposit) {
    return NextResponse.json({ error: "Payment not found" }, { status: 404 });
  }

  const cpStatus = await getCoinpayPaymentStatus(paymentId);

  return NextResponse.json({
    status: cpStatus.status,
    tx_hash: cpStatus.tx_hash ?? null,
  });
}
