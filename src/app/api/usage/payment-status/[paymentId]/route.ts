import { NextRequest, NextResponse } from "next/server";
import { getCoinpayPaymentStatus } from "@/lib/coinpay-client";

export async function GET(
  _req: NextRequest,
  { params }: { params: Promise<{ paymentId: string }> }
) {
  const { paymentId } = await params;

  if (!paymentId) {
    return NextResponse.json({ error: "paymentId required" }, { status: 400 });
  }

  const cpStatus = await getCoinpayPaymentStatus(paymentId);

  return NextResponse.json({
    status: cpStatus.status,
    tx_hash: cpStatus.tx_hash ?? null,
  });
}
