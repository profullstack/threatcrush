import { NextRequest, NextResponse } from "next/server";
import { getSupabaseAdmin, getSupabaseClient } from "@/lib/supabase";
import { parseWalletPaste, type PayoutCoin } from "@/lib/wallet-import";

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

    const body = await req.json();
    const pasteText: string = body.paste_text || "";

    if (!pasteText.trim()) {
      return NextResponse.json({ error: "No wallet data provided" }, { status: 400 });
    }

    const parsed = parseWalletPaste(pasteText);

    if (parsed.wallets.length === 0) {
      return NextResponse.json({
        error: "No valid wallet addresses found. Paste from CoinPay 'Copy All Addresses' format.",
        details: {
          invalidLines: parsed.invalidLines.slice(0, 5),
          unsupportedCoins: parsed.unsupportedCoins,
        },
      }, { status: 400 });
    }

    const admin = getSupabaseAdmin();
    const imported: Array<{ coin: string; address: string }> = [];
    const errors: Array<{ coin: string; error: string }> = [];

    for (const wallet of parsed.wallets) {
      const coin = wallet.coin as PayoutCoin;
      // Map CoinPay format to ThreatCrush payout_crypto format
      const payoutCrypto = mapCoinToPayoutCrypto(coin);

      const { error: updateErr } = await admin
        .from("user_profiles")
        .update({ wallet_address: wallet.address, payout_crypto: payoutCrypto })
        .eq("id", user.id);

      if (updateErr) {
        errors.push({ coin: wallet.coin, error: updateErr.message });
      } else {
        imported.push({ coin: wallet.coin, address: wallet.address });
      }
    }

    return NextResponse.json({
      success: true,
      imported,
      errors,
      skipped: {
        invalidLines: parsed.invalidLines,
        unsupportedCoins: parsed.unsupportedCoins,
        duplicateCoins: parsed.duplicateCoins,
      },
    });
  } catch (err) {
    console.error("[wallet-import] Error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}

/** Map CoinPay currency names to ThreatCrush payout_crypto options */
function mapCoinToPayoutCrypto(coin: string): string {
  const map: Record<string, string> = {
    "BTC": "BTC",
    "ETH": "ETH",
    "SOL": "SOL",
    "USDT": "USDT",
    "USDC": "USDC",
    "USDC_ETH": "USDC",
    "USDC_SOL": "USDC",
    "USDC_POL": "USDC",
    "USDT_ETH": "USDT",
    "USDT_SOL": "USDT",
    "USDT_POL": "USDT",
    "BNB": "BNB",
    "XRP": "XRP",
    "ADA": "ADA",
    "DOGE": "DOGE",
    "POL": "POL",
    "BCH": "BCH",
  };
  return map[coin] || coin;
}
