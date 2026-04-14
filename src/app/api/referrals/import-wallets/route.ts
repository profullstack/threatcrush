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

    // Fetch existing wallets to know which to update vs insert
    const { data: existing } = await admin
      .from("referral_wallets")
      .select("cryptocurrency")
      .eq("user_id", user.id);

    const existingCoins = new Set(existing?.map((w) => w.cryptocurrency) || []);

    const imported: Array<{ coin: string; address: string; action: "inserted" | "updated" }> = [];
    const errors: Array<{ coin: string; error: string }> = [];

    for (const wallet of parsed.wallets) {
      const coin = wallet.coin;
      const isUpdate = existingCoins.has(coin);

      const { error: upsertErr } = await admin.from("referral_wallets").upsert({
        user_id: user.id,
        cryptocurrency: coin,
        wallet_address: wallet.address,
        label: wallet.label || null,
      }, {
        onConflict: "user_id,cryptocurrency",
      });

      if (upsertErr) {
        errors.push({ coin: wallet.coin, error: upsertErr.message });
      } else {
        imported.push({
          coin: wallet.coin,
          address: wallet.address,
          action: isUpdate ? "updated" : "inserted",
        });
      }
    }

    // If no primary wallet exists, make the first imported one primary
    if (imported.length > 0) {
      const { data: primaryCheck } = await admin
        .from("referral_wallets")
        .select("id")
        .eq("user_id", user.id)
        .eq("is_primary", true)
        .maybeSingle();

      if (!primaryCheck) {
        await admin
          .from("referral_wallets")
          .update({ is_primary: true })
          .eq("user_id", user.id)
          .eq("cryptocurrency", imported[0].coin);
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

export async function GET(req: NextRequest) {
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

    const admin = getSupabaseAdmin();
    const { data: wallets, error } = await admin
      .from("referral_wallets")
      .select("*")
      .eq("user_id", user.id)
      .order("cryptocurrency", { ascending: true });

    if (error) {
      return NextResponse.json({ error: error.message }, { status: 500 });
    }

    return NextResponse.json({ wallets: wallets || [] });
  } catch (err) {
    console.error("[wallet-import] GET error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}

export async function DELETE(req: NextRequest) {
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

    const { searchParams } = new URL(req.url);
    const coin = searchParams.get("cryptocurrency");

    if (!coin) {
      return NextResponse.json({ error: "cryptocurrency query param required" }, { status: 400 });
    }

    const admin = getSupabaseAdmin();
    const { error } = await admin
      .from("referral_wallets")
      .delete()
      .eq("user_id", user.id)
      .eq("cryptocurrency", coin);

    if (error) {
      return NextResponse.json({ error: error.message }, { status: 500 });
    }

    return NextResponse.json({ success: true });
  } catch (err) {
    console.error("[wallet-import] DELETE error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
