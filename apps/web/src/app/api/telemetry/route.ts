import { NextResponse, type NextRequest } from "next/server";
import { getSupabaseAdmin } from "@/lib/supabase";
import { MAX_BODY, parsePing } from "@/lib/usage-ping";

// POST /api/telemetry: stores one anonymous CLI usage ping (see lib/usage-ping.ts).
// No IP or user is recorded.

export async function POST(request: NextRequest) {
  const text = await request.text().catch(() => "");
  if (!text || text.length > MAX_BODY) return NextResponse.json({ error: "bad ping" }, { status: 400 });
  let body: unknown;
  try {
    body = JSON.parse(text);
  } catch {
    return NextResponse.json({ error: "bad ping" }, { status: 400 });
  }
  const row = parsePing(body);
  if (!row) return NextResponse.json({ error: "bad ping" }, { status: 400 });
  const { error } = await getSupabaseAdmin().from("cli_usage_pings").insert(row);
  if (error) {
    console.error("[telemetry] insert failed", error.message);
    return NextResponse.json({ error: "not stored" }, { status: 500 });
  }
  return NextResponse.json({ ok: true }, { status: 202 });
}
