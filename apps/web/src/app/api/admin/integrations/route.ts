import { NextRequest, NextResponse } from "next/server";
import { randomBytes } from "node:crypto";
import { requireAdmin } from "@/lib/admin-guard";
import { getSupabaseAdmin } from "@/lib/supabase";

export async function GET(req: NextRequest) {
  const guard = await requireAdmin(req);
  if (guard instanceof NextResponse) return guard;

  const supabase = getSupabaseAdmin();
  const { data, error } = await supabase
    .from("outrank_integrations")
    .select("id, name, kind, access_token, created_at, last_used_at, request_count")
    .order("created_at", { ascending: false });

  if (error) {
    return NextResponse.json({ error: "Failed to load integrations" }, { status: 500 });
  }
  return NextResponse.json({ integrations: data ?? [] });
}

const ALLOWED_KINDS = ["outrank", "crawlproof"] as const;
type Kind = (typeof ALLOWED_KINDS)[number];

export async function POST(req: NextRequest) {
  const guard = await requireAdmin(req);
  if (guard instanceof NextResponse) return guard;

  let body: { name?: string; kind?: string };
  try {
    body = (await req.json()) as { name?: string; kind?: string };
  } catch {
    body = {};
  }
  const kind: Kind = (ALLOWED_KINDS as readonly string[]).includes(body.kind ?? "")
    ? (body.kind as Kind)
    : "outrank";
  const defaultName = kind === "crawlproof" ? "Crawlproof" : "Outrank";
  const name = (body.name || defaultName).trim().slice(0, 100);
  // Token prefix encodes the source so a leaked secret is identifiable
  // at a glance, and a Crawlproof bearer pasted into the Outrank flow
  // (or vice versa) is obviously wrong.
  const prefix = kind === "crawlproof" ? "cp_lx_" : "otrk_";
  const accessToken = `${prefix}${randomBytes(32).toString("base64url")}`;

  const supabase = getSupabaseAdmin();
  const { data, error } = await supabase
    .from("outrank_integrations")
    .insert({ name, kind, access_token: accessToken, created_by: guard.id })
    .select("id, name, kind, access_token, created_at, last_used_at, request_count")
    .single();

  if (error || !data) {
    return NextResponse.json({ error: "Failed to create integration" }, { status: 500 });
  }
  return NextResponse.json({ integration: data });
}
