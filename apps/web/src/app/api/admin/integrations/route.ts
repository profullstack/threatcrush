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
    .select("id, name, access_token, created_at, last_used_at, request_count")
    .order("created_at", { ascending: false });

  if (error) {
    return NextResponse.json({ error: "Failed to load integrations" }, { status: 500 });
  }
  return NextResponse.json({ integrations: data ?? [] });
}

export async function POST(req: NextRequest) {
  const guard = await requireAdmin(req);
  if (guard instanceof NextResponse) return guard;

  let body: { name?: string };
  try {
    body = (await req.json()) as { name?: string };
  } catch {
    body = {};
  }
  const name = (body.name || "Outrank").trim().slice(0, 100);
  const accessToken = `otrk_${randomBytes(32).toString("base64url")}`;

  const supabase = getSupabaseAdmin();
  const { data, error } = await supabase
    .from("outrank_integrations")
    .insert({ name, access_token: accessToken, created_by: guard.id })
    .select("id, name, access_token, created_at, last_used_at, request_count")
    .single();

  if (error || !data) {
    return NextResponse.json({ error: "Failed to create integration" }, { status: 500 });
  }
  return NextResponse.json({ integration: data });
}
