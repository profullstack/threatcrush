import { NextRequest, NextResponse } from "next/server";
import { getAuthenticatedRequestUser, getAdminClient, unauthorized } from "@/lib/api-auth";

type InstalledRow = {
  module_id: string;
  module_slug: string;
  version: string;
  status: string;
  installed_at: string;
  updated_at: string;
};

export async function GET(request: NextRequest) {
  const user = await getAuthenticatedRequestUser(request);
  if (!user) return unauthorized();

  const sb = getAdminClient();
  const { data, error } = await sb
    .from("user_installed_modules")
    .select("module_id, module_slug, version, status, installed_at, updated_at")
    .eq("user_id", user.userId)
    .order("installed_at", { ascending: false });

  if (error) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }

  return NextResponse.json({ installed: (data || []) as InstalledRow[] });
}

export async function PATCH(request: NextRequest) {
  const user = await getAuthenticatedRequestUser(request);
  if (!user) return unauthorized();

  const body = await request.json().catch(() => null) as { slug?: unknown; status?: unknown } | null;
  const slug = typeof body?.slug === "string" ? body.slug : "";
  const status = typeof body?.status === "string" ? body.status : "";

  if (!slug) {
    return NextResponse.json({ error: "slug is required" }, { status: 400 });
  }
  if (!["active", "disabled", "removed"].includes(status)) {
    return NextResponse.json({ error: "status must be active, disabled, or removed" }, { status: 400 });
  }

  const sb = getAdminClient();
  const { data, error } = await sb
    .from("user_installed_modules")
    .update({ status, updated_at: new Date().toISOString() })
    .eq("user_id", user.userId)
    .eq("module_slug", slug)
    .select("module_id, module_slug, version, status, installed_at, updated_at")
    .single();

  if (error) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }

  return NextResponse.json({ installed: data });
}
