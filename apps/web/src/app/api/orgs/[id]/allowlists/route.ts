import { NextRequest, NextResponse } from "next/server";
import { getSupabaseAdmin } from "@/lib/supabase";
import { allowlistValueError } from "@/lib/allowlist-value";

// GET /api/orgs/[id]/allowlists
export async function GET(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const authHeader = req.headers.get("authorization");
    const token = authHeader?.replace("Bearer ", "");
    if (!token) return NextResponse.json({ error: "Not authenticated" }, { status: 401 });

    const admin = getSupabaseAdmin();
    const { data: { user } } = await admin.auth.getUser(token);
    if (!user) return NextResponse.json({ error: "Invalid token" }, { status: 401 });

    const { id: orgId } = await params;

    const { data: membership } = await admin.from("organization_members")
      .select("role").eq("org_id", orgId).eq("user_id", user.id).single();
    // Guests see their teams' fleets and nothing org-wide.
    if (!membership || membership.role === "guest") return NextResponse.json({ error: "Not authorized" }, { status: 403 });

    const { data: entries, error } = await admin.from("allowlists")
      .select("*").eq("organization_id", orgId).order("created_at", { ascending: false });

    if (error) return NextResponse.json({ error: "Failed to fetch allowlists" }, { status: 500 });

    return NextResponse.json({ entries: entries || [] });
  } catch (err) {
    console.error("List allowlists error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}

// POST /api/orgs/[id]/allowlists
export async function POST(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const authHeader = req.headers.get("authorization");
    const token = authHeader?.replace("Bearer ", "");
    if (!token) return NextResponse.json({ error: "Not authenticated" }, { status: 401 });

    const admin = getSupabaseAdmin();
    const { data: { user } } = await admin.auth.getUser(token);
    if (!user) return NextResponse.json({ error: "Invalid token" }, { status: 401 });

    const { id: orgId } = await params;

    const { data: membership } = await admin.from("organization_members")
      .select("role").eq("org_id", orgId).eq("user_id", user.id).single();
    if (!membership || !["owner", "admin"].includes(membership.role)) {
      return NextResponse.json({ error: "Not authorized" }, { status: 403 });
    }

    const body = await req.json();
    const { type, value, note, label } = body as { type: string; value: string; note?: string; label?: string };

    if (!type || !value) return NextResponse.json({ error: "type and value required" }, { status: 400 });
    if (!["ip", "cidr", "user"].includes(type)) {
      return NextResponse.json({ error: "Invalid type" }, { status: 400 });
    }
    // Every daemon in the org stops blocking whatever is listed here.
    if (type !== "user") {
      const problem = allowlistValueError(value);
      if (problem) return NextResponse.json({ error: problem }, { status: 400 });
    }

    const { data: entry, error } = await admin.from("allowlists").insert({
      organization_id: orgId,
      type,
      value: type === "user" ? value : value.trim(),
      note: note || null,
      ...(typeof label === "string" && label.trim() ? { label: label.trim().slice(0, 100) } : {}),
    }).select().single();

    if (error) {
      if (error.code === "23505") return NextResponse.json({ error: "Already exists" }, { status: 409 });
      return NextResponse.json({ error: "Failed to add" }, { status: 500 });
    }

    return NextResponse.json({ entry }, { status: 201 });
  } catch (err) {
    console.error("Add allowlist error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}

// DELETE /api/orgs/[id]/allowlists
export async function DELETE(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const authHeader = req.headers.get("authorization");
    const token = authHeader?.replace("Bearer ", "");
    if (!token) return NextResponse.json({ error: "Not authenticated" }, { status: 401 });

    const admin = getSupabaseAdmin();
    const { data: { user } } = await admin.auth.getUser(token);
    if (!user) return NextResponse.json({ error: "Invalid token" }, { status: 401 });

    const { id: orgId } = await params;

    const { data: membership } = await admin.from("organization_members")
      .select("role").eq("org_id", orgId).eq("user_id", user.id).single();
    if (!membership || !["owner", "admin"].includes(membership.role)) {
      return NextResponse.json({ error: "Not authorized" }, { status: 403 });
    }

    const url = new URL(req.url);
    const entryId = url.searchParams.get("entry_id");
    if (!entryId) return NextResponse.json({ error: "entry_id required" }, { status: 400 });

    // A server's own IP is put back by its next heartbeat; removing it here
    // would only look like it worked. Remove the server instead.
    const { data: existing } = await admin.from("allowlists").select("source").eq("id", entryId).eq("organization_id", orgId).maybeSingle();
    if ((existing as { source?: string } | null)?.source === "server") {
      return NextResponse.json({ error: "This is a server's own IP and is kept automatically. Remove the server to drop it." }, { status: 409 });
    }

    const { error } = await admin.from("allowlists")
      .delete().eq("id", entryId).eq("organization_id", orgId);

    if (error) return NextResponse.json({ error: "Failed to delete" }, { status: 500 });

    return NextResponse.json({ success: true });
  } catch (err) {
    console.error("Delete allowlist error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}

// PATCH /api/orgs/[id]/allowlists?entry_id=…  { label?, note? } — rename or annotate an entry.
export async function PATCH(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const token = req.headers.get("authorization")?.replace("Bearer ", "");
    if (!token) return NextResponse.json({ error: "Not authenticated" }, { status: 401 });
    const admin = getSupabaseAdmin();
    const { data: { user } } = await admin.auth.getUser(token);
    if (!user) return NextResponse.json({ error: "Invalid token" }, { status: 401 });
    const { id: orgId } = await params;
    const { data: membership } = await admin.from("organization_members")
      .select("role").eq("org_id", orgId).eq("user_id", user.id).single();
    if (!membership || !["owner", "admin"].includes(membership.role)) {
      return NextResponse.json({ error: "Not authorized" }, { status: 403 });
    }
    const entryId = new URL(req.url).searchParams.get("entry_id");
    if (!entryId) return NextResponse.json({ error: "entry_id required" }, { status: 400 });
    const body = (await req.json().catch(() => ({}))) as { label?: unknown; note?: unknown };
    const patch: Record<string, string | null> = {};
    for (const k of ["label", "note"] as const) {
      if (body[k] === undefined) continue;
      if (body[k] !== null && typeof body[k] !== "string") return NextResponse.json({ error: `${k} must be a string` }, { status: 400 });
      patch[k] = body[k] === null || !(body[k] as string).trim() ? null : (body[k] as string).trim().slice(k === "label" ? 100 : 500);
    }
    if (!Object.keys(patch).length) return NextResponse.json({ error: "Nothing to update" }, { status: 400 });
    const { data: entry, error } = await admin.from("allowlists").update(patch)
      .eq("id", entryId).eq("organization_id", orgId).select().maybeSingle();
    if (error) return NextResponse.json({ error: "Failed to update" }, { status: 500 });
    if (!entry) return NextResponse.json({ error: "Not found" }, { status: 404 });
    return NextResponse.json({ entry });
  } catch (err) {
    console.error("Update allowlist error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
