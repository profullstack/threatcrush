import { randomBytes } from "node:crypto";
import { NextRequest, NextResponse } from "next/server";
import { getAuthenticatedRequestUser, unauthorized } from "@/lib/api-auth";
import { getSupabaseAdmin } from "@/lib/supabase";

// The public report link for an organization (/r/<token>). Owners and admins
// create, read and revoke it; there is at most one live link per org.

async function requireAdmin(req: NextRequest, orgId: string) {
  const user = await getAuthenticatedRequestUser(req);
  if (!user) return { error: unauthorized() };
  const { data: membership } = await getSupabaseAdmin()
    .from("organization_members")
    .select("role")
    .eq("org_id", orgId)
    .eq("user_id", user.userId)
    .maybeSingle();
  if (!membership || !["owner", "admin"].includes(membership.role)) {
    return { error: NextResponse.json({ error: "Only owners and admins can manage the public report" }, { status: 403 }) };
  }
  return { userId: user.userId };
}

function shareUrl(token: string) {
  const appUrl = (process.env.NEXT_PUBLIC_APP_URL || "https://threatcrush.com").replace(/\/$/, "");
  return `${appUrl}/r/${token}`;
}

async function liveShare(orgId: string) {
  const { data } = await getSupabaseAdmin()
    .from("report_shares")
    .select("token, created_at, last_viewed_at")
    .eq("org_id", orgId)
    .is("revoked_at", null)
    .maybeSingle();
  return data;
}

type Params = { params: Promise<{ id: string }> };

// GET — the live link, if any.
export async function GET(req: NextRequest, { params }: Params) {
  try {
    const { id: orgId } = await params;
    const auth = await requireAdmin(req, orgId);
    if (auth.error) return auth.error;
    const share = await liveShare(orgId);
    return NextResponse.json({
      share: share ? { url: shareUrl(share.token), created_at: share.created_at, last_viewed_at: share.last_viewed_at } : null,
    });
  } catch (err) {
    console.error("Report share GET error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}

// POST — create the link, or return the live one.
export async function POST(req: NextRequest, { params }: Params) {
  try {
    const { id: orgId } = await params;
    const auth = await requireAdmin(req, orgId);
    if (auth.error) return auth.error;

    const existing = await liveShare(orgId);
    if (existing) {
      return NextResponse.json({ share: { url: shareUrl(existing.token), created_at: existing.created_at, last_viewed_at: existing.last_viewed_at } });
    }

    const token = randomBytes(32).toString("base64url");
    const { data, error } = await getSupabaseAdmin()
      .from("report_shares")
      .insert({ org_id: orgId, token, created_by: auth.userId })
      .select("token, created_at, last_viewed_at")
      .single();
    if (error || !data) {
      console.error("Report share create failed:", error);
      return NextResponse.json({ error: "Could not create the link" }, { status: 500 });
    }
    return NextResponse.json({ share: { url: shareUrl(data.token), created_at: data.created_at, last_viewed_at: null } }, { status: 201 });
  } catch (err) {
    console.error("Report share POST error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}

// DELETE — revoke the live link. Its URL then answers 404.
export async function DELETE(req: NextRequest, { params }: Params) {
  try {
    const { id: orgId } = await params;
    const auth = await requireAdmin(req, orgId);
    if (auth.error) return auth.error;
    await getSupabaseAdmin()
      .from("report_shares")
      .update({ revoked_at: new Date().toISOString() })
      .eq("org_id", orgId)
      .is("revoked_at", null);
    return NextResponse.json({ share: null });
  } catch (err) {
    console.error("Report share DELETE error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
