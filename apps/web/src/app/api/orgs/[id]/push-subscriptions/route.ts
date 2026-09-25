import { NextRequest, NextResponse } from "next/server";
import { getAdminClient, getAuthenticatedRequestUser, unauthorized } from "@/lib/api-auth";

// Expo push tokens look like `ExponentPushToken[xxxxxxxxxxxxxxxxxxxxxx]` (older
// SDKs: `ExpoPushToken[...]`). Storing anything else would let a client park
// arbitrary URLs in a table a sender will later POST to.
const EXPO_TOKEN = /^Expo(nent)?PushToken\[[A-Za-z0-9_-]{1,200}\]$/;
const PLATFORMS = ["ios", "android"];

async function readJsonObject(req: NextRequest): Promise<Record<string, unknown> | null> {
  try {
    const body: unknown = await req.json();
    if (!body || typeof body !== "object" || Array.isArray(body)) return null;
    return body as Record<string, unknown>;
  } catch {
    return null;
  }
}

// POST /api/orgs/[id]/push-subscriptions — register this device's Expo push
// token for alerts from the org. One row per (user, token): registering again
// from another org moves the device to that org.
//
// Rows share push_subscriptions with PWA Web Push. Expo rows are the ones whose
// `endpoint` is an Expo token and whose `keys.provider` is "expo".
export async function POST(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) {
  try {
    const auth = await getAuthenticatedRequestUser(req);
    if (!auth) return unauthorized();

    const { id: orgId } = await params;
    const admin = getAdminClient();

    const { data: membership } = await admin
      .from("organization_members")
      .select("role")
      .eq("org_id", orgId)
      .eq("user_id", auth.userId)
      .maybeSingle();
    if (!membership) return NextResponse.json({ error: "Not authorized" }, { status: 403 });

    const body = await readJsonObject(req);
    if (!body) return NextResponse.json({ error: "Invalid JSON body" }, { status: 400 });

    const { token, platform } = body;
    if (typeof token !== "string" || !EXPO_TOKEN.test(token)) {
      return NextResponse.json({ error: "token must be an Expo push token" }, { status: 400 });
    }
    if (typeof platform !== "string" || !PLATFORMS.includes(platform)) {
      return NextResponse.json({ error: "platform must be ios or android" }, { status: 400 });
    }

    const { data: subscription, error } = await admin
      .from("push_subscriptions")
      .upsert(
        {
          user_id: auth.userId,
          organization_id: orgId,
          endpoint: token,
          keys: { provider: "expo", platform },
        },
        { onConflict: "user_id,endpoint" },
      )
      .select("id, organization_id, created_at")
      .single();

    if (error || !subscription) {
      console.error("Register push subscription error:", error);
      return NextResponse.json({ error: "Failed to register device" }, { status: 500 });
    }

    return NextResponse.json({ subscription });
  } catch (err) {
    console.error("Register push subscription error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}

// DELETE /api/orgs/[id]/push-subscriptions — forget this device (sign-out).
// Scoped to the caller's own rows, so it deliberately does not require current
// membership: someone removed from the org must still be able to unregister.
export async function DELETE(req: NextRequest) {
  try {
    const auth = await getAuthenticatedRequestUser(req);
    if (!auth) return unauthorized();

    const body = await readJsonObject(req);
    if (!body) return NextResponse.json({ error: "Invalid JSON body" }, { status: 400 });

    const { token } = body;
    if (typeof token !== "string" || !EXPO_TOKEN.test(token)) {
      return NextResponse.json({ error: "token must be an Expo push token" }, { status: 400 });
    }

    const { error } = await getAdminClient()
      .from("push_subscriptions")
      .delete()
      .eq("user_id", auth.userId)
      .eq("endpoint", token);

    if (error) {
      console.error("Delete push subscription error:", error);
      return NextResponse.json({ error: "Failed to unregister device" }, { status: 500 });
    }

    return NextResponse.json({ success: true });
  } catch (err) {
    console.error("Delete push subscription error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
