import { NextRequest, NextResponse } from "next/server";
import { getAdminClient, getAuthenticatedRequestUser, unauthorized } from "@/lib/api-auth";
import { isAllowedWebPushEndpoint } from "@/lib/push/webpush";

// Expo push tokens look like `ExponentPushToken[xxxxxxxxxxxxxxxxxxxxxx]` (older
// SDKs: `ExpoPushToken[...]`). Storing anything else would let a client park
// arbitrary URLs in a table a sender will later POST to.
const EXPO_TOKEN = /^Expo(nent)?PushToken\[[A-Za-z0-9_-]{1,200}\]$/;
const PLATFORMS = ["ios", "android"];
// Web Push keys are unpadded base64url: p256dh is a 65-byte P-256 point
// (87 chars), auth a 16-byte secret (22 chars). Allow padding and some slack.
const P256DH = /^[A-Za-z0-9_-]{80,100}={0,2}$/;
const AUTH_SECRET = /^[A-Za-z0-9_-]{16,32}={0,2}$/;
const MAX_ENDPOINT_LENGTH = 2048;

type SubscriptionInput =
  | { ok: true; endpoint: string; keys: Record<string, string> }
  | { ok: false; error: string };

function parseExpo(body: Record<string, unknown>): SubscriptionInput {
  const { token, platform } = body;
  if (typeof token !== "string" || !EXPO_TOKEN.test(token)) {
    return { ok: false, error: "token must be an Expo push token" };
  }
  if (typeof platform !== "string" || !PLATFORMS.includes(platform)) {
    return { ok: false, error: "platform must be ios or android" };
  }
  return { ok: true, endpoint: token, keys: { provider: "expo", platform } };
}

// Browser PushSubscription.toJSON(): { endpoint, keys: { p256dh, auth } }.
function parseWebPush(body: Record<string, unknown>): SubscriptionInput {
  const subscription = body.subscription as Record<string, unknown> | null | undefined;
  const endpoint = subscription?.endpoint;
  const keys = subscription?.keys as Record<string, unknown> | null | undefined;
  if (
    typeof endpoint !== "string" ||
    endpoint.length > MAX_ENDPOINT_LENGTH ||
    !isAllowedWebPushEndpoint(endpoint)
  ) {
    return { ok: false, error: "subscription.endpoint must be an https URL on a known push service" };
  }
  const p256dh = keys?.p256dh;
  const auth = keys?.auth;
  if (typeof p256dh !== "string" || !P256DH.test(p256dh) || typeof auth !== "string" || !AUTH_SECRET.test(auth)) {
    return { ok: false, error: "subscription.keys must contain base64url p256dh and auth" };
  }
  return { ok: true, endpoint, keys: { provider: "webpush", p256dh, auth } };
}

async function readJsonObject(req: NextRequest): Promise<Record<string, unknown> | null> {
  try {
    const body: unknown = await req.json();
    if (!body || typeof body !== "object" || Array.isArray(body)) return null;
    return body as Record<string, unknown>;
  } catch {
    return null;
  }
}

async function requireMembership(orgId: string, userId: string): Promise<boolean> {
  const { data: membership } = await getAdminClient()
    .from("organization_members")
    .select("role")
    .eq("org_id", orgId)
    .eq("user_id", userId)
    .maybeSingle();
  return Boolean(membership);
}

// GET /api/orgs/[id]/push-subscriptions — the caller's own devices registered
// for this org, so the PWA can tell whether this browser is subscribed here.
export async function GET(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) {
  try {
    const auth = await getAuthenticatedRequestUser(req);
    if (!auth) return unauthorized();

    const { id: orgId } = await params;
    if (!(await requireMembership(orgId, auth.userId))) {
      return NextResponse.json({ error: "Not authorized" }, { status: 403 });
    }

    const { data, error } = await getAdminClient()
      .from("push_subscriptions")
      .select("id, endpoint, keys, created_at")
      .eq("organization_id", orgId)
      .eq("user_id", auth.userId);
    if (error) return NextResponse.json({ error: "Failed to fetch" }, { status: 500 });

    const subscriptions = (data ?? []).map((row) => ({
      id: row.id,
      endpoint: row.endpoint,
      provider: (row.keys as { provider?: string } | null)?.provider ?? null,
      created_at: row.created_at,
    }));
    return NextResponse.json({ subscriptions });
  } catch (err) {
    console.error("List push subscriptions error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}

// POST /api/orgs/[id]/push-subscriptions — register a device for alerts from
// the org. One row per (user, endpoint): registering again from another org
// moves the device to that org.
//
// Two kinds share push_subscriptions, told apart by `keys.provider`:
// - Expo (mobile app): `{ token, platform }`, stored as endpoint = token,
//   keys = { provider: "expo", platform }.
// - Web Push (PWA): `{ kind: "webpush", subscription: { endpoint, keys: { p256dh, auth } } }`,
//   stored as keys = { provider: "webpush", p256dh, auth }.
export async function POST(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) {
  try {
    const auth = await getAuthenticatedRequestUser(req);
    if (!auth) return unauthorized();

    const { id: orgId } = await params;
    if (!(await requireMembership(orgId, auth.userId))) {
      return NextResponse.json({ error: "Not authorized" }, { status: 403 });
    }

    const body = await readJsonObject(req);
    if (!body) return NextResponse.json({ error: "Invalid JSON body" }, { status: 400 });

    const input = body.kind === "webpush" ? parseWebPush(body) : parseExpo(body);
    if (!input.ok) return NextResponse.json({ error: input.error }, { status: 400 });

    const { data: subscription, error } = await getAdminClient()
      .from("push_subscriptions")
      .upsert(
        {
          user_id: auth.userId,
          organization_id: orgId,
          endpoint: input.endpoint,
          keys: input.keys,
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

// DELETE /api/orgs/[id]/push-subscriptions — forget this device (sign-out, or
// turning browser notifications off). Body `{ token }` for Expo, `{ endpoint }`
// for Web Push. Scoped to the caller's own rows, so it deliberately does not
// require current membership: someone removed from the org must still be able
// to unregister.
export async function DELETE(req: NextRequest) {
  try {
    const auth = await getAuthenticatedRequestUser(req);
    if (!auth) return unauthorized();

    const body = await readJsonObject(req);
    if (!body) return NextResponse.json({ error: "Invalid JSON body" }, { status: 400 });

    const { token, endpoint } = body;
    let target: string;
    if (typeof endpoint === "string") {
      if (!isAllowedWebPushEndpoint(endpoint)) {
        return NextResponse.json({ error: "endpoint must be a Web Push endpoint" }, { status: 400 });
      }
      target = endpoint;
    } else if (typeof token === "string" && EXPO_TOKEN.test(token)) {
      target = token;
    } else {
      return NextResponse.json({ error: "token must be an Expo push token" }, { status: 400 });
    }

    const { error } = await getAdminClient()
      .from("push_subscriptions")
      .delete()
      .eq("user_id", auth.userId)
      .eq("endpoint", target);

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
