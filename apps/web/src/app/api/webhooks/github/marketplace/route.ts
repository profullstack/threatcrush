import { NextRequest, NextResponse } from "next/server";
import { getSupabaseAdmin } from "@/lib/supabase";
import {
  buildPurchaseRow,
  isMarketplaceAction,
  isStaleEvent,
  parseWebhookBody,
  verifyGithubSignature,
} from "@/lib/github-marketplace";

/**
 * GitHub Marketplace plan-change webhook.
 *
 * Configured on the Marketplace listing page (not in the App's developer
 * settings, which is where every other event is configured):
 *
 *   Payload URL   https://threatcrush.com/api/webhooks/github/marketplace
 *   Content type  application/json
 *   Secret        GITHUB_MARKETPLACE_WEBHOOK_SECRET
 *
 * GitHub does NOT resend failed deliveries. A 500 from here loses the
 * event permanently, so the raw payload is written to
 * github_marketplace_events before anything else can fail, and the
 * listing's delivery log is the only other copy.
 */

// node:crypto and the raw-body read both need the Node runtime.
export const runtime = "nodejs";

/**
 * Webhook fields land in log lines, and a value containing CRLF can forge
 * a whole extra entry. Strip the control characters and cap the length so
 * a field can only ever be one token.
 */
function logSafe(value: unknown): string {
  const collapsed = String(value ?? "")
    // eslint-disable-next-line no-control-regex
    .replace(/[\u0000-\u001f\u007f]/g, " ")
    .slice(0, 200);
  return collapsed.replace(/\n|\r/g, " ");
}

export async function POST(req: NextRequest) {
  // Must be the raw bytes: the signature is over the body as sent.
  const rawBody = await req.text();

  const secret = process.env.GITHUB_MARKETPLACE_WEBHOOK_SECRET;
  if (!secret) {
    // Refuse rather than accept-and-ignore. An unconfigured deployment
    // that returns 200 looks healthy in the delivery log while silently
    // dropping every purchase.
    console.error("[gh marketplace] GITHUB_MARKETPLACE_WEBHOOK_SECRET is not set");
    return NextResponse.json({ error: "Webhook not configured" }, { status: 503 });
  }

  const signature = req.headers.get("x-hub-signature-256");
  if (!verifyGithubSignature(rawBody, signature, secret)) {
    console.warn("[gh marketplace] rejected delivery with invalid signature");
    return NextResponse.json({ error: "Invalid signature" }, { status: 401 });
  }

  const event = req.headers.get("x-github-event") ?? "";
  const deliveryId = req.headers.get("x-github-delivery");

  // The listing only sends marketplace_purchase, but `ping` arrives when
  // the hook is first saved and must be answered 200 or the UI shows the
  // hook as broken.
  if (event === "ping") {
    return NextResponse.json({ received: true, pong: true });
  }
  if (event && event !== "marketplace_purchase") {
    return NextResponse.json({ received: true, ignored: event });
  }

  const payload = parseWebhookBody(rawBody, req.headers.get("content-type"));
  if (!payload) {
    return NextResponse.json({ error: "Invalid payload" }, { status: 400 });
  }

  const action = payload.action;
  if (!isMarketplaceAction(action)) {
    console.warn(`[gh marketplace] unknown action: ${logSafe(action)}`);
    return NextResponse.json({ received: true, ignored: String(action ?? "") });
  }

  const now = new Date().toISOString();
  const row = buildPurchaseRow(action, payload, now);

  let supabase;
  try {
    supabase = getSupabaseAdmin();
  } catch (e) {
    console.error("[gh marketplace] supabase unavailable:", e);
    // 500 so the delivery shows red in GitHub's log and can be replayed
    // by hand from the payload GitHub still holds.
    return NextResponse.json({ error: "Storage unavailable" }, { status: 500 });
  }

  // Record the delivery first. `delivery_id` is unique, so a replay of the
  // same delivery inserts nothing and we can stop early.
  const eventRow = {
    delivery_id: deliveryId,
    action,
    github_account_id: row?.github_account_id ?? null,
    github_account_login: row?.github_account_login ?? null,
    effective_date: row?.effective_date ?? null,
    applied: false,
    skip_reason: null as string | null,
    payload: payload as unknown as Record<string, unknown>,
    received_at: now,
  };

  const { data: insertedEvents, error: eventErr } = await supabase
    .from("github_marketplace_events")
    .upsert(eventRow, { onConflict: "delivery_id", ignoreDuplicates: true })
    .select("id");

  if (eventErr) {
    console.error("[gh marketplace] failed to log delivery:", eventErr);
    return NextResponse.json({ error: "Storage failed" }, { status: 500 });
  }

  const eventId = insertedEvents?.[0]?.id as string | undefined;
  if (deliveryId && !eventId) {
    // Already processed this exact delivery.
    return NextResponse.json({ received: true, duplicate: true });
  }

  const finish = async (applied: boolean, skipReason?: string) => {
    if (!eventId) return;
    await supabase
      .from("github_marketplace_events")
      .update({ applied, skip_reason: skipReason ?? null })
      .eq("id", eventId);
  };

  if (!row) {
    await finish(false, "no account id in payload");
    return NextResponse.json({ received: true, applied: false });
  }

  const { data: existing, error: readErr } = await supabase
    .from("github_marketplace_purchases")
    .select("id, effective_date")
    .eq("github_account_id", row.github_account_id)
    .maybeSingle();

  if (readErr) {
    console.error("[gh marketplace] failed to read purchase:", readErr);
    return NextResponse.json({ error: "Storage failed" }, { status: 500 });
  }

  if (existing && isStaleEvent(existing.effective_date as string | null, row.effective_date)) {
    console.warn(
      `[gh marketplace] ignoring out-of-order ${logSafe(action)} for ${logSafe(row.github_account_login)}`,
    );
    await finish(false, "older than the applied event");
    return NextResponse.json({ received: true, applied: false, stale: true });
  }

  const { error: upsertErr } = await supabase
    .from("github_marketplace_purchases")
    .upsert(row, { onConflict: "github_account_id" });

  if (upsertErr) {
    console.error("[gh marketplace] failed to upsert purchase:", upsertErr);
    return NextResponse.json({ error: "Storage failed" }, { status: 500 });
  }

  await finish(true);

  console.log(
    `[gh marketplace] ${logSafe(action)} ${logSafe(row.github_account_login)} -> ${logSafe(row.plan_name)}`,
  );

  return NextResponse.json({ received: true, applied: true, action });
}

/**
 * A GET here is almost always a human checking the URL is live before
 * pasting it into the listing. Answer usefully and never leak the secret.
 */
export async function GET() {
  return NextResponse.json({
    endpoint: "github-marketplace-webhook",
    method: "POST",
    event: "marketplace_purchase",
    contentType: "application/json",
    configured: Boolean(process.env.GITHUB_MARKETPLACE_WEBHOOK_SECRET),
  });
}
