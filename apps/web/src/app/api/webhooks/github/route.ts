// GitHub App webhook receiver.
//
// This is the Payload URL on the ThreatCrush GitHub App:
//   https://threatcrush.com/api/webhooks/github
//
// GitHub signs every delivery with HMAC-SHA256 over the raw body, keyed by the
// secret configured in the app's webhook settings, and sends it as
// `X-Hub-Signature-256: sha256=<hex>`. The secret lives in
// GITHUB_APP_WEBHOOK_SECRET.
//
// Scope note: nothing is persisted yet. There is no GitHub App backend — no
// installations table, no plan records — so this endpoint verifies, logs and
// acknowledges. That is what a Marketplace listing needs to be accepted; acting
// on `marketplace_purchase` is a separate build. Acknowledging is deliberate:
// GitHub retries and eventually disables an endpoint that keeps failing, and a
// 500 here would bury the real signal.

import { NextRequest, NextResponse } from "next/server";
import { createHmac, timingSafeEqual } from "node:crypto";

/**
 * Webhook fields land in log lines, and a value containing CRLF can forge a
 * whole extra entry. Strip the control characters and cap the length so a
 * field can only ever be one token. Same shape as the CoinPay receiver.
 */
export function logSafe(value: unknown): string {
  const collapsed = String(value ?? "")
    // eslint-disable-next-line no-control-regex
    .replace(/[\u0000-\u001f\u007f]/g, " ")
    .slice(0, 200);
  // The range above has already removed CR and LF, so this pass changes
  // nothing at runtime. It stays because it is the form static analysis
  // recognises as neutralising log injection.
  return collapsed.replace(/\n|\r/g, " ");
}

/**
 * Compare two signatures without leaking, through timing, how far along they
 * first differed. `timingSafeEqual` throws on a length mismatch, so the lengths
 * are checked first — that much is public anyway, since the digest length is
 * fixed by the algorithm.
 */
export function signaturesMatch(a: string, b: string): boolean {
  const ab = Buffer.from(a, "utf8");
  const bb = Buffer.from(b, "utf8");
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}

export function verifySignature(rawBody: string, header: string | null, secret: string): boolean {
  if (!header) return false;
  const expected = `sha256=${createHmac("sha256", secret).update(rawBody, "utf8").digest("hex")}`;
  return signaturesMatch(header, expected);
}

export async function POST(request: NextRequest) {
  const secret = process.env.GITHUB_APP_WEBHOOK_SECRET;
  if (!secret) {
    // Refusing beats accepting unverified deliveries: an unsigned-but-accepted
    // purchase event is worse than a failed one, which GitHub will redeliver.
    console.error("[github webhook] GITHUB_APP_WEBHOOK_SECRET is not set");
    return NextResponse.json({ error: "Webhook not configured" }, { status: 500 });
  }

  const rawBody = await request.text();
  if (!verifySignature(rawBody, request.headers.get("x-hub-signature-256"), secret)) {
    return NextResponse.json({ error: "Invalid signature" }, { status: 401 });
  }

  const event = request.headers.get("x-github-event") || "unknown";
  const delivery = request.headers.get("x-github-delivery") || "";

  let payload: Record<string, unknown>;
  try {
    payload = JSON.parse(rawBody) as Record<string, unknown>;
  } catch {
    return NextResponse.json({ error: "Invalid payload" }, { status: 400 });
  }

  const installation = payload.installation as { id?: unknown } | undefined;
  const account = (payload.marketplace_purchase as { account?: { login?: unknown } } | undefined)
    ?.account;

  console.log("[github webhook] received", {
    event: logSafe(event),
    delivery: logSafe(delivery),
    action: logSafe(payload.action),
    installationId: logSafe(installation?.id),
    account: logSafe(account?.login),
  });

  // `ping` is what GitHub sends when the webhook is first saved, and getting a
  // 200 back is how the settings page reports the endpoint as healthy.
  if (event === "ping") {
    return NextResponse.json({ ok: true, pong: true });
  }

  return NextResponse.json({ ok: true, event, received: true });
}
