import { createHmac, randomBytes } from "node:crypto";
import { NextRequest } from "next/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { POST, verifySignature, logSafe } from "../route";

// Generated per run rather than written down. These tests only need both sides
// of the signature to agree on *a* secret, so the literal bought nothing — and
// a 64-hex constant named SECRET is indistinguishable from a leaked webhook
// secret to every scanner that reads this tree, ours included.
const SECRET = randomBytes(32).toString("hex");
const URL_ = "https://threatcrush.com/api/webhooks/github";

function sign(body: string, secret = SECRET) {
  return `sha256=${createHmac("sha256", secret).update(body, "utf8").digest("hex")}`;
}

function post(body: string, headers: Record<string, string>) {
  return POST(new NextRequest(URL_, { method: "POST", body, headers }));
}

describe("POST /api/webhooks/github", () => {
  beforeEach(() => {
    vi.stubEnv("GITHUB_APP_WEBHOOK_SECRET", SECRET);
    vi.spyOn(console, "log").mockImplementation(() => {});
    vi.spyOn(console, "error").mockImplementation(() => {});
  });

  afterEach(() => {
    vi.unstubAllEnvs();
    vi.restoreAllMocks();
  });

  it("answers GitHub's ping so the settings page reports the endpoint healthy", async () => {
    const body = JSON.stringify({ zen: "Keep it logically awesome.", hook_id: 1 });
    const res = await post(body, {
      "x-hub-signature-256": sign(body),
      "x-github-event": "ping",
      "x-github-delivery": "d-1",
    });

    expect(res.status).toBe(200);
    expect(await res.json()).toMatchObject({ ok: true, pong: true });
  });

  it("accepts a correctly signed marketplace_purchase", async () => {
    const body = JSON.stringify({
      action: "purchased",
      marketplace_purchase: { account: { login: "profullstack" } },
    });
    const res = await post(body, {
      "x-hub-signature-256": sign(body),
      "x-github-event": "marketplace_purchase",
    });

    expect(res.status).toBe(200);
    expect(await res.json()).toMatchObject({ ok: true, event: "marketplace_purchase" });
  });

  it("rejects a body signed with the wrong secret", async () => {
    const body = JSON.stringify({ action: "purchased" });
    const res = await post(body, {
      "x-hub-signature-256": sign(body, "not-the-secret"),
      "x-github-event": "marketplace_purchase",
    });

    expect(res.status).toBe(401);
  });

  it("rejects a tampered body carrying a signature for the original", async () => {
    const original = JSON.stringify({ action: "purchased", amount: 1 });
    const tampered = JSON.stringify({ action: "purchased", amount: 999 });
    const res = await post(tampered, {
      "x-hub-signature-256": sign(original),
      "x-github-event": "marketplace_purchase",
    });

    expect(res.status).toBe(401);
  });

  it("rejects a delivery with no signature header at all", async () => {
    const body = JSON.stringify({ action: "purchased" });
    const res = await post(body, { "x-github-event": "marketplace_purchase" });

    expect(res.status).toBe(401);
  });

  it("refuses rather than accepting unverified deliveries when the secret is unset", async () => {
    vi.stubEnv("GITHUB_APP_WEBHOOK_SECRET", "");
    const body = JSON.stringify({ action: "purchased" });
    const res = await post(body, { "x-hub-signature-256": sign(body) });

    expect(res.status).toBe(500);
  });

  it("400s a signed body that is not JSON", async () => {
    const body = "not json";
    const res = await post(body, {
      "x-hub-signature-256": sign(body),
      "x-github-event": "installation",
    });

    expect(res.status).toBe(400);
  });

  it("verifySignature is false for a header of the wrong shape", () => {
    expect(verifySignature("{}", "sha1=abc", SECRET)).toBe(false);
    expect(verifySignature("{}", null, SECRET)).toBe(false);
  });

  it("logSafe strips CRLF so a field cannot forge a log line", () => {
    expect(logSafe("ok\r\nFAKE: entry")).toBe("ok  FAKE: entry");
  });
});
