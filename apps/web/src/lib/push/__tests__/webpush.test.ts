import { beforeEach, describe, expect, it, vi } from "vitest";

const { sendNotification, FakeWebPushError } = vi.hoisted(() => {
  class FakeWebPushError extends Error {
    constructor(message: string, readonly statusCode: number) {
      super(message);
    }
  }
  return { sendNotification: vi.fn(), FakeWebPushError };
});
vi.mock("web-push", () => ({ sendNotification, WebPushError: FakeWebPushError }));

import { isAllowedWebPushEndpoint, sendWebPush } from "../webpush";

const FCM = "https://fcm.googleapis.com/fcm/send/abc123";
const MOZILLA = "https://updates.push.services.mozilla.com/wpush/v2/gAAAA";
const target = (endpoint: string) => ({ endpoint, p256dh: "p".repeat(87), auth: "a".repeat(22) });
const notification = {
  title: "[HIGH] SSH brute force",
  body: "Server: web-1",
  url: "https://threatcrush.com/org/acme/detections?detection=det-1",
  tag: "detection-det-1",
};

beforeEach(() => {
  sendNotification.mockReset().mockResolvedValue({ statusCode: 201 });
  process.env.NEXT_PUBLIC_VAPID_PUBLIC_KEY = "BPublicKey";
  process.env.VAPID_PRIVATE_KEY = "privateKey";
  process.env.VAPID_SUBJECT = "mailto:ops@example.com";
});

describe("isAllowedWebPushEndpoint", () => {
  it.each([
    FCM,
    MOZILLA,
    "https://web.push.apple.com/QGuQyavXutnMH",
    "https://wns2-par02p.notify.windows.com/w/?token=BQYAAA",
    "https://jmt17.google.com/fcm/send/duL-N3R2IFA:APA91bE8",
  ])("accepts %s", (endpoint) => {
    expect(isAllowedWebPushEndpoint(endpoint)).toBe(true);
  });

  it.each([
    "http://fcm.googleapis.com/fcm/send/abc",
    "https://fcm.googleapis.com:8443/fcm/send/abc",
    "https://user:pw@fcm.googleapis.com/fcm/send/abc",
    "https://evil.example/push.apple.com",
    "https://push.apple.com.evil.example/x",
    "https://evil.google.com/fcm/send/x",
    "https://127.0.0.1/x",
    "not a url",
  ])("rejects %s", (endpoint) => {
    expect(isAllowedWebPushEndpoint(endpoint)).toBe(false);
  });
});

describe("sendWebPush", () => {
  it("sends the title/body/url/tag payload the service worker renders, signed with VAPID", async () => {
    const result = await sendWebPush([target(FCM)], notification);

    expect(result).toEqual({ sent: 1, failures: [], dead: [] });
    const [subscription, payload, options] = sendNotification.mock.calls[0];
    expect(subscription).toEqual({ endpoint: FCM, keys: { p256dh: "p".repeat(87), auth: "a".repeat(22) } });
    expect(JSON.parse(payload)).toEqual(notification);
    expect(options.vapidDetails).toEqual({
      subject: "mailto:ops@example.com",
      publicKey: "BPublicKey",
      privateKey: "privateKey",
    });
  });

  it("returns 404/410 subscriptions as dead and other errors as failures", async () => {
    sendNotification.mockImplementation(async (sub: { endpoint: string }) => {
      if (sub.endpoint === FCM) throw new FakeWebPushError("Received unexpected response code", 410);
      throw new FakeWebPushError("Received unexpected response code", 413);
    });

    const result = await sendWebPush([target(FCM), target(MOZILLA)], notification);

    expect(result.sent).toBe(0);
    expect(result.dead).toEqual([FCM]);
    expect(result.failures).toEqual(["web push HTTP 413: Received unexpected response code"]);
  });

  it("fails clearly without VAPID keys and sends nothing", async () => {
    delete process.env.VAPID_PRIVATE_KEY;
    const result = await sendWebPush([target(FCM)], notification);
    expect(result).toEqual({
      sent: 0,
      dead: [],
      failures: ["Web Push is not configured (VAPID_PRIVATE_KEY not set)"],
    });
    expect(sendNotification).not.toHaveBeenCalled();
  });

  it("skips stored endpoints that are not push services", async () => {
    const result = await sendWebPush([target("https://attacker.example/collect")], notification);
    expect(result.sent).toBe(0);
    expect(sendNotification).not.toHaveBeenCalled();
  });
});
