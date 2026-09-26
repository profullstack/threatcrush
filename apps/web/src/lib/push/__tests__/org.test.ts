import { beforeEach, describe, expect, it, vi } from "vitest";
import { recordQuery, type QueryCall } from "@/__tests__/helpers/query-recorder";

const { sendNotification, FakeWebPushError } = vi.hoisted(() => {
  class FakeWebPushError extends Error {
    constructor(message: string, readonly statusCode: number) {
      super(message);
    }
  }
  return { sendNotification: vi.fn(), FakeWebPushError };
});
vi.mock("web-push", () => ({ sendNotification, WebPushError: FakeWebPushError }));

const db = { rows: [] as unknown[], calls: [] as QueryCall[] };
vi.mock("@/lib/supabase", () => ({
  getSupabaseAdmin: () => ({
    from: (table: string) => {
      if (table !== "push_subscriptions") throw new Error(`Unexpected table ${table}`);
      return recordQuery({ data: db.rows, error: null }, db.calls);
    },
  }),
}));

import { sendOrgPush } from "../org";

const fetchMock = vi.mocked(fetch);
const GONE_WEB = "https://fcm.googleapis.com/fcm/send/gone";
const LIVE_WEB = "https://updates.push.services.mozilla.com/wpush/v2/live";
const keys = { p256dh: "p".repeat(87), auth: "a".repeat(22) };
const notification = { title: "t", body: "b", url: "https://threatcrush.com/dashboard", tag: "x" };

beforeEach(() => {
  process.env.NEXT_PUBLIC_VAPID_PUBLIC_KEY = "BPublicKey";
  process.env.VAPID_PRIVATE_KEY = "privateKey";
  db.calls = [];
  db.rows = [
    { id: "sub-expo-live", endpoint: "ExponentPushToken[live]", keys: { provider: "expo", platform: "ios" } },
    { id: "sub-expo-dead", endpoint: "ExponentPushToken[dead]", keys: { provider: "expo", platform: "android" } },
    { id: "sub-web-gone", endpoint: GONE_WEB, keys: { provider: "webpush", ...keys } },
    { id: "sub-web-live", endpoint: LIVE_WEB, keys: { provider: "webpush", ...keys } },
  ];
  fetchMock.mockReset().mockResolvedValue(
    new Response(
      JSON.stringify({
        data: [
          { status: "ok", id: "t1" },
          { status: "error", message: "not registered", details: { error: "DeviceNotRegistered" } },
        ],
      }),
      { status: 200 },
    ),
  );
  sendNotification.mockReset().mockImplementation(async (sub: { endpoint: string }) => {
    if (sub.endpoint === GONE_WEB) throw new FakeWebPushError("gone", 410);
    return { statusCode: 201 };
  });
});

describe("sendOrgPush", () => {
  it("reaches Expo and Web Push devices and deletes exactly the dead ones", async () => {
    const result = await sendOrgPush("org-1", notification);

    expect(result).toMatchObject({ devices: 4, sent: 2, failures: [] });
    expect(db.calls).toContainEqual(["eq", "organization_id", "org-1"]);
    expect(db.calls).toContainEqual(["delete"]);
    const deleted = db.calls.find(([method]) => method === "in");
    expect(deleted).toEqual(["in", "id", ["sub-expo-dead", "sub-web-gone"]]);
  });

  it("deletes nothing when every device is live", async () => {
    db.rows = db.rows.filter((row) => (row as { id: string }).id === "sub-web-live");
    const result = await sendOrgPush("org-1", notification);
    expect(result).toMatchObject({ devices: 1, sent: 1, dead: [] });
    expect(db.calls).not.toContainEqual(["delete"]);
  });
});
