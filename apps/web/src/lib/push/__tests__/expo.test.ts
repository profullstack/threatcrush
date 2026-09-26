import { beforeEach, describe, expect, it, vi } from "vitest";
import { EXPO_PUSH_URL, sendExpoPush } from "../expo";

const fetchMock = vi.mocked(fetch);
const notification = {
  title: "[HIGH] SSH brute force",
  body: "Server: web-1",
  url: "https://threatcrush.com/org/acme/detections?detection=det-1",
  tag: "detection-det-1",
  data: { detection_id: "det-1" },
};
const token = (i: number) => `ExponentPushToken[token${i}]`;

/** Answers each chunk with one ok ticket per message, except `unregistered`. */
function expoAnswers(unregistered: string[] = []) {
  fetchMock.mockImplementation(async (_url, init) => {
    const messages = JSON.parse((init as RequestInit).body as string) as { to: string }[];
    const data = messages.map((m) =>
      unregistered.includes(m.to)
        ? { status: "error", message: `"${m.to}" is not a registered push notification recipient`, details: { error: "DeviceNotRegistered" } }
        : { status: "ok", id: `ticket-${m.to}` },
    );
    return new Response(JSON.stringify({ data }), { status: 200 });
  });
}

beforeEach(() => {
  fetchMock.mockReset();
  delete process.env.EXPO_ACCESS_TOKEN;
});

describe("sendExpoPush", () => {
  it("sends in chunks of at most 100 messages carrying the dashboard link", async () => {
    expoAnswers();
    const tokens = Array.from({ length: 150 }, (_, i) => token(i));

    const result = await sendExpoPush(tokens, notification);

    expect(result).toEqual({ sent: 150, failures: [], dead: [] });
    expect(fetchMock).toHaveBeenCalledTimes(2);
    const chunks = fetchMock.mock.calls.map(([url, init]) => {
      expect(url).toBe(EXPO_PUSH_URL);
      return JSON.parse((init as RequestInit).body as string);
    });
    expect(chunks.map((c) => c.length)).toEqual([100, 50]);
    expect(chunks[0][0]).toMatchObject({
      to: token(0),
      title: notification.title,
      body: notification.body,
      data: { url: notification.url, detection_id: "det-1" },
    });
  });

  it("returns DeviceNotRegistered tokens as dead and nothing else", async () => {
    expoAnswers([token(1)]);
    const result = await sendExpoPush([token(0), token(1)], notification);
    expect(result).toEqual({ sent: 1, failures: [], dead: [token(1)] });
  });

  it("reports a failed request for the chunk without marking tokens dead", async () => {
    fetchMock.mockResolvedValue(new Response("upstream down", { status: 503 }));
    const result = await sendExpoPush([token(0)], notification);
    expect(result.sent).toBe(0);
    expect(result.dead).toEqual([]);
    expect(result.failures).toEqual(["expo HTTP 503: upstream down"]);
  });

  it("authenticates when EXPO_ACCESS_TOKEN is set", async () => {
    process.env.EXPO_ACCESS_TOKEN = "expo-secret";
    expoAnswers();
    await sendExpoPush([token(0)], notification);
    const headers = (fetchMock.mock.calls[0][1] as RequestInit).headers as Record<string, string>;
    expect(headers.Authorization).toBe("Bearer expo-secret");
  });
});
