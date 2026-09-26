import { describe, expect, it } from "vitest";
import { serverConnectionState } from "@/lib/server-status";

describe("serverConnectionState", () => {
  const now = Date.parse("2026-09-25T12:00:00Z");

  it("is online up to three minutes after the last heartbeat and offline after", () => {
    expect(serverConnectionState("2026-09-25T11:57:00Z", now)).toBe("online");
    expect(serverConnectionState("2026-09-25T11:56:59Z", now)).toBe("offline");
  });

  it("treats a server that never reported as offline", () => {
    expect(serverConnectionState(null, now)).toBe("offline");
    expect(serverConnectionState("garbage", now)).toBe("offline");
  });
});
