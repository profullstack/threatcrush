import { describe, expect, it } from "vitest";
import { serverConnectionState, withConnectionState } from "@/lib/server-status";

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

describe("withConnectionState", () => {
  const now = Date.parse("2026-10-19T12:00:00Z");

  it("replaces a stale stored online with offline", () => {
    // A box destroyed on Oct 6 still had status "online" on Oct 19.
    expect(withConnectionState({ status: "online", last_seen: "2026-10-06T02:27:00Z" }, now).status).toBe("offline");
    expect(withConnectionState({ status: "online", last_seen: "2026-10-19T11:59:00Z" }, now).status).toBe("online");
  });

  it("keeps a probe's unreachable while the server is still reporting", () => {
    expect(withConnectionState({ status: "unreachable", last_seen: "2026-10-19T11:59:00Z" }, now).status).toBe("unreachable");
    expect(withConnectionState({ status: "unreachable", last_seen: null }, now).status).toBe("offline");
  });
});
