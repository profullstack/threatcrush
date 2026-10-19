import { describe, expect, it } from "vitest";
import { connectionStatus } from "../servers.js";

describe("servers list status", () => {
  const now = Date.parse("2026-10-19T12:00:00Z");

  it("shows a server that stopped reporting as offline, whatever was stored", () => {
    expect(connectionStatus({ status: "online", last_seen: "2026-10-04T02:05:00Z" }, now)).toBe("offline");
    expect(connectionStatus({ status: "online", last_seen: null }, now)).toBe("offline");
  });

  it("shows a reporting server as online, or unreachable if a probe said so", () => {
    expect(connectionStatus({ status: "online", last_seen: "2026-10-19T11:58:30Z" }, now)).toBe("online");
    expect(connectionStatus({ status: "unreachable", last_seen: "2026-10-19T11:58:30Z" }, now)).toBe("unreachable");
  });
});
