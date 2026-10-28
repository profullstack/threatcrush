import { describe, expect, it } from "vitest";
import { jobStatus, type JobItem } from "@/lib/daemon-job";

const NOW = Date.parse("2026-10-28T12:00:00Z");
const at = (secondsFromNow: number) => new Date(NOW + secondsFromNow * 1000).toISOString();
const item = (over: Partial<JobItem> = {}): JobItem => ({
  action_id: "a1", org_id: "o1", server_id: "s1", server_name: "dev2",
  action_type: "restart", intent: "restart", from_version: "0.13.60", ...over,
});
const action = (status: string, over: Record<string, unknown> = {}) => ({ id: "a1", status, executed_at: null, expires_at: at(600), ...over });

describe("jobStatus", () => {
  it("walks queued → running → restarting → online", () => {
    expect(jobStatus(item(), action("pending"), undefined, NOW).phase).toBe("queued");
    expect(jobStatus(item(), action("executing"), undefined, NOW).phase).toBe("running");
    const done = action("executed", { executed_at: at(-10) });
    // A heartbeat from just before the 3s restart delay is the old process.
    expect(jobStatus(item(), done, { last_seen: at(-8), threatcrushd_version: "0.13.60" }, NOW).phase).toBe("restarting");
    const s = jobStatus(item(), done, { last_seen: at(-2), threatcrushd_version: "0.13.60" }, NOW);
    expect(s).toEqual({ phase: "online", detail: "Back online on v0.13.60" });
  });

  it("an update is done as soon as the version changes", () => {
    const s = jobStatus(item({ action_type: "update", intent: "update" }), action("executed", { executed_at: at(-5) }), { last_seen: at(-20), threatcrushd_version: "0.13.61" }, NOW);
    expect(s).toEqual({ phase: "online", detail: "Updated v0.13.60 → v0.13.61" });
  });

  it("a restart sent for an update says the auto-updater finishes it", () => {
    const s = jobStatus(item({ intent: "update" }), action("executed", { executed_at: at(-30) }), { last_seen: at(-1), threatcrushd_version: "0.13.60" }, NOW);
    expect(s.phase).toBe("online");
    expect(s.detail).toMatch(/auto-updater/);
  });

  it("reports failures, expiry and a missing heartbeat", () => {
    expect(jobStatus(item(), action("failed", { metadata: { error: "npm E404" } }), undefined, NOW)).toEqual({ phase: "failed", detail: "npm E404" });
    expect(jobStatus(item(), action("pending", { expires_at: at(-1) }), undefined, NOW).phase).toBe("expired");
    expect(jobStatus(item(), action("expired"), undefined, NOW).phase).toBe("expired");
    expect(jobStatus(item(), action("executed", { executed_at: at(-400) }), { last_seen: at(-500), threatcrushd_version: "0.13.60" }, NOW).phase).toBe("stalled");
  });
});
