import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { installId, sendUsagePing, usagePingDisabled } from "../usage-ping.js";

const dirs: string[] = [];
const tmp = () => { const d = mkdtempSync(join(tmpdir(), "tc-ping-")); dirs.push(d); return d; };
afterEach(() => { for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true }); });

function capture() {
  const calls: { url: string; body: Record<string, unknown> }[] = [];
  const fetchImpl = (async (url: string, init?: RequestInit) => {
    calls.push({ url, body: JSON.parse(String(init?.body)) });
    return new Response("{}", { status: 202 });
  }) as unknown as typeof fetch;
  return { calls, fetchImpl };
}

describe("usage ping", () => {
  it("is off with THREATCRUSH_TELEMETRY=0/off/false/no or DO_NOT_TRACK=1", () => {
    for (const v of ["0", "off", "false", "no", "OFF"]) expect(usagePingDisabled({ THREATCRUSH_TELEMETRY: v })).toBe(true);
    expect(usagePingDisabled({ DO_NOT_TRACK: "1" })).toBe(true);
    expect(usagePingDisabled({ DO_NOT_TRACK: "0" })).toBe(false);
    expect(usagePingDisabled({})).toBe(false);
  });

  it("sends nothing when disabled", async () => {
    const { calls, fetchImpl } = capture();
    const ok = await sendUsagePing({ event: "ai-scan", findings: 1, duration_ms: 5 }, { fetchImpl, dir: tmp(), env: { DO_NOT_TRACK: "1" } });
    expect(ok).toBe(false);
    expect(calls).toHaveLength(0);
  });

  it("keeps one install id and prints the notice only the first time", async () => {
    const dir = tmp(), notices: string[] = [];
    const { calls, fetchImpl } = capture();
    const ping = { event: "ai-scan" as const, probes: 12, findings: 2, severity: { high: 2 }, duration_ms: 40 };
    await sendUsagePing(ping, { fetchImpl, dir, env: {}, notice: (s) => notices.push(s) });
    await sendUsagePing(ping, { fetchImpl, dir, env: {}, notice: (s) => notices.push(s) });
    expect(notices).toHaveLength(1);
    expect(notices[0]).toMatch(/THREATCRUSH_TELEMETRY=0/);
    expect(calls).toHaveLength(2);
    expect(calls[0].url).toMatch(/\/api\/telemetry$/);
    expect(calls[0].body.install_id).toBe(calls[1].body.install_id);
    expect(calls[0].body.install_id).toBe(JSON.parse(readFileSync(join(dir, "usage-ping.json"), "utf-8")).install_id);
  });

  it("carries counts and environment, never the target", async () => {
    const { calls, fetchImpl } = capture();
    await sendUsagePing({ event: "ai-scan", probes: 3, findings: 0, duration_ms: 9 }, { fetchImpl, dir: tmp(), env: { CI: "true" }, notice: () => {} });
    const b = calls[0].body;
    expect(Object.keys(b).sort()).toEqual(["arch", "ci", "duration_ms", "event", "findings", "install_id", "node", "platform", "probes", "version"]);
    expect(b.ci).toBe(true);
  });

  it("never throws when the network fails", async () => {
    const fetchImpl = (async () => { throw new Error("offline"); }) as unknown as typeof fetch;
    await expect(sendUsagePing({ event: "ai-scan-run", scans: 1, findings: 0, duration_ms: 1 }, { fetchImpl, dir: tmp(), env: {}, notice: () => {} })).resolves.toBe(false);
  });

  it("reuses an id already on disk", () => {
    const dir = tmp();
    const a = installId(dir), b = installId(dir);
    expect(a.fresh).toBe(true);
    expect(b).toEqual({ id: a.id, fresh: false });
  });
});
