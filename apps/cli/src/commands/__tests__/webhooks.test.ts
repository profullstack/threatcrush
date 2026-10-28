import { describe, it, expect, vi, beforeAll, afterAll, afterEach } from "vitest";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const home = mkdtempSync(join(tmpdir(), "tc-webhooks-"));
mkdirSync(join(home, ".threatcrush"));
writeFileSync(join(home, ".threatcrush", "config.json"), JSON.stringify({ token: "jwt-123", current_org_id: "org-1" }));
vi.mock("node:os", async (orig) => ({ ...(await orig<typeof import("node:os")>()), homedir: () => home }));

let mod: typeof import("../webhooks.js");
beforeAll(async () => {
  mod = await import("../webhooks.js");
});
afterAll(() => rmSync(home, { recursive: true, force: true }));
afterEach(() => vi.unstubAllGlobals());

const strip = (s: string) => s.replace(/\u001b\[[0-9;]*m/g, "");

function stubFetch(status: number, body: unknown) {
  const calls: Array<{ url: string; init: RequestInit }> = [];
  vi.stubGlobal("fetch", async (url: string, init: RequestInit) => {
    calls.push({ url, init });
    return new Response(JSON.stringify(body), { status });
  });
  return calls;
}

describe("webhooks CLI", () => {
  it("add posts url + events for the current org and prints the secret", async () => {
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    const calls = stubFetch(201, { endpoint: { id: "wh_1", url: "https://hooks.example.com/x", events: ["findings.*"] }, secret: "fixture-secret-shown-once" });
    await mod.webhooksAddCommand("https://hooks.example.com/x", { events: "findings.*" });
    expect(calls[0].url).toMatch(/\/api\/v1\/webhooks\?org_id=org-1$/);
    expect(calls[0].init.method).toBe("POST");
    expect(JSON.parse(String(calls[0].init.body))).toEqual({ url: "https://hooks.example.com/x", events: ["findings.*"] });
    expect(log.mock.calls.map((c) => strip(String(c[0]))).join("\n")).toContain("fixture-secret-shown-once");
    log.mockRestore();
  });

  it("test, rotate and retry hit the right routes", async () => {
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    let calls = stubFetch(200, { ok: true, status: 204, error: null });
    await mod.webhooksTestCommand("wh_1");
    expect(calls[0].url).toContain("/api/v1/webhooks/wh_1/test?org_id=org-1");
    calls = stubFetch(200, { secret: "fixture-rotated" });
    await mod.webhooksSecretCommand("wh_1", { rotate: true });
    expect(calls[0].url).toContain("/api/v1/webhooks/wh_1/rotate?");
    calls = stubFetch(202, {});
    await mod.webhooksRetryCommand("dlv_1");
    expect(calls[0].url).toContain("/api/v1/webhooks/deliveries/dlv_1/retry?");
    log.mockRestore();
  });

  it("a refused call sets exit code 1", async () => {
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    process.exitCode = 0;
    stubFetch(403, { error: "Only org owners and admins manage webhooks" });
    await mod.webhooksListCommand();
    expect(process.exitCode).toBe(1);
    process.exitCode = 0;
    log.mockRestore();
  });
});
