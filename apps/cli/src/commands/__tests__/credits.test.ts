import { describe, it, expect, vi, beforeAll, afterAll } from "vitest";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const home = mkdtempSync(join(tmpdir(), "tc-credits-"));
mkdirSync(join(home, ".threatcrush"));
writeFileSync(join(home, ".threatcrush", "config.json"), JSON.stringify({ token: "jwt-123" }));
vi.mock("node:os", async (orig) => ({ ...(await orig<typeof import("node:os")>()), homedir: () => home }));

let mod: typeof import("../credits.js");
beforeAll(async () => {
  mod = await import("../credits.js");
});
afterAll(() => rmSync(home, { recursive: true, force: true }));

const strip = (s: string) => s.replace(/\u001b\[[0-9;]*m/g, "");

function fakeFetch(status: number, body: unknown) {
  const calls: Array<{ url: string; init: RequestInit }> = [];
  const f = (async (url: string, init: RequestInit) => {
    calls.push({ url, init });
    return new Response(JSON.stringify(body), { status });
  }) as unknown as typeof fetch;
  return { f, calls };
}

describe("credits CLI", () => {
  it("redeem posts the code with the login session and prints the balance", async () => {
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    const { f, calls } = fakeFetch(200, { message: "Code redeemed: 5 credits ($5.00) added.", balance_usd: 15 });
    await mod.redeemCommand("CR-1", f);
    expect(calls[0].url).toMatch(/\/api\/credits\/redeem$/);
    expect((calls[0].init.headers as Record<string, string>).Authorization).toBe("Bearer jwt-123");
    expect(JSON.parse(String(calls[0].init.body))).toEqual({ code: "CR-1" });
    expect(log.mock.calls.map((c) => strip(String(c[0]))).join("\n")).toContain("Credit balance: $15.00");
    log.mockRestore();
  });

  it("redeem sets exit code 1 on a refused code", async () => {
    const err = vi.spyOn(console, "error").mockImplementation(() => {});
    process.exitCode = 0;
    await mod.redeemCommand("CR-1", fakeFetch(400, { error: "That code has expired." }).f);
    expect(process.exitCode).toBe(1);
    expect(strip(String(err.mock.calls[0][0]))).toContain("expired");
    process.exitCode = 0;
    err.mockRestore();
  });

  it("invites create, accept and revoke hit the right routes", async () => {
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    const { f, calls } = fakeFetch(200, { url: "https://threatcrush.com/i/INV-1", message: "Invite accepted." });
    await mod.invitesCommand("create", "for bob", f);
    await mod.invitesCommand("accept", "INV-1", f);
    await mod.invitesCommand("revoke", "abc", f);
    expect(calls.map((c) => `${c.init.method ?? "GET"} ${new URL(c.url).pathname}`)).toEqual([
      "POST /api/credits/invites",
      "POST /api/credits/invites/accept",
      "DELETE /api/credits/invites/abc",
    ]);
    expect(log.mock.calls.map((c) => strip(String(c[0]))).join("\n")).toContain("https://threatcrush.com/i/INV-1");
    log.mockRestore();
  });
});
