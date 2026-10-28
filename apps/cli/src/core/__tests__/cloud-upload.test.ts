import { beforeEach, describe, expect, it, vi } from "vitest";

let session = true;
let cfg: Record<string, unknown> = { current_org_id: "org-1", current_org_slug: "acme" };
const calls: Array<{ path: string; body: Record<string, unknown> }> = [];
let reply: { status: number; body: unknown } = { status: 201, body: { sync: { new: 2, seen: 1, reopened: 0, fixed: 3 }, property_name: "x" } };

vi.mock("../cli-config.js", () => ({
  apiUrl: () => "https://tc.test",
  hasSession: () => session,
  readCliConfig: () => cfg,
  cloudFetch: async (path: string, init: { body: string }) => {
    calls.push({ path, body: JSON.parse(init.body) });
    return new Response(JSON.stringify(reply.body), { status: reply.status });
  },
}));

const { cleanUrl, repoTarget, uploadDisabled, uploadResult } = await import("../cloud-upload.js");

const result = {
  type: "scan" as const, target: ".", summary: "1 finding",
  findings: [{ type: "SQLi", severity: "high" as const, message: "m", location: "a.ts:1" }],
  severity_summary: { critical: 0, high: 1, medium: 0, low: 0, info: 0 },
};
const quiet = () => vi.spyOn(process.stdout, "write").mockImplementation(() => true);

describe("cloud upload", () => {
  beforeEach(() => { session = true; cfg = { current_org_id: "org-1", current_org_slug: "acme" }; calls.length = 0; reply = { status: 201, body: { sync: { new: 2, seen: 1, reopened: 0, fixed: 3 } } }; });

  it("is off with --no-upload or THREATCRUSH_UPLOAD=0", () => {
    expect(uploadDisabled(false, {})).toBe(true);
    expect(uploadDisabled(undefined, { THREATCRUSH_UPLOAD: "0" })).toBe(true);
    expect(uploadDisabled(undefined, { THREATCRUSH_UPLOAD: "off" })).toBe(true);
    expect(uploadDisabled(true, {})).toBe(false);
  });

  it("sends nothing when disabled, signed out or without an org", async () => {
    const w = quiet();
    expect((await uploadResult(result, { source: "scan", target: "t", kind: "repo", upload: false })).reason).toBe("disabled");
    session = false;
    expect((await uploadResult(result, { source: "scan", target: "t", kind: "repo" })).reason).toBe("signed-out");
    session = true; cfg = {};
    expect((await uploadResult(result, { source: "scan", target: "t", kind: "repo" })).reason).toBe("no-org");
    w.mockRestore();
    expect(calls).toHaveLength(0);
  });

  it("posts the run to the current org and reports what changed", async () => {
    const out: string[] = [];
    const w = vi.spyOn(process.stdout, "write").mockImplementation((s) => { out.push(String(s)); return true; });
    const r = await uploadResult(result, { source: "ai-scan", target: "https://bot/chat", kind: "api", scope: "categories=a" });
    w.mockRestore();
    expect(r).toMatchObject({ uploaded: true, sync: { new: 2, fixed: 3 } });
    expect(calls[0].path).toBe("/api/orgs/org-1/scan-findings/report");
    expect(calls[0].body).toMatchObject({ source: "ai-scan", target: "https://bot/chat", kind: "api", scope: "categories=a" });
    expect((calls[0].body.result as { findings: unknown[] }).findings).toHaveLength(1);
    expect(out.join("")).toMatch(/Saved to acme: 2 new · 1 still open · 3 fixed/);
  });

  it("cleans URL locations in findings like the target", async () => {
    const w = quiet();
    await uploadResult({ ...result, findings: [{ type: "p", severity: "high", message: "m", location: "https://bot/chat?key=sk-1" }, { ...result.findings[0] }] },
      { source: "ai-scan", target: "https://bot/chat", kind: "api" });
    w.mockRestore();
    const sent = (calls[0].body.result as { findings: Array<{ location: string }> }).findings.map((f) => f.location);
    expect(sent).toEqual(["https://bot/chat", "a.ts:1"]);
  });

  it("THREATCRUSH_API_KEY uploads to the key's org with no login and no org picked", async () => {
    session = false; cfg = {};
    const seen: Array<{ url: string; auth: string }> = [];
    const f = vi.spyOn(globalThis, "fetch").mockImplementation(async (url, init) => {
      seen.push({ url: String(url), auth: (init?.headers as Record<string, string>).Authorization });
      return new Response(JSON.stringify({ sync: { new: 1, seen: 0, reopened: 0, fixed: 0 } }), { status: 201 });
    });
    const out: string[] = [];
    const w = vi.spyOn(process.stdout, "write").mockImplementation((s) => { out.push(String(s)); return true; });
    const r = await uploadResult(result, { source: "scan", target: "github.com/acme/app", kind: "repo", env: { THREATCRUSH_API_KEY: " tc_agent_abc " } });
    w.mockRestore(); f.mockRestore();
    expect(r.uploaded).toBe(true);
    expect(seen).toEqual([{ url: "https://tc.test/api/v1/findings/report", auth: "Bearer tc_agent_abc" }]);
    expect(calls).toHaveLength(0);
    expect(out.join("")).toMatch(/Saved to the API key's org: 1 new/);
  });

  it("a server error is reported, never thrown", async () => {
    reply = { status: 403, body: { error: "Not authorized" } };
    const out: string[] = [];
    const w = vi.spyOn(process.stdout, "write").mockImplementation((s) => { out.push(String(s)); return true; });
    expect((await uploadResult(result, { source: "scan", target: "t", kind: "repo" })).reason).toBe("error");
    w.mockRestore();
    expect(out.join("")).toMatch(/Not saved to the cloud: Not authorized/);
  });

  it("machine-readable output keeps stdout clean", async () => {
    const out = vi.spyOn(process.stdout, "write").mockImplementation(() => true);
    const err = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
    await uploadResult(result, { source: "scan", target: "t", kind: "repo", machineReadable: true });
    expect(out).not.toHaveBeenCalled();
    expect(err).toHaveBeenCalled();
    out.mockRestore(); err.mockRestore();
  });
});

describe("targets", () => {
  it("strips credentials, query and fragment from URLs", () => {
    expect(cleanUrl("https://u:p@bot.example/chat?key=sk-123#x")).toBe("https://bot.example/chat");
  });

  it("names a repo by its origin remote, credentials stripped, and scopes a subfolder", () => {
    const fake = (remote: string) => (args: string[]) => (args[0] === "rev-parse" ? "/work/app" : remote);
    expect(repoTarget("/work/app", fake("git@github.com:acme/app.git")).target).toBe("github.com/acme/app");
    expect(repoTarget("/work/app", fake("https://x:ghp_tok@github.com/acme/app.git")).target).toBe("github.com/acme/app");
    expect(repoTarget("/work/app/api", fake("https://github.com/acme/app")).sub).toBe("api");
    expect(repoTarget("/work/app", fake("https://github.com/acme/app")).sub).toBe(".");
  });

  it("falls back to host:path outside git", () => {
    const t = repoTarget("/tmp/x", () => { throw new Error("not a repo"); });
    expect(t.target).toMatch(/:\/tmp\/x$/);
  });
});
