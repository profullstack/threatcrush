import { describe, it, expect, vi } from "vitest";

vi.mock("@/lib/reputation-auth", () => ({ reputationCaller: vi.fn().mockResolvedValue(null) }));

import { POST } from "@/app/api/mcp/route";

const call = (body: unknown) =>
  POST(
    new Request("http://localhost/api/mcp", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    }) as unknown as import("next/server").NextRequest,
  );

describe("/api/mcp", () => {
  it("initializes and lists the reputation tools without a key", async () => {
    const init = await (await call({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} })).json();
    expect(init.result.serverInfo.name).toBe("ThreatCrush");
    const list = await (await call({ jsonrpc: "2.0", id: 2, method: "tools/list" })).json();
    expect(list.result.tools.map((t: { name: string }) => t.name)).toEqual(["reputation_lookup", "reputation_bulk"]);
  });

  it("a tool call without a key is a tool error the model can read", async () => {
    const res = await (
      await call({ jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "reputation_lookup", arguments: { indicator: "1.2.3.4" } } })
    ).json();
    expect(res.result.isError).toBe(true);
    expect(res.result.content[0].text).toContain("API key is required");
  });

  it("notifications get 202, unknown methods an error, bad JSON a parse error", async () => {
    expect((await call({ jsonrpc: "2.0", method: "notifications/initialized" })).status).toBe(202);
    const unknown = await (await call({ jsonrpc: "2.0", id: 4, method: "nope" })).json();
    expect(unknown.error.code).toBe(-32601);
    const bad = await POST(
      new Request("http://localhost/api/mcp", { method: "POST", body: "{" }) as unknown as import("next/server").NextRequest,
    );
    expect(bad.status).toBe(400);
  });
});
