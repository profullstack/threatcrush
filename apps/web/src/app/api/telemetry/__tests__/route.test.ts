import { beforeEach, describe, expect, it, vi } from "vitest";

const inserted: unknown[] = [];
let insertError: { message: string } | null = null;

vi.mock("@/lib/supabase", () => ({
  getSupabaseAdmin: () => ({
    from: (table: string) => ({
      insert: async (row: unknown) => {
        inserted.push({ table, row });
        return { error: insertError };
      },
    }),
  }),
}));

import { POST } from "@/app/api/telemetry/route";
import { parsePing } from "@/lib/usage-ping";

const req = (body: string) =>
  new Request("http://localhost/api/telemetry", { method: "POST", body }) as unknown as import("next/server").NextRequest;

const PING = {
  event: "ai-scan", probes: 12, findings: 2, severity: { high: 2, bogus: 9 }, duration_ms: 812,
  version: "0.13.53", platform: "linux", arch: "x64", node: "v24.22.1", ci: false,
  install_id: "0b9c3f2e-6a1d-4c55-9f3e-2d4b8a7c1e90",
};

describe("POST /api/telemetry", () => {
  beforeEach(() => { inserted.length = 0; insertError = null; });

  it("stores a valid ping and keeps only documented fields", async () => {
    const res = await POST(req(JSON.stringify({ ...PING, target: "https://secret.example/llm", ip: "1.2.3.4" })));
    expect(res.status).toBe(202);
    expect(inserted).toHaveLength(1);
    const { table, row } = inserted[0] as { table: string; row: Record<string, unknown> };
    expect(table).toBe("cli_usage_pings");
    expect(row).not.toHaveProperty("target");
    expect(row).not.toHaveProperty("ip");
    expect(row.severity).toEqual({ high: 2 });
    expect(row.findings).toBe(2);
  });

  it("rejects unknown events, junk and oversize bodies without storing", async () => {
    for (const body of [JSON.stringify({ ...PING, event: "scan" }), "not json", "[]", "x".repeat(5000), ""]) {
      expect((await POST(req(body))).status).toBe(400);
    }
    expect(inserted).toHaveLength(0);
  });

  it("drops malformed strings and clamps numbers", () => {
    const row = parsePing({ ...PING, version: "<script>", install_id: "nope", probes: -1, duration_ms: 1e12, ci: "yes" })!;
    expect(row.version).toBeNull();
    expect(row.install_id).toBeNull();
    expect(row.probes).toBeNull();
    expect(row.duration_ms).toBe(1_000_000);
    expect(row.ci).toBe(false);
  });

  it("answers 500 when the insert fails", async () => {
    insertError = { message: "relation does not exist" };
    expect((await POST(req(JSON.stringify(PING)))).status).toBe(500);
  });
});
