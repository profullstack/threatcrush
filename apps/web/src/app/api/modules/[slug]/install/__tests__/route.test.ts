import { describe, it, expect, vi, beforeEach } from "vitest";
import { TEST_MODULE } from "@/__tests__/helpers/supabase-mock";

// ─── Supabase mock ───

const mockUpdate = vi.fn();
const mockInsert = vi.fn();
let moduleLookupResult: { data: unknown; error: unknown } = {
  data: { id: "mod-001", downloads: 42, version: "1.0.0" },
  error: null,
};

vi.mock("@/lib/supabase", () => ({
  getSupabaseAdmin: () => ({
    from: (table: string) => {
      if (table === "modules") {
        return {
          select: vi.fn().mockReturnValue({
            eq: vi.fn().mockReturnValue({
              eq: vi.fn().mockReturnValue({
                single: vi.fn().mockResolvedValue(moduleLookupResult),
              }),
            }),
          }),
          update: mockUpdate.mockReturnValue({
            eq: vi.fn().mockResolvedValue({ error: null }),
          }),
        };
      }
      if (table === "module_installs") {
        return {
          insert: mockInsert.mockResolvedValue({ error: null }),
        };
      }
      return {};
    },
  }),
}));

import { POST } from "@/app/api/modules/[slug]/install/route";

function makeRequest(body?: unknown) {
  return new Request("http://localhost/api/modules/test-scanner/install", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: body ? JSON.stringify(body) : "{}",
  }) as unknown as import("next/server").NextRequest;
}

function makeContext(slug: string) {
  return { params: Promise.resolve({ slug }) };
}

describe("POST /api/modules/:slug/install", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    moduleLookupResult = {
      data: { id: "mod-001", downloads: 42, version: "1.0.0" },
      error: null,
    };
  });

  it("increments download count", async () => {
    const req = makeRequest({ platform: "linux" });
    const res = await POST(req, makeContext("test-scanner"));
    const body = await res.json();

    expect(res.status).toBe(200);
    expect(body.success).toBe(true);
    expect(body.downloads).toBe(43);
  });

  it("logs install with platform info", async () => {
    const req = makeRequest({
      user_email: "user@example.com",
      version: "1.0.0",
      platform: "linux",
    });
    await POST(req, makeContext("test-scanner"));

    expect(mockInsert).toHaveBeenCalledWith(
      expect.objectContaining({
        module_id: "mod-001",
        user_email: "user@example.com",
        version: "1.0.0",
        platform: "linux",
      })
    );
  });

  it("returns 404 for unknown module", async () => {
    moduleLookupResult = { data: null, error: { message: "not found" } };

    const req = makeRequest({});
    const res = await POST(req, makeContext("nonexistent"));
    const body = await res.json();

    expect(res.status).toBe(404);
    expect(body.error).toBe("Module not found");
  });

  it("handles empty body gracefully", async () => {
    const req = new Request("http://localhost/api/modules/test-scanner/install", {
      method: "POST",
    }) as unknown as import("next/server").NextRequest;
    const res = await POST(req, makeContext("test-scanner"));
    const body = await res.json();

    expect(res.status).toBe(200);
    expect(body.success).toBe(true);
  });
});
