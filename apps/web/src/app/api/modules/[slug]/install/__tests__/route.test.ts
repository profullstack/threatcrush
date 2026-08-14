import { describe, it, expect, vi, beforeEach } from "vitest";
import { TEST_MODULE } from "@/__tests__/helpers/supabase-mock";

// ─── Supabase mock ───

const mockUpdate = vi.fn();
const mockInsert = vi.fn();
// TC-24: the download count is now incremented by an atomic RPC rather than
// read-modify-write, so it returns the new value directly.
const mockRpc = vi.fn();
let moduleLookupResult: { data: unknown; error: unknown } = {
  data: {
    id: "mod-001",
    name: "Test Scanner",
    slug: "test-scanner",
    downloads: 42,
    version: "1.0.0",
    git_url: "https://github.com/test/scanner",
    license: "MIT",
    min_threatcrush_version: ">=0.2.0",
    os_support: ["linux"],
  },
  error: null,
};

vi.mock("@/lib/supabase", () => ({
  getSupabaseAdmin: () => ({
    rpc: mockRpc,
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
    mockRpc.mockResolvedValue({ data: 43, error: null });
    moduleLookupResult = {
      data: {
        id: "mod-001",
        name: "Test Scanner",
        slug: "test-scanner",
        downloads: 42,
        version: "1.0.0",
        git_url: "https://github.com/test/scanner",
        license: "MIT",
        min_threatcrush_version: ">=0.2.0",
        os_support: ["linux"],
      },
      error: null,
    };
  });

  it("increments download count atomically via RPC", async () => {
    const req = makeRequest({ platform: "linux" });
    const res = await POST(req, makeContext("test-scanner"));
    const body = await res.json();

    expect(res.status).toBe(200);
    expect(body.success).toBe(true);
    expect(body.downloads).toBe(43);
    expect(mockRpc).toHaveBeenCalledWith("increment_module_downloads", {
      p_module_id: "mod-001",
    });
    // The old read-modify-write path must be gone.
    expect(mockUpdate).not.toHaveBeenCalled();
  });

  it("returns git install info from the marketplace module record", async () => {
    const req = makeRequest({ platform: "linux" });
    const res = await POST(req, makeContext("test-scanner"));
    const body = await res.json();

    expect(res.status).toBe(200);
    expect(body.module.install.git_url).toBe("https://github.com/test/scanner");
    expect(body.module.install.npm_package).toBeNull();
    expect(body.module.install.tarball_url).toBeNull();
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
