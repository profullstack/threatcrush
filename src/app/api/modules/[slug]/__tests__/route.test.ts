import { describe, it, expect, vi, beforeEach } from "vitest";
import { TEST_MODULE } from "@/__tests__/helpers/supabase-mock";

// ─── Supabase mock ───

let mockFromResponses: Record<string, unknown> = {};

vi.mock("@/lib/supabase", () => ({
  getSupabaseAdmin: () => ({
    from: (table: string) => {
      if (mockFromResponses[table]) return mockFromResponses[table];
      return createChainable({ data: null, error: null });
    },
  }),
}));

function createChainable(result: { data: unknown; error: unknown }) {
  const handler: ProxyHandler<object> = {
    get(_target, prop: string) {
      if (prop === "then") {
        // Make the proxy thenable — when awaited directly, resolve to result
        return (resolve: (v: unknown) => void) => resolve(result);
      }
      if (prop === "single" || prop === "maybeSingle") {
        return vi.fn().mockResolvedValue(result);
      }
      return vi.fn().mockReturnValue(new Proxy({}, handler));
    },
  };
  return new Proxy({}, handler);
}

import { GET, PATCH, DELETE } from "@/app/api/modules/[slug]/route";

function makeRequest(url: string, init?: RequestInit) {
  const req = new Request(url, init);
  // NextRequest needs nextUrl
  (req as unknown as Record<string, unknown>).nextUrl = new URL(url);
  return req as unknown as import("next/server").NextRequest;
}

function makeContext(slug: string) {
  return { params: Promise.resolve({ slug }) };
}

const TEST_VERSIONS = [
  { id: "v-001", module_id: "mod-001", version: "1.0.0", changelog: "Initial", created_at: "2025-01-01T00:00:00Z" },
];

const TEST_REVIEWS = [
  { id: "rev-001", module_id: "mod-001", user_email: "r@test.com", rating: 5, title: "Great", body: "Works", created_at: "2025-03-01T00:00:00Z" },
];

describe("GET /api/modules/:slug", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockFromResponses = {
      modules: createChainable({ data: TEST_MODULE, error: null }),
      module_versions: createChainable({ data: TEST_VERSIONS, error: null }),
      module_reviews: createChainable({ data: TEST_REVIEWS, error: null }),
    };
  });

  it("returns module with versions and reviews", async () => {
    const req = makeRequest("http://localhost/api/modules/test-scanner");
    const res = await GET(req, makeContext("test-scanner"));
    const body = await res.json();

    expect(res.status).toBe(200);
    expect(body.module).toBeDefined();
    expect(body.module.slug).toBe("test-scanner");
    expect(body.versions).toBeDefined();
    expect(body.reviews).toBeDefined();
  });

  it("returns 404 for unknown slug", async () => {
    mockFromResponses.modules = createChainable({ data: null, error: { message: "not found" } });

    const req = makeRequest("http://localhost/api/modules/nonexistent");
    const res = await GET(req, makeContext("nonexistent"));
    const body = await res.json();

    expect(res.status).toBe(404);
    expect(body.error).toBe("Module not found");
  });
});

describe("PATCH /api/modules/:slug", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockFromResponses = {
      modules: createChainable({
        data: { id: "mod-001", author_email: "test@example.com" },
        error: null,
      }),
    };
  });

  it("updates module fields", async () => {
    // Override to return updated module on the update call
    const updatedModule = { ...TEST_MODULE, description: "Updated description" };
    mockFromResponses.modules = createChainable({
      data: updatedModule,
      error: null,
    });

    const req = makeRequest("http://localhost/api/modules/test-scanner", {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ author_email: "test@example.com", description: "Updated description" }),
    });
    const res = await PATCH(req, makeContext("test-scanner"));
    const body = await res.json();

    expect(res.status).toBe(200);
    expect(body.module).toBeDefined();
  });

  it("rejects missing author_email", async () => {
    const req = makeRequest("http://localhost/api/modules/test-scanner", {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ description: "Updated" }),
    });
    const res = await PATCH(req, makeContext("test-scanner"));
    const body = await res.json();

    expect(res.status).toBe(400);
    expect(body.error).toContain("author_email");
  });

  it("rejects invalid JSON", async () => {
    const req = makeRequest("http://localhost/api/modules/test-scanner", {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: "not json",
    });
    const res = await PATCH(req, makeContext("test-scanner"));
    const body = await res.json();

    expect(res.status).toBe(400);
    expect(body.error).toContain("Invalid JSON");
  });
});

describe("DELETE /api/modules/:slug", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("deletes a module", async () => {
    mockFromResponses = {
      modules: createChainable({
        data: { id: "mod-001", author_email: "test@example.com" },
        error: null,
      }),
    };

    const req = makeRequest("http://localhost/api/modules/test-scanner?author_email=test@example.com", {
      method: "DELETE",
    });
    const res = await DELETE(req, makeContext("test-scanner"));
    const body = await res.json();

    expect(res.status).toBe(200);
    expect(body.deleted).toBe(true);
  });

  it("rejects missing author_email", async () => {
    const req = makeRequest("http://localhost/api/modules/test-scanner", {
      method: "DELETE",
    });
    const res = await DELETE(req, makeContext("test-scanner"));
    const body = await res.json();

    expect(res.status).toBe(400);
    expect(body.error).toContain("author_email");
  });

  it("returns 404 for unknown slug", async () => {
    mockFromResponses = {
      modules: createChainable({ data: null, error: null }),
    };

    const req = makeRequest("http://localhost/api/modules/nonexistent?author_email=test@example.com", {
      method: "DELETE",
    });
    const res = await DELETE(req, makeContext("nonexistent"));
    const body = await res.json();

    expect(res.status).toBe(404);
  });
});
