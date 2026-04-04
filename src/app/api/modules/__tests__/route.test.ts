import { describe, it, expect, vi, beforeEach } from "vitest";
import { TEST_MODULE } from "@/__tests__/helpers/supabase-mock";

// ─── Supabase mock setup ───

const mockSelect = vi.fn();
const mockInsert = vi.fn();
const mockEq = vi.fn();
const mockOr = vi.fn();
const mockOrder = vi.fn();
const mockRange = vi.fn();
const mockSingle = vi.fn();
const mockSelectChain = vi.fn();

function resetChain(overrides: {
  rangeResult?: { data: unknown; error: unknown; count: number | null };
  singleResult?: { data: unknown; error: unknown };
} = {}) {
  const rangeResult = overrides.rangeResult ?? { data: [TEST_MODULE], error: null, count: 1 };
  const singleResult = overrides.singleResult ?? { data: null, error: null };

  mockRange.mockResolvedValue(rangeResult);
  mockSingle.mockResolvedValue(singleResult);
  mockSelectChain.mockReturnValue({ single: mockSingle });
  mockInsert.mockReturnValue({ select: mockSelectChain });
  mockOrder.mockReturnValue({ range: mockRange });
  mockOr.mockReturnValue({ eq: mockEq, order: mockOrder });
  mockEq.mockReturnValue({ or: mockOr, eq: mockEq, order: mockOrder, range: mockRange, single: mockSingle });
  mockSelect.mockReturnValue({ eq: mockEq });
}

vi.mock("@/lib/supabase", () => ({
  getSupabaseAdmin: () => ({
    from: () => ({
      select: mockSelect,
      insert: mockInsert,
    }),
  }),
  slugify: (name: string) =>
    name
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-|-$/g, ""),
}));

import { GET, POST } from "@/app/api/modules/route";

function makeRequest(url: string, init?: RequestInit) {
  return new Request(url, init) as unknown as import("next/server").NextRequest;
}

describe("GET /api/modules", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    resetChain();
  });

  it("returns module list with defaults", async () => {
    const req = makeRequest("http://localhost/api/modules");
    const res = await GET(req);
    const body = await res.json();

    expect(res.status).toBe(200);
    expect(body.modules).toEqual([TEST_MODULE]);
    expect(body.total).toBe(1);
    expect(body.page).toBe(1);
    expect(body.limit).toBe(20);
  });

  it("supports search parameter", async () => {
    const req = makeRequest("http://localhost/api/modules?search=scanner");
    await GET(req);

    expect(mockOr).toHaveBeenCalledWith(
      expect.stringContaining("scanner")
    );
  });

  it("supports category filter", async () => {
    const req = makeRequest("http://localhost/api/modules?category=security");
    await GET(req);

    // eq is called for published=true and category=security
    expect(mockEq).toHaveBeenCalledWith("category", "security");
  });

  it("supports pagination", async () => {
    const req = makeRequest("http://localhost/api/modules?page=2&limit=10");
    await GET(req);

    // offset = (2-1)*10 = 10, range(10, 19)
    expect(mockRange).toHaveBeenCalledWith(10, 19);
  });

  it("handles database errors", async () => {
    resetChain({
      rangeResult: { data: null, error: { message: "DB error" }, count: null },
    });

    const req = makeRequest("http://localhost/api/modules");
    const res = await GET(req);
    const body = await res.json();

    expect(res.status).toBe(500);
    expect(body.error).toBe("DB error");
  });
});

describe("POST /api/modules", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    resetChain();
  });

  it("creates a module with valid data", async () => {
    const newModule = { ...TEST_MODULE, id: "mod-new" };
    // slug check returns no existing, then insert returns new module
    resetChain({
      singleResult: { data: null, error: null },
    });
    mockSingle
      .mockResolvedValueOnce({ data: null, error: null })
      .mockResolvedValueOnce({ data: newModule, error: null });

    const req = makeRequest("http://localhost/api/modules", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: "test-scanner", author_email: "test@example.com" }),
    });
    const res = await POST(req);
    const body = await res.json();

    expect(res.status).toBe(201);
    expect(body.module).toBeDefined();
  });

  it("rejects missing name", async () => {
    const req = makeRequest("http://localhost/api/modules", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ author_email: "test@example.com" }),
    });
    const res = await POST(req);
    const body = await res.json();

    expect(res.status).toBe(400);
    expect(body.error).toContain("name");
  });

  it("rejects missing author_email", async () => {
    const req = makeRequest("http://localhost/api/modules", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: "test-scanner" }),
    });
    const res = await POST(req);
    const body = await res.json();

    expect(res.status).toBe(400);
    expect(body.error).toContain("author_email");
  });

  it("rejects duplicate slug", async () => {
    resetChain({
      singleResult: { data: { id: "existing-id" }, error: null },
    });

    const req = makeRequest("http://localhost/api/modules", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: "test-scanner", author_email: "test@example.com" }),
    });
    const res = await POST(req);
    const body = await res.json();

    expect(res.status).toBe(409);
    expect(body.error).toContain("already exists");
  });

  it("rejects invalid JSON", async () => {
    const req = makeRequest("http://localhost/api/modules", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "not json",
    });
    const res = await POST(req);
    const body = await res.json();

    expect(res.status).toBe(400);
    expect(body.error).toContain("Invalid JSON");
  });
});
