import { describe, it, expect, vi, beforeEach } from "vitest";
import { TEST_REVIEW } from "@/__tests__/helpers/supabase-mock";

// ─── Supabase mock ───

let moduleResult: { data: unknown; error: unknown } = {
  data: { id: "mod-001", rating_avg: 4.5, rating_count: 10 },
  error: null,
};
let reviewsResult: { data: unknown; error: unknown; count: number | null } = {
  data: [TEST_REVIEW],
  error: null,
  count: 1,
};
let upsertResult: { data: unknown; error: unknown } = {
  data: TEST_REVIEW,
  error: null,
};
let allReviewsResult: { data: unknown } = {
  data: [{ rating: 5 }, { rating: 4 }],
};
let authenticatedUser: { id: string } | null = { id: "user-1" };
let profileResult: { data: unknown; error: unknown } = {
  data: { id: "user-1", email: "reviewer@example.com" },
  error: null,
};
const mockUpdateRating = vi.fn().mockReturnValue({
  eq: vi.fn().mockResolvedValue({ error: null }),
});
const mockReviewRange = vi.fn().mockResolvedValue(reviewsResult);
const mockReviewUpsert = vi.fn().mockReturnValue({
  select: vi.fn().mockReturnValue({
    single: vi.fn().mockResolvedValue(upsertResult),
  }),
});

vi.mock("@/lib/supabase", () => ({
  getSupabaseAdmin: () => ({
    auth: {
      getUser: vi.fn().mockImplementation(async () => ({
        data: { user: authenticatedUser },
      })),
    },
    from: (table: string) => {
      if (table === "modules") {
        return {
          select: vi.fn().mockReturnValue({
            eq: vi.fn().mockReturnValue({
              single: vi.fn().mockResolvedValue(moduleResult),
              eq: vi.fn().mockReturnValue({
                single: vi.fn().mockResolvedValue(moduleResult),
              }),
            }),
          }),
          update: mockUpdateRating,
        };
      }
      if (table === "module_reviews") {
        return {
          select: vi.fn().mockReturnValue({
            eq: vi.fn().mockReturnValue({
              order: vi.fn().mockReturnValue({
                range: mockReviewRange,
                limit: vi.fn().mockResolvedValue({ data: [TEST_REVIEW] }),
              }),
              eq: vi.fn().mockResolvedValue(allReviewsResult),
            }),
          }),
          upsert: mockReviewUpsert,
        };
      }
      if (table === "user_profiles") {
        return {
          select: vi.fn().mockReturnValue({
            eq: vi.fn().mockReturnValue({
              single: vi.fn().mockImplementation(async () => profileResult),
            }),
          }),
        };
      }
      return {};
    },
  }),
}));

import { GET, POST } from "@/app/api/modules/[slug]/review/route";

function makeGetRequest(slug: string, page: string | number = 1) {
  const url = `http://localhost/api/modules/${slug}/review?page=${page}`;
  return new Request(url) as unknown as import("next/server").NextRequest;
}

function makePostRequest(body: unknown, authenticated = true) {
  return new Request("http://localhost/api/modules/test-scanner/review", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(authenticated ? { Authorization: "Bearer test-token" } : {}),
    },
    body: JSON.stringify(body),
  }) as unknown as import("next/server").NextRequest;
}

function makeContext(slug: string) {
  return { params: Promise.resolve({ slug }) };
}

describe("GET /api/modules/:slug/review", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    moduleResult = { data: { id: "mod-001" }, error: null };
    reviewsResult = { data: [TEST_REVIEW], error: null, count: 1 };
    mockReviewRange.mockResolvedValue(reviewsResult);
  });

  it("returns reviews for a module", async () => {
    const req = makeGetRequest("test-scanner");
    const res = await GET(req, makeContext("test-scanner"));
    const body = await res.json();

    expect(res.status).toBe(200);
    expect(body.reviews).toBeDefined();
    expect(body.total).toBeDefined();
    expect(body.page).toBe(1);
  });

  it("falls back to page 1 for non-numeric page values", async () => {
    const req = makeGetRequest("test-scanner", "not-a-number");
    const res = await GET(req, makeContext("test-scanner"));
    const body = await res.json();

    expect(res.status).toBe(200);
    expect(body.page).toBe(1);
    expect(mockReviewRange).toHaveBeenCalledWith(0, 19);
  });

  it("returns 404 for unknown module", async () => {
    moduleResult = { data: null, error: null };

    const req = makeGetRequest("nonexistent");
    const res = await GET(req, makeContext("nonexistent"));
    const body = await res.json();

    expect(res.status).toBe(404);
    expect(body.error).toBe("Module not found");
  });
});

describe("POST /api/modules/:slug/review", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    moduleResult = { data: { id: "mod-001", rating_avg: 4.5, rating_count: 10 }, error: null };
    upsertResult = { data: TEST_REVIEW, error: null };
    allReviewsResult = { data: [{ rating: 5 }, { rating: 4 }] };
    authenticatedUser = { id: "user-1" };
    profileResult = {
      data: { id: "user-1", email: "reviewer@example.com" },
      error: null,
    };
  });

  it("creates a review with valid rating", async () => {
    const req = makePostRequest({
      user_email: "victim@example.com",
      rating: 5,
      title: "Great module",
      body: "Works perfectly",
    });
    const res = await POST(req, makeContext("test-scanner"));
    const body = await res.json();

    expect(res.status).toBe(201);
    expect(body.review).toBeDefined();
    expect(mockReviewUpsert).toHaveBeenCalledWith(
      expect.objectContaining({ user_email: "reviewer@example.com" }),
      { onConflict: "module_id,user_email" }
    );
  });

  it("rejects unauthenticated reviews", async () => {
    const req = makePostRequest({ rating: 5 }, false);
    const res = await POST(req, makeContext("test-scanner"));
    const body = await res.json();

    expect(res.status).toBe(401);
    expect(body.error).toContain("logged in");
    expect(mockReviewUpsert).not.toHaveBeenCalled();
  });

  it("rejects rating below 1", async () => {
    const req = makePostRequest({
      rating: 0,
    });
    const res = await POST(req, makeContext("test-scanner"));
    const body = await res.json();

    expect(res.status).toBe(400);
    expect(body.error).toContain("rating must be 1-5");
  });

  it("rejects rating above 5", async () => {
    const req = makePostRequest({
      rating: 6,
    });
    const res = await POST(req, makeContext("test-scanner"));
    const body = await res.json();

    expect(res.status).toBe(400);
    expect(body.error).toContain("rating must be 1-5");
  });

  it("rejects fractional ratings before writing to the integer column", async () => {
    const req = makePostRequest({
      rating: 4.5,
    });
    const res = await POST(req, makeContext("test-scanner"));
    const body = await res.json();

    expect(res.status).toBe(400);
    expect(body.error).toContain("integer");
    expect(mockReviewUpsert).not.toHaveBeenCalled();
  });

  it("rejects missing rating", async () => {
    const req = makePostRequest({});
    const res = await POST(req, makeContext("test-scanner"));
    const body = await res.json();

    expect(res.status).toBe(400);
    expect(body.error).toContain("rating");
  });

  it("rejects invalid JSON", async () => {
    const req = new Request("http://localhost/api/modules/test-scanner/review", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: "Bearer test-token",
      },
      body: "not json",
    }) as unknown as import("next/server").NextRequest;
    const res = await POST(req, makeContext("test-scanner"));
    const body = await res.json();

    expect(res.status).toBe(400);
  });
});
