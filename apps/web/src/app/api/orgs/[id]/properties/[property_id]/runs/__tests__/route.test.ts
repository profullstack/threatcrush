import { beforeEach, describe, expect, it, vi } from "vitest";

const limitMock = vi.fn();

vi.mock("@/lib/supabase", () => ({
  getSupabaseAdmin: () => ({
    auth: {
      getUser: vi.fn().mockResolvedValue({
        data: { user: { id: "user-1" } },
      }),
    },
    from: (table: string) => {
      if (table === "organization_members") {
        return {
          select: vi.fn().mockReturnThis(),
          eq: vi.fn().mockReturnThis(),
          single: vi.fn().mockResolvedValue({ data: { role: "member" }, error: null }),
        };
      }

      if (table === "property_runs") {
        return {
          select: vi.fn().mockReturnThis(),
          eq: vi.fn().mockReturnThis(),
          order: vi.fn().mockReturnThis(),
          limit: limitMock.mockResolvedValue({ data: [], error: null }),
        };
      }

      throw new Error(`Unexpected table ${table}`);
    },
  }),
}));

import { GET } from "@/app/api/orgs/[id]/properties/[property_id]/runs/route";

function makeRequest(url: string) {
  const req = new Request(url, {
    headers: { authorization: "Bearer test-token" },
  });
  return req as unknown as import("next/server").NextRequest;
}

function makeContext() {
  return { params: Promise.resolve({ id: "org-1", property_id: "prop-1" }) };
}

describe("GET /api/orgs/:id/properties/:property_id/runs", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("falls back to the default limit for malformed or negative values", async () => {
    const malformed = makeRequest("http://localhost/api/orgs/org-1/properties/prop-1/runs?limit=abc");
    await GET(malformed, makeContext());

    const negative = makeRequest("http://localhost/api/orgs/org-1/properties/prop-1/runs?limit=-5");
    await GET(negative, makeContext());

    expect(limitMock).toHaveBeenNthCalledWith(1, 25);
    expect(limitMock).toHaveBeenNthCalledWith(2, 25);
  });

  it("caps valid positive limits at 100", async () => {
    const req = makeRequest("http://localhost/api/orgs/org-1/properties/prop-1/runs?limit=500");
    await GET(req, makeContext());

    expect(limitMock).toHaveBeenCalledWith(100);
  });
});
