import { describe, it, expect, vi, beforeEach } from "vitest";

const getUser = vi.fn();
const upsert = vi.fn();

vi.mock("@/lib/api-auth", () => ({
  getAuthenticatedRequestUser: (...args: unknown[]) => getUser(...args),
}));

vi.mock("@/lib/supabase", () => ({
  getSupabaseAdmin: () => ({
    auth: {},
    from: (table: string) => ({
      upsert: (row: Record<string, unknown>, opts: unknown) => {
        upsert(table, row, opts);
        return { select: () => ({ single: async () => ({ data: { email: "ada@acme.com", ...row }, error: null }) }) };
      },
    }),
  }),
}));

import { GET, PATCH } from "@/app/api/v1/me/profile/route";

const url = "https://threatcrush.com/api/v1/me/profile";
const req = (init?: RequestInit) => new Request(url, init) as unknown as import("next/server").NextRequest;

describe("/api/v1/me/profile", () => {
  beforeEach(() => vi.clearAllMocks());

  it("is 401 JSON when signed out", async () => {
    getUser.mockResolvedValue(null);
    const r = await GET(req());
    expect(r.status).toBe(401);
    expect(await r.json()).toHaveProperty("error");
  });

  it("PATCH saves normalized fields and never changes the account email", async () => {
    getUser.mockResolvedValue({ userId: "u1", email: "ada@acme.com", githubLogin: null });
    const r = await PATCH(
      req({
        method: "PATCH",
        headers: { "content-type": "application/json", authorization: "Bearer t" },
        body: JSON.stringify({ email: "someone@else.com", job_title: "  CTO ", company_domain: "https://www.Acme.com" }),
      }),
    );
    expect(r.status).toBe(200);
    expect(upsert).toHaveBeenCalledWith(
      "user_profiles",
      expect.objectContaining({ id: "u1", job_title: "CTO", company_domain: "acme.com" }),
      { onConflict: "id" },
    );
    expect(upsert.mock.calls[0][1]).not.toHaveProperty("email");
  });
});
