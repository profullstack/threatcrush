import type { NextRequest } from "next/server";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { recordQuery, type QueryCall, type QueryResult } from "@/__tests__/helpers/query-recorder";

/**
 * Admin review actions and the source health check, through the real admin
 * guard: only a profile with is_admin can change a listing's review state.
 */

const mockSafeFetch = vi.fn();

const state = {
  profiles: {} as Record<string, { id: string; email: string; is_admin: boolean }>,
  modulesResults: [] as QueryResult[],
  moduleQueries: [] as QueryCall[][],
};

vi.mock("@/lib/ssrf-guard", () => ({
  safeFetch: (...args: unknown[]) => mockSafeFetch(...args),
}));

vi.mock("@/lib/supabase", () => ({
  getSupabaseClient: () => ({
    auth: {
      getUser: async (token: string) =>
        state.profiles[token]
          ? { data: { user: { id: state.profiles[token].id } }, error: null }
          : { data: { user: null }, error: { message: "bad jwt" } },
    },
  }),
  getSupabaseAdmin: () => ({
    from: (table: string) => {
      if (table === "user_profiles") {
        return {
          select: () => ({
            eq: (_col: string, id: string) => ({
              single: async () => {
                const profile = Object.values(state.profiles).find((p) => p.id === id);
                return { data: profile ?? null, error: profile ? null : { message: "not found" } };
              },
            }),
          }),
        };
      }
      if (table === "modules") {
        const calls: QueryCall[] = [];
        state.moduleQueries.push(calls);
        return recordQuery(state.modulesResults.shift() ?? { data: null, error: null }, calls);
      }
      throw new Error(`Unexpected table ${table}`);
    },
  }),
}));

import { GET as listForReview } from "@/app/api/admin/marketplace/modules/route";
import { PATCH as reviewModule } from "@/app/api/admin/marketplace/modules/[slug]/route";
import { POST as checkSources } from "@/app/api/admin/marketplace/source-health/route";

function request(url: string, token: string | null, init: RequestInit = {}) {
  const headers = new Headers(init.headers);
  if (token) headers.set("authorization", `Bearer ${token}`);
  return new Request(`http://localhost${url}`, { ...init, headers }) as unknown as NextRequest;
}

function review(token: string | null, body: unknown, slug = "fresh-module") {
  return reviewModule(
    request(`/api/admin/marketplace/modules/${slug}`, token, { method: "PATCH", body: JSON.stringify(body) }),
    { params: Promise.resolve({ slug }) },
  );
}

const updateOf = (calls: QueryCall[]) => calls.find(([method]) => method === "update")?.[1];

beforeEach(() => {
  state.profiles = {
    "admin-token": { id: "admin-1", email: "admin@example.com", is_admin: true },
    "user-token": { id: "user-1", email: "author@example.com", is_admin: false },
  };
  state.modulesResults = [];
  state.moduleQueries = [];
  mockSafeFetch.mockReset();
});

describe("PATCH /api/admin/marketplace/modules/:slug", () => {
  it("approving publishes the module and records the reviewer", async () => {
    state.modulesResults = [{ data: { slug: "fresh-module", review_status: "approved", published: true }, error: null }];

    const res = await review("admin-token", { action: "approve", note: "Looks good" });

    expect(res.status).toBe(200);
    expect(updateOf(state.moduleQueries[0])).toMatchObject({
      review_status: "approved",
      published: true,
      reviewed_by: "admin-1",
      review_note: "Looks good",
      reviewed_at: expect.any(String),
    });
  });

  it.each([
    ["a signed-in non-admin", "user-token", 403],
    ["an anonymous caller", null, 401],
  ])("refuses %s and changes nothing", async (_label, token, status) => {
    const res = await review(token, { action: "approve" });

    expect(res.status).toBe(status);
    expect(state.moduleQueries).toHaveLength(0);
  });

  it("rejecting requires a note for the author", async () => {
    const res = await review("admin-token", { action: "reject", note: "  " });

    expect(res.status).toBe(400);
    expect(state.moduleQueries).toHaveLength(0);
  });

  it("rejecting hides the module", async () => {
    state.modulesResults = [{ data: { slug: "fresh-module" }, error: null }];

    await review("admin-token", { action: "reject", note: "Source repo is empty" });

    expect(updateOf(state.moduleQueries[0])).toMatchObject({ review_status: "rejected", published: false });
  });

  it("unpublishing hides the module without changing its review verdict", async () => {
    state.modulesResults = [{ data: { slug: "fresh-module" }, error: null }];

    await review("admin-token", { action: "unpublish" });

    const update = updateOf(state.moduleQueries[0]);
    expect(update).toMatchObject({ published: false });
    expect(update).not.toHaveProperty("review_status");
  });

  it("rejects an unknown action", async () => {
    const res = await review("admin-token", { action: "publish-everything" });

    expect(res.status).toBe(400);
  });

  it("returns 404 for an unknown slug", async () => {
    state.modulesResults = [{ data: null, error: null }];

    const res = await review("admin-token", { action: "approve" }, "nope");

    expect(res.status).toBe(404);
  });
});

describe("GET /api/admin/marketplace/modules", () => {
  it("is admin-only", async () => {
    const res = await listForReview(request("/api/admin/marketplace/modules", "user-token"));

    expect(res.status).toBe(403);
  });

  it("lists every review state, optionally narrowed", async () => {
    state.modulesResults = [{ data: [{ slug: "a", review_status: "pending" }], error: null }];

    const res = await listForReview(request("/api/admin/marketplace/modules?review_status=pending", "admin-token"));

    expect(res.status).toBe(200);
    expect(state.moduleQueries[0]).toContainEqual(["eq", "review_status", "pending"]);
    expect(state.moduleQueries[0]).not.toContainEqual(["eq", "published", true]);
  });
});

describe("POST /api/admin/marketplace/source-health", () => {
  it("is admin-only", async () => {
    const res = await checkSources(request("/api/admin/marketplace/source-health", "user-token", { method: "POST" }));

    expect(res.status).toBe(403);
    expect(mockSafeFetch).not.toHaveBeenCalled();
  });

  it("records each listing's source status", async () => {
    state.modulesResults = [
      {
        data: [
          { id: "m1", slug: "good-repo", git_url: "https://github.com/acme/good" },
          { id: "m2", slug: "gone-repo", git_url: "https://github.com/acme/gone" },
        ],
        error: null,
      },
    ];
    mockSafeFetch.mockImplementation(async (url: string) =>
      url.includes("/acme/good/")
        ? new Response("", { status: 200, headers: { "content-type": "application/x-git-upload-pack-advertisement" } })
        : new Response("", { status: 401 }),
    );

    const res = await checkSources(request("/api/admin/marketplace/source-health", "admin-token", { method: "POST" }));
    const body = await res.json();

    expect(res.status).toBe(200);
    expect(body.results.map((r: { slug: string; status: string }) => [r.slug, r.status])).toEqual([
      ["gone-repo", "not_found"],
      ["good-repo", "ok"],
    ]);
    const updates = state.moduleQueries.slice(1).map((calls) => ({
      id: calls.find(([method]) => method === "eq")?.[2],
      status: (updateOf(calls) as { source_status: string }).source_status,
    }));
    expect(updates).toEqual(expect.arrayContaining([
      { id: "m1", status: "ok" },
      { id: "m2", status: "not_found" },
    ]));
  });
});
