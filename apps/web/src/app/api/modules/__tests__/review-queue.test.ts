import type { NextRequest } from "next/server";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { recordQuery, type QueryCall, type QueryResult } from "@/__tests__/helpers/query-recorder";

/**
 * The review queue's public contract: submissions start private and pending,
 * only approved + published listings are served publicly, authors can still
 * see their own, and a listing with a broken source can't be installed.
 */

const AUTHOR = { id: "user-1", email: "author@example.com" };

const state = {
  /** Result for each successive query, per table. */
  results: {} as Record<string, QueryResult[]>,
  queries: [] as Array<{ table: string; calls: QueryCall[] }>,
  rpc: vi.fn(),
};

function queriesOn(table: string) {
  return state.queries.filter((q) => q.table === table).map((q) => q.calls);
}

vi.mock("@/lib/supabase", () => {
  const getUser = async (token: string) =>
    token === "author-token"
      ? { data: { user: AUTHOR }, error: null }
      : { data: { user: null }, error: { message: "bad jwt" } };
  return {
    getSupabaseClient: () => ({ auth: { getUser } }),
    getSupabaseAdmin: () => ({
      auth: { getUser },
      rpc: state.rpc,
      from: (table: string) => {
        const calls: QueryCall[] = [];
        state.queries.push({ table, calls });
        return recordQuery(state.results[table]?.shift() ?? { data: null, error: null }, calls);
      },
    }),
    slugify: (name: string) => name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, ""),
  };
});

import { GET as listModules, POST as submitModule } from "@/app/api/modules/route";
import { GET as getModule, PATCH as patchModule } from "@/app/api/modules/[slug]/route";
import { POST as installModule } from "@/app/api/modules/[slug]/install/route";

function request(url: string, init: RequestInit & { token?: string } = {}) {
  const headers = new Headers(init.headers);
  if (init.token) headers.set("authorization", `Bearer ${init.token}`);
  return new Request(`http://localhost${url}`, { ...init, headers }) as unknown as NextRequest;
}

const ctx = (slug: string) => ({ params: Promise.resolve({ slug }) });

const PENDING = {
  id: "mod-1",
  slug: "fresh-module",
  author_email: AUTHOR.email,
  published: false,
  review_status: "pending",
  reviewed_by: null,
  review_note: null,
};

beforeEach(() => {
  state.results = {};
  state.queries = [];
  state.rpc.mockReset().mockResolvedValue({ data: 1, error: null });
});

describe("POST /api/modules (submission)", () => {
  function submit(body: Record<string, unknown>) {
    return submitModule(
      request("/api/modules", {
        method: "POST",
        token: "author-token",
        body: JSON.stringify({ name: "fresh-module", author_email: AUTHOR.email, ...body }),
      }),
    );
  }

  beforeEach(() => {
    state.results.user_profiles = [{ data: { id: AUTHOR.id, email: AUTHOR.email, email_verified: true }, error: null }];
    state.results.modules = [
      { data: null, error: null }, // slug is free
      { data: PENDING, error: null }, // insert
    ];
  });

  it("stores a new submission unpublished and pending review", async () => {
    const res = await submit({ git_url: "https://github.com/acme/fresh-module" });

    expect(res.status).toBe(201);
    const insert = queriesOn("modules")[1].find(([method]) => method === "insert");
    expect(insert?.[1]).toMatchObject({ published: false, review_status: "pending", pricing_type: "free" });
  });

  it.each([
    { pricing_type: "paid", price_usd: 9.99 },
    { pricing_type: "freemium" },
    { pricing_type: "free", price_usd: 5 },
  ])("rejects paid pricing %o without storing anything", async (pricing) => {
    const res = await submit(pricing);

    expect(res.status).toBe(400);
    expect((await res.json()).error).toMatch(/paid modules aren't supported yet/i);
    expect(queriesOn("modules")).toHaveLength(0);
  });

  it("accepts explicit free pricing with a zero price", async () => {
    const res = await submit({ pricing_type: "free", price_usd: 0 });

    expect(res.status).toBe(201);
  });
});

describe("GET /api/modules (listing)", () => {
  it("serves only approved and published listings, without reviewer details", async () => {
    state.results.modules = [
      { data: [{ slug: "live", reviewed_by: "admin-1", review_note: "internal" }], error: null, count: 1 },
    ];

    const res = await listModules(request("/api/modules"));
    const body = await res.json();

    const [calls] = queriesOn("modules");
    expect(calls).toContainEqual(["eq", "published", true]);
    expect(calls).toContainEqual(["eq", "review_status", "approved"]);
    expect(body.modules).toEqual([{ slug: "live" }]);
  });

  it("lists the signed-in author's own submissions in every review state with ?mine=1", async () => {
    state.results.modules = [{ data: [PENDING], error: null, count: 1 }];

    const res = await listModules(request("/api/modules?mine=1", { token: "author-token" }));
    const body = await res.json();

    const [calls] = queriesOn("modules");
    expect(calls).toContainEqual(["eq", "author_email", AUTHOR.email]);
    expect(calls).not.toContainEqual(["eq", "review_status", "approved"]);
    expect(body.modules[0].review_status).toBe("pending");
  });

  it("requires sign-in for ?mine=1", async () => {
    const res = await listModules(request("/api/modules?mine=1"));

    expect(res.status).toBe(401);
    expect(queriesOn("modules")).toHaveLength(0);
  });
});

describe("GET /api/modules/:slug", () => {
  it.each([
    ["pending", { ...PENDING }],
    ["rejected", { ...PENDING, review_status: "rejected" }],
    ["approved but unpublished", { ...PENDING, review_status: "approved", published: false }],
  ])("hides a %s module from the public", async (_label, row) => {
    state.results.modules = [{ data: row, error: null }];

    const res = await getModule(request("/api/modules/fresh-module"), ctx("fresh-module"));

    expect(res.status).toBe(404);
  });

  it("hides a pending module from a signed-in user who isn't the author", async () => {
    state.results.modules = [{ data: { ...PENDING, author_email: "someone@example.com" }, error: null }];

    const res = await getModule(request("/api/modules/fresh-module", { token: "author-token" }), ctx("fresh-module"));

    expect(res.status).toBe(404);
  });

  it("shows the author their own rejected module with the reviewer's note", async () => {
    state.results.modules = [{ data: { ...PENDING, review_status: "rejected", review_note: "Repo is empty" }, error: null }];

    const res = await getModule(request("/api/modules/fresh-module", { token: "author-token" }), ctx("fresh-module"));
    const body = await res.json();

    expect(res.status).toBe(200);
    expect(body.module).toMatchObject({ review_status: "rejected", review_note: "Repo is empty" });
  });
});

describe("PATCH /api/modules/:slug (author edits)", () => {
  function patch(body: Record<string, unknown>) {
    return patchModule(
      request("/api/modules/fresh-module", { method: "PATCH", token: "author-token", body: JSON.stringify(body) }),
      ctx("fresh-module"),
    );
  }

  it("sends an approved module back to review when its source changes", async () => {
    state.results.modules = [
      { data: { id: "mod-1", author_email: AUTHOR.email, review_status: "approved", git_url: "https://github.com/acme/a" }, error: null },
      { data: { id: "mod-1" }, error: null },
    ];

    const res = await patch({ git_url: "https://github.com/acme/b" });

    expect(res.status).toBe(200);
    const update = queriesOn("modules")[1].find(([method]) => method === "update");
    expect(update?.[1]).toMatchObject({ review_status: "pending", published: false, source_status: null });
  });

  it("keeps an approved module live for edits that don't touch the source", async () => {
    state.results.modules = [
      { data: { id: "mod-1", author_email: AUTHOR.email, review_status: "approved", git_url: "https://github.com/acme/a" }, error: null },
      { data: { id: "mod-1" }, error: null },
    ];

    await patch({ description: "Better words", git_url: "https://github.com/acme/a" });

    const update = queriesOn("modules")[1].find(([method]) => method === "update");
    expect(update?.[1]).not.toHaveProperty("review_status");
    expect(update?.[1]).not.toHaveProperty("published");
  });

  it("resubmits a rejected module for review on edit", async () => {
    state.results.modules = [
      { data: { id: "mod-1", author_email: AUTHOR.email, review_status: "rejected", git_url: null }, error: null },
      { data: { id: "mod-1" }, error: null },
    ];

    await patch({ description: "Fixed" });

    const update = queriesOn("modules")[1].find(([method]) => method === "update");
    expect(update?.[1]).toMatchObject({ review_status: "pending" });
  });

  it("rejects switching a module to paid pricing", async () => {
    state.results.modules = [
      { data: { id: "mod-1", author_email: AUTHOR.email, review_status: "approved", git_url: null }, error: null },
    ];

    const res = await patch({ pricing_type: "paid", price_usd: 20 });

    expect(res.status).toBe(400);
    expect(queriesOn("modules")).toHaveLength(1);
  });
});

describe("POST /api/modules/:slug/install", () => {
  it("only installs approved and published modules", async () => {
    state.results.modules = [{ data: null, error: { message: "no rows" } }];

    const res = await installModule(request("/api/modules/fresh-module/install", { method: "POST" }), ctx("fresh-module"));

    expect(res.status).toBe(404);
    const [calls] = queriesOn("modules");
    expect(calls).toContainEqual(["eq", "published", true]);
    expect(calls).toContainEqual(["eq", "review_status", "approved"]);
  });

  it("refuses a module whose source failed its last check, with the reason, without counting a download", async () => {
    state.results.modules = [
      {
        data: {
          id: "mod-1",
          slug: "urlhaus-feed",
          name: "urlhaus-feed",
          version: "0.1.0",
          source_status: "not_found",
          source_checked_at: "2026-09-25T12:00:00.000Z",
          source_check_detail: "git repository not found or private (HTTP 401)",
        },
        error: null,
      },
    ];

    const res = await installModule(request("/api/modules/urlhaus-feed/install", { method: "POST" }), ctx("urlhaus-feed"));
    const body = await res.json();

    expect(res.status).toBe(409);
    expect(body.error).toContain("could not be found");
    expect(body.error).toContain("2026-09-25");
    expect(state.rpc).not.toHaveBeenCalled();
    expect(queriesOn("module_installs")).toHaveLength(0);
  });

  it("installs a module whose source checked ok", async () => {
    state.results.modules = [
      { data: { id: "mod-1", slug: "good", name: "good", version: "0.1.0", source_status: "ok" }, error: null },
    ];

    const res = await installModule(request("/api/modules/good/install", { method: "POST" }), ctx("good"));

    expect(res.status).toBe(200);
    expect(state.rpc).toHaveBeenCalled();
  });
});
