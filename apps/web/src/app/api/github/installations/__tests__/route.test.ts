import { NextRequest } from "next/server";
import { beforeEach, describe, expect, it, vi } from "vitest";

type Result = { data: unknown; error: { code?: string; message: string } | null };

const { state, resetOpenThreatCache } = vi.hoisted(() => {
  type Result = { data: unknown; error: { code?: string; message: string } | null };
  /** A chainable stand-in for the supabase query builder that resolves to a scripted result. */
  class FakeQuery {
    calls: Array<[string, unknown[]]> = [];
    constructor(private readonly result: Result, log: FakeQuery[]) {
      log.push(this);
    }
    private chain(name: string, args: unknown[]) {
      this.calls.push([name, args]);
      return this;
    }
    select(...a: unknown[]) { return this.chain("select", a); }
    or(...a: unknown[]) { return this.chain("or", a); }
    eq(...a: unknown[]) { return this.chain("eq", a); }
    update(...a: unknown[]) { return this.chain("update", a); }
    maybeSingle() { return this.chain("maybeSingle", []); }
    single() { return this.chain("single", []); }
    then<T>(resolve: (r: Result) => T) { return Promise.resolve(this.result).then(resolve); }
  }
  const state: { user: unknown; results: Result[]; queries: FakeQuery[] } = {
    user: null,
    results: [],
    queries: [],
  };
  const from = () => new FakeQuery(state.results.shift() ?? { data: null, error: null }, state.queries);
  return { state: Object.assign(state, { from }), resetOpenThreatCache: vi.fn() };
});

vi.mock("@/lib/api-auth", () => ({
  getAuthenticatedRequestUser: vi.fn(async () => state.user),
  unauthorized: () => new Response(JSON.stringify({ error: "Not authenticated" }), { status: 401 }),
  getAdminClient: () => ({ from: state.from }),
}));

vi.mock("@/lib/open-threats", () => ({ resetOpenThreatCache }));

import { GET, PATCH } from "../route";
import { managesInstallation } from "@/lib/github-announce";

const mine = { installation_id: 10, account_login: "ada", sender_login: "ada", account_type: "User", repository_selection: "all", status: "active", announce: true, installed_at: null };
const orgByMe = { installation_id: 11, account_login: "acme", sender_login: "Ada", account_type: "Organization", repository_selection: "selected", status: "active", announce: false, installed_at: null };
const theirs = { installation_id: 12, account_login: "bob", sender_login: "bob", account_type: "User", repository_selection: "all", status: "active", announce: true, installed_at: null };

function patch(body: unknown) {
  return PATCH(
    new NextRequest("https://threatcrush.com/api/github/installations", {
      method: "PATCH",
      body: JSON.stringify(body),
    })
  );
}

beforeEach(() => {
  state.user = null;
  state.results = [];
  state.queries = [];
  resetOpenThreatCache.mockClear();
});

describe("managesInstallation", () => {
  it("matches the account or the installer, case-insensitively, and never without a login", () => {
    expect(managesInstallation("ada", mine)).toBe(true);
    expect(managesInstallation("ADA", orgByMe)).toBe(true);
    expect(managesInstallation("ada", theirs)).toBe(false);
    expect(managesInstallation(null, mine)).toBe(false);
  });
});

describe("GET /api/github/installations", () => {
  it("requires a session", async () => {
    const res = await GET(new NextRequest("https://threatcrush.com/api/github/installations"));
    expect(res.status).toBe(401);
  });

  it("returns nothing for a sign-in without a GitHub login", async () => {
    state.user = { userId: "u1", email: "a@example.com", githubLogin: null };
    const res = await GET(new NextRequest("https://threatcrush.com/api/github/installations"));
    const body = await res.json();
    expect(res.status).toBe(200);
    expect(body.installations).toEqual([]);
    expect(body.githubLogin).toBeNull();
  });

  it("lists only the installations the login manages, without sender_login", async () => {
    state.user = { userId: "u1", email: "a@example.com", githubLogin: "ada" };
    state.results = [{ data: [mine, orgByMe, theirs], error: null }];
    const res = await GET(new NextRequest("https://threatcrush.com/api/github/installations"));
    const body = await res.json();
    expect(body.installations.map((i: { installation_id: number }) => i.installation_id)).toEqual([10, 11]);
    expect(body.installations[1].announce).toBe(false);
    expect(JSON.stringify(body)).not.toContain("sender_login");
  });
});

describe("PATCH /api/github/installations", () => {
  it("refuses a sign-in without a GitHub login", async () => {
    state.user = { userId: "u1", email: "a@example.com", githubLogin: null };
    const res = await patch({ installation_id: 10, announce: false });
    expect(res.status).toBe(403);
  });

  it("validates the body", async () => {
    state.user = { userId: "u1", email: "a@example.com", githubLogin: "ada" };
    const res = await patch({ installation_id: "x", announce: "no" });
    expect(res.status).toBe(400);
  });

  it("answers 404 for an installation that is not the login's, and writes nothing", async () => {
    state.user = { userId: "u1", email: "a@example.com", githubLogin: "ada" };
    state.results = [{ data: theirs, error: null }];
    const res = await patch({ installation_id: 12, announce: false });
    expect(res.status).toBe(404);
    expect(state.queries.some((q) => q.calls.some(([name]) => name === "update"))).toBe(false);
    expect(resetOpenThreatCache).not.toHaveBeenCalled();
  });

  it("turns announcements off for the login's own installation and drops the descriptor cache", async () => {
    state.user = { userId: "u1", email: "a@example.com", githubLogin: "ada" };
    state.results = [
      { data: mine, error: null },
      { data: { ...mine, announce: false }, error: null },
    ];
    const res = await patch({ installation_id: 10, announce: false });
    const body = await res.json();
    expect(res.status).toBe(200);
    expect(body.installation.announce).toBe(false);
    const update = state.queries[1].calls.find(([name]) => name === "update");
    expect((update?.[1][0] as { announce: boolean }).announce).toBe(false);
    expect(resetOpenThreatCache).toHaveBeenCalledTimes(1);
  });

  it("says so when the announce column is not there yet", async () => {
    state.user = { userId: "u1", email: "a@example.com", githubLogin: "ada" };
    state.results = [
      { data: mine, error: null },
      { data: null, error: { code: "42703", message: "column announce does not exist" } },
    ];
    const res = await patch({ installation_id: 10, announce: false });
    expect(res.status).toBe(503);
  });
});

// Keep the module-level Result type in use so the linter does not flag it.
export type { Result };
