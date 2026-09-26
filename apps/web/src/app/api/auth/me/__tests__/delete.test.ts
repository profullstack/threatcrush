import type { NextRequest } from "next/server";
import { beforeEach, describe, expect, it, vi } from "vitest";

type Row = Record<string, unknown>;

// A small in-memory stand-in for the two org tables, so the route's queries
// are answered by what is actually stored rather than by canned results.
const db = {
  organizations: [] as Row[],
  organization_members: [] as Row[],
};
const deletedUsers: string[] = [];
const passwordChecks: { email: string; password: string }[] = [];
let deleteUserError: { message: string } | null = null;

const USERS: Record<string, Row> = {
  "token-pw": {
    id: "u-pw",
    email: "pw@example.com",
    app_metadata: { provider: "email", providers: ["email"] },
  },
  "token-gh": {
    id: "u-gh",
    email: "gh@example.com",
    app_metadata: { provider: "github", providers: ["github"] },
  },
};

function table(name: keyof typeof db) {
  const filters: ((r: Row) => boolean)[] = [];
  let op: { kind: "select" } | { kind: "update"; patch: Row } | { kind: "delete" } = { kind: "select" };

  const run = () => {
    const matches = db[name].filter((r) => filters.every((f) => f(r)));
    if (op.kind === "update") for (const r of matches) Object.assign(r, op.patch);
    if (op.kind === "delete") db[name] = db[name].filter((r) => !matches.includes(r));
    return { data: matches.map((r) => ({ ...r })), error: null };
  };

  const builder = {
    select: () => builder,
    update: (patch: Row) => ((op = { kind: "update", patch }), builder),
    delete: () => ((op = { kind: "delete" }), builder),
    eq: (col: string, value: unknown) => (filters.push((r) => r[col] === value), builder),
    in: (col: string, values: unknown[]) => (filters.push((r) => values.includes(r[col])), builder),
    then: (resolve: (v: unknown) => unknown, reject: (e: unknown) => unknown) =>
      Promise.resolve().then(run).then(resolve, reject),
  };
  return builder;
}

vi.mock("@/lib/supabase", () => ({
  getSupabaseClient: () => ({
    auth: {
      getUser: async (token: string) => ({ data: { user: USERS[token] ?? null } }),
    },
  }),
  createSupabaseAuthClient: () => ({
    auth: {
      signInWithPassword: async (creds: { email: string; password: string }) => {
        passwordChecks.push(creds);
        return creds.password === "right password"
          ? { data: { session: {} }, error: null }
          : { data: { session: null }, error: { status: 400, message: "Invalid login credentials" } };
      },
    },
  }),
  getSupabaseAdmin: () => ({
    from: (name: keyof typeof db) => table(name),
    auth: {
      admin: {
        deleteUser: async (id: string) => {
          if (deleteUserError) return { error: deleteUserError };
          deletedUsers.push(id);
          // user_profiles ON DELETE CASCADE takes the memberships with it.
          db.organization_members = db.organization_members.filter((m) => m.user_id !== id);
          return { error: null };
        },
      },
    },
  }),
}));

import { DELETE } from "@/app/api/auth/me/route";

function request(body: unknown, token: string | null = "token-pw") {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (token) headers.authorization = `Bearer ${token}`;
  return new Request("http://localhost/api/auth/me", {
    method: "DELETE",
    headers,
    body: typeof body === "string" ? body : JSON.stringify(body),
  }) as unknown as NextRequest;
}

function org(id: string, createdBy: string, members: [string, string, string][]) {
  db.organizations.push({ id, name: `Org ${id}`, slug: `org-${id}`, created_by: createdBy });
  for (const [user_id, role, joined_at] of members) {
    db.organization_members.push({ org_id: id, user_id, role, joined_at });
  }
}

const orgIds = () => db.organizations.map((o) => o.id);

describe("DELETE /api/auth/me", () => {
  beforeEach(() => {
    db.organizations = [];
    db.organization_members = [];
    deletedUsers.length = 0;
    passwordChecks.length = 0;
    deleteUserError = null;
  });

  it("requires a bearer token", async () => {
    const res = await DELETE(request({ password: "right password" }, null));
    expect(res.status).toBe(401);
    expect(deletedUsers).toEqual([]);
  });

  it.each([
    ["no body", "{"],
    ["a non-object body", "[]"],
    ["no password", {}],
    ["an empty password", { password: "" }],
  ])("rejects %s from a password account with 400", async (_label, body) => {
    const res = await DELETE(request(body));
    expect(res.status).toBe(400);
    expect(deletedUsers).toEqual([]);
  });

  it("refuses a wrong password and deletes nothing", async () => {
    org("solo", "u-pw", [["u-pw", "owner", "2026-01-01"]]);

    const res = await DELETE(request({ password: "wrong" }));

    expect(res.status).toBe(403);
    expect((await res.json()).error).toBe("Incorrect password");
    expect(passwordChecks).toEqual([{ email: "pw@example.com", password: "wrong" }]);
    expect(orgIds()).toEqual(["solo"]);
    expect(deletedUsers).toEqual([]);
  });

  it("does not accept a typed email in place of the password", async () => {
    const res = await DELETE(request({ confirm_email: "pw@example.com" }));
    expect(res.status).toBe(400);
    expect(deletedUsers).toEqual([]);
  });

  it("confirms an OAuth-only account by its typed email, case-insensitively", async () => {
    const wrong = await DELETE(request({ confirm_email: "someone@example.com" }, "token-gh"));
    expect(wrong.status).toBe(400);
    expect(deletedUsers).toEqual([]);

    const res = await DELETE(request({ confirm_email: "  GH@Example.com " }, "token-gh"));
    expect(res.status).toBe(200);
    expect(passwordChecks).toEqual([]);
    expect(deletedUsers).toEqual(["u-gh"]);
  });

  it("refuses the only owner of an org with other members, before checking the password", async () => {
    org("shared", "u-pw", [
      ["u-pw", "owner", "2026-01-01"],
      ["u-other", "admin", "2026-01-02"],
    ]);
    org("solo", "u-pw", [["u-pw", "owner", "2026-01-01"]]);

    const res = await DELETE(request({ password: "right password" }));
    const body = await res.json();

    expect(res.status).toBe(409);
    expect(body.organizations).toEqual([{ id: "shared", name: "Org shared", slug: "org-shared" }]);
    expect(body.error).toContain("Org shared");
    expect(passwordChecks).toEqual([]);
    expect(orgIds()).toEqual(["shared", "solo"]);
    expect(deletedUsers).toEqual([]);
  });

  it("deletes orgs only the user belongs to and leaves shared ones alone", async () => {
    org("solo", "u-pw", [["u-pw", "owner", "2026-01-01"]]);
    org("theirs", "u-other", [
      ["u-other", "owner", "2026-01-01"],
      ["u-pw", "member", "2026-01-02"],
    ]);

    const res = await DELETE(request({ password: "right password" }));

    expect(res.status).toBe(200);
    expect(orgIds()).toEqual(["theirs"]);
    expect(db.organizations[0].created_by).toBe("u-other");
    expect(deletedUsers).toEqual(["u-pw"]);
  });

  it("hands a shared org the user created to the longest-standing remaining owner", async () => {
    org("shared", "u-pw", [
      ["u-pw", "owner", "2026-01-01"],
      ["u-member", "member", "2026-01-02"],
      ["u-late-owner", "owner", "2026-03-01"],
      ["u-early-owner", "owner", "2026-02-01"],
    ]);

    const res = await DELETE(request({ password: "right password" }));

    expect(res.status).toBe(200);
    expect(db.organizations).toEqual([
      { id: "shared", name: "Org shared", slug: "org-shared", created_by: "u-early-owner" },
    ]);
    expect(deletedUsers).toEqual(["u-pw"]);
  });

  it("deletes an org the user created but no longer belongs to once it has no members", async () => {
    org("abandoned", "u-pw", []);

    const res = await DELETE(request({ password: "right password" }));

    expect(res.status).toBe(200);
    expect(orgIds()).toEqual([]);
  });

  it("reports a failed auth-user delete as 500", async () => {
    deleteUserError = { message: "Database error deleting user" };

    const res = await DELETE(request({ password: "right password" }));

    expect(res.status).toBe(500);
    expect((await res.json()).error).toBe("Failed to delete account");
  });
});
