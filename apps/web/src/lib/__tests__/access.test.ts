import { describe, expect, it, vi } from "vitest";

vi.mock("@/lib/api-auth", () => ({
  getAuthenticatedRequestUser: async () => null,
}));

import type { Principal } from "@/lib/access";

const { atLeast, hashSecret, roleInScope, serverRoleOf, serverScopeIn, teamRoleOf, visibleIn } = await import("@/lib/access");

/**
 * A tiny in-memory PostgREST stand-in with the tables and calls lib/access
 * makes: organization_members, team_members (with an embedded team and its
 * fleets), fleets.
 */
function fakeDb(db: {
  orgMembers: Array<{ org_id: string; user_id: string; role: string }>;
  teamMembers: Array<{ team_id: string; user_id: string; role: string }>;
  teams: Array<{ id: string; org_id: string }>;
  fleets: Array<{ id: string; team_id: string }>;
}) {
  return {
    from(table: string) {
      const filters: Array<[string, unknown]> = [];
      const rows = (): Array<Record<string, unknown>> => {
        if (table === "organization_members") return db.orgMembers;
        if (table === "fleets") return db.fleets;
        if (table === "team_members") {
          return db.teamMembers.map((m) => {
            const team = db.teams.find((t) => t.id === m.team_id)!;
            return { ...m, "teams.org_id": team.org_id, teams: { ...team, fleets: db.fleets.filter((f) => f.team_id === team.id) } };
          });
        }
        return [];
      };
      const run = () => rows().filter((r) => filters.every(([c, v]) => r[c] === v));
      const b = {
        select() { return b; },
        eq(c: string, v: unknown) { filters.push([c, v]); return b; },
        async maybeSingle() { return { data: run()[0] ?? null, error: null }; },
        then(resolve: (v: unknown) => void) { resolve({ data: run(), error: null }); },
      };
      return b;
    },
  } as never;
}

const db = fakeDb({
  orgMembers: [
    { org_id: "o1", user_id: "owner", role: "owner" },
    { org_id: "o1", user_id: "member", role: "member" },
    { org_id: "o1", user_id: "reader", role: "guest" },
    { org_id: "o1", user_id: "writer", role: "guest" },
  ],
  teams: [{ id: "t-ops", org_id: "o1" }, { id: "t-web", org_id: "o1" }],
  teamMembers: [
    { team_id: "t-ops", user_id: "reader", role: "read" },
    { team_id: "t-ops", user_id: "writer", role: "write" },
  ],
  fleets: [{ id: "f-prod", team_id: "t-ops" }, { id: "f-web", team_id: "t-web" }],
});

const user = (userId: string): Principal => ({ kind: "user", userId, email: null });
const agent = (role: "read" | "write" | "admin"): Principal =>
  ({ kind: "agent", keyId: "k", orgId: "o1", teamId: "t-ops", role, name: "ci" });

const prodServer = { org_id: "o1", fleet_id: "f-prod" };
const webServer = { org_id: "o1", fleet_id: "f-web" };
const looseServer = { org_id: "o1", fleet_id: null };

describe("roles", () => {
  it("ranks read < write < admin", () => {
    expect(atLeast("admin", "write")).toBe(true);
    expect(atLeast("read", "write")).toBe(false);
    expect(atLeast(null, "read")).toBe(false);
  });

  it("hashes secrets deterministically and never returns the secret", () => {
    expect(hashSecret("abc")).toBe(hashSecret("abc"));
    expect(hashSecret("abc")).not.toContain("abc");
  });
});

describe("serverRoleOf", () => {
  it("gives org owners admin everywhere", async () => {
    for (const s of [prodServer, webServer, looseServer]) expect(await serverRoleOf(db, user("owner"), s)).toBe("admin");
  });

  it("gives org members write on fleet-less servers only (today's behaviour)", async () => {
    expect(await serverRoleOf(db, user("member"), looseServer)).toBe("write");
    expect(await serverRoleOf(db, user("member"), prodServer)).toBeNull();
  });

  it("gives team members their team role on the team's fleets and nothing else", async () => {
    expect(await serverRoleOf(db, user("reader"), prodServer)).toBe("read");
    expect(await serverRoleOf(db, user("writer"), prodServer)).toBe("write");
    expect(await serverRoleOf(db, user("reader"), webServer)).toBeNull();
    // A guest never sees fleet-less servers.
    expect(await serverRoleOf(db, user("reader"), looseServer)).toBeNull();
  });

  it("limits an agent key to its team's fleets at its role", async () => {
    expect(await serverRoleOf(db, agent("read"), prodServer)).toBe("read");
    expect(await serverRoleOf(db, agent("write"), webServer)).toBeNull();
    expect(await serverRoleOf(db, agent("admin"), looseServer)).toBeNull();
  });

  it("gives an outsider nothing", async () => {
    expect(await serverRoleOf(db, user("stranger"), looseServer)).toBeNull();
    expect(await teamRoleOf(db, user("stranger"), { id: "t-ops", org_id: "o1" })).toBeNull();
  });
});

describe("serverScopeIn", () => {
  const servers = [
    { id: "a", ...prodServer },
    { id: "b", ...webServer },
    { id: "c", ...looseServer },
  ];

  it("filters a list to what each caller can see", async () => {
    const ids = async (p: Principal) => {
      const scope = await serverScopeIn(db, p, "o1");
      return scope ? visibleIn(scope, servers).map((s) => s.id) : null;
    };
    expect(await ids(user("owner"))).toEqual(["a", "b", "c"]);
    expect(await ids(user("member"))).toEqual(["c"]);
    expect(await ids(user("reader"))).toEqual(["a"]);
    expect(await ids(agent("write"))).toEqual(["a"]);
    expect(await ids(user("stranger"))).toBeNull();
  });

  it("reports the role per server", async () => {
    const scope = (await serverScopeIn(db, user("writer"), "o1"))!;
    expect(roleInScope(scope, prodServer)).toBe("write");
    expect(roleInScope(scope, webServer)).toBeNull();
  });

  it("gives an agent key nothing in another organization", async () => {
    expect(await serverScopeIn(db, agent("admin"), "o2")).toBeNull();
  });
});
