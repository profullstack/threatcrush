import { describe, expect, it, vi } from "vitest";

vi.mock("@/lib/api-auth", () => ({
  getAuthenticatedRequestUser: async () => null,
}));

import type { Principal } from "@/lib/access";

const { atLeast, findingsRoleOf, hashSecret, incidentRoleInScope, incidentRoleOf, incidentScopeIn, roleInScope, serverRoleOf, serverScopeIn, teamRoleOf, visibleIn } = await import("@/lib/access");

/**
 * A tiny in-memory PostgREST stand-in with the tables and calls lib/access
 * makes: organization_members, team_members (with an embedded team and its
 * fleets), fleets.
 */
function fakeDb(db: {
  orgMembers: Array<{ org_id: string; user_id: string; role: string }>;
  teamMembers: Array<{ team_id: string; user_id: string; role: string }>;
  teams: Array<{ id: string; org_id: string }>;
  fleets: Array<{ id: string; team_id: string; org_id: string }>;
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
  fleets: [{ id: "f-prod", team_id: "t-ops", org_id: "o1" }, { id: "f-web", team_id: "t-web", org_id: "o1" }],
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

describe("incidentRoleOf", () => {
  it("a team incident takes the team role; org owner is admin; outsiders get nothing", async () => {
    const inc = { org_id: "o1", team_id: "t-ops" };
    expect(await incidentRoleOf(db, user("owner"), inc)).toBe("admin");
    expect(await incidentRoleOf(db, user("writer"), inc)).toBe("write");
    expect(await incidentRoleOf(db, user("reader"), inc)).toBe("read");
    expect(await incidentRoleOf(db, user("member"), inc)).toBeNull();
    expect(await incidentRoleOf(db, user("reader"), { org_id: "o1", team_id: "t-web" })).toBeNull();
  });

  it("an agent key sees only its own team's incidents", async () => {
    expect(await incidentRoleOf(db, agent("write"), { org_id: "o1", team_id: "t-ops" })).toBe("write");
    expect(await incidentRoleOf(db, agent("write"), { org_id: "o1", team_id: "t-web" })).toBeNull();
    expect(await incidentRoleOf(db, agent("write"), { org_id: "o2", team_id: "t-ops" })).toBeNull();
  });

  it("a team-less incident follows the findings rule", async () => {
    const inc = { org_id: "o1", team_id: null };
    expect(await incidentRoleOf(db, user("owner"), inc)).toBe("admin");
    expect(await incidentRoleOf(db, user("member"), inc)).toBe("write");
    expect(await incidentRoleOf(db, user("reader"), inc)).toBeNull();
  });
});

describe("incidentScopeIn", () => {
  it("owner sees all; a team reader sees their team; a guest no team-less ones; agent its team", async () => {
    const owner = (await incidentScopeIn(db, user("owner"), "o1"))!;
    expect(incidentRoleInScope(owner, { team_id: "t-web" })).toBe("admin");
    const reader = (await incidentScopeIn(db, user("reader"), "o1"))!;
    expect(incidentRoleInScope(reader, { team_id: "t-ops" })).toBe("read");
    expect(incidentRoleInScope(reader, { team_id: "t-web" })).toBeNull();
    expect(incidentRoleInScope(reader, { team_id: null })).toBeNull();
    const member = (await incidentScopeIn(db, user("member"), "o1"))!;
    expect(incidentRoleInScope(member, { team_id: null })).toBe("write");
    expect(incidentRoleInScope(member, { team_id: "t-ops" })).toBeNull();
    const key = (await incidentScopeIn(db, agent("read"), "o1"))!;
    expect(incidentRoleInScope(key, { team_id: "t-ops" })).toBe("read");
    expect(incidentRoleInScope(key, { team_id: "t-web" })).toBeNull();
    expect(await incidentScopeIn(db, agent("read"), "o2")).toBeNull();
    expect(await incidentScopeIn(db, user("nobody"), "o1")).toBeNull();
  });
});

describe("findingsRoleOf", () => {
  it("owner = admin, member = write, guest and strangers = nothing", async () => {
    expect(await findingsRoleOf(db, user("owner"), "o1")).toBe("admin");
    expect(await findingsRoleOf(db, user("member"), "o1")).toBe("write");
    expect(await findingsRoleOf(db, user("reader"), "o1")).toBeNull();
    expect(await findingsRoleOf(db, user("nobody"), "o1")).toBeNull();
  });

  it("an agent key gets its own role, in its own org only", async () => {
    expect(await findingsRoleOf(db, agent("write"), "o1")).toBe("write");
    expect(await findingsRoleOf(db, agent("read"), "o1")).toBe("read");
    expect(await findingsRoleOf(db, agent("admin"), "o2")).toBeNull();
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

  it("ignores a fleet_id that points into another org (no cross-org grant)", async () => {
    // A server of org o2 whose fleet_id names o1's prod fleet: o1's team and keys get nothing.
    const foreign = { org_id: "o2", fleet_id: "f-prod" };
    expect(await serverRoleOf(db, user("reader"), foreign)).toBeNull();
    expect(await serverRoleOf(db, user("writer"), foreign)).toBeNull();
    expect(await serverRoleOf(db, agent("admin"), foreign)).toBeNull();
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
