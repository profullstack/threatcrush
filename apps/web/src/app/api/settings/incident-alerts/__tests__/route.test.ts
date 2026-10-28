import { beforeEach, describe, expect, it, vi } from "vitest";
import { fakeDb } from "@/lib/incidents/__tests__/fake-db";

vi.mock("server-only", () => ({}));
const h = vi.hoisted(() => ({ db: null as unknown as ReturnType<typeof import("@/lib/incidents/__tests__/fake-db").fakeDb>, principal: null as unknown }));
vi.mock("@/lib/supabase", () => ({ getSupabaseAdmin: () => h.db }));
vi.mock("@/lib/access", () => ({ getPrincipal: async () => h.principal }));

const { PATCH } = await import("@/app/api/settings/incident-alerts/route");
const T1 = "00000000-0000-4000-8000-0000000000b1";
const T2 = "00000000-0000-4000-8000-0000000000b2";
const patch = (b: unknown) => PATCH(new Request("http://x", { method: "PATCH", body: JSON.stringify(b) }) as never);

describe("PATCH /api/settings/incident-alerts", () => {
  beforeEach(() => {
    h.db = fakeDb({ team_members: [{ team_id: T1, user_id: "u1", role: "read", notify_incidents: true }, { team_id: T2, user_id: "u2", role: "read", notify_incidents: true }] });
    h.principal = { kind: "user", userId: "u1", email: null };
  });

  it("mutes only your own seat", async () => {
    expect((await patch({ team_id: T1, notify_incidents: false })).status).toBe(200);
    expect(h.db.tables.team_members[0].notify_incidents).toBe(false);
    expect((await patch({ team_id: T2, notify_incidents: false })).status).toBe(404);
    expect(h.db.tables.team_members[1].notify_incidents).toBe(true);
  });

  it("validates and needs a person", async () => {
    expect((await patch({ team_id: "x", notify_incidents: false })).status).toBe(400);
    expect((await patch({ team_id: T1, notify_incidents: "no" })).status).toBe(400);
    h.principal = { kind: "agent", keyId: "k", orgId: "o", teamId: T1, role: "write", name: "a" };
    expect((await patch({ team_id: T1, notify_incidents: false })).status).toBe(401);
  });
});
