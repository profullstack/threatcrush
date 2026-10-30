import { beforeEach, describe, expect, it, vi } from "vitest";
import { fakeDb } from "@/lib/incidents/__tests__/fake-db";

const h = vi.hoisted(() => ({
  db: null as unknown,
  principal: null as unknown,
  canRead: false,
}));

vi.mock("@/lib/supabase", () => ({ getSupabaseAdmin: () => h.db }));
vi.mock("@/lib/access", () => ({
  getPrincipal: async () => h.principal,
  incidentRoleOf: async () => h.canRead ? "read" : null,
}));

const { GET } = await import("@/app/api/incident-links/[code]/route");
const INCIDENT_ID = "11111111-1111-4111-8111-111111111111";

function request(code = "012345") {
  return new Request(`https://threatcrush.com/api/incident-links/${code}`) as never;
}

function context(code = "012345") {
  return { params: Promise.resolve({ code }) };
}

beforeEach(() => {
  h.db = fakeDb({
    organizations: [{ id: "org-1", slug: "acme" }],
    incidents: [{ id: INCIDENT_ID, org_id: "org-1", team_id: "team-1", human_code: "012345", short_code: "incidentabc1234567890" }],
  });
  h.principal = { kind: "user", userId: "user-1", email: null };
  h.canRead = false;
});

describe("GET /api/incident-links/:code", () => {
  it("requires sign-in before resolving a code", async () => {
    h.principal = null;
    const response = await GET(request(), context());
    expect(response.status).toBe(401);
  });

  it("does not resolve incidents the signed-in caller cannot read", async () => {
    const response = await GET(request(), context());
    expect(response.status).toBe(404);
    expect(await response.json()).toEqual({ error: "Incident not found" });
  });

  it("resolves the short numeric code for a caller entitled to read it", async () => {
    h.canRead = true;
    const response = await GET(request(), context());
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ href: `/org/acme/incidents/${INCIDENT_ID}` });
  });

  it("continues to resolve previously sent long links", async () => {
    h.canRead = true;
    const response = await GET(request("incidentabc1234567890"), context("incidentabc1234567890"));
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ href: `/org/acme/incidents/${INCIDENT_ID}` });
  });
});
