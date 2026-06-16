import { describe, it, expect, vi, beforeEach } from "vitest";

const mockAuthGetUser = vi.fn();
const mockProfileSingle = vi.fn();
const mockModuleSingle = vi.fn();
const mockModuleEq = vi.fn();
const mockVersionsOrder = vi.fn();
const mockVersionMaybeSingle = vi.fn();
const mockVersionInsert = vi.fn();
const mockVersionInsertSingle = vi.fn();
const mockModuleUpdate = vi.fn();
const mockModuleUpdateEq = vi.fn();

vi.mock("@/lib/supabase", () => ({
  getSupabaseAdmin: () => ({
    auth: {
      getUser: mockAuthGetUser,
    },
    from: (table: string) => {
      if (table === "user_profiles") {
        return {
          select: () => ({ eq: () => ({ single: mockProfileSingle }) }),
        };
      }
      if (table === "module_versions") {
        const versionFilter = {
          eq: vi.fn().mockReturnThis(),
          order: mockVersionsOrder,
          maybeSingle: mockVersionMaybeSingle,
        };
        versionFilter.eq.mockReturnValue(versionFilter);
        return {
          select: () => versionFilter,
          insert: mockVersionInsert.mockReturnValue({
            select: () => ({ single: mockVersionInsertSingle }),
          }),
        };
      }
      if (table === "modules") {
        const moduleFilter = {
          eq: mockModuleEq,
          single: mockModuleSingle,
        };
        mockModuleEq.mockReturnValue(moduleFilter);
        return {
          select: () => moduleFilter,
          update: mockModuleUpdate.mockReturnValue({
            eq: mockModuleUpdateEq,
          }),
        };
      }
      return {};
    },
  }),
}));

import { GET, POST } from "@/app/api/modules/[slug]/versions/route";

function makeRequest(url: string, init?: RequestInit) {
  return new Request(url, init) as unknown as import("next/server").NextRequest;
}

function makeContext(slug: string) {
  return { params: Promise.resolve({ slug }) };
}

const TEST_MODULE = {
  id: "mod-001",
  slug: "test-scanner",
  author_email: "test@example.com",
};

const TEST_VERSION = {
  id: "ver-001",
  module_id: "mod-001",
  version: "1.2.0",
  changelog: "Patch release",
  package_url: "https://example.com/pkg.tgz",
  git_tag: "v1.2.0",
  min_threatcrush_version: ">=0.2.0",
  created_at: "2026-06-16T00:00:00.000Z",
};

describe("GET /api/modules/:slug/versions", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockModuleSingle.mockResolvedValue({ data: TEST_MODULE, error: null });
    mockVersionsOrder.mockResolvedValue({ data: [TEST_VERSION], error: null });
  });

  it("lists module versions newest first", async () => {
    const req = makeRequest("http://localhost/api/modules/test-scanner/versions");
    const res = await GET(req, makeContext("test-scanner"));
    const body = await res.json();

    expect(res.status).toBe(200);
    expect(body.versions).toEqual([TEST_VERSION]);
    expect(mockVersionsOrder).toHaveBeenCalledWith("created_at", { ascending: false });
  });

  it("returns 404 for an unknown module", async () => {
    mockModuleSingle.mockResolvedValue({ data: null, error: { message: "not found" } });

    const req = makeRequest("http://localhost/api/modules/missing/versions");
    const res = await GET(req, makeContext("missing"));
    const body = await res.json();

    expect(res.status).toBe(404);
    expect(body.error).toBe("Module not found");
  });
});

describe("POST /api/modules/:slug/versions", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockAuthGetUser.mockResolvedValue({ data: { user: { id: "user-1" } } });
    mockProfileSingle.mockResolvedValue({
      data: { id: "user-1", email: "test@example.com", email_verified: true },
      error: null,
    });
    mockModuleSingle.mockResolvedValue({ data: TEST_MODULE, error: null });
    mockVersionMaybeSingle.mockResolvedValue({ data: null, error: null });
    mockVersionInsertSingle.mockResolvedValue({ data: TEST_VERSION, error: null });
    mockModuleUpdateEq.mockResolvedValue({ error: null });
  });

  it("publishes a new semantic version for the authenticated module author", async () => {
    const req = makeRequest("http://localhost/api/modules/test-scanner/versions", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: "Bearer token-123",
      },
      body: JSON.stringify({
        version: "1.2.0",
        changelog: "Patch release",
        package_url: "https://example.com/pkg.tgz",
        git_tag: "v1.2.0",
        min_threatcrush_version: ">=0.2.0",
      }),
    });

    const res = await POST(req, makeContext("test-scanner"));
    const body = await res.json();

    expect(res.status).toBe(201);
    expect(body.version).toEqual(TEST_VERSION);
    expect(mockVersionInsert).toHaveBeenCalledWith(
      expect.objectContaining({
        module_id: "mod-001",
        version: "1.2.0",
        changelog: "Patch release",
      })
    );
    expect(mockModuleUpdate).toHaveBeenCalledWith(
      expect.objectContaining({
        version: "1.2.0",
        min_threatcrush_version: ">=0.2.0",
      })
    );
  });

  it("rejects duplicate module versions", async () => {
    mockVersionMaybeSingle.mockResolvedValue({ data: { id: "existing-version" }, error: null });

    const req = makeRequest("http://localhost/api/modules/test-scanner/versions", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: "Bearer token-123",
      },
      body: JSON.stringify({ version: "1.2.0" }),
    });

    const res = await POST(req, makeContext("test-scanner"));
    const body = await res.json();

    expect(res.status).toBe(409);
    expect(body.error).toContain("already exists");
    expect(mockVersionInsert).not.toHaveBeenCalled();
  });

  it("rejects unauthenticated version publishes", async () => {
    mockAuthGetUser.mockResolvedValue({ data: { user: null } });

    const req = makeRequest("http://localhost/api/modules/test-scanner/versions", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ version: "1.2.0" }),
    });

    const res = await POST(req, makeContext("test-scanner"));
    const body = await res.json();

    expect(res.status).toBe(401);
    expect(body.error).toContain("logged in");
  });

  it("rejects non-semantic versions", async () => {
    const req = makeRequest("http://localhost/api/modules/test-scanner/versions", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: "Bearer token-123",
      },
      body: JSON.stringify({ version: "latest" }),
    });

    const res = await POST(req, makeContext("test-scanner"));
    const body = await res.json();

    expect(res.status).toBe(400);
    expect(body.error).toContain("semantic version");
  });

  it("rejects users who do not own the module", async () => {
    mockProfileSingle.mockResolvedValue({
      data: { id: "user-1", email: "other@example.com", email_verified: true },
      error: null,
    });

    const req = makeRequest("http://localhost/api/modules/test-scanner/versions", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: "Bearer token-123",
      },
      body: JSON.stringify({ version: "1.2.0" }),
    });

    const res = await POST(req, makeContext("test-scanner"));
    const body = await res.json();

    expect(res.status).toBe(403);
    expect(body.error).toBe("Unauthorized");
  });
});
