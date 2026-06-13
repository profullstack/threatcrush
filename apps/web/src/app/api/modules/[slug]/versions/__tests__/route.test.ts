import { beforeEach, describe, expect, it, vi } from "vitest";

const mockAuth = vi.fn();
const mockModuleSingle = vi.fn();
const mockVersionsOrder = vi.fn();
const mockVersionSingle = vi.fn();
const mockVersionInsert = vi.fn();
const mockModuleUpdate = vi.fn();
const mockModuleUpdateEq = vi.fn();

function moduleQuery() {
  const query = {
    eq: vi.fn(() => query),
    single: mockModuleSingle,
  };
  return query;
}

function versionsQuery() {
  const query = {
    eq: vi.fn(() => query),
    order: mockVersionsOrder,
  };
  return query;
}

vi.mock("@/lib/api-auth", () => ({
  getAuthenticatedRequestUser: (...args: unknown[]) => mockAuth(...args),
}));

vi.mock("@/lib/supabase", () => ({
  getSupabaseAdmin: () => ({
    from: (table: string) => {
      if (table === "modules") {
        return {
          select: vi.fn(moduleQuery),
          update: mockModuleUpdate,
        };
      }
      if (table === "module_versions") {
        return {
          select: vi.fn(versionsQuery),
          insert: mockVersionInsert,
        };
      }
      return {};
    },
  }),
}));

import { GET, POST } from "@/app/api/modules/[slug]/versions/route";

function makeRequest(body?: unknown, token = "token-123") {
  return new Request("http://localhost/api/modules/test-scanner/versions", {
    method: body === undefined ? "GET" : "POST",
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  }) as unknown as import("next/server").NextRequest;
}

function makeContext(slug = "test-scanner") {
  return { params: Promise.resolve({ slug }) };
}

describe("GET /api/modules/:slug/versions", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockModuleSingle.mockResolvedValue({
      data: { id: "mod-001" },
      error: null,
    });
    mockVersionsOrder.mockResolvedValue({
      data: [{ id: "ver-1", version: "1.0.0" }],
      error: null,
    });
  });

  it("lists versions newest first", async () => {
    const response = await GET(makeRequest(), makeContext());
    const body = await response.json();

    expect(response.status).toBe(200);
    expect(body.versions).toEqual([{ id: "ver-1", version: "1.0.0" }]);
    expect(mockVersionsOrder).toHaveBeenCalledWith("created_at", {
      ascending: false,
    });
  });

  it("returns 404 for an unknown module", async () => {
    mockModuleSingle.mockResolvedValue({ data: null, error: { message: "missing" } });

    const response = await GET(makeRequest(), makeContext("missing"));

    expect(response.status).toBe(404);
  });
});

describe("POST /api/modules/:slug/versions", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockAuth.mockResolvedValue({
      userId: "user-1",
      email: "author@example.com",
    });
    mockModuleSingle.mockResolvedValue({
      data: { id: "mod-001", author_email: "author@example.com" },
      error: null,
    });
    mockVersionSingle.mockResolvedValue({
      data: { id: "ver-2", module_id: "mod-001", version: "1.1.0" },
      error: null,
    });
    mockVersionInsert.mockReturnValue({
      select: vi.fn(() => ({ single: mockVersionSingle })),
    });
    mockModuleUpdateEq.mockResolvedValue({ error: null });
    mockModuleUpdate.mockReturnValue({ eq: mockModuleUpdateEq });
  });

  it("publishes a version and updates the module release", async () => {
    const response = await POST(
      makeRequest({
        version: "1.1.0",
        changelog: "Adds scheduled scans",
        package_url: "https://example.com/releases/1.1.0.tgz",
        git_tag: "v1.1.0",
        min_threatcrush_version: ">=0.2.0",
      }),
      makeContext(),
    );
    const body = await response.json();

    expect(response.status).toBe(201);
    expect(body.version.version).toBe("1.1.0");
    expect(mockVersionInsert).toHaveBeenCalledWith(
      expect.objectContaining({
        module_id: "mod-001",
        version: "1.1.0",
        git_tag: "v1.1.0",
      }),
    );
    expect(mockModuleUpdate).toHaveBeenCalledWith(
      expect.objectContaining({
        version: "1.1.0",
        min_threatcrush_version: ">=0.2.0",
      }),
    );
  });

  it("requires authentication", async () => {
    mockAuth.mockResolvedValue(null);

    const response = await POST(makeRequest({ version: "1.1.0" }, ""), makeContext());

    expect(response.status).toBe(401);
    expect(mockVersionInsert).not.toHaveBeenCalled();
  });

  it("rejects releases from a different author", async () => {
    mockAuth.mockResolvedValue({
      userId: "user-2",
      email: "other@example.com",
    });

    const response = await POST(makeRequest({ version: "1.1.0" }), makeContext());

    expect(response.status).toBe(403);
    expect(mockVersionInsert).not.toHaveBeenCalled();
  });

  it.each(["1", "v1.2.3", "1.2", "latest"])(
    "rejects invalid semantic version %s",
    async (version) => {
      const response = await POST(makeRequest({ version }), makeContext());

      expect(response.status).toBe(400);
      expect(mockVersionInsert).not.toHaveBeenCalled();
    },
  );

  it("rejects a non-HTTP package URL", async () => {
    const response = await POST(
      makeRequest({ version: "1.1.0", package_url: "file:///tmp/module.tgz" }),
      makeContext(),
    );

    expect(response.status).toBe(400);
    expect(mockVersionInsert).not.toHaveBeenCalled();
  });

  it("returns 409 for an existing version", async () => {
    mockVersionSingle.mockResolvedValue({
      data: null,
      error: { code: "23505", message: "duplicate key" },
    });

    const response = await POST(makeRequest({ version: "1.1.0" }), makeContext());
    const body = await response.json();

    expect(response.status).toBe(409);
    expect(body.error).toContain("already exists");
  });
});
