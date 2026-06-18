import { describe, it, expect, vi, beforeEach } from "vitest";
import { TEST_MODULE } from "@/__tests__/helpers/supabase-mock";

type QueryResult = { data: unknown; error: { message: string; code?: string } | null };

const mockAuthGetUser = vi.fn();
const mockInsertVersion = vi.fn();
const mockUpdateModule = vi.fn();

let tableResults: Record<string, {
  awaited?: QueryResult[];
  single?: QueryResult[];
  maybeSingle?: QueryResult[];
}> = {};

function createChainable(table: string) {
  const handler: ProxyHandler<object> = {
    get(_target, prop: string) {
      if (prop === "then") {
        return (resolve: (value: QueryResult) => void) => {
          const result = tableResults[table]?.awaited?.shift() || { data: null, error: null };
          resolve(result);
        };
      }
      if (prop === "single") {
        return vi.fn().mockImplementation(() => {
          const result = tableResults[table]?.single?.shift() || { data: null, error: null };
          return Promise.resolve(result);
        });
      }
      if (prop === "maybeSingle") {
        return vi.fn().mockImplementation(() => {
          const result = tableResults[table]?.maybeSingle?.shift() || { data: null, error: null };
          return Promise.resolve(result);
        });
      }
      if (prop === "insert") {
        return mockInsertVersion.mockReturnValue(new Proxy({}, handler));
      }
      if (prop === "update") {
        return mockUpdateModule.mockReturnValue(new Proxy({}, handler));
      }
      return vi.fn().mockReturnValue(new Proxy({}, handler));
    },
  };

  return new Proxy({}, handler);
}

vi.mock("@/lib/supabase", () => ({
  getSupabaseAdmin: () => ({
    auth: {
      getUser: mockAuthGetUser,
    },
    from: (table: string) => createChainable(table),
  }),
}));

import { GET, POST } from "@/app/api/modules/[slug]/versions/route";

function makeRequest(url: string, init?: RequestInit) {
  return new Request(url, init) as unknown as import("next/server").NextRequest;
}

function makeContext(slug: string) {
  return { params: Promise.resolve({ slug }) };
}

const TEST_VERSION = {
  id: "v-001",
  module_id: "mod-001",
  version: "1.0.0",
  changelog: "Initial",
  created_at: "2025-01-01T00:00:00Z",
};

describe("GET /api/modules/:slug/versions", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    tableResults = {
      modules: { single: [{ data: { id: "mod-001" }, error: null }] },
      module_versions: { awaited: [{ data: [TEST_VERSION], error: null }] },
    };
  });

  it("returns versions newest first", async () => {
    const req = makeRequest("http://localhost/api/modules/test-scanner/versions");
    const res = await GET(req, makeContext("test-scanner"));
    const body = await res.json();

    expect(res.status).toBe(200);
    expect(body.versions).toEqual([TEST_VERSION]);
  });

  it("returns 404 for unknown modules", async () => {
    tableResults.modules = { single: [{ data: null, error: null }] };

    const req = makeRequest("http://localhost/api/modules/nope/versions");
    const res = await GET(req, makeContext("nope"));
    const body = await res.json();

    expect(res.status).toBe(404);
    expect(body.error).toBe("Module not found");
  });
});

describe("POST /api/modules/:slug/versions", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockAuthGetUser.mockResolvedValue({ data: { user: { id: "user-1", email: "test@example.com" } } });
    tableResults = {
      user_profiles: {
        single: [{ data: { id: "user-1", email: "test@example.com", email_verified: true }, error: null }],
      },
      modules: {
        single: [
          { data: { id: "mod-001", author_email: "test@example.com" }, error: null },
          { data: { ...TEST_MODULE, version: "1.1.0" }, error: null },
        ],
      },
      module_versions: {
        maybeSingle: [{ data: null, error: null }],
        single: [{ data: { ...TEST_VERSION, version: "1.1.0" }, error: null }],
      },
    };
  });

  it("rejects unauthenticated release publishing", async () => {
    mockAuthGetUser.mockResolvedValue({ data: { user: null } });

    const req = makeRequest("http://localhost/api/modules/test-scanner/versions", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ version: "1.1.0" }),
    });
    const res = await POST(req, makeContext("test-scanner"));
    const body = await res.json();

    expect(res.status).toBe(401);
    expect(body.error).toContain("logged in");
  });

  it("rejects invalid semver", async () => {
    const req = makeRequest("http://localhost/api/modules/test-scanner/versions", {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: "Bearer token-123" },
      body: JSON.stringify({ version: "latest" }),
    });
    const res = await POST(req, makeContext("test-scanner"));
    const body = await res.json();

    expect(res.status).toBe(400);
    expect(body.error).toContain("semantic version");
  });

  it("rejects duplicate versions", async () => {
    tableResults.module_versions = {
      maybeSingle: [{ data: { id: "existing-version" }, error: null }],
    };

    const req = makeRequest("http://localhost/api/modules/test-scanner/versions", {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: "Bearer token-123" },
      body: JSON.stringify({ version: "1.1.0" }),
    });
    const res = await POST(req, makeContext("test-scanner"));
    const body = await res.json();

    expect(res.status).toBe(409);
    expect(body.error).toContain("already exists");
  });

  it("returns conflict when the database rejects a duplicate release", async () => {
    tableResults.module_versions = {
      maybeSingle: [{ data: null, error: null }],
      single: [{ data: null, error: { message: "duplicate key value violates unique constraint", code: "23505" } }],
    };

    const req = makeRequest("http://localhost/api/modules/test-scanner/versions", {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: "Bearer token-123" },
      body: JSON.stringify({ version: "1.1.0" }),
    });
    const res = await POST(req, makeContext("test-scanner"));
    const body = await res.json();

    expect(res.status).toBe(409);
    expect(body.error).toContain("already exists");
  });

  it("creates a release and synchronizes module metadata", async () => {
    const req = makeRequest("http://localhost/api/modules/test-scanner/versions", {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: "Bearer token-123" },
      body: JSON.stringify({
        version: "1.1.0",
        changelog: "Adds indicator modules",
        git_tag: "v1.1.0",
        package_url: "https://example.com/module.tgz",
        min_threatcrush_version: ">=0.2.0",
      }),
    });
    const res = await POST(req, makeContext("test-scanner"));
    const body = await res.json();

    expect(res.status).toBe(201);
    expect(body.version.version).toBe("1.1.0");
    expect(body.module.version).toBe("1.1.0");
    expect(mockInsertVersion).toHaveBeenCalledWith(expect.objectContaining({
      version: "1.1.0",
      changelog: "Adds indicator modules",
      git_tag: "v1.1.0",
      package_url: "https://example.com/module.tgz",
    }));
    expect(mockUpdateModule).toHaveBeenCalledWith(expect.objectContaining({
      version: "1.1.0",
      min_threatcrush_version: ">=0.2.0",
    }));
  });
});
