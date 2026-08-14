import { describe, it, expect, vi, beforeEach } from "vitest";

const mockGetUser = vi.fn();

// Mock supabase (used by captureScreenshot and the auth gate)
vi.mock("@/lib/supabase", () => ({
  getSupabaseAdmin: () => ({
    auth: { getUser: mockGetUser },
    storage: {
      from: () => ({
        upload: vi.fn().mockResolvedValue({ error: null }),
        getPublicUrl: () => ({ data: { publicUrl: "https://test.supabase.co/storage/screenshot.png" } }),
      }),
    },
  }),
}));

// The guard does real DNS lookups; its own behaviour is covered in
// ssrf-guard.test.ts. Here it just forwards to the stubbed global fetch so the
// existing per-call mock sequences keep describing what this route does.
vi.mock("@/lib/ssrf-guard", () => ({
  safeFetch: (url: string, init?: RequestInit) => fetch(url, init),
}));

import { POST } from "@/app/api/modules/fetch-meta/route";

function makeRequest(body: unknown, headers: Record<string, string> = {}) {
  return new Request("http://localhost/api/modules/fetch-meta", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      authorization: "Bearer test-token",
      ...headers,
    },
    body: JSON.stringify(body),
  }) as unknown as import("next/server").NextRequest;
}

describe("POST /api/modules/fetch-meta", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockGetUser.mockResolvedValue({ data: { user: { id: "user-123" } } });
    // Reset global fetch mock
    vi.stubGlobal("fetch", vi.fn());
  });

  // TC-08: this endpoint was an open server-side fetch primitive.
  it("rejects an unauthenticated caller", async () => {
    const req = new Request("http://localhost/api/modules/fetch-meta", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: "https://example.com" }),
    }) as unknown as import("next/server").NextRequest;

    const res = await POST(req);
    expect(res.status).toBe(401);
  });

  it("rejects a caller whose token does not resolve to a user", async () => {
    mockGetUser.mockResolvedValue({ data: { user: null } });

    const res = await POST(makeRequest({ url: "https://example.com" }));
    expect(res.status).toBe(401);
  });

  it("rejects when no url or git_url provided", async () => {
    const req = makeRequest({});
    const res = await POST(req);
    const body = await res.json();

    expect(res.status).toBe(400);
    expect(body.error).toContain("url or git_url is required");
  });

  it("rejects invalid JSON", async () => {
    const req = new Request("http://localhost/api/modules/fetch-meta", {
      method: "POST",
      headers: { "Content-Type": "application/json", authorization: "Bearer test-token" },
      body: "not json",
    }) as unknown as import("next/server").NextRequest;
    const res = await POST(req);

    expect(res.status).toBe(400);
  });

  it("fetches metadata from a web URL", async () => {
    const mockFetch = vi.fn();

    // Web page fetch
    mockFetch.mockResolvedValueOnce({
      ok: true,
      text: () =>
        Promise.resolve(
          `<html><head>
            <title>My Security Tool</title>
            <meta property="og:description" content="A great security tool">
            <meta name="keywords" content="security,scanner,tool">
          </head><body></body></html>`
        ),
    });

    // Logo HEAD checks (all fail)
    mockFetch.mockResolvedValueOnce({ ok: false }); // logo.svg
    mockFetch.mockResolvedValueOnce({ ok: false }); // logo.png
    mockFetch.mockResolvedValueOnce({ ok: false }); // favicon.svg
    mockFetch.mockResolvedValueOnce({ ok: false }); // favicon.png

    // Microlink screenshot (fail gracefully)
    mockFetch.mockResolvedValueOnce({ ok: false });

    vi.stubGlobal("fetch", mockFetch);

    const req = makeRequest({ url: "https://example.com/tool" });
    const res = await POST(req);
    const body = await res.json();

    expect(res.status).toBe(200);
    expect(body.name).toBe("My Security Tool");
    expect(body.description).toBe("A great security tool");
    expect(body.tags).toContain("security");
  });

  it("fetches metadata from a GitHub URL", async () => {
    const mockFetch = vi.fn();

    // GitHub API: repo info
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () =>
        Promise.resolve({
          name: "threat-scanner",
          description: "Scans for threats",
          topics: ["security", "scanner"],
          homepage: "https://threatscanner.dev",
          default_branch: "main",
          license: { spdx_id: "Apache-2.0" },
          owner: { login: "testuser", avatar_url: "https://avatars.githubusercontent.com/u/1234" },
          stargazers_count: 150,
        }),
    });

    // README fetch
    mockFetch.mockResolvedValueOnce({
      ok: true,
      text: () => Promise.resolve("# Threat Scanner\nThis is a great tool."),
    });

    // package.json fetch
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({ version: "2.1.0", keywords: ["threat"] }),
    });

    // Logo HEAD checks (fail)
    mockFetch.mockResolvedValueOnce({ ok: false }); // logo.png
    mockFetch.mockResolvedValueOnce({ ok: false }); // logo.svg

    vi.stubGlobal("fetch", mockFetch);

    const req = makeRequest({ git_url: "https://github.com/testuser/threat-scanner" });
    const res = await POST(req);
    const body = await res.json();

    expect(res.status).toBe(200);
    expect(body.name).toBe("threat-scanner");
    expect(body.description).toBe("Scans for threats");
    expect(body.version).toBe("2.1.0");
    expect(body.license).toBe("Apache-2.0");
    expect(body.stars).toBe(150);
    expect(body.tags).toContain("security");
  });

  it("handles fetch timeout gracefully", async () => {
    const mockFetch = vi.fn().mockRejectedValue(new Error("AbortError: signal timed out"));
    vi.stubGlobal("fetch", mockFetch);

    const req = makeRequest({ url: "https://slow-site.example.com" });
    const res = await POST(req);

    // Should still return 200 with empty/default metadata since web fetch catches errors
    expect(res.status).toBe(200);
  });

  it("handles non-github git_url gracefully", async () => {
    const mockFetch = vi.fn();
    vi.stubGlobal("fetch", mockFetch);

    const req = makeRequest({ git_url: "https://gitlab.com/user/repo" });
    const res = await POST(req);
    const body = await res.json();

    expect(res.status).toBe(200);
    // GitHub parser returns null, so defaults
    expect(body.name).toBe("");
  });
});
