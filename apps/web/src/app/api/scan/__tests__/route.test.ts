import { describe, it, expect, vi, beforeEach } from "vitest";

const { mockLookup } = vi.hoisted(() => ({
  mockLookup: vi.fn(),
}));

vi.mock("dns/promises", () => ({
  default: {
    lookup: mockLookup,
  },
}));

import { POST } from "@/app/api/scan/route";

function makeRequest(body: unknown) {
  return new Request("http://localhost/api/scan", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  }) as unknown as import("next/server").NextRequest;
}

describe("POST /api/scan", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.stubGlobal("fetch", vi.fn());
  });

  it("rejects IPv4-mapped loopback addresses", async () => {
    const fetchMock = vi.mocked(fetch);

    const res = await POST(makeRequest({ url: "http://[::ffff:127.0.0.1]/admin" }));
    const body = await res.json();

    expect(res.status).toBe(400);
    expect(body.error).toBe("Scanning internal addresses is not allowed");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("rejects IPv6 multicast addresses", async () => {
    const fetchMock = vi.mocked(fetch);

    const res = await POST(makeRequest({ url: "http://[ff02::1]/" }));
    const body = await res.json();

    expect(res.status).toBe(400);
    expect(body.error).toBe("Scanning internal addresses is not allowed");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("allows public IPv6 literal addresses", async () => {
    const fetchMock = vi.mocked(fetch);
    fetchMock
      .mockResolvedValueOnce(
        new Response(null, {
          status: 200,
          headers: {
            "Strict-Transport-Security": "max-age=31536000",
          },
        })
      )
      .mockResolvedValue(new Response(null, { status: 404 }));

    const res = await POST(makeRequest({ url: "https://[2606:4700:4700::1111]/" }));
    const body = await res.json();

    expect(res.status).toBe(200);
    expect(body.url).toBe("https://[2606:4700:4700::1111]/");
    expect(fetchMock).toHaveBeenCalledWith(
      "https://[2606:4700:4700::1111]/",
      expect.objectContaining({ method: "GET", redirect: "manual" })
    );
  });

  it("rejects redirects to internal addresses", async () => {
    mockLookup.mockResolvedValue([{ address: "203.0.113.10", family: 4 }]);
    const fetchMock = vi.mocked(fetch);
    fetchMock.mockResolvedValueOnce(
      new Response(null, {
        status: 302,
        headers: { location: "http://127.0.0.1/admin" },
      })
    );

    const res = await POST(makeRequest({ url: "https://example.com/scan-me" }));
    const body = await res.json();

    expect(res.status).toBe(400);
    expect(body.error).toBe("Scanning internal addresses is not allowed");
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("rejects redirects instead of following them", async () => {
    mockLookup
      .mockResolvedValueOnce([{ address: "203.0.113.10", family: 4 }])
      .mockResolvedValueOnce([{ address: "203.0.113.11", family: 4 }])
      .mockResolvedValue([{ address: "203.0.113.11", family: 4 }]);

    const fetchMock = vi.mocked(fetch);
    fetchMock
      .mockResolvedValueOnce(
        new Response(null, {
          status: 302,
          headers: { location: "https://safe.example/final" },
        })
      )
      .mockResolvedValueOnce(
        new Response(null, {
          status: 200,
          headers: {
            "Strict-Transport-Security": "max-age=31536000",
            "X-Content-Type-Options": "nosniff",
          },
        })
      )
      .mockResolvedValue(new Response(null, { status: 404 }));

    const res = await POST(makeRequest({ url: "https://example.com/scan-me" }));
    const body = await res.json();

    expect(res.status).toBe(400);
    expect(body.error).toBe("Redirect responses are not followed by the scanner");
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });
});
