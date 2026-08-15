import { describe, it, expect, vi, beforeEach } from "vitest";
import { EventEmitter } from "node:events";

const mockLookup = vi.fn();
const mockHttpsRequest = vi.fn();
const mockHttpRequest = vi.fn();

vi.mock("dns/promises", () => ({
  default: { lookup: (...args: unknown[]) => mockLookup(...args) },
}));
vi.mock("node:https", () => ({
  default: { request: (...args: unknown[]) => mockHttpsRequest(...args) },
}));
vi.mock("node:http", () => ({
  default: { request: (...args: unknown[]) => mockHttpRequest(...args) },
}));

import { POST } from "@/app/api/scan/route";

interface FakeResponseSpec {
  status: number;
  headers?: Record<string, string>;
  body?: string;
}

/** Stands in for http(s).request: hands back the scripted response on end(). */
function scriptRequest(spec: FakeResponseSpec) {
  return (_options: unknown, callback: (res: unknown) => void) => {
    const req = new EventEmitter() as EventEmitter & Record<string, unknown>;
    req.write = vi.fn();
    req.destroy = vi.fn();
    req.setTimeout = vi.fn();
    req.end = () => {
      const res = new EventEmitter() as EventEmitter & Record<string, unknown>;
      res.statusCode = spec.status;
      res.headers = spec.headers ?? {};
      res.destroy = vi.fn();
      callback(res);
      queueMicrotask(() => {
        if (spec.body) res.emit("data", Buffer.from(spec.body));
        res.emit("end");
      });
    };
    return req;
  };
}

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
  });

  it("rejects IPv4-mapped loopback addresses", async () => {
    const res = await POST(makeRequest({ url: "http://[::ffff:127.0.0.1]/admin" }));
    const body = await res.json();

    expect(res.status).toBe(400);
    expect(body.error).toBe("Requests to internal addresses are not allowed");
    expect(mockHttpRequest).not.toHaveBeenCalled();
    expect(mockHttpsRequest).not.toHaveBeenCalled();
  });

  it("rejects IPv6 multicast addresses", async () => {
    const res = await POST(makeRequest({ url: "http://[ff02::1]/" }));
    const body = await res.json();

    expect(res.status).toBe(400);
    expect(body.error).toBe("Requests to internal addresses are not allowed");
    expect(mockHttpRequest).not.toHaveBeenCalled();
    expect(mockHttpsRequest).not.toHaveBeenCalled();
  });

  it("allows public IPv6 literal addresses", async () => {
    mockHttpsRequest
      .mockImplementationOnce(
        scriptRequest({
          status: 200,
          headers: { "strict-transport-security": "max-age=31536000" },
        }),
      )
      .mockImplementation(scriptRequest({ status: 404 }));

    const res = await POST(makeRequest({ url: "https://[2606:4700:4700::1111]/" }));
    const body = await res.json();

    expect(res.status).toBe(200);
    expect(body.url).toBe("https://[2606:4700:4700::1111]/");
    // A literal address is never resolved, and the socket goes to that literal.
    expect(mockLookup).not.toHaveBeenCalled();
    expect(mockHttpsRequest).toHaveBeenCalledWith(
      expect.objectContaining({ method: "GET", hostname: "2606:4700:4700::1111" }),
      expect.any(Function),
    );
  });

  it("rejects redirects to internal addresses", async () => {
    mockLookup.mockResolvedValue([{ address: "203.0.113.10", family: 4 }]);
    mockHttpsRequest.mockImplementation(
      scriptRequest({ status: 302, headers: { location: "http://127.0.0.1/admin" } }),
    );

    const res = await POST(makeRequest({ url: "https://example.com/scan-me" }));
    const body = await res.json();

    expect(res.status).toBe(400);
    expect(body.error).toBe("Requests to internal addresses are not allowed");
    expect(mockHttpsRequest).toHaveBeenCalledTimes(1);
  });

  it("rejects redirects instead of following them", async () => {
    mockLookup.mockResolvedValue([{ address: "203.0.113.10", family: 4 }]);
    mockHttpsRequest.mockImplementation(
      scriptRequest({ status: 302, headers: { location: "https://safe.example/final" } }),
    );

    const res = await POST(makeRequest({ url: "https://example.com/scan-me" }));
    const body = await res.json();

    expect(res.status).toBe(400);
    expect(body.error).toBe("Redirect responses are not followed by the scanner");
    // safeFetch must hand the 3xx back rather than chase it.
    expect(mockHttpsRequest).toHaveBeenCalledTimes(1);
  });

  it("pins the scan request to the validated address", async () => {
    mockLookup.mockResolvedValue([{ address: "203.0.113.10", family: 4 }]);
    mockHttpsRequest.mockImplementation(scriptRequest({ status: 200 }));

    await POST(makeRequest({ url: "https://example.com/scan-me" }));

    const options = mockHttpsRequest.mock.calls[0][0];
    expect(options.hostname).toBe("example.com");
    expect(options.servername).toBe("example.com");

    // The socket resolves through our pinned lookup, not a second DNS answer.
    const pinned = vi.fn();
    options.lookup("example.com", {}, pinned);
    expect(pinned).toHaveBeenCalledWith(null, "203.0.113.10", 4);
  });
});
