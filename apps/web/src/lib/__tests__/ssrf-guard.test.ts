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

import {
  isBlockedAddress,
  isPrivateIP,
  validateExternalHttpUrl,
  resolveSafeAddress,
  safeFetch,
} from "@/lib/ssrf-guard";

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

describe("isBlockedAddress", () => {
  it("blocks loopback, private, link-local and multicast IPv4", () => {
    for (const address of [
      "127.0.0.1",
      "10.0.0.5",
      "172.16.0.1",
      "172.31.255.255",
      "192.168.1.1",
      "169.254.169.254", // cloud metadata
      "0.0.0.0",
      "224.0.0.1",
    ]) {
      expect(isBlockedAddress(address), address).toBe(true);
    }
  });

  it("blocks IPv6 loopback, unique-local and link-local", () => {
    for (const address of ["::1", "::", "fe80::1", "fc00::1", "fd12::1", "ff02::1"]) {
      expect(isBlockedAddress(address), address).toBe(true);
    }
  });

  it("blocks IPv4-mapped IPv6 loopback", () => {
    expect(isBlockedAddress("::ffff:127.0.0.1")).toBe(true);
    expect(isBlockedAddress("::ffff:7f00:1")).toBe(true);
  });

  it("allows ordinary public addresses", () => {
    expect(isBlockedAddress("93.184.216.34")).toBe(false);
    expect(isBlockedAddress("2606:2800:220:1::1")).toBe(false);
  });
});

describe("isPrivateIP", () => {
  beforeEach(() => vi.clearAllMocks());

  it("does not resolve a literal IP", async () => {
    expect(await isPrivateIP("127.0.0.1")).toBe(true);
    expect(mockLookup).not.toHaveBeenCalled();
  });

  it("handles bracketed IPv6 literals", async () => {
    expect(await isPrivateIP("[::1]")).toBe(true);
  });

  it("blocks a hostname that resolves to a private address", async () => {
    mockLookup.mockResolvedValue([{ address: "10.1.2.3" }]);
    expect(await isPrivateIP("internal.example")).toBe(true);
  });

  it("blocks when ANY resolved address is private", async () => {
    mockLookup.mockResolvedValue([{ address: "93.184.216.34" }, { address: "127.0.0.1" }]);
    expect(await isPrivateIP("mixed.example")).toBe(true);
  });

  it("allows a hostname that resolves publicly", async () => {
    mockLookup.mockResolvedValue([{ address: "93.184.216.34" }]);
    expect(await isPrivateIP("example.com")).toBe(false);
  });

  it("fails closed when resolution fails", async () => {
    mockLookup.mockRejectedValue(new Error("ENOTFOUND"));
    expect(await isPrivateIP("nope.invalid")).toBe(true);
  });
});

describe("validateExternalHttpUrl", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockLookup.mockResolvedValue([{ address: "93.184.216.34" }]);
  });

  it("rejects non-http protocols", async () => {
    await expect(validateExternalHttpUrl(new URL("file:///etc/passwd"))).rejects.toThrow(
      "http or https",
    );
    await expect(validateExternalHttpUrl(new URL("gopher://example.com"))).rejects.toThrow();
  });

  it("rejects internal targets", async () => {
    await expect(validateExternalHttpUrl(new URL("http://127.0.0.1:3000/api/health"))).rejects
      .toThrow("internal addresses");
    await expect(validateExternalHttpUrl(new URL("http://[::1]:3000/api/health"))).rejects
      .toThrow("internal addresses");
  });

  it("allows a public https URL", async () => {
    await expect(validateExternalHttpUrl(new URL("https://example.com"))).resolves.toBeUndefined();
  });
});

describe("resolveSafeAddress", () => {
  beforeEach(() => vi.clearAllMocks());

  it("returns the resolved address for a public host", async () => {
    mockLookup.mockResolvedValue([{ address: "93.184.216.34" }]);
    expect(await resolveSafeAddress(new URL("https://example.com"))).toBe("93.184.216.34");
  });

  // A name answering with both a public and a private address is the shape of a
  // rebinding attack, so there is no address here that is safe to pick.
  it("rejects when ANY resolved address is private", async () => {
    mockLookup.mockResolvedValue([{ address: "93.184.216.34" }, { address: "169.254.169.254" }]);
    await expect(resolveSafeAddress(new URL("https://rebind.example"))).rejects.toThrow(
      "internal addresses",
    );
  });

  it("rejects a non-http protocol", async () => {
    await expect(resolveSafeAddress(new URL("file:///etc/passwd"))).rejects.toThrow(
      "http or https",
    );
  });
});

describe("safeFetch", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockLookup.mockResolvedValue([{ address: "93.184.216.34" }]);
  });

  it("refuses an internal target outright", async () => {
    await expect(safeFetch("http://169.254.169.254/latest/meta-data/")).rejects.toThrow(
      "internal addresses",
    );
    expect(mockHttpRequest).not.toHaveBeenCalled();
    expect(mockHttpsRequest).not.toHaveBeenCalled();
  });

  // TC-21: validating the name then letting the client resolve it a second time
  // leaves a window where the record can flip. The socket must be pinned to the
  // address that was actually checked.
  it("pins the connection to the validated address", async () => {
    mockHttpsRequest.mockImplementation(scriptRequest({ status: 200 }));

    await safeFetch("https://example.com/path?q=1");

    const options = mockHttpsRequest.mock.calls[0][0] as {
      hostname: string;
      servername?: string;
      lookup: (h: string, o: unknown, cb: (e: unknown, a: unknown, f?: number) => void) => void;
    };

    // Cert validation still keyed to the real name, not the IP.
    expect(options.hostname).toBe("example.com");
    expect(options.servername).toBe("example.com");

    // The pinned lookup ignores whatever the DNS layer would say next time.
    const single = vi.fn();
    options.lookup("example.com", {}, single);
    expect(single).toHaveBeenCalledWith(null, "93.184.216.34", 4);

    const all = vi.fn();
    options.lookup("example.com", { all: true }, all);
    expect(all).toHaveBeenCalledWith(null, [{ address: "93.184.216.34", family: 4 }]);
  });

  // A public host that 302s to the metadata service is the classic bypass of a
  // check-then-follow implementation.
  it("re-validates redirect hops instead of following them blindly", async () => {
    mockHttpsRequest.mockImplementation(
      scriptRequest({
        status: 302,
        headers: { location: "http://169.254.169.254/latest/meta-data/" },
      }),
    );

    await expect(safeFetch("https://example.com")).rejects.toThrow("internal addresses");
    expect(mockHttpsRequest).toHaveBeenCalledTimes(1);
    // The internal hop was never dialled.
    expect(mockHttpRequest).not.toHaveBeenCalled();
  });

  it("follows a public redirect and returns the final response", async () => {
    mockHttpsRequest
      .mockImplementationOnce(
        scriptRequest({ status: 301, headers: { location: "https://example.com/final" } }),
      )
      .mockImplementationOnce(scriptRequest({ status: 200, body: "ok" }));

    const res = await safeFetch("https://example.com");
    expect(res.status).toBe(200);
    expect(await res.text()).toBe("ok");
    expect(mockHttpsRequest).toHaveBeenCalledTimes(2);
  });

  it("gives up on a redirect loop", async () => {
    mockHttpsRequest.mockImplementation(
      scriptRequest({ status: 302, headers: { location: "https://example.com/loop" } }),
    );

    await expect(safeFetch("https://example.com")).rejects.toThrow("Too many redirects");
  });

  it("does not attach a body to a 204 response", async () => {
    mockHttpsRequest.mockImplementation(scriptRequest({ status: 204 }));
    const res = await safeFetch("https://example.com");
    expect(res.status).toBe(204);
  });

  it("returns the 3xx untouched when the caller asks for manual redirects", async () => {
    mockHttpsRequest.mockImplementation(
      scriptRequest({ status: 302, headers: { location: "https://example.com/next" } }),
    );

    const res = await safeFetch("https://example.com", { redirect: "manual" });
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("https://example.com/next");
    // The hop is the caller's to decide on, so we must not have taken it.
    expect(mockHttpsRequest).toHaveBeenCalledTimes(1);
  });

  it("rejects immediately when the caller's signal is already aborted", async () => {
    mockHttpsRequest.mockImplementation(scriptRequest({ status: 200, body: "ok" }));

    await expect(
      safeFetch("https://example.com", { signal: AbortSignal.abort() }),
    ).rejects.toThrow("Request aborted");
    expect(mockHttpsRequest).not.toHaveBeenCalled();
  });
});
