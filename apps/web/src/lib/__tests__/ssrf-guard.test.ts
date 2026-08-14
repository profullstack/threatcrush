import { describe, it, expect, vi, beforeEach } from "vitest";

const mockLookup = vi.fn();

vi.mock("dns/promises", () => ({
  default: { lookup: (...args: unknown[]) => mockLookup(...args) },
}));

import {
  isBlockedAddress,
  isPrivateIP,
  validateExternalHttpUrl,
  safeFetch,
} from "@/lib/ssrf-guard";

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

describe("safeFetch", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockLookup.mockResolvedValue([{ address: "93.184.216.34" }]);
  });

  it("refuses an internal target outright", async () => {
    vi.stubGlobal("fetch", vi.fn());
    await expect(safeFetch("http://169.254.169.254/latest/meta-data/")).rejects.toThrow(
      "internal addresses",
    );
    expect(fetch).not.toHaveBeenCalled();
  });

  // A public host that 302s to the metadata service is the classic bypass of a
  // check-then-`redirect: "follow"` implementation.
  it("re-validates redirect hops instead of following them blindly", async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      status: 302,
      headers: new Headers({ location: "http://169.254.169.254/latest/meta-data/" }),
    });
    vi.stubGlobal("fetch", mockFetch);

    await expect(safeFetch("https://example.com")).rejects.toThrow("internal addresses");
    expect(mockFetch).toHaveBeenCalledTimes(1);
  });

  it("never passes redirect:follow to fetch", async () => {
    const mockFetch = vi.fn().mockResolvedValue({ status: 200, headers: new Headers() });
    vi.stubGlobal("fetch", mockFetch);

    await safeFetch("https://example.com");
    expect(mockFetch.mock.calls[0][1]).toMatchObject({ redirect: "manual" });
  });

  it("follows a public redirect and returns the final response", async () => {
    const mockFetch = vi
      .fn()
      .mockResolvedValueOnce({
        status: 301,
        headers: new Headers({ location: "https://example.com/final" }),
      })
      .mockResolvedValueOnce({ status: 200, headers: new Headers() });
    vi.stubGlobal("fetch", mockFetch);

    const res = await safeFetch("https://example.com");
    expect(res.status).toBe(200);
    expect(mockFetch).toHaveBeenCalledTimes(2);
  });

  it("gives up on a redirect loop", async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      status: 302,
      headers: new Headers({ location: "https://example.com/loop" }),
    });
    vi.stubGlobal("fetch", mockFetch);

    await expect(safeFetch("https://example.com")).rejects.toThrow("Too many redirects");
  });
});
