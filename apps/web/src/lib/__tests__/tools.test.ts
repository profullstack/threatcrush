import { describe, expect, it } from "vitest";
import { analyzePassword } from "../haystack";
import { cleanHost, isForbiddenHost } from "../fingerprint";

describe("web haystack lib", () => {
  it("detects pool size and reports a larger space for richer passwords", () => {
    const weak = analyzePassword("aaaa");
    const strong = analyzePassword("Ab1!Ab1!Ab1!");
    expect(weak.poolSize).toBe(26);
    expect(strong.poolSize).toBe(95);
    expect(BigInt(strong.searchSpace)).toBeGreaterThan(BigInt(weak.searchSpace));
  });
  it("gives human time strings", () => {
    const r = analyzePassword("Tr0ub4dour&3xtra");
    expect(r.times.online).toMatch(/year|month|day/);
  });
});

describe("fingerprint host guard", () => {
  it("cleanHost strips scheme, path and port", () => {
    expect(cleanHost("https://example.com:8443/path")).toBe("example.com");
  });
  it("forbids private, loopback and link-local hosts", () => {
    for (const h of ["localhost", "127.0.0.1", "10.0.0.1", "192.168.1.1", "169.254.1.1", "172.16.0.1", "box.local"]) {
      expect(isForbiddenHost(h)).toBe(true);
    }
  });
  it("allows ordinary public hostnames", () => {
    expect(isForbiddenHost("example.com")).toBe(false);
    expect(isForbiddenHost("8.8.8.8")).toBe(false);
  });
});
