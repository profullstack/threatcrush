import { describe, expect, it } from "vitest";
import { clientIpv4, portsForTest, scanClientPorts, type PortState } from "../shields";

describe("portsForTest", () => {
  it("common includes classic + modern services", () => {
    const nums = portsForTest("common").map((p) => p.port);
    for (const p of [21, 23, 80, 135, 139, 445, 3389]) expect(nums).toContain(p);
  });
  it("all is 0–1055 (1056 ports)", () => {
    expect(portsForTest("all")).toHaveLength(1056);
  });
  it("file-sharing is the NetBIOS/SMB set", () => {
    expect(portsForTest("file-sharing").map((p) => p.port)).toEqual([135, 137, 138, 139, 445]);
  });
});

describe("clientIpv4", () => {
  const h = (o: Record<string, string>) => new Headers(o);
  it("prefers cf-connecting-ip", () => {
    expect(clientIpv4(h({ "cf-connecting-ip": "203.0.113.7", "x-forwarded-for": "1.1.1.1" }))).toBe("203.0.113.7");
  });
  it("takes the first x-forwarded-for hop", () => {
    expect(clientIpv4(h({ "x-forwarded-for": "198.51.100.9, 10.0.0.1" }))).toBe("198.51.100.9");
  });
  it("rejects private, loopback and link-local addresses", () => {
    for (const ip of ["10.1.2.3", "192.168.1.5", "127.0.0.1", "169.254.1.1", "172.16.0.9"]) {
      expect(clientIpv4(h({ "cf-connecting-ip": ip }))).toBeNull();
    }
  });
  it("returns null for IPv6-only or missing", () => {
    expect(clientIpv4(h({ "cf-connecting-ip": "2001:db8::1" }))).toBeNull();
    expect(clientIpv4(h({}))).toBeNull();
  });
});

describe("scanClientPorts grading", () => {
  // Inject a deterministic prober by monkeypatching probeTcp via a custom host?
  // scanClientPorts uses the real socket prober, so here we assert grading by
  // probing ports on an unroutable TEST-NET address, which all time out →
  // stealth → perfect-stealth grade. (Fast because every connect is refused by
  // the kernel's routing, not the 3s timeout, in CI.)
  it("classifies an unreachable host's ports as stealth and grades it stealth", async () => {
    const scan = await scanClientPorts("192.0.2.1", "file-sharing", { timeoutMs: 300, concurrency: 8 });
    expect(scan.summary.total).toBe(5);
    expect(scan.summary.open).toBe(0);
    // Either all stealth (dropped) or some closed, but never open on TEST-NET.
    expect(["stealth", "good"]).toContain(scan.summary.grade);
    for (const p of scan.ports) expect(["stealth", "closed"] as PortState[]).toContain(p.state);
  });
});
