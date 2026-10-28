import { describe, expect, it } from "vitest";
import { allowlistValueError, isSingleIp } from "@/lib/allowlist-value";
import { isSafeHostname, isSafeSshUsername, serverFieldsError } from "@/lib/server-fields";

describe("allowlist values", () => {
  it("takes addresses and reasonable ranges", () => {
    for (const v of ["203.0.113.9", "10.0.0.0/8", "198.51.100.0/24", "2001:db8::1", "2001:db8::/32", "2606:4700::/16"]) {
      expect(allowlistValueError(v)).toBeNull();
    }
  });

  it("refuses ranges that would switch blocking off for the internet", () => {
    for (const v of ["0.0.0.0/0", "0.0.0.0/1", "128.0.0.0/1", "1.0.0.0/7", "::/0", "::/1", "2000::/3", "2000::/15"]) {
      expect(allowlistValueError(v)).toMatch(/wider than/);
    }
  });

  it("refuses junk", () => {
    for (const v of ["", "evil.com", "1.2.3.4/33", "1.2.3.4/8/8", "::/129", 42, null]) {
      expect(allowlistValueError(v)).not.toBeNull();
    }
  });

  it("block/unblock take one address only", () => {
    expect(isSingleIp("203.0.113.9")).toBe(true);
    expect(isSingleIp("203.0.113.0/24")).toBe(false);
    expect(isSingleIp("0.0.0.0/0")).toBe(false);
  });
});

describe("server connection fields (fed to ssh by `threatcrush connect`)", () => {
  it("refuses option-looking usernames and hostnames", () => {
    expect(isSafeSshUsername("-oProxyCommand=sh -c id")).toBe(false);
    expect(isSafeSshUsername("deploy")).toBe(true);
    expect(isSafeHostname("-oProxyCommand=x")).toBe(false);
    expect(isSafeHostname("dev2.profullstack.com")).toBe(true);
    expect(isSafeHostname("2001:db8::1")).toBe(true);
    expect(serverFieldsError({ ssh_username: "-oProxyCommand=touch /tmp/x" })).toMatch(/ssh_username/);
    expect(serverFieldsError({ hostname: "a b" })).toMatch(/hostname/);
    expect(serverFieldsError({ port: 70000 })).toMatch(/port/);
    expect(serverFieldsError({ hostname: "box.example.com", ssh_username: "root", port: 22 })).toBeNull();
    expect(serverFieldsError({ ssh_username: null, hostname: "" })).toBeNull();
  });
});
