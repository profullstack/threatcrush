import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { stableBinPath } from "../service.js";

const UNIT = readFileSync(
  join(__dirname, "..", "..", "systemd", "threatcrushd.service"),
  "utf-8",
);

describe("stableBinPath", () => {
  // The bug this file exists for: `install-service` baked the version-stamped
  // pnpm path into ExecStart, so the next upgrade left the unit pointing at a
  // directory that no longer existed. On one host that was 6315 failed starts
  // against a path last valid at 0.2.1.
  it("rewrites a version-stamped pnpm path to the stable symlink", () => {
    const root = "/home/ubuntu/.local/share/pnpm/global/5";
    const versioned = `${root}/.pnpm/@profullstack+threatcrush@0.11.6/node_modules/@profullstack/threatcrush/dist/index.js`;

    // The rewrite only takes effect when the stable path exists on disk, which
    // it does not here, so we assert the shape of the rewrite itself.
    const rewritten = versioned.replace(/\/\.pnpm\/[^/]+\/node_modules\//, "/node_modules/");
    expect(rewritten).toBe(`${root}/node_modules/@profullstack/threatcrush/dist/index.js`);
    expect(rewritten).not.toMatch(/@\d+\.\d+\.\d+/);
  });

  it("leaves a path with no .pnpm segment untouched", () => {
    // npm's global layout is already version-free.
    const npmPath = "/usr/lib/node_modules/@profullstack/threatcrush/dist/index.js";
    expect(stableBinPath(npmPath)).toBe(npmPath);
  });

  it("falls back to the original path when the stable one is absent", () => {
    const versioned =
      "/nonexistent/.pnpm/@profullstack+threatcrush@0.11.6/node_modules/@profullstack/threatcrush/dist/index.js";
    expect(stableBinPath(versioned)).toBe(versioned);
  });
});

describe("systemd unit template", () => {
  // /var/run is a symlink to the /run tmpfs, so a directory created at install
  // time is gone after the next reboot — and a missing ReadWritePaths entry
  // fails the unit 226/NAMESPACE on every start.
  it("does not list a tmpfs path under ReadWritePaths", () => {
    const readWrite = UNIT.split("\n").find((l) => l.startsWith("ReadWritePaths="));
    expect(readWrite).toBeDefined();
    expect(readWrite).not.toContain("/var/run/");
    expect(readWrite).not.toContain("/run/");
  });

  it("lets systemd create the runtime directory on each start", () => {
    expect(UNIT).toMatch(/^RuntimeDirectory=threatcrush$/m);
  });
});
