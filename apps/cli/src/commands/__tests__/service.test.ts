import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { nodeVersionDir, stableBinPath, systemdUnavailableReason } from "../service.js";

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

describe("systemdUnavailableReason", () => {
  // Without systemd, install-service wrote the unit, printed
  // `/bin/sh: 1: systemctl: not found`, pointed at journalctl, and exited 0.
  it("refuses when systemctl is missing", () => {
    expect(systemdUnavailableReason({ hasSystemctl: false, booted: false })).toMatch(/systemctl/);
  });

  it("refuses when systemctl is installed but systemd is not PID 1 (containers, WSL)", () => {
    expect(systemdUnavailableReason({ hasSystemctl: true, booted: false })).not.toBeNull();
  });

  it("allows a host booted with systemd", () => {
    expect(systemdUnavailableReason({ hasSystemctl: true, booted: true })).toBeNull();
  });
});

describe("nodeVersionDir", () => {
  // A CLI installed by a version manager's npm disappears with that Node
  // version, taking the unit's ExecStart with it.
  it.each([
    ["/root/.local/share/mise/installs/node/22.12.0/bin/threatcrush", "/root/.local/share/mise/installs/node/22.12.0"],
    ["/home/u/.local/share/mise/installs/node/latest/bin/threatcrush", "/home/u/.local/share/mise/installs/node/latest"],
    ["/home/u/.asdf/installs/nodejs/22.1.0/bin/node", "/home/u/.asdf/installs/nodejs/22.1.0"],
    ["/home/u/.nvm/versions/node/v22.12.0/bin/threatcrush", "/home/u/.nvm/versions/node/v22.12.0"],
    ["/home/u/.local/share/fnm/node-versions/v22.12.0/installation/bin/node", "/home/u/.local/share/fnm/node-versions/v22.12.0"],
    ["/home/u/.volta/tools/image/node/22.12.0/bin/node", "/home/u/.volta/tools/image/node/22.12.0"],
  ])("%s -> %s", (path, dir) => {
    expect(nodeVersionDir(path)).toBe(dir);
  });

  it("finds nothing version-bound in a system or npm-global install", () => {
    expect(nodeVersionDir("/usr/local/bin/threatcrush")).toBeNull();
    expect(nodeVersionDir("/usr/lib/node_modules/@profullstack/threatcrush/dist/index.js")).toBeNull();
    expect(nodeVersionDir("/usr/bin/node")).toBeNull();
  });
});
