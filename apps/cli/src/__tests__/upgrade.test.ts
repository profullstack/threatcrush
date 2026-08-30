import { describe, expect, it } from "vitest";
import {
  daemonRefreshPlan,
  globalHolders,
  globalInstallCommand,
  globalListCommand,
  parseVersionOutput,
  shadowedUpdateWarning,
  staleDaemonWarning,
  systemdOwnsDaemon,
  type PackageManager,
  type Runner,
} from "../upgrade.js";

const PKG = "@profullstack/threatcrush";
const MANAGERS: PackageManager[] = ["npm", "pnpm", "yarn", "bun"];

describe("globalInstallCommand", () => {
  // The bug this file exists for: `pnpm update -g` walked a 0.2.0 install to
  // 0.2.2 and printed "(0.11.5 is available)" while doing it, because the
  // recorded `^0.2.0` range can never cross a 0.x minor.
  it("never uses a range-bound `update` subcommand", () => {
    for (const pm of MANAGERS) {
      const cmd = globalInstallCommand(pm, PKG, "update");
      expect(cmd).not.toContain("update -g");
      expect(cmd).not.toContain("global upgrade");
    }
  });

  it("pins the update to an explicit @latest for every package manager", () => {
    for (const pm of MANAGERS) {
      expect(globalInstallCommand(pm, PKG, "update")).toContain(`${PKG}@latest`);
    }
  });

  it("installs and updates through the same @latest command", () => {
    for (const pm of MANAGERS) {
      expect(globalInstallCommand(pm, PKG, "install")).toBe(globalInstallCommand(pm, PKG, "update"));
    }
  });

  it("uses each package manager's own global install form", () => {
    expect(globalInstallCommand("npm", PKG, "update")).toBe(`npm i -g ${PKG}@latest`);
    expect(globalInstallCommand("pnpm", PKG, "update")).toBe(`pnpm add -g ${PKG}@latest`);
    expect(globalInstallCommand("yarn", PKG, "update")).toBe(`yarn global add ${PKG}@latest`);
    expect(globalInstallCommand("bun", PKG, "update")).toBe(`bun add -g ${PKG}@latest`);
  });

  it("removes without a version tag", () => {
    expect(globalInstallCommand("pnpm", PKG, "remove")).toBe(`pnpm remove -g ${PKG}`);
    expect(globalInstallCommand("npm", PKG, "remove")).toBe(`npm uninstall -g ${PKG}`);
    expect(globalInstallCommand("npm", PKG, "remove")).not.toContain("@latest");
  });

  it("falls back to npm for an unrecognized package manager", () => {
    const cmd = globalInstallCommand("deno" as PackageManager, PKG, "update");
    expect(cmd).toBe(`npm i -g ${PKG}@latest`);
  });
});

describe("globalHolders", () => {
  const runnerFor = (holders: string[]): Runner => (cmd) => {
    const pm = cmd.split(" ")[0];
    if (!holders.includes(pm)) return null; // command missing, or package absent
    return `/home/u/.global\n${PKG} 0.2.0\n`;
  };

  it("reports every package manager with a global copy", () => {
    expect(globalHolders(PKG, runnerFor(["npm", "pnpm"]))).toEqual(["npm", "pnpm"]);
  });

  it("ignores a package manager whose listing does not mention the package", () => {
    const run: Runner = (cmd) => (cmd.startsWith("pnpm") ? "/home/u/.global\n(empty)\n" : null);
    expect(globalHolders(PKG, run)).toEqual([]);
  });

  it("returns nothing when the package is installed nowhere", () => {
    expect(globalHolders(PKG, () => null)).toEqual([]);
  });

  it("asks each package manager with its own listing command", () => {
    const seen: string[] = [];
    globalHolders(PKG, (cmd) => {
      seen.push(cmd);
      return null;
    });
    expect(seen).toEqual(MANAGERS.map((pm) => globalListCommand(pm, PKG)));
  });
});

describe("parseVersionOutput", () => {
  it("reads a bare version line", () => {
    expect(parseVersionOutput("0.11.5\n")).toBe("0.11.5");
  });

  it("reads a version out of surrounding text", () => {
    expect(parseVersionOutput("threatcrush v0.11.5 (node 22)")).toBe("0.11.5");
  });

  it("keeps a prerelease suffix", () => {
    expect(parseVersionOutput("0.12.0-beta.1")).toBe("0.12.0-beta.1");
  });

  it("returns null when there is no version and when the command failed", () => {
    expect(parseVersionOutput("command not found")).toBeNull();
    expect(parseVersionOutput(null)).toBeNull();
  });
});

describe("shadowedUpdateWarning", () => {
  it("stays quiet when PATH already resolves to the latest", () => {
    expect(shadowedUpdateWarning("0.11.5", "0.11.5", "/usr/bin/threatcrush")).toBeNull();
  });

  it("stays quiet when the registry lookup failed, rather than crying wolf offline", () => {
    expect(shadowedUpdateWarning(null, "0.2.2", "/usr/bin/threatcrush")).toBeNull();
  });

  it("stays quiet when the active version could not be read", () => {
    expect(shadowedUpdateWarning("0.11.5", null, "/usr/bin/threatcrush")).toBeNull();
  });

  it("names both versions and the shadowing path when they differ", () => {
    const lines = shadowedUpdateWarning("0.11.5", "0.2.2", "/home/u/.local/bin/threatcrush");
    expect(lines).not.toBeNull();
    const text = (lines ?? []).join("\n");
    expect(text).toContain("0.11.5");
    expect(text).toContain("0.2.2");
    expect(text).toContain("/home/u/.local/bin/threatcrush");
    expect(text).toContain("hash -r");
  });

  it("degrades to a placeholder when the path is unknown", () => {
    const text = (shadowedUpdateWarning("0.11.5", "0.2.2", null) ?? []).join("\n");
    expect(text).toContain("unknown");
    expect(text).toContain("rm <path>");
  });
});

describe("systemdOwnsDaemon", () => {
  it("matches when the unit's MainPID is the running daemon", () => {
    expect(systemdOwnsDaemon("1138793\n", 1138793)).toBe(true);
  });

  it("treats MainPID=0 as not managed", () => {
    // systemd reports 0 for a unit that is not running — a bare `threatcrush
    // start` daemon must not be mistaken for a supervised one.
    expect(systemdOwnsDaemon("0\n", 1138793)).toBe(false);
  });

  it("is false when systemctl is absent or the pids differ", () => {
    expect(systemdOwnsDaemon(null, 1138793)).toBe(false);
    expect(systemdOwnsDaemon("42\n", 1138793)).toBe(false);
    expect(systemdOwnsDaemon("1138793\n", null)).toBe(false);
  });
});

describe("daemonRefreshPlan", () => {
  it("does nothing when no daemon is running", () => {
    expect(daemonRefreshPlan({ daemonRunning: false, systemdManaged: false })).toEqual({
      action: "none",
    });
  });

  it("restarts a daemon we started ourselves", () => {
    expect(daemonRefreshPlan({ daemonRunning: true, systemdManaged: false })).toEqual({
      action: "restart",
    });
  });

  // Restarting a systemd-managed daemon ourselves would swap the supervised
  // copy for an unsupervised one that systemd knows nothing about.
  it("hands over the command for a systemd-managed daemon", () => {
    expect(daemonRefreshPlan({ daemonRunning: true, systemdManaged: true })).toEqual({
      action: "manual",
      command: "sudo systemctl restart threatcrushd.service",
    });
  });
});

describe("staleDaemonWarning", () => {
  it("stays quiet when the daemon matches the CLI", () => {
    expect(staleDaemonWarning("0.11.7", "0.11.7")).toBeNull();
  });

  it("stays quiet when the daemon is down or unreadable", () => {
    expect(staleDaemonWarning("0.11.7", null)).toBeNull();
    expect(staleDaemonWarning(null, "0.11.3")).toBeNull();
  });

  // The failure this exists for: a CLI on 0.11.6 beside a daemon still running
  // 0.11.3 out of a store path for a version no longer installed.
  it("names both versions and how to fix it", () => {
    const text = (staleDaemonWarning("0.11.6", "0.11.3") ?? []).join("\n");
    expect(text).toContain("0.11.6");
    expect(text).toContain("0.11.3");
    expect(text).toContain("threatcrush restart");
  });

  it("uses the supplied restart command", () => {
    const text = (
      staleDaemonWarning("0.11.6", "0.11.3", "sudo systemctl restart threatcrushd") ?? []
    ).join("\n");
    expect(text).toContain("sudo systemctl restart threatcrushd");
  });
});
