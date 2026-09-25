import { afterEach, describe, expect, it } from "vitest";
import { execFileSync } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const repoRoot = join(__dirname, "..", "..");
const installScriptPath = join(repoRoot, "public", "install.sh");
const installScript = readFileSync(installScriptPath, "utf8");
const PKG = "@profullstack/threatcrush";

/** Host tools the installer shells out to; everything else on PATH is a stub. */
const HOST_TOOLS = ["cat", "dirname", "grep", "id", "mkdir", "mktemp", "rm", "tail", "uname"];

/**
 * Run install.sh against a sandboxed PATH whose only package manager is a stub
 * that records its argv, and return the recorded invocations.
 */
function runInstallerWith(pm: "npm" | "pnpm" | "yarn" | "bun", sandboxes: string[]): string[] {
  const root = mkdtempSync(join(tmpdir(), "tc-install-"));
  sandboxes.push(root);
  const bin = join(root, "bin");
  const home = join(root, "home");
  const calls = join(root, "calls.log");
  mkdirSync(bin);
  mkdirSync(join(home, ".npm-global", "lib", "node_modules"), { recursive: true });
  mkdirSync(join(home, ".npm-global", "bin"), { recursive: true });
  writeFileSync(calls, "");

  for (const tool of HOST_TOOLS) {
    const hostPath = execFileSync("sh", ["-c", `command -v ${tool}`], { encoding: "utf8" }).trim();
    symlinkSync(hostPath, join(bin, tool));
  }

  const stub = (name: string, body: string) => {
    writeFileSync(join(bin, name), `#!/bin/sh\n${body}\n`);
    chmodSync(join(bin, name), 0o755);
  };
  stub("node", 'if [ "$1" = "--version" ]; then echo v22.0.0; exit 0; fi\nexit 1');
  stub(
    pm,
    [
      `echo "$*" >> "${calls}"`,
      'if [ "$1 $2 $3" = "config get prefix" ]; then echo "$HOME/.npm-global"; fi',
      'if [ "$1" = "root" ]; then exit 1; fi',
      "exit 0",
    ].join("\n"),
  );

  execFileSync("/bin/sh", [installScriptPath], {
    env: { PATH: bin, HOME: home, THREATCRUSH_INSTALL_MODE: "server" },
    stdio: "pipe",
  });

  return readFileSync(calls, "utf8").split("\n").filter(Boolean);
}

describe("install.sh", () => {
  it("documents the blessed curl pipe sh install path", () => {
    expect(installScript).toContain("curl -fsSL https://threatcrush.com/install.sh | sh");
  });

  it("can bootstrap bare machines with mise", () => {
    expect(installScript).toContain("MISE_INSTALL_URL=\"https://mise.run\"");
    expect(installScript).toContain("install_mise()");
    expect(installScript).toContain("mise use -g node@lts");
  });

  it("detects whether the machine is server or desktop and records platform kind", () => {
    expect(installScript).toContain("detect_install_mode()");
    expect(installScript).toContain("DISPLAY");
    expect(installScript).toContain("WAYLAND_DISPLAY");
    expect(installScript).toContain("SSH_CONNECTION");
    expect(installScript).toContain("PLATFORM_KIND");
    expect(installScript).toContain("desktop-client");
    expect(installScript).toContain("linux-server");
    expect(installScript).toContain("write_install_config");
  });

  it("frames threatcrush update/remove as the supported lifecycle path", () => {
    expect(installScript).toContain("threatcrush update");
    expect(installScript).toContain("threatcrush remove");
    expect(installScript).toContain("Platform kind:");
  });

  it("installs the CLI on every platform, including macOS and Windows", () => {
    // Regression: the desktop-client branch skipped the CLI entirely and tried
    // to `add -g @profullstack/threatcrush-desktop`, which has never been
    // published. Under `set -e` the 404 aborted the whole install on macOS.
    expect(installScript).toContain('install_global_package "$PKG_NAME"');
    expect(installScript).not.toContain("@profullstack/threatcrush-desktop");
  });

  describe("reinstalling over an existing copy", () => {
    // Regression: a bare package name lets pnpm's global lockfile pin (and
    // npm's satisfying tree) hand back the version already on disk, so
    // rerunning the installer over an old install reported success and changed
    // nothing. Whatever package manager is used, it must be asked for @latest.
    const sandboxes: string[] = [];
    afterEach(() => {
      for (const dir of sandboxes.splice(0)) rmSync(dir, { recursive: true, force: true });
    });

    it.skipIf(process.platform === "win32").each([
      ["npm", `i -g ${PKG}@latest`],
      ["pnpm", `add -g ${PKG}@latest`],
      ["yarn", `global add ${PKG}@latest`],
      ["bun", `add -g ${PKG}@latest`],
    ] as const)("asks %s for the latest release, never a bare package name", (pm, expected) => {
      const calls = runInstallerWith(pm, sandboxes);
      expect(calls).toContain(expected);
      expect(calls.some((call) => call.split(" ").includes(PKG))).toBe(false);
    });
  });

  it("reads the installed version from whichever package manager installed it", () => {
    // `npm root -g` is empty after a pnpm install, which silently disabled the
    // shadowed-install warning on exactly the machines that needed it.
    expect(installScript).toContain('for ROOT_CMD in "npm root -g" "pnpm root -g"');
    expect(installScript).toContain("warn_if_shadowed");
  });

  it("points desktop users at the GitHub Releases bundle", () => {
    expect(installScript).toContain("DESKTOP_RELEASES_URL");
    expect(installScript).toContain("releases/latest");
    expect(installScript).toContain("announce_desktop_bundle");
    expect(installScript).toContain("desktop-client");
  });
});
