import { afterEach, describe, expect, it } from "vitest";
import { execFileSync, spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const repoRoot = join(__dirname, "..", "..");
const installScriptPath = join(repoRoot, "public", "install.sh");
const installScript = readFileSync(installScriptPath, "utf8");
const cliPackage = JSON.parse(readFileSync(join(repoRoot, "..", "cli", "package.json"), "utf8")) as {
  engines?: { node?: string };
};
const PKG = "@profullstack/threatcrush";
const CLI_VERSION = "0.13.7";
const MISE_NODE_VERSION = "v24.11.0";

/** Host tools the installer and the stubs shell out to; everything else on PATH is a stub. */
const HOST_TOOLS = ["cat", "chmod", "cp", "dirname", "grep", "id", "mkdir", "mktemp", "rm", "sh", "tail", "uname"];

interface Sandbox {
  root: string;
  /** Stubs: node, npm, curl... whatever the scenario puts on the machine. */
  bin: string;
  /** Real host tools only, the PATH a brand-new login shell starts from. */
  hostBin: string;
  /** Files that are not on PATH until something installs them. */
  fixtures: string;
  home: string;
  /** The system npm's global prefix; `<prefix>/bin` is on PATH, as /usr/local/bin is. */
  globalPrefix: string;
  calls: string;
}

const sandboxes: string[] = [];
afterEach(() => {
  for (const dir of sandboxes.splice(0)) rmSync(dir, { recursive: true, force: true });
});

function writeExecutable(path: string, body: string) {
  writeFileSync(path, `#!/bin/sh\n${body}\n`);
  chmodSync(path, 0o755);
}

function makeSandbox(): Sandbox {
  const root = mkdtempSync(join(tmpdir(), "tc-install-"));
  sandboxes.push(root);
  const sb: Sandbox = {
    root,
    bin: join(root, "bin"),
    hostBin: join(root, "host-bin"),
    fixtures: join(root, "fixtures"),
    home: join(root, "home"),
    globalPrefix: join(root, "global"),
    calls: join(root, "calls.log"),
  };
  for (const dir of [sb.bin, sb.hostBin, sb.fixtures, sb.home]) mkdirSync(dir);
  writeFileSync(sb.calls, "");

  for (const tool of HOST_TOOLS) {
    const hostPath = execFileSync("sh", ["-c", `command -v ${tool}`], { encoding: "utf8" }).trim();
    symlinkSync(hostPath, join(sb.hostBin, tool));
  }

  // The CLI that a successful `npm i -g` leaves behind.
  writeExecutable(join(sb.fixtures, "threatcrush"), `[ "$1" = --version ] && echo ${CLI_VERSION}`);

  // Any download is recorded; only the mise installer is served. Nothing here
  // may reach the network.
  writeExecutable(
    join(sb.bin, "curl"),
    [
      `echo "curl $*" >> "${sb.calls}"`,
      'case "$*" in',
      `  *https://mise.run*) echo 'mkdir -p "$HOME/.local/bin" && cp "${sb.fixtures}/mise" "$HOME/.local/bin/mise"' ;;`,
      "  *) exit 22 ;;",
      "esac",
    ].join("\n"),
  );
  return sb;
}

/**
 * An npm that records its argv, reports `prefix` as its global prefix and, on
 * `i -g`, links the CLI into `<prefix>/bin` the way npm does.
 */
function npmScript(sb: Sandbox, prefix: string): string {
  return [
    `echo "npm $*" >> "${sb.calls}"`,
    `prefix="${prefix}"`,
    'if [ "$1 $2 $3" = "config get prefix" ]; then echo "$prefix"; exit 0; fi',
    'if [ "$1" = "root" ]; then exit 1; fi',
    `if [ "$1 $2" = "i -g" ]; then mkdir -p "$prefix/bin" && cp "${sb.fixtures}/threatcrush" "$prefix/bin/threatcrush"; fi`,
    "exit 0",
  ].join("\n");
}

/** A machine whose PATH already has a Node.js of this version, plus npm. */
function withSystemNode(sb: Sandbox, version: string) {
  writeExecutable(join(sb.bin, "node"), `if [ "$1" = "--version" ]; then echo ${version}; exit 0; fi\nexit 1`);
  writeExecutable(join(sb.bin, "npm"), npmScript(sb, sb.globalPrefix));
}

/**
 * What mise.run installs: a mise whose `use -g node@lts` puts node and npm
 * under its data dir, and whose `reshim` writes a shim for every executable
 * there -- but which, like the real one, puts nothing on anyone's PATH.
 */
function withMiseInstaller(sb: Sandbox) {
  const nodeFixture = join(sb.fixtures, "mise-node");
  const npmFixture = join(sb.fixtures, "mise-npm");
  writeExecutable(nodeFixture, `if [ "$1" = "--version" ]; then echo ${MISE_NODE_VERSION}; exit 0; fi\nexit 1`);
  writeExecutable(npmFixture, npmScript(sb, '$(dirname "$(dirname "$0")")'));
  writeExecutable(
    join(sb.fixtures, "mise"),
    [
      `echo "mise $*" >> "${sb.calls}"`,
      'data="${MISE_DATA_DIR:-${XDG_DATA_HOME:-$HOME/.local/share}/mise}"',
      `node_bin="$data/installs/node/${MISE_NODE_VERSION.slice(1)}/bin"`,
      'case "$1" in',
      "  use)",
      '    mkdir -p "$node_bin"',
      `    cp "${nodeFixture}" "$node_bin/node" && cp "${npmFixture}" "$node_bin/npm"`,
      '    exec "$0" reshim',
      "    ;;",
      "  reshim)",
      '    mkdir -p "$data/shims"',
      '    for exe in "$node_bin"/*; do',
      '      printf \'#!/bin/sh\\nPATH="%s:$PATH" exec "%s" "$@"\\n\' "$node_bin" "$exe" > "$data/shims/${exe##*/}"',
      '      chmod +x "$data/shims/${exe##*/}"',
      "    done",
      "    ;;",
      "  *) exit 1 ;;",
      "esac",
    ].join("\n"),
  );
}

function runInstaller(sb: Sandbox, env: Record<string, string> = {}) {
  const result = spawnSync("/bin/sh", [installScriptPath], {
    // Exactly these variables, nothing inherited. The cast is because Next's
    // ambient types make NODE_ENV mandatory on ProcessEnv.
    env: {
      PATH: `${sb.bin}:${join(sb.globalPrefix, "bin")}:${sb.hostBin}`,
      HOME: sb.home,
      TMPDIR: sb.root,
      THREATCRUSH_INSTALL_MODE: "server",
      ...env,
    } as unknown as NodeJS.ProcessEnv,
    encoding: "utf8",
  });
  return {
    status: result.status,
    output: `${result.stdout}${result.stderr}`,
    calls: readFileSync(sb.calls, "utf8").split("\n").filter(Boolean),
  };
}

/** Run `command` the way a fresh login shell would: host PATH, then the startup file. */
function inNewLoginShell(sb: Sandbox, profile: string, command: string) {
  return spawnSync("/bin/sh", ["-c", `. "${join(sb.home, profile)}" && ${command}`], {
    env: { PATH: sb.hostBin, HOME: sb.home } as unknown as NodeJS.ProcessEnv,
    encoding: "utf8",
  });
}

/** The lowest version `engines.node` (">=MAJOR.MINOR") admits, and the release just below it. */
function engineBoundary() {
  const match = /^>=(\d+)\.(\d+)$/.exec(cliPackage.engines?.node ?? "");
  if (!match) throw new Error(`apps/cli/package.json engines.node is not ">=MAJOR.MINOR": ${cliPackage.engines?.node}`);
  const [major, minor] = [Number(match[1]), Number(match[2])];
  return {
    lowest: `v${major}.${minor}.0`,
    justBelow: minor > 0 ? `v${major}.${minor - 1}.99` : `v${major - 1}.99.0`,
    nextMajor: `v${major + 1}.0.0`,
  };
}

describe.skipIf(process.platform === "win32")("install.sh", () => {
  it("documents the blessed curl pipe sh install path", () => {
    expect(installScript).toContain("curl -fsSL https://threatcrush.com/install.sh | sh");
  });

  describe("on a machine with no Node.js", () => {
    // Regression: mise installed node fine, but its shims never reached PATH,
    // so the installer declared "Failed to install Node.js via mise." and
    // exited 1 on every bare box.
    it("bootstraps Node.js with mise and installs the CLI with its npm", () => {
      const sb = makeSandbox();
      withMiseInstaller(sb);

      const { status, output, calls } = runInstaller(sb);

      expect(output).not.toContain("Failed to install Node.js");
      expect(status).toBe(0);
      expect(calls).toContain("mise use -g node@lts");
      expect(calls).toContain(`npm i -g ${PKG}@latest`);
      expect(output).toContain(`ThreatCrush ${CLI_VERSION} installed successfully`);
    });

    it("leaves threatcrush runnable from a new login shell", () => {
      const sb = makeSandbox();
      withMiseInstaller(sb);

      expect(runInstaller(sb).status).toBe(0);

      const login = inNewLoginShell(sb, ".profile", "threatcrush --version");
      expect(login.stderr).toBe("");
      expect(login.stdout.trim()).toBe(CLI_VERSION);
    });

    it.each([
      ["/bin/bash", ".bash_profile"],
      ["/bin/bash", ".bash_login"],
      ["/usr/bin/zsh", ".zprofile"],
    ])("leaves %s's %s alone and prints a PATH line that works there", (shell, startupFile) => {
      // Those shells never read ~/.profile, and the file they do read is the
      // user's own: the installer must not edit it, and must not pretend an
      // edit to ~/.profile did anything.
      const sb = makeSandbox();
      withMiseInstaller(sb);
      const startupPath = join(sb.home, startupFile);
      if (shell.endsWith("bash")) writeFileSync(startupPath, "# user's own\n");
      const before = existsSync(startupPath) ? readFileSync(startupPath, "utf8") : null;

      const { status, output } = runInstaller(sb, { SHELL: shell });

      expect(status).toBe(0);
      expect(existsSync(startupPath) ? readFileSync(startupPath, "utf8") : null).toBe(before);
      expect(existsSync(join(sb.home, ".profile"))).toBe(false);
      expect(output).toContain(startupFile);

      const printed = output
        // The installer colours its output.
        .replace(/\x1b\[[0-9;]*m/g, "")
        .split("\n")
        .map((line) => line.trim())
        .filter((line) => line.startsWith("export PATH="));
      writeFileSync(join(sb.home, "scratch-profile"), `${printed[0]}\n`);
      expect(inNewLoginShell(sb, "scratch-profile", "threatcrush --version").stdout.trim()).toBe(CLI_VERSION);
    });

    it("adds its PATH line once, however many times it is re-run", () => {
      const sb = makeSandbox();
      withMiseInstaller(sb);

      expect(runInstaller(sb).status).toBe(0);
      expect(runInstaller(sb).status).toBe(0);

      const profile = readFileSync(join(sb.home, ".profile"), "utf8");
      expect(profile.split("\n").filter((line) => line.startsWith("export PATH=")).length).toBe(1);
    });
  });

  describe("on a machine whose Node.js is too old for the CLI", () => {
    // Regression: Ubuntu's `apt install nodejs npm` (18.19.1) got EBADENGINE
    // warnings, "installed successfully!", and a daemon that segfaulted
    // loading better-sqlite3.
    it("stops before installing and names the found and required versions", () => {
      const sb = makeSandbox();
      withSystemNode(sb, "v18.19.1");
      withMiseInstaller(sb);

      const { status, output, calls } = runInstaller(sb);

      expect(status).not.toBe(0);
      expect(output).not.toContain("installed successfully");
      expect(output).toContain("v18.19.1");
      expect(output).toContain(cliPackage.engines?.node?.replace(/^>=/, "") ?? "<no engines.node>");
      expect(calls.filter((call) => call.startsWith("npm i "))).toEqual([]);
      // ...and without planting a second Node.js next to the user's own.
      expect(calls.filter((call) => call.startsWith("curl ") || call.startsWith("mise "))).toEqual([]);
    });

    it("accepts exactly the Node.js versions the CLI's engines field allows", () => {
      const { lowest, justBelow, nextMajor } = engineBoundary();
      const outcome = (version: string) => {
        const sb = makeSandbox();
        withSystemNode(sb, version);
        const { status, calls } = runInstaller(sb);
        return { status, installed: calls.includes(`npm i -g ${PKG}@latest`) };
      };

      expect(outcome(justBelow)).toEqual({ status: 1, installed: false });
      expect(outcome(lowest)).toEqual({ status: 0, installed: true });
      expect(outcome(nextMajor)).toEqual({ status: 0, installed: true });
    });
  });

  it("uses a supported Node.js already on PATH as is", () => {
    const sb = makeSandbox();
    withSystemNode(sb, "v22.12.0");
    withMiseInstaller(sb);

    const { status, output, calls } = runInstaller(sb);

    expect(status).toBe(0);
    expect(calls).toContain(`npm i -g ${PKG}@latest`);
    expect(calls.filter((call) => call.startsWith("curl ") || call.startsWith("mise "))).toEqual([]);
    expect(output).toContain(`ThreatCrush ${CLI_VERSION} installed successfully`);
    expect(existsSync(join(sb.home, ".profile"))).toBe(false);
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
    it.each([
      ["npm", `i -g ${PKG}@latest`],
      ["pnpm", `add -g ${PKG}@latest`],
      ["yarn", `global add ${PKG}@latest`],
      ["bun", `add -g ${PKG}@latest`],
    ] as const)("asks %s for the latest release, never a bare package name", (pm, expected) => {
      const sb = makeSandbox();
      writeExecutable(join(sb.bin, "node"), `if [ "$1" = "--version" ]; then echo ${engineBoundary().lowest}; exit 0; fi\nexit 1`);
      writeExecutable(
        join(sb.bin, pm),
        [
          `echo "$*" >> "${sb.calls}"`,
          'if [ "$1 $2 $3" = "config get prefix" ]; then echo "$HOME/.npm-global"; fi',
          'if [ "$1" = "root" ]; then exit 1; fi',
          "exit 0",
        ].join("\n"),
      );

      const { status, calls } = runInstaller(sb);

      expect(status).toBe(0);
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
