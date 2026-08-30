import { execSync } from "node:child_process";

export type PackageManager = "npm" | "pnpm" | "yarn" | "bun";
export type InstallAction = "install" | "update" | "remove";

export const PACKAGE_MANAGERS: PackageManager[] = ["npm", "pnpm", "yarn", "bun"];

/** Runs a command and returns its stdout, or null when it fails or is missing. */
export type Runner = (cmd: string) => string | null;

const defaultRunner: Runner = (cmd) => {
  try {
    return execSync(cmd, { encoding: "utf-8", stdio: ["pipe", "pipe", "pipe"] });
  } catch {
    return null;
  }
};

/**
 * Every upgrade path is a plain install of an explicit `@latest`.
 *
 * `npm update -g` and `pnpm update -g` only move a package *within the semver
 * range recorded when it was first installed*. A box that installed 0.2.0 is
 * pinned to `^0.2.0` and can never cross a 0.x minor, so `threatcrush update`
 * there walked 0.2.0 -> 0.2.2 while pnpm printed "(0.11.5 is available)" in the
 * same breath. `pnpm add -g pkg@latest` ignores both the recorded range and
 * pnpm's global lockfile pin, and is the only form that reliably lands on the
 * published latest.
 */
export function globalInstallCommand(pm: PackageManager, pkgName: string, action: InstallAction): string {
  if (action === "remove") {
    const removals: Record<PackageManager, string> = {
      npm: `npm uninstall -g ${pkgName}`,
      pnpm: `pnpm remove -g ${pkgName}`,
      yarn: `yarn global remove ${pkgName}`,
      bun: `bun remove -g ${pkgName}`,
    };
    return removals[pm] ?? removals.npm;
  }

  const target = `${pkgName}@latest`;
  const installs: Record<PackageManager, string> = {
    npm: `npm i -g ${target}`,
    pnpm: `pnpm add -g ${target}`,
    yarn: `yarn global add ${target}`,
    bun: `bun add -g ${target}`,
  };
  return installs[pm] ?? installs.npm;
}

export function globalListCommand(pm: PackageManager, pkgName: string): string {
  const lists: Record<PackageManager, string> = {
    npm: `npm ls -g --depth=0 ${pkgName}`,
    pnpm: `pnpm list -g --depth=0 ${pkgName}`,
    yarn: `yarn global list --pattern ${pkgName}`,
    bun: `bun pm ls -g`,
  };
  return lists[pm] ?? lists.npm;
}

/**
 * Which package managers actually hold a global copy right now.
 *
 * Updating only the *detected* package manager leaves a copy installed by
 * another one sitting on PATH, so the user reruns `threatcrush update`, watches
 * it succeed, and still gets the old binary. Updating every holder ends that.
 */
export function globalHolders(pkgName: string, run: Runner = defaultRunner): PackageManager[] {
  return PACKAGE_MANAGERS.filter((pm) => {
    const out = run(globalListCommand(pm, pkgName));
    return typeof out === "string" && out.includes(pkgName);
  });
}

/** Pulls a version out of `threatcrush --version` output. */
export function parseVersionOutput(output: string | null): string | null {
  if (!output) return null;
  const match = output.match(/\d+\.\d+\.\d+[^\s]*/);
  return match ? match[0] : null;
}

export function activeCliVersion(bin = "threatcrush", run: Runner = defaultRunner): string | null {
  return parseVersionOutput(run(`${bin} --version`));
}

export function activeCliPath(bin = "threatcrush", run: Runner = defaultRunner): string | null {
  const out = run(`command -v ${bin}`);
  return out ? out.trim().split("\n")[0] || null : null;
}

/** The version the registry currently serves as `latest`. Null when offline. */
export async function latestPublishedVersion(pkgName: string, timeoutMs = 8000): Promise<string | null> {
  try {
    // The registry serves a scoped name unescaped (`/@scope/name/latest`), so
    // the slash needs no encoding here — and hand-rolling one is how you write
    // an escape that only replaces the first occurrence.
    const res = await fetch(`https://registry.npmjs.org/${pkgName}/latest`, {
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (!res.ok) return null;
    const body = (await res.json()) as { version?: string };
    return body.version ?? null;
  } catch {
    return null;
  }
}

/**
 * Lines to print when the update ran clean but PATH still resolves to an older
 * copy — a stale shell hash, or a second install the package manager we used
 * does not own. Returns null when there is nothing to warn about.
 */
export function shadowedUpdateWarning(
  latest: string | null,
  active: string | null,
  activePath: string | null,
): string[] | null {
  if (!latest || !active || latest === active) return null;

  return [
    "⚠ The update ran, but PATH still resolves to an older ThreatCrush.",
    `  Latest published: ${latest}`,
    `  Running from PATH: ${active}  (${activePath || "unknown"})`,
    "",
    "  Usually a stale shell hash. Try first:",
    "    hash -r    # or open a new terminal",
    "  If it persists, that path is a second copy — remove it:",
    `    rm ${activePath || "<path>"}`,
  ];
}
