import { execSync, spawnSync } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, readFileSync, realpathSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import chalk from 'chalk';
import { banner } from '../core/logger.js';

const UNIT_PATH = '/etc/systemd/system/threatcrushd.service';
export const DAEMON_UNIT_NAME = 'threatcrushd.service';

function resolveTemplate(): string {
  const templatePath = join(__dirname, 'systemd', 'threatcrushd.service');
  if (!existsSync(templatePath)) {
    throw new Error(`systemd unit template not found at ${templatePath}`);
  }
  return readFileSync(templatePath, 'utf-8');
}

// pnpm installs a global package under a version-stamped directory
// (`.pnpm/@profullstack+threatcrush@0.11.6/node_modules/…`) and points a stable
// symlink at it from the store root. Baking the version-stamped path into
// ExecStart means the very next upgrade leaves the unit pointing at a directory
// that no longer exists — the unit then fails on every start, forever, and
// `Restart=on-failure` turns that into a permanent loop. Observed in the wild at
// 6315 restarts against a path last valid at 0.2.1.
export function stableBinPath(binPath: string): string {
  const stable = binPath.replace(/\/\.pnpm\/[^/]+\/node_modules\//, '/node_modules/');
  if (stable === binPath) return binPath;
  // Only take the rewrite if the symlink is really there; a layout we have not
  // seen is better served by the path we were actually invoked with.
  return existsSync(stable) ? stable : binPath;
}

function resolveBinPath(): string {
  // When installed globally the script path is the CLI bin.
  const arg = process.argv[1];
  if (arg && existsSync(arg)) return stableBinPath(arg);
  try {
    return execSync('command -v threatcrush', { encoding: 'utf-8' }).trim();
  } catch {
    return 'threatcrush';
  }
}

/**
 * mise, nvm, fnm and friends install node under a version-stamped directory and
 * keep a `latest` symlink beside it. Baking the stamped path into a unit file
 * means the next node upgrade leaves ExecStart pointing at a directory that no
 * longer exists — the same failure mode `stableBinPath` exists for.
 */
export function stableNodePath(execPath: string): string {
  const stable = execPath.replace(/(\/installs\/node\/)[^/]+\//, '$1latest/');
  if (stable === execPath) return execPath;
  return existsSync(stable) ? stable : execPath;
}

/**
 * Does this file start with a `#!... node` shebang?
 *
 * It matters because such a file can only be executed when `node` is on the
 * PATH of whoever executes it. Under sudo, and under systemd, it is not: a
 * version-managed node lives in the user's PATH and nowhere else, which is why
 * `sudo threatcrush install-service` died with
 * `env: 'node': No such file or directory`. When we see that shebang we run the
 * script through an explicit node instead of relying on someone else's PATH.
 */
export function looksLikeNodeScript(path: string): boolean {
  try {
    const head = readFileSync(path, 'utf-8').slice(0, 120);
    return /^#!.*\bnode\b/.test(head);
  } catch {
    return false;
  }
}

/**
 * The ExecStart line for the unit: an explicit node when the CLI is a shebang
 * script, so systemd never has to find node on a PATH it does not have.
 */
export function execStartCommand(binPath: string, nodePath: string, isNodeScript: boolean): string {
  return isNodeScript ? `${nodePath} ${binPath} daemon` : `${binPath} daemon`;
}

/**
 * The install tree of one particular Node version that `path` lives in, if any:
 * mise (`installs/node/<v>`, including its moving `latest`), asdf
 * (`installs/nodejs/<v>`), nvm
 * (`.nvm/versions/node/<v>`), fnm (`node-versions/<v>`), volta
 * (`tools/image/node/<v>`), n (`n/versions/node/<v>`).
 *
 * A CLI installed with that node's npm lives in that tree too, so a node
 * upgrade (or pruning the old version) removes it — and a unit whose ExecStart
 * points there fails on every start. There is no stable path to switch to in
 * that case, only the honest warning.
 */
export function nodeVersionDir(path: string): string | null {
  const m = path.match(
    /^(.*?\/(?:installs\/node(?:js)?|\.nvm\/versions\/node|node-versions|tools\/image\/node|n\/versions\/node)\/[^/]+)\//,
  );
  return m ? m[1] : null;
}

/**
 * Why the unit cannot be installed on this host, or null when systemd is there
 * to run it. `/run/systemd/system` exists only when systemd is PID 1 — the
 * check `sd_booted()` makes — so a container that merely has the `systemctl`
 * binary installed still counts as no systemd.
 */
export function systemdUnavailableReason(o: { hasSystemctl: boolean; booted: boolean }): string | null {
  if (!o.hasSystemctl) return 'systemctl is not installed';
  if (!o.booted) return 'systemd is not running as the init system (common in containers and WSL)';
  return null;
}

function isRoot(): boolean {
  return typeof process.getuid === 'function' && process.getuid() === 0;
}

/**
 * Re-run ourselves under sudo instead of telling the operator to do it.
 *
 * A command whose whole job needs root should ask for root, not print a line
 * for a human to retype. sudo's own prompt appears in their terminal because we
 * inherit stdio, so this is exactly as safe as them typing it — and one step
 * shorter.
 *
 * Returns false when there is no sudo to use, or the operator declined it.
 */
export function reexecWithSudo(args: string[]): boolean {
  if (spawnSync('sudo', ['--version'], { stdio: 'pipe' }).status !== 0) return false;

  console.log(chalk.dim('  This needs root — sudo will ask for your password.\n'));
  const bin = resolveBinPath();

  // Running the script directly makes the kernel honour its `#!/usr/bin/env
  // node` shebang, and root's PATH has no version-managed node, so it died with
  // `env: 'node': No such file or directory`. Pass our own node explicitly.
  const argv = looksLikeNodeScript(bin)
    ? [stableNodePath(process.execPath), bin, ...args]
    : [bin, ...args];

  // `sudo -E` would carry the caller's environment into a root process; we let
  // sudo set SUDO_USER itself and leave the rest to root.
  const result = spawnSync('sudo', argv, { stdio: 'inherit' });
  return result.status === 0;
}

/**
 * The home directory of whoever invoked sudo, so a root install can find the
 * user-mode daemon it is replacing.
 */
function callerHome(): string | null {
  const user = process.env.SUDO_USER;
  if (!user) return null;
  try {
    const line = execSync(`getent passwd ${user}`, { encoding: 'utf-8' }).trim();
    const home = line.split(':')[5];
    return home && existsSync(home) ? home : null;
  } catch {
    return null;
  }
}

/**
 * Stop a user-mode daemon before the system one starts.
 *
 * Both would otherwise run at once, and `resolveClientSocket` prefers the
 * user's socket — so the dashboard would keep talking to the unprivileged
 * daemon that cannot ban anything, which is the exact confusion this install is
 * meant to end.
 */
function stopUserModeDaemon(): void {
  const home = callerHome();
  if (!home) return;

  const runDir = join(home, '.threatcrush', 'run');
  const pidFile = join(runDir, 'threatcrushd.pid');
  const socket = join(runDir, 'threatcrushd.sock');
  if (!existsSync(pidFile) && !existsSync(socket)) return;

  let pid: number | null = null;
  try {
    pid = Number.parseInt(readFileSync(pidFile, 'utf-8').trim(), 10);
  } catch {
    pid = null;
  }

  if (pid && Number.isFinite(pid)) {
    try {
      process.kill(pid, 'SIGTERM');
      console.log(chalk.dim(`  Stopped the user-mode daemon (pid ${pid}).`));
    } catch {
      // Already gone, or not ours to signal. Either way it is not in the way.
    }
  }

  // A daemon killed mid-flight leaves its socket behind, and a stale socket
  // still wins the client's preference order.
  for (const path of [socket, pidFile]) {
    try { if (existsSync(path)) rmSync(path); } catch { /* best-effort */ }
  }
}

/** Is systemd actually running the daemon right now? */
function unitIsActive(): boolean {
  const result = spawnSync('systemctl', ['is-active', '--quiet', DAEMON_UNIT_NAME], { stdio: 'pipe' });
  return result.status === 0;
}

export async function installServiceCommand(): Promise<void> {
  banner();

  if (process.platform !== 'linux') {
    console.log(chalk.yellow('  systemd install is only supported on Linux.'));
    process.exitCode = 1;
    return;
  }

  // Before sudo and before writing anything: without systemd the unit is a file
  // nobody will ever read, and `systemctl` fails only after it is written.
  const noSystemd = systemdUnavailableReason({
    hasSystemctl: spawnSync('sh', ['-c', 'command -v systemctl'], { stdio: 'ignore' }).status === 0,
    booted: existsSync('/run/systemd/system'),
  });
  if (noSystemd) {
    console.log(chalk.red(`  ✗ systemd isn't available here: ${noSystemd}.`));
    console.log(chalk.dim('  Nothing was installed. Run the daemon without a service manager instead:'));
    console.log(chalk.dim(`    ${chalk.white('threatcrush start')}      # background daemon`));
    console.log(chalk.dim(`    ${chalk.white('threatcrush daemon')}     # foreground, e.g. as a container's command`));
    console.log();
    process.exitCode = 1;
    return;
  }

  if (!isRoot()) {
    // Asking for root ourselves, rather than printing a command to retype.
    if (reexecWithSudo(['install-service'])) return;
    console.log(chalk.red('  Needs root and sudo is unavailable or was declined.'));
    console.log(chalk.dim('  Run this as root:  threatcrush install-service'));
    process.exitCode = 1;
    return;
  }

  // The template's `{{BIN_PATH}} daemon` becomes `<node> <script> daemon` for a
  // shebang script: systemd has no more chance of finding a version-managed
  // node on its PATH than sudo did.
  let binPath = resolveBinPath();
  const isNodeScript = looksLikeNodeScript(binPath);
  let nodePath = stableNodePath(process.execPath);
  if (isNodeScript && nodeVersionDir(binPath)) {
    // Installed by one Node version's npm, so it exists only as long as that
    // version does. Name that version outright — mise's `latest` would move to a
    // new Node that does not have threatcrush installed — and run it with the
    // node it was installed for.
    binPath = realpathSync(binPath);
    nodePath = process.execPath;
  }
  const exec = execStartCommand(binPath, nodePath, isNodeScript);
  const unit = resolveTemplate().replace('{{BIN_PATH}} daemon', exec).replace('{{BIN_PATH}}', binPath);
  writeFileSync(UNIT_PATH, unit, { mode: 0o644 });
  console.log(chalk.green(`  ✓ Installed unit file: ${UNIT_PATH}`));
  console.log(chalk.dim(`    ExecStart=${exec}`));

  // A `latest` node is fine on its own: any node runs a CLI living outside it.
  const nodeDir = nodeVersionDir(nodePath);
  const pinnedTo =
    nodeVersionDir(binPath) ?? (isNodeScript && nodeDir && !nodeDir.endsWith('/latest') ? nodeDir : null);
  if (pinnedTo) {
    console.log(chalk.yellow(`  ! ExecStart depends on the Node install in ${pinnedTo}.`));
    console.log(chalk.dim('    Upgrading or removing that Node version breaks the service. Afterwards, reinstall'));
    console.log(chalk.dim(`    threatcrush for the new Node and re-run ${chalk.white('threatcrush install-service')}.`));
    console.log(chalk.dim('    Installing with a system Node (/usr/bin/node or /usr/local/bin/node) avoids this.'));
  }

  ensureSystemDirs();

  // The daemon this service replaces has to go first, or two daemons run at
  // once and the client prefers the wrong one.
  stopUserModeDaemon();

  try {
    execSync('systemctl daemon-reload', { stdio: 'inherit' });
    // `--now` enables *and* starts. Enabling alone left the operator with a
    // service that would come up at the next boot and not one minute sooner,
    // which is not what "install the service" means to anybody.
    execSync(`systemctl enable --now ${DAEMON_UNIT_NAME}`, { stdio: 'inherit' });
  } catch (err) {
    console.log(chalk.yellow(`  ! systemctl error: ${(err as Error).message}`));
    console.log(chalk.dim(`  Logs:  journalctl -u ${DAEMON_UNIT_NAME} -n 50`));
    process.exitCode = 1;
    return;
  }

  if (unitIsActive()) {
    console.log(chalk.green('  ✓ Service enabled on boot and running now, as root.'));
    console.log(chalk.dim('  It can write firewall rules, so bans from the dashboard will apply.'));
    console.log(chalk.dim(`  Logs:  journalctl -u ${DAEMON_UNIT_NAME} -f`));
  } else {
    // Say so rather than letting a green tick imply a daemon that is not there.
    console.log(chalk.yellow('  ! The unit is installed but did not come up.'));
    console.log(chalk.dim(`  Logs:  journalctl -u ${DAEMON_UNIT_NAME} -n 50`));
    process.exitCode = 1;
  }
  console.log();
}

// systemd `ReadWritePaths=` requires these to exist before the unit starts,
// and we want module installs / config edits to be writable by `adm` group
// members (same boundary used for log read access and IPC socket access).
function ensureSystemDirs(): void {
  // Only the config side is group-writable. The runtime dirs used to be 0775
  // adm as well, which meant an adm member could replace files the daemon
  // relies on for its own authorization — including the control token that now
  // gates `shutdown` (TC-33). They are root-owned; adm still needs no more than
  // traverse-and-read there.
  const dirs: Array<{ path: string; groupWritable: boolean; sticky?: boolean }> = [
    { path: '/etc/threatcrush', groupWritable: true },
    { path: '/etc/threatcrush/modules', groupWritable: true, sticky: true },
    { path: '/etc/threatcrush/threatcrushd.conf.d', groupWritable: true },
    { path: '/var/log/threatcrush', groupWritable: false },
    { path: '/var/lib/threatcrush', groupWritable: false },
    // /run/threatcrush is deliberately absent: it lives on a tmpfs, so creating
    // it here only lasts until the next reboot. The unit's RuntimeDirectory=
    // recreates it on every start instead.
  ];
  let admGid: number | null = null;
  try {
    admGid = statSync('/var/log/auth.log').gid;
  } catch {
    // adm group not present — leave permissions as root-only
  }

  for (const { path, groupWritable, sticky } of dirs) {
    try { mkdirSync(path, { recursive: true }); } catch {}
    try {
      if (groupWritable && admGid !== null) {
        // 2775 = setgid + group writable; setgid makes new files inherit `adm`.
        chmodSync(path, sticky ? 0o2775 : 0o775);
        execSync(`chgrp adm ${path}`, { stdio: 'ignore' });
      } else {
        chmodSync(path, 0o755);
      }
    } catch { /* best-effort */ }
  }
  console.log(chalk.green('  ✓ Runtime dirs prepared (group `adm` may install modules / edit config without sudo).'));
}

export async function uninstallServiceCommand(): Promise<void> {
  banner();

  if (process.platform !== 'linux') {
    console.log(chalk.yellow('  systemd uninstall is only supported on Linux.'));
    return;
  }
  if (!isRoot()) {
    // Same reasoning as the install: ask for the privilege, do not assign
    // homework.
    if (reexecWithSudo(['uninstall-service'])) return;
    console.log(chalk.red('  Needs root and sudo is unavailable or was declined.'));
    console.log(chalk.dim('  Run this as root:  threatcrush uninstall-service'));
    return;
  }

  try { execSync('systemctl stop threatcrushd.service', { stdio: 'inherit' }); } catch {}
  try { execSync('systemctl disable threatcrushd.service', { stdio: 'inherit' }); } catch {}
  try {
    if (existsSync(UNIT_PATH)) {
      execSync(`rm -f ${UNIT_PATH}`);
      console.log(chalk.green(`  ✓ Removed unit file: ${UNIT_PATH}`));
    }
  } catch {}
  try { execSync('systemctl daemon-reload', { stdio: 'inherit' }); } catch {}

  console.log(chalk.green('  ✓ threatcrushd service removed.'));
}
