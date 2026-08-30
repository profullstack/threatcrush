import { execSync } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import chalk from 'chalk';
import { banner } from '../core/logger.js';

const UNIT_PATH = '/etc/systemd/system/threatcrushd.service';

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

function isRoot(): boolean {
  return typeof process.getuid === 'function' && process.getuid() === 0;
}

export async function installServiceCommand(): Promise<void> {
  banner();

  if (process.platform !== 'linux') {
    console.log(chalk.yellow('  systemd install is only supported on Linux.'));
    return;
  }

  if (!isRoot()) {
    console.log(chalk.red('  Must run as root (try `sudo threatcrush install-service`).'));
    return;
  }

  const unit = resolveTemplate().replace('{{BIN_PATH}}', resolveBinPath());
  writeFileSync(UNIT_PATH, unit, { mode: 0o644 });
  console.log(chalk.green(`  ✓ Installed unit file: ${UNIT_PATH}`));

  ensureSystemDirs();

  try {
    execSync('systemctl daemon-reload', { stdio: 'inherit' });
    execSync('systemctl enable threatcrushd.service', { stdio: 'inherit' });
    console.log(chalk.green('  ✓ Service enabled on boot.'));
    console.log(chalk.dim('  Start now with: systemctl start threatcrushd'));
    console.log(chalk.dim('  View logs with: journalctl -u threatcrushd -f'));
  } catch (err) {
    console.log(chalk.yellow(`  ! systemctl error: ${(err as Error).message}`));
  }
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
    console.log(chalk.red('  Must run as root (try `sudo threatcrush uninstall-service`).'));
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
