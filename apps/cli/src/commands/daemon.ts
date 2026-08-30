import { spawn } from 'node:child_process';
import { existsSync, unlinkSync } from 'node:fs';
import { join } from 'node:path';
import { openSync } from 'node:fs';
import chalk from 'chalk';
import { runDaemon } from '../daemon/index.js';
import { PATHS, ensureRuntimeDirs } from '../daemon/paths.js';
import { findRunningDaemon, isProcessAlive, removePidFile } from '../daemon/pidfile.js';
import { IpcClient } from '../core/ipc-client.js';

const DAEMON_ENTRY = join(__dirname, 'daemon.js');

export async function daemonForeground(): Promise<void> {
  await runDaemon();
}

export async function daemonStart(): Promise<void> {
  const pid = findRunningDaemon();
  if (pid) {
    console.log(chalk.yellow(`  threatcrushd already running (pid ${pid}).`));
    return;
  }

  ensureRuntimeDirs();

  if (!existsSync(DAEMON_ENTRY)) {
    console.log(chalk.red(`  Daemon entry not found at ${DAEMON_ENTRY}.`));
    console.log(chalk.dim('  Reinstall with `threatcrush update` or `pnpm run build` in the cli package.'));
    return;
  }

  let out: number;
  let err: number;
  try {
    out = openSync(PATHS.logFile, 'a');
    err = openSync(PATHS.logFile, 'a');
  } catch (e) {
    const code = (e as NodeJS.ErrnoException).code;
    console.log(chalk.red(`  ✗ Cannot write daemon log at ${PATHS.logFile} (${code ?? 'error'}).`));
    if (code === 'EACCES') {
      console.log(
        chalk.dim(
          PATHS.mode === 'system'
            ? '  Run as root (sudo) to use system paths, or run without sudo to use ~/.threatcrush.'
            : `  Fix permissions on ${PATHS.logDir} (it should be owned by your user).`,
        ),
      );
    }
    return;
  }

  const child = spawn(process.execPath, [DAEMON_ENTRY], {
    detached: true,
    stdio: ['ignore', out, err],
    env: { ...process.env, THREATCRUSH_DAEMON: '1' },
  });
  child.unref();

  // Wait briefly for the socket to come up
  const deadline = Date.now() + 3000;
  while (Date.now() < deadline) {
    if (IpcClient.isDaemonRunning()) break;
    await new Promise((r) => setTimeout(r, 100));
  }

  if (IpcClient.isDaemonRunning()) {
    console.log(chalk.green(`  ✓ threatcrushd started (pid ${child.pid})`));
    console.log(chalk.dim(`    socket: ${PATHS.socket}`));
    console.log(chalk.dim(`    log:    ${PATHS.logFile}\n`));
  } else {
    console.log(chalk.red(`  ✗ threatcrushd did not come up within 3s.`));
    console.log(chalk.dim(`    check log: ${PATHS.logFile}\n`));
  }
}

/**
 * Returns true when no daemon is running once this resolves — either it was
 * already down, or we brought it down. `restart` needs that answer: starting a
 * second daemon while the first is alive makes it unlink the live socket.
 */
export async function daemonStop(): Promise<boolean> {
  const pid = findRunningDaemon();
  if (!pid) {
    console.log(chalk.dim('  No running daemon found.'));
    return true;
  }

  try {
    const client = new IpcClient();
    await client.connect();
    await client.shutdown().catch(() => {});
    client.close();
  } catch {
    try { process.kill(pid, 'SIGTERM'); } catch {}
  }

  // `isProcessAlive` treats EPERM as alive. A raw `process.kill(pid, 0)` here
  // would read the EPERM from signalling a root-owned daemon as "it's gone".
  if (await waitForExit(pid, 3000)) {
    removePidFile();
    console.log(chalk.green(`  ✓ threatcrushd stopped.`));
    return true;
  }

  try { process.kill(pid, 'SIGKILL'); } catch {}

  if (!(await waitForExit(pid, 1000))) {
    console.log(chalk.red(`  ✗ threatcrushd (pid ${pid}) is still running and could not be stopped.`));
    console.log(chalk.dim('    It may be owned by another user — try `sudo threatcrush stop`.\n'));
    // Leave the pidfile: it still points at a live process.
    return false;
  }

  removePidFile();
  console.log(chalk.yellow(`  ! threatcrushd was killed (SIGKILL).`));
  return true;
}

export async function daemonRestart(): Promise<void> {
  if (!(await daemonStop())) return;
  await releaseStaleSocket();
  await daemonStart();
}

async function waitForExit(pid: number, timeoutMs: number): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (isProcessAlive(pid)) {
    if (Date.now() >= deadline) return false;
    await new Promise((r) => setTimeout(r, 100));
  }
  return true;
}

/**
 * A daemon that exits cleanly unlinks its own socket, but one we SIGKILLed
 * leaves the file behind — and `daemonStart` reads socket existence as
 * "it's up", so a leftover would make the restart report success without the
 * new daemon ever binding.
 */
async function releaseStaleSocket(): Promise<void> {
  const deadline = Date.now() + 2000;
  while (existsSync(PATHS.socket) && Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, 50));
  }
  if (existsSync(PATHS.socket)) {
    try { unlinkSync(PATHS.socket); } catch {}
  }
}
