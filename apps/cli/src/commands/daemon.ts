import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { openSync } from 'node:fs';
import chalk from 'chalk';
import { runDaemon } from '../daemon/index.js';
import { PATHS, ensureRuntimeDirs } from '../daemon/paths.js';
import { findRunningDaemon, removePidFile } from '../daemon/pidfile.js';
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

  const out = openSync(PATHS.logFile, 'a');
  const err = openSync(PATHS.logFile, 'a');

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

export async function daemonStop(): Promise<void> {
  const pid = findRunningDaemon();
  if (!pid) {
    console.log(chalk.dim('  No running daemon found.'));
    return;
  }

  try {
    const client = new IpcClient();
    await client.connect();
    await client.shutdown().catch(() => {});
    client.close();
  } catch {
    try { process.kill(pid, 'SIGTERM'); } catch {}
  }

  const deadline = Date.now() + 3000;
  while (Date.now() < deadline) {
    try { process.kill(pid, 0); } catch { break; }
    await new Promise((r) => setTimeout(r, 100));
  }

  try { process.kill(pid, 0); } catch {
    removePidFile();
    console.log(chalk.green(`  ✓ threatcrushd stopped.`));
    return;
  }

  try { process.kill(pid, 'SIGKILL'); } catch {}
  removePidFile();
  console.log(chalk.yellow(`  ! threatcrushd was killed (SIGKILL).`));
}
