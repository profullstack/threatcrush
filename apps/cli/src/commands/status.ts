import chalk from 'chalk';
import { banner, logger } from '../core/logger.js';
import { discoverModules } from '../core/module-loader.js';
import { initStateDB, getEventCount, getThreatCount, getRecentEvents } from '../core/state.js';
import { IpcClient } from '../core/ipc-client.js';
import { findRunningDaemon } from '../daemon/pidfile.js';
import { PATHS } from '../daemon/paths.js';

export async function statusCommand(): Promise<void> {
  banner();

  const pid = findRunningDaemon();
  const client = new IpcClient();
  let live: Awaited<ReturnType<IpcClient['status']>> | null = null;
  if (pid) {
    try {
      await client.connect();
      live = await client.status();
    } catch {
      // daemon PID present but IPC unreachable
    } finally {
      client.close();
    }
  }

  console.log(chalk.green.bold('  Daemon Status'));
  console.log(chalk.gray('  ' + '─'.repeat(60)));

  if (live) {
    console.log(`  Status:     ${chalk.green.bold('● RUNNING')}`);
    console.log(`  PID:        ${chalk.white(String(live.pid))}`);
    console.log(`  Started:    ${chalk.white(live.startedAt)}`);
    console.log(`  Uptime:     ${chalk.white(formatUptime(live.uptimeSeconds))}`);
    console.log(`  Version:    ${chalk.white(live.version)}`);
    console.log(`  Mode:       ${chalk.white(live.mode)}`);
    console.log(`  Socket:     ${chalk.gray(live.paths.socket)}`);
  } else if (pid) {
    console.log(`  Status:     ${chalk.yellow.bold('● RUNNING (IPC unreachable)')}`);
    console.log(`  PID:        ${chalk.white(String(pid))}`);
    console.log(`  Socket:     ${chalk.gray(PATHS.socket)}`);
  } else {
    console.log(`  Status:     ${chalk.gray('○ NOT RUNNING')}`);
    console.log(`  Start it:   ${chalk.white('threatcrush start')}`);
  }
  console.log();

  // Modules
  console.log(chalk.green.bold('  Modules'));
  console.log(chalk.gray('  ' + '─'.repeat(60)));
  if (live && live.modules.length > 0) {
    for (const mod of live.modules) {
      const dot =
        mod.status === 'running' ? chalk.green('●') :
        mod.status === 'loaded' ? chalk.cyan('○') :
        mod.status === 'error' ? chalk.red('✗') : chalk.gray('○');
      console.log(`  ${dot}  ${chalk.white.bold(mod.name.padEnd(18))} ${chalk.gray(mod.status.padEnd(10))} ${chalk.dim(`${mod.events} events`)}`);
    }
  } else {
    const modules = discoverModules();
    if (modules.length === 0) {
      console.log(chalk.gray('  No modules discovered. Run `threatcrush init`.'));
    } else {
      for (const mod of modules) {
        const enabled = mod.config.enabled !== false;
        const status = enabled ? chalk.green('● enabled ') : chalk.gray('○ disabled');
        console.log(`  ${status}  ${chalk.white.bold(mod.manifest.name.padEnd(18))} ${chalk.gray('v' + mod.manifest.version)}`);
      }
    }
  }
  console.log();

  // Event stats
  try {
    if (!live) initStateDB(PATHS.stateDb);
    const total = live ? live.counters.events : getEventCount();
    const threats = live ? live.counters.threats : getThreatCount();
    const last24h = getEventCount(new Date(Date.now() - 86400000));
    const threats24h = getThreatCount(new Date(Date.now() - 86400000));

    console.log(chalk.green.bold('  Event Statistics'));
    console.log(chalk.gray('  ' + '─'.repeat(60)));
    console.log(`  Total events:     ${chalk.white(total.toString())}`);
    console.log(`  Total threats:    ${chalk.red(threats.toString())}`);
    console.log(`  Events (24h):     ${chalk.white(last24h.toString())}`);
    console.log(`  Threats (24h):    ${chalk.red(threats24h.toString())}`);
    console.log();

    const recent = getRecentEvents(5);
    if (recent.length > 0) {
      console.log(chalk.green.bold('  Recent Events'));
      console.log(chalk.gray('  ' + '─'.repeat(60)));
      for (const evt of recent) {
        const sev = evt.severity === 'critical' || evt.severity === 'high'
          ? chalk.red(`[${evt.severity.toUpperCase()}]`)
          : evt.severity === 'medium'
            ? chalk.yellow(`[${evt.severity.toUpperCase()}]`)
            : chalk.green(`[${evt.severity.toUpperCase()}]`);
        console.log(`  ${chalk.gray(evt.timestamp.toISOString().slice(0, 19))} ${sev.padEnd(20)} ${evt.message}`);
      }
    }
  } catch {
    logger.info('No event data available yet.');
  }
  console.log();
}

function formatUptime(seconds: number): string {
  if (seconds < 60) return `${seconds}s`;
  const m = Math.floor(seconds / 60);
  if (m < 60) return `${m}m ${seconds % 60}s`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ${m % 60}m`;
  const d = Math.floor(h / 24);
  return `${d}d ${h % 24}h`;
}
