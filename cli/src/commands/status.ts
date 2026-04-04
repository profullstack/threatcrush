import chalk from 'chalk';
import { banner, logger } from '../core/logger.js';
import { discoverModules } from '../core/module-loader.js';
import { initStateDB, getEventCount, getThreatCount, getRecentEvents } from '../core/state.js';

export async function statusCommand(): Promise<void> {
  banner();

  // Check if daemon is running (look for PID file or process)
  const daemonRunning = checkDaemon();

  console.log(chalk.green.bold('  Daemon Status'));
  console.log(chalk.gray('  ' + '─'.repeat(50)));
  console.log(`  Status:     ${daemonRunning ? chalk.green.bold('● RUNNING') : chalk.yellow('○ NOT RUNNING')}`);
  console.log(`  PID:        ${daemonRunning ? chalk.white('—') : chalk.gray('N/A')}`);
  console.log(`  Uptime:     ${daemonRunning ? chalk.white('—') : chalk.gray('N/A')}`);
  console.log();

  // Show modules
  const modules = discoverModules();
  console.log(chalk.green.bold('  Loaded Modules'));
  console.log(chalk.gray('  ' + '─'.repeat(50)));

  if (modules.length === 0) {
    console.log(chalk.gray('  No modules found. Run `threatcrush init` to set up.'));
  } else {
    for (const mod of modules) {
      const enabled = mod.config.enabled !== false;
      const status = enabled ? chalk.green('● enabled ') : chalk.gray('○ disabled');
      console.log(`  ${status}  ${chalk.white.bold(mod.manifest.name.padEnd(18))} ${chalk.gray('v' + mod.manifest.version)}`);
    }
  }
  console.log();

  // Show event stats
  try {
    initStateDB();
    const totalEvents = getEventCount();
    const totalThreats = getThreatCount();
    const last24h = getEventCount(new Date(Date.now() - 86400000));
    const threats24h = getThreatCount(new Date(Date.now() - 86400000));

    console.log(chalk.green.bold('  Event Statistics'));
    console.log(chalk.gray('  ' + '─'.repeat(50)));
    console.log(`  Total events:     ${chalk.white(totalEvents.toString())}`);
    console.log(`  Total threats:    ${chalk.red(totalThreats.toString())}`);
    console.log(`  Events (24h):     ${chalk.white(last24h.toString())}`);
    console.log(`  Threats (24h):    ${chalk.red(threats24h.toString())}`);
    console.log();

    // Show recent events
    const recent = getRecentEvents(5);
    if (recent.length > 0) {
      console.log(chalk.green.bold('  Recent Events'));
      console.log(chalk.gray('  ' + '─'.repeat(50)));
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
    console.log(chalk.gray('  No event data available. Start monitoring to collect events.'));
  }

  console.log();
}

function checkDaemon(): boolean {
  try {
    const { execSync } = await_import_child_process();
    execSync('pgrep -f threatcrushd', { stdio: 'pipe' });
    return true;
  } catch {
    return false;
  }
}

// Avoid top-level await for dynamic import
function await_import_child_process() {
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  return require('node:child_process');
}
