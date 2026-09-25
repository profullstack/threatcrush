import chalk from 'chalk';
import { banner } from '../core/logger.js';
import { IpcClient } from '../core/ipc-client.js';
import { PATHS } from '../daemon/paths.js';
import { formatDuration } from '../daemon/firewall/backoff.js';
import type { BlocklistReply } from '../daemon/ipc-protocol.js';

/**
 * These four used to print a description of what a running daemon would have
 * done, which meant `threatcrush block <ip>` blocked nothing at all. They now
 * talk to the daemon, which is the only thing that can actually write a rule.
 */
async function connect(): Promise<IpcClient | null> {
  if (!IpcClient.isDaemonRunning()) {
    console.log(chalk.red(`  No daemon at ${PATHS.socket}.`));
    console.log(chalk.gray('  Start it first:  threatcrush start'));
    console.log();
    return null;
  }
  const client = new IpcClient();
  try {
    await client.connect();
    return client;
  } catch (err) {
    console.log(chalk.red(`  Cannot reach threatcrushd: ${(err as Error).message}`));
    console.log();
    return null;
  }
}

export async function blockCommand(ip: string, opts: { ttl?: string }): Promise<void> {
  banner();
  console.log(chalk.green.bold('  Firewall Block'));
  console.log(chalk.gray('  ' + '─'.repeat(50)));

  const client = await connect();
  if (!client) return;

  try {
    const entry = await client.block(ip, 'banned from CLI', opts.ttl);
    const ttl = formatDuration(Math.round((entry.expires_at - Date.now()) / 1000));
    const mode = entry.dry_run ? chalk.yellow(' [DRY-RUN]') : '';
    console.log(`  ${chalk.red('✖')} Banned ${chalk.white(ip)} for ${chalk.white(ttl)}${mode}`);
    console.log(chalk.gray(`  Offence #${entry.strikes} — repeat offences escalate 1m → 2m → 3m → 5m → 8m …`));
  } catch (err) {
    console.log(`  ${chalk.red('✗')} ${(err as Error).message}`);
  } finally {
    client.close();
    console.log();
  }
}

export async function unblockCommand(ip: string): Promise<void> {
  banner();
  console.log(chalk.green.bold('  Firewall Unblock'));
  console.log(chalk.gray('  ' + '─'.repeat(50)));

  const client = await connect();
  if (!client) return;

  try {
    await client.unblock(ip);
    console.log(`  ${chalk.green('✓')} Unbanned ${chalk.white(ip)} ${chalk.gray('(strike history cleared)')}`);
  } catch (err) {
    console.log(`  ${chalk.red('✗')} ${(err as Error).message}`);
  } finally {
    client.close();
    console.log();
  }
}

export async function blocklistCommand(): Promise<void> {
  banner();
  console.log(chalk.green.bold('  Active Blocklist'));
  console.log(chalk.gray('  ' + '─'.repeat(70)));

  const client = await connect();
  if (!client) return;

  let reply: BlocklistReply;
  try {
    reply = await client.blocklist();
  } catch (err) {
    console.log(`  ${chalk.red('✗')} ${(err as Error).message}`);
    client.close();
    console.log();
    return;
  }
  client.close();

  const mode = reply.dry_run ? chalk.yellow('dry-run') : chalk.green('enforcing');
  console.log(`  Auto-defence: ${reply.enabled ? mode : chalk.red('disabled')}`);
  console.log(`  Backend:      ${chalk.white(reply.backend)}`);
  console.log(`  Bans at:      ${chalk.white(reply.min_severity)} severity and above`);
  console.log();

  if (reply.entries.length === 0) {
    console.log(chalk.gray('  Nothing is banned.'));
    console.log();
    return;
  }

  const now = Date.now();
  console.log(
    chalk.gray('  ') +
    chalk.gray('IP'.padEnd(40)) +
    chalk.gray('#'.padEnd(5)) +
    chalk.gray('LEFT'.padEnd(9)) +
    chalk.gray('SOURCE'),
  );
  for (const entry of reply.entries) {
    const left = formatDuration(Math.round((entry.expires_at - now) / 1000));
    console.log(
      '  ' +
      chalk.white(entry.ip.padEnd(40)) +
      chalk.gray(String(entry.strikes).padEnd(5)) +
      chalk.yellow(left.padEnd(9)) +
      chalk.gray(entry.source + (entry.dry_run ? ' (dry-run)' : '')),
    );
    console.log(chalk.gray(`      ${entry.reason}`));
  }
  console.log();
}

export async function allowlistCommand(opts: { action?: string; value?: string }): Promise<void> {
  banner();
  const action = opts.action || 'list';

  console.log(chalk.green.bold('  Allowlist (never banned)'));
  console.log(chalk.gray('  ' + '─'.repeat(50)));

  if (action === 'list' || action === 'ls') {
    const client = await connect();
    if (!client) return;
    try {
      const reply = await client.blocklist();
      for (const entry of reply.protected) {
        console.log(`  ${chalk.green('⛊')} ${chalk.white(entry)}`);
      }
      console.log();
      console.log(chalk.gray('  Loopback, private ranges, the default gateway and the SSH client'));
      console.log(chalk.gray('  that started the daemon are always protected. Add more under'));
      console.log(chalk.gray(`  [remediation] protected = [...] in ${PATHS.configFile}`));
    } catch (err) {
      console.log(`  ${chalk.red('✗')} ${(err as Error).message}`);
    } finally {
      client.close();
      console.log();
    }
    return;
  }

  // Adding and removing are config edits: the daemon rebuilds the protected set
  // at start, so a live mutation would be forgotten on restart and the two
  // would silently disagree.
  console.log(chalk.gray(`  Edit ${PATHS.configFile}:`));
  console.log();
  console.log(chalk.gray('    [remediation]'));
  console.log(chalk.gray(`    protected = ["${opts.value || '203.0.113.7/32'}"]`));
  console.log();
  console.log(chalk.gray('  then: threatcrush restart'));
  console.log();
}
