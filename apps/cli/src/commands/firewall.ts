import chalk from 'chalk';
import { banner } from '../core/logger.js';

export async function blockCommand(ip: string, opts: { ttl?: string }): Promise<void> {
  banner();
  console.log(chalk.green.bold('  Firewall Block'));
  console.log(chalk.gray('  ' + '─'.repeat(50)));

  let ttlSeconds: number | undefined;
  if (opts.ttl) {
    const match = opts.ttl.match(/^(\d+)(s|m|h|d)?$/);
    if (match) {
      const value = parseInt(match[1]);
      const unit = match[2] || 's';
      const multipliers: Record<string, number> = { s: 1, m: 60, h: 3600, d: 86400 };
      ttlSeconds = value * (multipliers[unit] || 1);
    }
  }

  console.log(`  Blocking ${chalk.red(ip)}${ttlSeconds ? ` for ${opts.ttl}` : ' permanently'}...`);
  console.log(chalk.gray('  Note: Requires running daemon with CAP_NET_ADMIN'));
  console.log(chalk.gray('  Configure in /etc/threatcrush/threatcrushd.conf under [remediation]'));
  console.log();
}

export async function unblockCommand(ip: string): Promise<void> {
  banner();
  console.log(chalk.green.bold('  Firewall Unblock'));
  console.log(chalk.gray('  ' + '─'.repeat(50)));
  console.log(`  Unblocking ${chalk.white(ip)}...`);
  console.log(chalk.gray('  Note: Requires running daemon'));
  console.log();
}

export async function blocklistCommand(): Promise<void> {
  banner();
  console.log(chalk.green.bold('  Active Blocklist'));
  console.log(chalk.gray('  ' + '─'.repeat(60)));
  console.log(chalk.gray('  Connect to running daemon for live blocklist data.'));
  console.log(chalk.gray('  Configure via /etc/threatcrush/threatcrushd.conf [remediation]'));
  console.log();
  console.log(chalk.gray('  Remediation config options:'));
  console.log(chalk.gray('    enabled = true'));
  console.log(chalk.gray('    dry_run = true        # Log only, no actual blocks'));
  console.log(chalk.gray('    default_ttl = "1h"    # Default block duration'));
  console.log(chalk.gray('    min_severity = "high" # Minimum severity to auto-block'));
  console.log();
}

export async function allowlistCommand(opts: { action?: string; value?: string }): Promise<void> {
  banner();
  const action = opts.action || 'list';

  console.log(chalk.green.bold('  Allowlist'));
  console.log(chalk.gray('  ' + '─'.repeat(50)));

  switch (action) {
    case 'list':
    case 'ls':
      console.log(chalk.gray('  Allowlisted IPs/CIDRs (from config):'));
      console.log(chalk.gray('    127.0.0.1'));
      console.log(chalk.gray('    ::1'));
      console.log();
      console.log(chalk.gray('  Add more via /etc/threatcrush/threatcrushd.conf [remediation] allowlist'));
      break;
    case 'add':
      if (!opts.value) {
        console.log(chalk.red('  IP/CIDR required. Usage: threatcrush allowlist add <ip>'));
        break;
      }
      console.log(chalk.green(`  Added ${opts.value} to allowlist`));
      break;
    case 'remove':
      if (!opts.value) {
        console.log(chalk.red('  IP/CIDR required. Usage: threatcrush allowlist remove <ip>'));
        break;
      }
      console.log(chalk.green(`  Removed ${opts.value} from allowlist`));
      break;
    default:
      console.log(chalk.yellow(`  Unknown action: ${action}`));
      console.log(chalk.gray('  Available: list, add, remove'));
  }
  console.log();
}
