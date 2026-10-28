import { existsSync, readFileSync, statSync } from 'node:fs';
import { isIP } from 'node:net';
import { join } from 'node:path';
import chalk from 'chalk';
import { loadConfig } from '../core/config.js';
import { TOR_BULK_EXIT_LIST_URL, normalizeIp, parseTorExitList } from '../core/tor-exits.js';
import { SYSTEM_PATHS, USER_PATHS } from '../daemon/paths.js';

/**
 * `threatcrush tor` — the Tor exit list the daemon bans SSH from (count, age,
 * whether the ban is on); `threatcrush tor check <ip>` looks one address up
 * (exit 1 when it is an exit).
 */
export async function torCommand(action: string | undefined, value: string | undefined, opts: { json?: boolean }): Promise<void> {
  let exits = new Set<string>();
  let from = '';
  let updated: Date | null = null;
  for (const dir of [SYSTEM_PATHS.stateDir, USER_PATHS.stateDir]) {
    const path = join(dir, 'tor-exits.txt');
    try {
      if (!existsSync(path)) continue;
      exits = parseTorExitList(readFileSync(path, 'utf-8'));
      from = path;
      updated = statSync(path).mtime;
      break;
    } catch { /* not readable as this user */ }
  }
  if (!exits.size) {
    try {
      const res = await fetch(TOR_BULK_EXIT_LIST_URL, { signal: AbortSignal.timeout(20_000) });
      if (res.ok) { exits = parseTorExitList(await res.text()); from = `${TOR_BULK_EXIT_LIST_URL} (live; no daemon cache readable)`; updated = new Date(); }
    } catch { /* offline */ }
  }
  const remediation = loadConfig(join(SYSTEM_PATHS.configDir, 'threatcrushd.conf')).remediation;
  const ban = remediation?.block_tor_ssh !== false && remediation?.enabled !== false;

  if (action === 'check') {
    if (!value || !isIP(value)) {
      console.error('Usage: threatcrush tor check <ip>');
      process.exitCode = 2;
      return;
    }
    const listed = exits.has(normalizeIp(value));
    if (opts.json) console.log(JSON.stringify({ ip: value, tor_exit: listed, list_size: exits.size, from }, null, 2));
    else console.log(listed ? `${chalk.red('TOR EXIT')} ${value}` : `${chalk.green('not a Tor exit')} ${value}`);
    process.exitCode = listed ? 1 : 0;
    return;
  }

  const status = {
    exits: exits.size,
    from,
    updated_at: updated?.toISOString() ?? null,
    block_tor_ssh: ban,
    pinned_in_config: typeof remediation?.block_tor_ssh === 'boolean',
  };
  if (opts.json) { console.log(JSON.stringify(status, null, 2)); return; }
  console.log(`Tor exits known: ${chalk.bold(String(status.exits))}${status.updated_at ? ` (updated ${status.updated_at})` : ''}`);
  console.log(`Source: ${status.from || 'none (daemon not running yet, and the list could not be fetched)'}`);
  console.log(`SSH from Tor: ${ban ? chalk.red('banned at once, for max_ban, even in dry_run') : chalk.yellow('alert only ([remediation] block_tor_ssh = false)')}${status.pinned_in_config ? ' (set in threatcrushd.conf)' : ' (default; the dashboard org setting can change it)'}`);
}
