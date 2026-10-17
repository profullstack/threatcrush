import { isIP } from 'node:net';
import { join } from 'node:path';
import chalk from 'chalk';
import { loadConfig } from '../core/config.js';
import { fetchFeeds, matchDomain, matchIp, readFeedCache, type FeedSet } from '../core/threat-feeds/index.js';
import { SYSTEM_PATHS, USER_PATHS } from '../daemon/paths.js';
import { threatFeedSettings } from '../daemon/workers/threat-feeds.js';
import { resolverCommand } from './feeds-resolver.js';

/** The daemon's cached list, or a fresh fetch when there is none this user can read. */
async function loadSet(): Promise<{ set: FeedSet; from: string }> {
  for (const dir of [SYSTEM_PATHS.stateDir, USER_PATHS.stateDir]) {
    const path = join(dir, 'threat-feeds.json');
    const set = readFeedCache(path);
    if (set) return { set, from: path };
  }
  const settings = threatFeedSettings(loadConfig(join(SYSTEM_PATHS.configDir, 'threatcrushd.conf')).threat_feeds);
  return { set: await fetchFeeds(settings), from: 'abuse.ch (live; no daemon cache readable)' };
}

/**
 * `threatcrush feeds` — the abuse.ch C2/malware list the daemon matches
 * against; `threatcrush feeds check <ip|domain>` looks one value up.
 */
export async function feedsCommand(action: string | undefined, value: string | undefined, opts: { json?: boolean }): Promise<void> {
  if (action === 'resolver') {
    process.exitCode = resolverCommand(value, SYSTEM_PATHS.stateDir);
    return;
  }
  const { set, from } = await loadSet();

  if (action === 'check') {
    if (!value) {
      console.error('Usage: threatcrush feeds check <ip|domain>');
      process.exitCode = 2;
      return;
    }
    const ipHit = isIP(value) ? matchIp(value, set) : null;
    const domainHit = isIP(value) ? null : matchDomain(value, set);
    const listed = ipHit ?? domainHit?.indicator ?? null;
    if (opts.json) {
      console.log(JSON.stringify({ value, listed: Boolean(listed), indicator: listed, matched: domainHit?.domain ?? (ipHit ? value : null), fetched_at: set.fetched_at }, null, 2));
    } else if (listed) {
      console.log(`${chalk.red('LISTED')} ${value}${domainHit && domainHit.domain !== value ? ` (via ${domainHit.domain})` : ''}: ${listed.malware} ${listed.threat} [${listed.feed}]`);
    } else {
      console.log(`${chalk.green('not listed')} ${value}`);
    }
    process.exitCode = listed ? 1 : 0;
    return;
  }

  const ips = Object.keys(set.ips).length;
  const domains = Object.keys(set.domains).length;
  if (opts.json) {
    console.log(JSON.stringify({ from, fetched_at: set.fetched_at, ips, domains, skipped_shared: set.skipped_shared, sources: set.sources }, null, 2));
    return;
  }
  console.log(`  ${chalk.white.bold('Threat feeds')} ${chalk.gray(`(${from})`)}`);
  console.log(`  Fetched: ${set.fetched_at.replace('T', ' ').slice(0, 16)} UTC`);
  console.log(`  ${ips} C2/payload IPs, ${domains} malware domains; ${set.skipped_shared} shared or protected entries skipped`);
  for (const s of set.sources) {
    console.log(`    ${s.ok ? chalk.green('✓') : chalk.red('✗')} ${s.feed.padEnd(16)} ${s.ok ? `${s.count}` : chalk.red(s.error ?? 'failed')}`);
  }
  console.log(chalk.gray('\n  Blocking egress needs [threat_feeds] block = true and [remediation] in enforce mode.'));
}
