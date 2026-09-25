import { execSync, execFileSync, spawnSync } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { isIP } from 'node:net';

export interface FirewallAdapter {
  name: string;
  isAvailable(): boolean;
  block(ip: string): Promise<void>;
  unblock(ip: string): Promise<void>;
  isBlocked(ip: string): Promise<boolean>;
  listBlocked(): Promise<string[]>;
  /** False when the backend only pretends to block, i.e. the dry-run adapter. */
  enforces?: boolean;
}

function assertValidFirewallIp(ip: string): void {
  if (isIP(ip) !== 4) {
    throw new Error(`Invalid IPv4 address: ${ip}`);
  }
}

function assertBannableIp(ip: string): void {
  if (isIP(ip) === 0) {
    throw new Error(`Invalid IP address: ${ip}`);
  }
}

/**
 * Create a file only if it is not already there, without the check-then-write
 * race: `wx` makes the test and the creation one syscall, so two daemons
 * starting together cannot have one clobber the other's config half-written.
 * An existing file is left exactly as the operator left it.
 */
function writeIfAbsent(path: string, contents: string): void {
  mkdirSync(dirname(path), { recursive: true });
  try {
    writeFileSync(path, contents, { flag: 'wx' });
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== 'EEXIST') throw err;
  }
}

export const FAIL2BAN_JAIL = 'threatcrush';
const FAIL2BAN_FILTER_FILE = '/etc/fail2ban/filter.d/threatcrush.conf';
const FAIL2BAN_JAIL_FILE = '/etc/fail2ban/jail.d/threatcrush.conf';

/**
 * fail2ban, driven as a ban executor rather than a log reader.
 *
 * Detection already happened — the rule engine and the modules did it — so the
 * jail we install deliberately matches nothing on its own. We only ever reach
 * it through `set <jail> banip`, which keeps every ban attributable to a
 * ThreatCrush decision and keeps the operator's own jails untouched.
 *
 * Expiry is ours, not fail2ban's: the jail's bantime is a long backstop and
 * `RemediationManager` unbans on the Fibonacci schedule. Owning the clock is
 * what makes escalating durations possible at all, since a jail has exactly one
 * bantime and we need a different one per offender.
 */
export class Fail2banAdapter implements FirewallAdapter {
  name = 'fail2ban';
  enforces = true;
  private jailReady = false;

  constructor(private jail: string = FAIL2BAN_JAIL, private backstopSeconds = 86400) {}

  isAvailable(): boolean {
    // `ping` answers only when the server is up. A client binary on its own
    // means fail2ban is installed but not running, which cannot ban anything.
    const result = spawnSync('fail2ban-client', ['ping'], { stdio: 'pipe' });
    return result.status === 0;
  }

  private client(args: string[]): string {
    return execFileSync('fail2ban-client', args, {
      encoding: 'utf-8',
      stdio: ['ignore', 'pipe', 'pipe'],
    });
  }

  /**
   * Create the jail if it is missing. Writing to /etc/fail2ban needs root; when
   * we cannot, the error surfaces to the caller instead of a ban that silently
   * goes nowhere.
   */
  private ensureJail(): void {
    if (this.jailReady) return;
    try {
      this.client(['status', this.jail]);
      this.jailReady = true;
      return;
    } catch {
      // Jail not configured yet — install it below.
    }

    writeIfAbsent(
      FAIL2BAN_FILTER_FILE,
      [
        '# Installed by ThreatCrush. Intentionally matches nothing:',
        '# detection happens in threatcrushd, this jail only executes bans.',
        '[Definition]',
        'failregex = ^threatcrush-never-matches <HOST>$',
        'ignoreregex =',
        '',
      ].join('\n'),
    );

    writeIfAbsent(
      FAIL2BAN_JAIL_FILE,
      [
        '# Installed by ThreatCrush — bans arrive via `fail2ban-client set threatcrush banip`.',
        '# bantime is only a backstop; threatcrushd unbans on its own schedule.',
        `[${this.jail}]`,
        'enabled = true',
        'filter = threatcrush',
        'backend = polling',
        'logpath = /var/log/threatcrush/threatcrushd.log',
        'maxretry = 1000000',
        'findtime = 1',
        `bantime = ${this.backstopSeconds}`,
        '',
      ].join('\n'),
    );

    this.client(['reload', this.jail]);
    this.jailReady = true;
  }

  async block(ip: string): Promise<void> {
    assertBannableIp(ip);
    this.ensureJail();
    this.client(['set', this.jail, 'banip', ip]);
  }

  async unblock(ip: string): Promise<void> {
    assertBannableIp(ip);
    try {
      this.client(['set', this.jail, 'unbanip', ip]);
    } catch {
      // Not currently banned in this jail — the desired end state either way.
    }
  }

  async isBlocked(ip: string): Promise<boolean> {
    assertBannableIp(ip);
    return (await this.listBlocked()).includes(ip);
  }

  async listBlocked(): Promise<string[]> {
    // `get <jail> banned` exists from 0.11 and prints a Python list. Older
    // servers only have `status`, which prints a space-separated tail.
    try {
      return parseBannedList(this.client(['get', this.jail, 'banned']));
    } catch {
      try {
        const status = this.client(['status', this.jail]);
        const line = status.split('\n').find((l) => /Banned IP list:/i.test(l));
        if (!line) return [];
        return line.split(':').slice(1).join(':').trim().split(/\s+/).filter((s) => isIP(s) !== 0);
      } catch {
        return [];
      }
    }
  }
}

/** Pulls addresses out of fail2ban's `['1.2.3.4', '5.6.7.8']` output. */
export function parseBannedList(output: string): string[] {
  const found: string[] = [];
  for (const match of output.matchAll(/['"]([^'"]+)['"]/g)) {
    if (isIP(match[1]) !== 0) found.push(match[1]);
  }
  if (found.length > 0) return found;
  // A bare or empty list: fall back to whitespace splitting.
  return output
    .replace(/[[\],]/g, ' ')
    .split(/\s+/)
    .filter((s) => isIP(s) !== 0);
}

export class NftablesAdapter implements FirewallAdapter {
  name = 'nftables';
  private table = 'threatcrush';
  private set = 'blocklist';

  isAvailable(): boolean {
    const result = spawnSync('nft', ['--version'], { stdio: 'pipe' });
    return result.status === 0;
  }

  private ensureSetup(): void {
    try {
      execSync(`nft list table inet ${this.table} 2>/dev/null`, { stdio: 'pipe' });
    } catch {
      execSync(`nft add table inet ${this.table}`);
      execSync(`nft add set inet ${this.table} ${this.set} '{ type ipv4_addr; flags timeout; }'`);
      execSync(`nft add chain inet ${this.table} input '{ type filter hook input priority -1; policy accept; }'`);
      execSync(`nft add rule inet ${this.table} input ip saddr @${this.set} drop`);
    }
  }

  async block(ip: string): Promise<void> {
    assertValidFirewallIp(ip);
    this.ensureSetup();
    execSync(`nft add element inet ${this.table} ${this.set} '{ ${ip} }'`);
  }

  async unblock(ip: string): Promise<void> {
    assertValidFirewallIp(ip);
    try {
      execSync(`nft delete element inet ${this.table} ${this.set} '{ ${ip} }'`);
    } catch { /* element may not exist */ }
  }

  async isBlocked(ip: string): Promise<boolean> {
    assertValidFirewallIp(ip);
    try {
      const output = execSync(`nft list set inet ${this.table} ${this.set}`, { encoding: 'utf-8' });
      return output.includes(ip);
    } catch { return false; }
  }

  async listBlocked(): Promise<string[]> {
    try {
      const output = execSync(`nft list set inet ${this.table} ${this.set}`, { encoding: 'utf-8' });
      const match = output.match(/elements\s*=\s*\{([^}]*)\}/);
      if (!match) return [];
      return match[1].split(',').map(s => s.trim().split(/\s/)[0]).filter(Boolean);
    } catch { return []; }
  }
}

export class IptablesAdapter implements FirewallAdapter {
  name = 'iptables';
  private chain = 'THREATCRUSH';

  isAvailable(): boolean {
    const result = spawnSync('iptables', ['--version'], { stdio: 'pipe' });
    return result.status === 0;
  }

  private ensureChain(): void {
    try {
      execSync(`iptables -n -L ${this.chain} 2>/dev/null`, { stdio: 'pipe' });
    } catch {
      execSync(`iptables -N ${this.chain}`);
      execSync(`iptables -I INPUT 1 -j ${this.chain}`);
    }
  }

  async block(ip: string): Promise<void> {
    assertValidFirewallIp(ip);
    this.ensureChain();
    if (await this.isBlocked(ip)) return;
    execSync(`iptables -A ${this.chain} -s ${ip} -j DROP`);
  }

  async unblock(ip: string): Promise<void> {
    assertValidFirewallIp(ip);
    try { execSync(`iptables -D ${this.chain} -s ${ip} -j DROP`); }
    catch { /* rule may not exist */ }
  }

  async isBlocked(ip: string): Promise<boolean> {
    assertValidFirewallIp(ip);
    try {
      const output = execSync(`iptables -n -L ${this.chain}`, { encoding: 'utf-8' });
      return output.includes(ip);
    } catch { return false; }
  }

  async listBlocked(): Promise<string[]> {
    try {
      const output = execSync(`iptables -n -L ${this.chain}`, { encoding: 'utf-8' });
      const ips: string[] = [];
      for (const line of output.split('\n')) {
        const match = line.match(/DROP\s+all\s+--\s+(\d+\.\d+\.\d+\.\d+)/);
        if (match) ips.push(match[1]);
      }
      return ips;
    } catch { return []; }
  }
}

export class DryRunAdapter implements FirewallAdapter {
  name = 'dry-run';
  enforces = false;
  private blocked = new Set<string>();

  isAvailable(): boolean { return true; }
  async block(ip: string): Promise<void> { assertValidFirewallIp(ip); this.blocked.add(ip); }
  async unblock(ip: string): Promise<void> { assertValidFirewallIp(ip); this.blocked.delete(ip); }
  async isBlocked(ip: string): Promise<boolean> { assertValidFirewallIp(ip); return this.blocked.has(ip); }
  async listBlocked(): Promise<string[]> { return [...this.blocked]; }
}

export type FirewallBackend = 'auto' | 'fail2ban' | 'nftables' | 'iptables' | 'dry-run';

/**
 * fail2ban first when it is running: operators who have it already have jails,
 * an unban command and a ban history they trust, and a second tool writing raw
 * nft rules behind its back is how a host ends up with bans nobody can find.
 * Otherwise we manage our own chain.
 */
export function detectFirewallAdapter(backend: FirewallBackend = 'auto'): FirewallAdapter {
  const byName: Record<Exclude<FirewallBackend, 'auto'>, () => FirewallAdapter> = {
    fail2ban: () => new Fail2banAdapter(),
    nftables: () => new NftablesAdapter(),
    iptables: () => new IptablesAdapter(),
    'dry-run': () => new DryRunAdapter(),
  };

  if (backend !== 'auto') {
    const chosen = byName[backend]?.();
    // An explicitly named backend that is not usable falls back rather than
    // silently doing nothing, and the daemon logs which one it landed on.
    if (chosen?.isAvailable()) return chosen;
  }

  const f2b = new Fail2banAdapter();
  if (f2b.isAvailable()) return f2b;
  const nft = new NftablesAdapter();
  if (nft.isAvailable()) return nft;
  const ipt = new IptablesAdapter();
  if (ipt.isAvailable()) return ipt;
  return new DryRunAdapter();
}
