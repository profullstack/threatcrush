import { execFile } from 'node:child_process';
import { isIP } from 'node:net';

/** Runs `nft <args>`, optionally feeding a ruleset on stdin (for `nft -f -`). */
export type NftRunner = (args: string[], stdin?: string) => Promise<void>;

/** Its own table, so threatcrushd's ban-set reloads never touch it. */
export const TOR_NFT_TABLE = 'threatcrush-tor';

export function defaultNftRunner(): NftRunner {
  return (args, stdin) =>
    new Promise<void>((resolve, reject) => {
      const child = execFile('nft', args, { maxBuffer: 16 * 1024 * 1024 }, (err) =>
        err ? reject(err) : resolve(),
      );
      if (stdin !== undefined) child.stdin?.end(stdin);
    });
}

export interface TorExitSource {
  values(): string[];
  readonly size: number;
}

export interface TorExitBlockOptions {
  /** The live Tor exit list (daemon/core/tor-exits.ts). */
  exits: TorExitSource;
  /** True only when block_tor_ssh is on AND the backend is nftables. */
  enabled: () => boolean;
  runNft?: NftRunner;
  log?: (line: string) => void;
  intervalMs?: number;
  sshPort?: number;
}

/**
 * Proactively drops the whole Tor exit list on the SSH port, in its own
 * nftables table (`inet threatcrush-tor`) at input hook priority -100 — before
 * any accept rule is reached.
 *
 * Reactive banning (ssh-intrusion.ts) only fires *after* a login is observed,
 * and two things defeat it together: a stolen-but-valid key logs in cleanly
 * (no failed-auth to trip on), and an attacker rotates through a fresh Tor exit
 * each time, so every address is unseen on its first and only login. The dev2
 * intrusion of 2026-11-20 walked straight through ~12 exits that way. The only
 * real defence is to refuse every exit before it can connect. Nobody we operate
 * for logs in over Tor, so blocking the entire exit list on tcp/22 is safe.
 */
export class TorExitBlockEnforcer {
  private timer: NodeJS.Timeout | null = null;
  private applied = false;
  /** Set once if nft is not installed here; stops retrying and logging. */
  private unavailable = false;
  private readonly runNft: NftRunner;
  private readonly log: (line: string) => void;
  private readonly intervalMs: number;
  private readonly sshPort: number;

  constructor(private opts: TorExitBlockOptions) {
    this.runNft = opts.runNft ?? defaultNftRunner();
    this.log = opts.log ?? (() => {});
    this.intervalMs = Math.max(60_000, opts.intervalMs ?? 3_600_000);
    this.sshPort = opts.sshPort ?? 22;
  }

  start(): void {
    void this.sync();
    this.timer = setInterval(() => void this.sync(), this.intervalMs);
    this.timer.unref?.();
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
  }

  /** Apply (or tear down) the block to match the current setting and list. */
  async sync(): Promise<void> {
    if (this.unavailable) return;
    if (!this.opts.enabled()) {
      await this.teardown();
      return;
    }
    // The set is IPv4 (the bulk exit list is overwhelmingly v4); an empty list
    // is a failed refresh, never a reason to drop a block that is working.
    const ipv4 = this.opts.exits.values().filter((ip) => isIP(ip) === 4);
    if (ipv4.length === 0) return;
    try {
      await this.apply(ipv4);
      if (!this.applied) {
        this.log(`[tor] proactively blocking ${ipv4.length} Tor exits on tcp/${this.sshPort} (table inet ${TOR_NFT_TABLE})`);
      }
      this.applied = true;
    } catch (err) {
      // nft not installed: this host can't do a proactive block. Say so once
      // and stop — nothing here is going to make nft appear.
      if ((err as NodeJS.ErrnoException).code === 'ENOENT') {
        this.unavailable = true;
        this.log('[tor] nft is not installed; the proactive Tor exit block is unavailable on this host');
        return;
      }
      this.log(`[tor] could not apply the proactive Tor exit block: ${(err as Error).message}`);
    }
  }

  /** One atomic `nft -f -` transaction: declare the table, then load the set. */
  private async apply(ipv4: string[]): Promise<void> {
    const t = TOR_NFT_TABLE;
    const ruleset =
      `add table inet ${t}\n` +
      `add set inet ${t} exits { type ipv4_addr; }\n` +
      `add chain inet ${t} input { type filter hook input priority -100 ; policy accept ; }\n` +
      `flush chain inet ${t} input\n` +
      `add rule inet ${t} input tcp dport ${this.sshPort} ip saddr @exits counter drop\n` +
      `flush set inet ${t} exits\n` +
      `add element inet ${t} exits { ${ipv4.join(', ')} }\n`;
    await this.runNft(['-f', '-'], ruleset);
  }

  private async teardown(): Promise<void> {
    if (!this.applied) return;
    try {
      await this.runNft(['delete', 'table', 'inet', TOR_NFT_TABLE]);
      this.log('[tor] removed the proactive Tor exit block (block_tor_ssh off)');
    } catch {
      /* table may already be gone */
    }
    this.applied = false;
  }
}
