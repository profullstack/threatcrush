import { execSync, spawnSync } from 'node:child_process';

export interface FirewallAdapter {
  name: string;
  isAvailable(): boolean;
  block(ip: string): Promise<void>;
  unblock(ip: string): Promise<void>;
  isBlocked(ip: string): Promise<boolean>;
  listBlocked(): Promise<string[]>;
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
    this.ensureSetup();
    execSync(`nft add element inet ${this.table} ${this.set} '{ ${ip} }'`);
  }

  async unblock(ip: string): Promise<void> {
    try {
      execSync(`nft delete element inet ${this.table} ${this.set} '{ ${ip} }'`);
    } catch { /* element may not exist */ }
  }

  async isBlocked(ip: string): Promise<boolean> {
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
    this.ensureChain();
    if (await this.isBlocked(ip)) return;
    execSync(`iptables -A ${this.chain} -s ${ip} -j DROP`);
  }

  async unblock(ip: string): Promise<void> {
    try { execSync(`iptables -D ${this.chain} -s ${ip} -j DROP`); }
    catch { /* rule may not exist */ }
  }

  async isBlocked(ip: string): Promise<boolean> {
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
  private blocked = new Set<string>();

  isAvailable(): boolean { return true; }
  async block(ip: string): Promise<void> { this.blocked.add(ip); }
  async unblock(ip: string): Promise<void> { this.blocked.delete(ip); }
  async isBlocked(ip: string): Promise<boolean> { return this.blocked.has(ip); }
  async listBlocked(): Promise<string[]> { return [...this.blocked]; }
}

export function detectFirewallAdapter(): FirewallAdapter {
  const nft = new NftablesAdapter();
  if (nft.isAvailable()) return nft;
  const ipt = new IptablesAdapter();
  if (ipt.isAvailable()) return ipt;
  return new DryRunAdapter();
}
