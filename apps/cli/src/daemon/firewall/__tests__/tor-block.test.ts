import { describe, expect, it } from 'vitest';
import { TOR_NFT_TABLE, TorExitBlockEnforcer, type NftRunner } from '../tor-block.js';

function recorder(): { runNft: NftRunner; calls: Array<{ args: string[]; stdin?: string }> } {
  const calls: Array<{ args: string[]; stdin?: string }> = [];
  const runNft: NftRunner = async (args, stdin) => {
    calls.push({ args, stdin });
  };
  return { runNft, calls };
}

describe('TorExitBlockEnforcer', () => {
  it('loads the IPv4 exits into an isolated nft table that drops tcp/22', async () => {
    const { runNft, calls } = recorder();
    const enforcer = new TorExitBlockEnforcer({
      exits: { values: () => ['185.220.101.55', '2.56.246.1', '::ffff:1.2.3.4'], size: 3 },
      enabled: () => true,
      runNft,
      sshPort: 22,
    });

    await enforcer.sync();

    expect(calls).toHaveLength(1);
    expect(calls[0].args).toEqual(['-f', '-']);
    const ruleset = calls[0].stdin ?? '';
    expect(ruleset).toContain(`add table inet ${TOR_NFT_TABLE}`);
    expect(ruleset).toContain('priority -100');
    expect(ruleset).toContain('tcp dport 22 ip saddr @exits counter drop');
    // IPv4 exits are loaded; the IPv6 one is skipped (set is ipv4_addr).
    expect(ruleset).toContain('185.220.101.55');
    expect(ruleset).toContain('2.56.246.1');
    expect(ruleset).not.toContain('1.2.3.4');
  });

  it('never tears down a working block over a momentarily empty list', async () => {
    const { runNft, calls } = recorder();
    const exits = { list: ['185.220.101.55'], get values() { return () => this.list; }, size: 1 };
    const enforcer = new TorExitBlockEnforcer({ exits: exits as never, enabled: () => true, runNft });

    await enforcer.sync(); // applies
    exits.list = []; // a failed refresh
    await enforcer.sync(); // must NOT delete the table

    expect(calls).toHaveLength(1);
    expect(calls.some((c) => c.args[0] === 'delete')).toBe(false);
  });

  it('removes the table when blocking is turned off, only if it was applied', async () => {
    const { runNft, calls } = recorder();
    let on = true;
    const enforcer = new TorExitBlockEnforcer({
      exits: { values: () => ['185.220.101.55'], size: 1 },
      enabled: () => on,
      runNft,
    });

    await enforcer.sync(); // apply
    on = false;
    await enforcer.sync(); // teardown

    const teardown = calls.find((c) => c.args[0] === 'delete');
    expect(teardown?.args).toEqual(['delete', 'table', 'inet', TOR_NFT_TABLE]);

    // A second disabled sync is a no-op (nothing to tear down).
    calls.length = 0;
    await enforcer.sync();
    expect(calls).toHaveLength(0);
  });

  it('does nothing while disabled and never applied', async () => {
    const { runNft, calls } = recorder();
    const enforcer = new TorExitBlockEnforcer({
      exits: { values: () => ['185.220.101.55'], size: 1 },
      enabled: () => false,
      runNft,
    });
    await enforcer.sync();
    expect(calls).toHaveLength(0);
  });
});
