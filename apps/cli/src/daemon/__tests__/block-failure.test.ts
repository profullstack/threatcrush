import { describe, it, expect, vi } from 'vitest';

vi.mock('../../core/state.js', () => ({
  getModuleState: () => undefined,
  setModuleState: () => {},
}));

const { explainBlockFailure } = await import('../firewall/remediation.js');

describe('explainBlockFailure', () => {
  it('turns a permission error into what to actually do about it', () => {
    // What the dashboard used to show verbatim:
    //   ban failed: Command failed: nft add table inet threatcrush
    //   Error: Could not process rule: Operation not permitted
    // — which reads as "you are not root", when the privilege that is missing
    // belongs to the daemon.
    const message = explainBlockFailure(
      new Error(
        'Command failed: nft add table inet threatcrush\n' +
        'Error: Could not process rule: Operation not permitted',
      ),
      'nftables',
    );
    expect(message).toMatch(/threatcrushd is running/);
    expect(message).toMatch(/not by whoever asked for it/);
    expect(message).toMatch(/install-service/);
    expect(message).toContain('nftables');
  });

  it('recognises the other spellings of a denial', () => {
    for (const raw of ['EACCES: permission denied', 'EPERM', 'you must be root']) {
      expect(explainBlockFailure(new Error(raw), 'iptables')).toMatch(/threatcrushd is running/);
    }
  });

  it('passes a non-permission error through with the backend named', () => {
    const message = explainBlockFailure(new Error('set is full'), 'nftables');
    expect(message).toContain('set is full');
    expect(message).toContain('nftables');
    expect(message).not.toMatch(/install-service/);
  });
});
