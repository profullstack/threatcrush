import { describe, expect, it, vi } from 'vitest';

// The adapter writes its jail under /etc/fail2ban; keep the test off the disk.
vi.mock('node:fs', async (orig) => ({
  ...(await orig<typeof import('node:fs')>()),
  mkdirSync: vi.fn(),
  writeFileSync: vi.fn(),
}));

const { Fail2banAdapter } = await import('../firewall/adapters.js');

/** fail2ban-client as it behaves before the threatcrush jail exists. */
class FakeFail2ban extends Fail2banAdapter {
  calls: string[] = [];
  running = false;

  protected override client(args: string[]): string {
    this.calls.push(args.join(' '));
    const [cmd, jail] = args;
    if (cmd === 'status' && !this.running) throw new Error("Sorry but the jail 'threatcrush' does not exist");
    if (cmd === 'reload' && jail && !this.running) throw new Error("NOK: ('threatcrush',)");
    if (cmd === 'reload' && !jail) this.running = true;
    return '';
  }
}

describe('Fail2banAdapter first ban', () => {
  it('starts a freshly written jail with a full reload, then bans', async () => {
    const f2b = new FakeFail2ban();
    await f2b.block('203.0.113.9');
    expect(f2b.calls).toEqual([
      'status threatcrush',
      'reload threatcrush',
      'reload',
      'set threatcrush banip 203.0.113.9',
    ]);
  });

  it('reloads only its own jail when the server already runs it', async () => {
    const f2b = new FakeFail2ban();
    f2b.running = true;
    await f2b.block('203.0.113.9');
    expect(f2b.calls).toEqual(['status threatcrush', 'set threatcrush banip 203.0.113.9']);
  });
});
