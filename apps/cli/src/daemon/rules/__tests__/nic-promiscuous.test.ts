import { describe, expect, it } from 'vitest';
import { DEFAULT_RULES } from '../default-rules.js';

const rule = DEFAULT_RULES.find((r) => r.id === 'nic-promiscuous-mode');
const re = new RegExp(rule!.match.value as string);

describe('nic-promiscuous-mode rule', () => {
  it('exists, is medium, and only alerts (no attacker IP to ban)', () => {
    expect(rule).toBeDefined();
    expect(rule!.severity).toBe('medium');
    expect(rule!.remediation?.action).toBe('alert');
  });

  it('fires for a real/physical interface', () => {
    for (const m of [
      '[kernel] enp11s0: entered promiscuous mode',
      'eth0: entered promiscuous mode',
      '[kernel] eno1: entered promiscuous mode',
      'wlp3s0: entered promiscuous mode',
    ]) {
      expect(re.test(m), m).toBe(true);
    }
  });

  it('ignores container and virtual interfaces (the normal churn)', () => {
    for (const m of [
      '[kernel] veth69e02ee: entered promiscuous mode',
      '[kernel] docker0: entered promiscuous mode',
      '[kernel] br-7f3a2b1c: entered promiscuous mode',
      '[kernel] tailscale0: entered promiscuous mode',
      '[kernel] vethe7d4cc3 (unregistering): left promiscuous mode',
      '[kernel] veth69e02ee: entered allmulticast mode',
    ]) {
      expect(re.test(m), m).toBe(false);
    }
  });
});
